from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pykeepass import PyKeePass

from secure_credentials.src.api import workspace
from secure_credentials.src.api.config import Settings
from secure_credentials.src.api.server import create_app
from secure_credentials.src.keepass_backend import KeePassHandler

MASTER = "workspace-master"
ENTRY_PASSWORD = "entry-password"
ENTRY = {
    "name": "Production console",
    "type": "login",
    "secret": "fictional-secret",
    "notes": "fictional-private-notes",
    "credential_password": ENTRY_PASSWORD,
    "account": "ops@example.test",
    "tag": "Infrastructure",
    "issue": "Rotation due",
}


@pytest.fixture()
def path(tmp_path: Path) -> Path:
    path = tmp_path / "workspace.kdbx"
    handler = KeePassHandler(str(path))
    assert handler.create_database(MASTER)
    assert handler.add_credential("Legacy entry", "legacy-secret", "api_key", ENTRY_PASSWORD)
    return path


def sign_in(client: TestClient, password: str = MASTER) -> None:
    result = client.post("/api/unlock", json={"master_password": password})
    assert result.status_code == 200


@pytest.fixture()
def client(path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(Settings(vault_path=str(path), web_writes=True))) as client:
        sign_in(client)
        yield client


def revision(client: TestClient) -> str:
    return str(client.get("/api/workspace").json()["revision"])


def create(client: TestClient) -> str:
    response = client.post("/api/workspace/items", json=ENTRY, headers={"If-Match": revision(client)})
    assert response.status_code == 201, response.text
    return str(response.json()["ids"][0])


def test_workspace_roundtrip_persistence_and_recovery(client: TestClient, path: Path, tmp_path: Path) -> None:
    entry_id = create(client)
    item_path = f"/api/workspace/items/{entry_id}"
    view = client.get("/api/workspace")
    items = view.json()["items"]
    assert {item["type"] for item in items} == {"key", "login"}
    assert ENTRY["secret"] not in view.text and ENTRY["notes"] not in view.text
    assert items[1]["issue"] == ENTRY["issue"]
    assert client.post(f"{item_path}/retrieve", json={"credential_password": "wrong"}).status_code == 403
    credentials = {"credential_password": ENTRY_PASSWORD}
    result = client.post(f"{item_path}/retrieve", json=credentials)
    assert result.json() == {"value": ENTRY["secret"], "notes": ENTRY["notes"]}
    assert client.post(
        f"{item_path}/favorite", json={"favorite": True}, headers={"If-Match": revision(client)}
    ).status_code == 200
    edit = {key: value for key, value in ENTRY.items() if key not in {"secret", "notes"}}
    assert client.patch(
        item_path, json={**edit, "name": "Renamed console", "issue": ""}, headers={"If-Match": revision(client)}
    ).status_code == 200
    client.post("/api/lock")
    sign_in(client)
    item = next(item for item in client.get("/api/workspace").json()["items"] if item["id"] == entry_id)
    assert item["name"] == "Renamed console" and item["favorite"] and not item["issue"]
    assert client.post(f"{item_path}/retrieve", json=credentials).json() == result.json()

    backup = client.get("/api/workspace/backup")
    assert backup.status_code == 200
    snapshot = tmp_path / "restored.kdbx"
    snapshot.write_bytes(backup.content)
    restored = KeePassHandler(str(snapshot))
    assert restored.open_database(MASTER)
    assert restored.get_credential("Renamed console", ENTRY_PASSWORD, persist=False)["value"] == ENTRY["secret"]

    wrong = client.request(
        "DELETE", item_path, json={"credential_password": "wrong"}, headers={"If-Match": revision(client)}
    )
    assert wrong.status_code == 403
    deleted = client.request("DELETE", item_path, json=credentials, headers={"If-Match": revision(client)})
    assert deleted.status_code == 200
    assert client.post(f"{item_path}/retrieve", json=credentials).status_code == 403
    assert client.post(
        "/api/credentials/retrieve", json={"name": "Renamed console", **credentials}
    ).status_code == 403
    assert [item["name"] for item in client.get("/api/workspace").json()["items"]] == ["Legacy entry"]
    db = PyKeePass(str(path), password=MASTER)
    assert [entry.title for entry in db.recyclebin_group.entries] == ["Renamed console"]
    predecessor = path.with_name(f"{path.name}.previous.kdbx")
    assert predecessor.read_bytes() == snapshot.read_bytes()


def test_concurrent_writes_have_one_winner(client: TestClient) -> None:
    headers = {"If-Match": revision(client)}

    def add(name: str) -> int:
        return client.post("/api/workspace/items", json={**ENTRY, "name": name}, headers=headers).status_code

    with ThreadPoolExecutor(2) as executor:
        assert sorted(executor.map(add, ("First", "Second"))) == [201, 409]
    assert len(client.get("/api/workspace").json()["items"]) == 2


def test_write_failure_keeps_file_and_memory_intact(
    client: TestClient, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = path.read_bytes()
    replace = workspace.os.replace

    def fail_live(stage: Path, target: Path) -> None:
        if target == path:
            raise OSError("simulated write failure")
        replace(stage, target)

    with monkeypatch.context() as patch:
        patch.setattr(workspace.os, "replace", fail_live)
        error = client.post("/api/workspace/items", json=ENTRY, headers={"If-Match": revision(client)})
    assert error.status_code == 503
    assert path.read_bytes() == original
    assert [item["name"] for item in client.get("/api/workspace").json()["items"]] == ["Legacy entry"]
    assert not list(path.parent.glob(".vaultroom-*"))
    create(client)


def test_import_collision_is_atomic(client: TestClient, path: Path) -> None:
    headers = {"If-Match": revision(client)}
    original = path.read_bytes()
    duplicate = {**ENTRY, "name": "LEGACY ENTRY"}
    result = client.post("/api/workspace/import", json={"entries": [ENTRY, duplicate]}, headers=headers)
    assert result.status_code == 409
    assert path.read_bytes() == original
    good = client.post("/api/workspace/import", json={"entries": [ENTRY, {**ENTRY, "name": "New"}]}, headers=headers)
    assert good.status_code == 201
    assert len(good.json()["ids"]) == 2


def test_external_vault_replacement_blocks_writes_and_revokes_old_cookie(client: TestClient, path: Path) -> None:
    old_revision = revision(client)
    new_password = "different-master-password"
    replacement = path.with_name("replacement.kdbx")
    assert KeePassHandler(str(replacement)).create_database(new_password)
    replacement.replace(path)
    original = path.read_bytes()
    assert client.post("/api/workspace/items", json=ENTRY, headers={"If-Match": old_revision}).status_code == 409
    assert path.read_bytes() == original
    with TestClient(client.app) as other:
        sign_in(other, new_password)
        assert client.get("/api/workspace").status_code == 401
        assert other.get("/api/workspace").json()["items"] == []


def test_authorization_and_validation_errors_do_not_echo_secrets(path: Path) -> None:
    with TestClient(create_app(Settings(vault_path=str(path)))) as client:
        assert client.get("/api/workspace/backup").status_code == 401
        assert client.post("/api/workspace/items", json=ENTRY).status_code == 401
        sign_in(client)
        assert client.get("/api/workspace").json()["writable"] is False
        assert client.post("/api/workspace/items", json=ENTRY).status_code == 403
        result = client.post("/api/workspace/items", json={**ENTRY, "name": "", "secret": {"value": ENTRY["secret"]}})
        assert result.status_code == 422
        assert ENTRY["secret"] not in result.text


def test_limits_apply_to_chunked_posts_and_origins(client: TestClient) -> None:
    result = client.post("/api/unlock", content=iter((b"0" * 8192, b"0" * 8192, b"0")))
    assert result.status_code == 413
    result = client.post("/api/lock", headers={"Origin": "https://testserver"})
    assert result.status_code == 403
    assert client.get("/api/status").json()["locked"] is False
    assert client.post("/api/workspace/items", json=ENTRY).status_code == 428


def test_session_timeout_is_bounded_and_only_changes_current_session(path: Path) -> None:
    now = 1000.0
    app = create_app(Settings(vault_path=str(path), auto_lock_seconds=60), lambda: now)
    with TestClient(app) as client:
        sign_in(client)
        other = TestClient(app)
        sign_in(other)
        assert client.post("/api/workspace/timeout", json={"seconds": 61}).status_code == 422
        assert client.post("/api/workspace/timeout", json={"seconds": 10}).status_code == 200
        now += 10
        assert client.get("/api/status").json()["locked"] is True
        assert other.get("/api/status").json()["locked"] is False
        assert client.post("/api/lock").status_code == 200
        assert other.get("/api/status").json()["locked"] is False


def test_activity_survives_restart_and_is_scoped(path: Path, tmp_path: Path) -> None:
    from secure_credentials.src.api.server import configure_audit_log, logger

    audit = tmp_path / "api.log"
    handler = configure_audit_log(audit)
    try:
        settings = Settings(vault_path=str(path), web_writes=True)
        with TestClient(create_app(settings, activity_log=audit)) as first:
            sign_in(first)
            create(first)
        with TestClient(create_app(settings, activity_log=audit)) as second:
            sign_in(second)
            actions = [event["action"] for event in second.get("/api/workspace").json()["activity"]]
            assert actions[:2] == ["Vault unlocked", "Credential created"]
        other_path = tmp_path / "unrelated.kdbx"
        assert KeePassHandler(str(other_path)).create_database(MASTER)
        with TestClient(create_app(Settings(vault_path=str(other_path)), activity_log=audit)) as unrelated:
            sign_in(unrelated)
            assert [event["action"] for event in unrelated.get("/api/workspace").json()["activity"]] == [
                "Vault unlocked",
            ]
        other_path.replace(path)
        with TestClient(create_app(settings, activity_log=audit)) as replaced:
            sign_in(replaced)
            assert [event["action"] for event in replaced.get("/api/workspace").json()["activity"]] == [
                "Vault unlocked",
            ]
    finally:
        logger.removeHandler(handler)
        handler.close()
    text = audit.read_text(encoding="utf-8")
    for secret in (MASTER, ENTRY_PASSWORD, ENTRY["secret"], ENTRY["notes"], ENTRY["name"]):
        assert secret not in text


def test_independent_servers_cannot_overwrite_each_others_commit(client: TestClient, path: Path) -> None:
    app = create_app(Settings(vault_path=str(path), web_writes=True))
    with TestClient(app) as other:
        sign_in(other)
        old_revision = revision(other)
        assert old_revision == revision(client)
        create(client)
        response = other.post(
            "/api/workspace/items", json={**ENTRY, "name": "Other writer"}, headers={"If-Match": old_revision}
        )
        assert response.status_code == 409
    assert [item["name"] for item in client.get("/api/workspace").json()["items"]] == ["Legacy entry", ENTRY["name"]]
