from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from secure_credentials.src.api.config import Settings
from secure_credentials.src.api.server import SESSION_COOKIE, create_app
from secure_credentials.src.keepass_backend import KeePassHandler

MASTER: str = "master-pass-123"
CRED_PW: str = "cred-pass-456"
CRED_NAME: str = "<b>x</b>&amp;`y`"


class FakeClock:
    def __init__(self) -> None:
        self.now: float = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(scope="module")
def vault_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path: Path = tmp_path_factory.mktemp("vault") / "vault.kdbx"
    handler = KeePassHandler(str(path))
    assert handler.create_database(MASTER)
    assert handler.open_database(MASTER)
    assert handler.add_credential(CRED_NAME, "secret-value", "api", CRED_PW)
    return path


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def client(vault_file: Path, clock: FakeClock) -> Iterator[TestClient]:
    app = create_app(Settings(vault_path=str(vault_file), auto_lock_seconds=60), clock)
    with TestClient(app) as c:
        yield c


def unlock(client: TestClient, password: str = MASTER) -> Response:
    return client.post("/api/unlock", json={"master_password": password})


def test_locked_by_default_and_api_requires_session(client: TestClient) -> None:
    assert client.get("/api/status").json()["locked"] is True
    assert client.get("/api/credentials").status_code == 401
    body = {"name": "x", "credential_password": "y"}
    assert client.post("/api/credentials/retrieve", json=body).status_code == 401


def test_unlock_flow_retrieve_and_lock(client: TestClient) -> None:
    assert unlock(client, "wrong").status_code == 403
    r = unlock(client)
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/api/status").json()["locked"] is False
    names = [c["name"] for c in client.get("/api/credentials").json()]
    assert names == [CRED_NAME]
    bad = client.post("/api/credentials/retrieve", json={"name": CRED_NAME, "credential_password": "no"})
    assert bad.status_code == 403
    ok = client.post("/api/credentials/retrieve", json={"name": CRED_NAME, "credential_password": CRED_PW})
    assert ok.status_code == 200 and ok.json()["value"] == "secret-value"
    assert client.post("/api/lock").status_code == 200
    assert client.get("/api/credentials").status_code == 401


def test_session_is_per_client(client: TestClient) -> None:
    unlock(client)
    other = TestClient(client.app)
    assert other.get("/api/credentials").status_code == 401
    assert other.get("/api/status").json()["locked"] is True


def test_forged_cookie_rejected(client: TestClient) -> None:
    unlock(client)
    forged = TestClient(client.app, cookies={SESSION_COOKIE: "x" * 43})
    assert forged.get("/api/credentials").status_code == 401


def test_auto_lock_after_idle(client: TestClient, clock: FakeClock) -> None:
    unlock(client)
    clock.now += 30
    assert client.get("/api/credentials").status_code == 200
    clock.now += 61
    assert client.get("/api/status").json()["locked"] is True
    assert client.get("/api/credentials").status_code == 401


def test_status_poll_does_not_extend_session(client: TestClient, clock: FakeClock) -> None:
    unlock(client)
    for _ in range(4):
        clock.now += 20
        client.get("/api/status")
    assert client.get("/api/status").json()["locked"] is True


def test_unlock_backoff_returns_429_with_retry_after(client: TestClient, clock: FakeClock) -> None:
    for _ in range(4):
        assert unlock(client, "wrong").status_code == 403
    r = unlock(client, MASTER)
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) >= 1
    clock.now += 5
    assert unlock(client, MASTER).status_code == 200


def test_retrieve_backoff(client: TestClient) -> None:
    unlock(client)
    body = {"name": CRED_NAME, "credential_password": "bad"}
    codes = [client.post("/api/credentials/retrieve", json=body).status_code for _ in range(7)]
    assert 429 in codes


def test_security_headers_and_no_openapi(client: TestClient) -> None:
    for path in ("/", "/api/health", "/static/app.js", "/static/style.css"):
        r = client.get(path)
        assert r.status_code == 200
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    html = client.get("/").text
    assert "onclick" not in html and "style=" not in html and "<script>" not in html


def test_input_limits(client: TestClient) -> None:
    assert client.post("/api/unlock", json={"master_password": "x" * 2000}).status_code == 422
    assert client.post("/api/unlock", json={"master_password": ""}).status_code == 422


def test_cross_origin_post_rejected_same_origin_allowed(client: TestClient) -> None:
    body = {"master_password": MASTER}
    evil = client.post("/api/unlock", json=body, headers={"Origin": "http://evil.example"})
    assert evil.status_code == 403
    assert client.get("/api/status").json()["locked"] is True
    same = client.post("/api/unlock", json=body, headers={"Origin": "http://testserver"})
    assert same.status_code == 200
    assert client.post("/api/lock").status_code == 200  # no Origin header: allowed


def test_audit_log_records_events_without_secrets(client: TestClient, tmp_path: Path) -> None:
    from secure_credentials.src.api.server import configure_audit_log, logger

    log_file: Path = tmp_path / "logs" / "api.log"
    handler = configure_audit_log(log_file)
    try:
        unlock(client, "super-secret-wrong-guess")
        unlock(client)
        client.post("/api/credentials/retrieve", json={"name": CRED_NAME, "credential_password": "guess-xyz"})
    finally:
        handler.flush()
        logger.removeHandler(handler)
        handler.close()
    text: str = log_file.read_text(encoding="utf-8")
    assert "Failed unlock attempt" in text and "Vault unlocked" in text and "Failed credential retrieval" in text
    for secret in ("super-secret-wrong-guess", MASTER, "guess-xyz", CRED_PW, CRED_NAME):
        assert secret not in text


def test_replaced_vault_file_is_seen_after_relock(tmp_path: Path, clock: FakeClock) -> None:
    """Sync model: a vault file copied over the server's copy is picked up on the next unlock."""
    import shutil

    def build(path: Path, cred: str) -> None:
        h = KeePassHandler(str(path))
        assert h.create_database(MASTER) and h.open_database(MASTER)
        assert h.add_credential(cred, "v", "api", CRED_PW)

    live: Path = tmp_path / "live.kdbx"
    updated: Path = tmp_path / "updated.kdbx"
    build(live, "first")
    build(updated, "second")
    with TestClient(create_app(Settings(vault_path=str(live), auto_lock_seconds=60), clock)) as c:
        assert unlock(c).status_code == 200
        assert [x["name"] for x in c.get("/api/credentials").json()] == ["first"]
        assert c.post("/api/lock").status_code == 200
        shutil.copyfile(updated, live)
        assert unlock(c).status_code == 200
        assert [x["name"] for x in c.get("/api/credentials").json()] == ["second"]


def test_retrieve_does_not_modify_vault_file(client: TestClient, vault_file: Path) -> None:
    import hashlib

    before: str = hashlib.sha256(vault_file.read_bytes()).hexdigest()
    unlock(client)
    ok = client.post("/api/credentials/retrieve", json={"name": CRED_NAME, "credential_password": CRED_PW})
    assert ok.status_code == 200
    assert hashlib.sha256(vault_file.read_bytes()).hexdigest() == before


def test_oversized_body_rejected_and_headers_on_rejections(client: TestClient) -> None:
    big = client.post("/api/unlock", content=b"x" * 20_000, headers={"Content-Type": "application/json"})
    assert big.status_code == 413
    evil = client.post(
        "/api/unlock", json={"master_password": MASTER}, headers={"Origin": "http://evil.example"}
    )
    assert evil.status_code == 403
    assert "frame-ancestors" in evil.headers["content-security-policy"]
