import importlib
from pathlib import Path

import pytest

MASTER: str = "master-pass-123"
CRED_PW: str = "cred-pass-456"


def test_hash_utility_roundtrip() -> None:
    from secure_credentials.src import hash_utility

    token: bytes = hash_utility.password_encrypt(b"secret", "pw", iterations=1000)
    assert hash_utility.password_decrypt(token, "pw") == b"secret"


def test_keepass_roundtrip(tmp_path: Path) -> None:
    from secure_credentials.src.keepass_backend import KeePassHandler

    vault: Path = tmp_path / "vault.kdbx"
    handler = KeePassHandler(str(vault))
    assert handler.create_database(MASTER)
    assert handler.open_database(MASTER)
    assert handler.add_credential("svc", "api-key-value", "api", CRED_PW)
    got = handler.get_credential("svc", CRED_PW)
    assert got is not None
    assert got["value"] == "api-key-value"
    assert handler.get_credential("svc", "wrong") is None


def test_api_unlock_flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from secure_credentials.src.keepass_backend import KeePassHandler

    vault: Path = tmp_path / "vault.kdbx"
    assert KeePassHandler(str(vault)).create_database(MASTER)
    monkeypatch.setenv("YGGDRASIL_IP", "127.0.0.1")
    monkeypatch.setenv("VAULT_PATH", str(vault))
    server = importlib.import_module("secure_credentials.src.api.server")

    client = TestClient(server.app)
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/unlock", json={"master_password": "bad"}).status_code == 403
    assert client.post("/api/unlock", json={"master_password": MASTER}).status_code == 200
    assert client.post("/api/lock").json() == {"status": "locked"}


def test_gui_module_imports() -> None:
    importlib.import_module("secure_credentials.src.ui.gui")
