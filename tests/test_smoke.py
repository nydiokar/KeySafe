import importlib
from pathlib import Path


def test_hash_utility_roundtrip() -> None:
    from secure_credentials.src import hash_utility

    token: bytes = hash_utility.password_encrypt(b"secret", "pw", iterations=1000)
    assert hash_utility.password_decrypt(token, "pw") == b"secret"


def test_keepass_roundtrip(tmp_path: Path) -> None:
    from secure_credentials.src.keepass_backend import KeePassHandler

    handler = KeePassHandler(str(tmp_path / "vault.kdbx"))
    assert handler.create_database("master-pass-123")
    assert handler.open_database("master-pass-123")
    assert handler.add_credential("svc", "api-key-value", "api", "cred-pass-456")
    got = handler.get_credential("svc", "cred-pass-456")
    assert got is not None
    assert got["value"] == "api-key-value"
    assert handler.get_credential("svc", "wrong") is None


def test_gui_module_imports() -> None:
    importlib.import_module("secure_credentials.src.ui.gui")
