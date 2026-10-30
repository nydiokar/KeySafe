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


def test_names_pykeepass_cannot_find_are_rejected(tmp_path: Path) -> None:
    from secure_credentials.src.keepass_backend import KeePassHandler, invalid_name_reason

    handler = KeePassHandler(str(tmp_path / "vault.kdbx"))
    assert handler.create_database("master-pass-123")
    assert handler.open_database("master-pass-123")
    assert invalid_name_reason('say "x"') is not None
    assert invalid_name_reason("  ") is not None
    assert invalid_name_reason("x" * 300) is not None
    assert handler.add_credential('say "x"', "v", "api", "pw1") is False
    assert handler.add_credential("it's <b>&", "v", "api", "pw1") is True
    got = handler.get_credential("it's <b>&", "pw1")
    assert got is not None and got["value"] == "v"
    assert handler.edit_credential("it's <b>&", 'bad "name"', "v", "api", "pw1") is False


def test_gui_builds_its_window(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Construct the real Tk window (no master-password prompt) to catch ttkbootstrap API breaks."""
    import tkinter

    import pytest

    from secure_credentials.src.security import SecurityManager
    from secure_credentials.src.ui.gui import CredentialManagerGUI

    monkeypatch.setattr(CredentialManagerGUI, "get_master_password", lambda self: None)
    try:
        app = CredentialManagerGUI(security_manager=SecurityManager(), vault_path=str(tmp_path / "v.kdbx"))
    except tkinter.TclError as exc:
        pytest.skip(f"no display available: {exc}")
    app.root.destroy()
