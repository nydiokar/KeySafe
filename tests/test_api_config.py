import pytest

from secure_credentials.src.api.config import load_settings


def test_defaults_to_loopback() -> None:
    s = load_settings({})
    assert s.bind_host == "127.0.0.1"
    assert s.port == 8080
    assert s.auto_lock_seconds == 300


def test_bind_host_any_network_and_legacy_alias() -> None:
    assert load_settings({"BIND_HOST": "100.101.102.103"}).bind_host == "100.101.102.103"
    assert load_settings({"BIND_HOST": "fd7a:115c:a1e0::1"}).bind_host == "fd7a:115c:a1e0::1"
    assert load_settings({"YGGDRASIL_IP": "201:abcd::1"}).bind_host == "201:abcd::1"
    assert load_settings({"BIND_HOST": "a", "YGGDRASIL_IP": "b"}).bind_host == "a"


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "[::]", "*"])
def test_wildcard_refused_unless_allowed(host: str) -> None:
    with pytest.raises(ValueError):
        load_settings({"BIND_HOST": host})
    assert load_settings({"BIND_HOST": host, "ALLOW_PUBLIC_BIND": "1"}).allow_public_bind


def test_tls_requires_both_and_marks_cookie_secure() -> None:
    with pytest.raises(ValueError):
        load_settings({"TLS_CERT": "c.pem"})
    assert load_settings({"TLS_CERT": "c.pem", "TLS_KEY": "k.pem"}).cookie_secure


def test_invalid_numbers_rejected() -> None:
    with pytest.raises(ValueError):
        load_settings({"API_PORT": "70000"})
    with pytest.raises(ValueError):
        load_settings({"AUTO_LOCK_TIMEOUT": "1"})


def test_main_exits_on_wildcard_bind_and_missing_vault(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from secure_credentials.src.api import server

    monkeypatch.setattr(server, "load_dotenv", lambda: None)
    monkeypatch.setenv("BIND_HOST", "0.0.0.0")
    with pytest.raises(SystemExit) as wildcard:
        server.main()
    assert wildcard.value.code == 2

    monkeypatch.setenv("BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("VAULT_PATH", str(tmp_path / "missing.kdbx"))
    with pytest.raises(SystemExit) as missing:
        server.main()
    assert missing.value.code == 1
