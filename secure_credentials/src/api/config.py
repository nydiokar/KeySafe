"""Server settings, loaded from environment variables."""

import ipaddress
from collections.abc import Mapping

from pydantic import BaseModel, Field

DEFAULT_BIND_HOST: str = "127.0.0.1"


class Settings(BaseModel):
    bind_host: str = DEFAULT_BIND_HOST
    port: int = Field(default=8080, ge=1, le=65535)
    auto_lock_seconds: int = Field(default=300, ge=10, le=86400)
    vault_path: str | None = None
    allow_public_bind: bool = False
    cookie_secure: bool = False
    trusted_proxy: bool = False
    tls_cert: str | None = None
    tls_key: str | None = None


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_wildcard(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_unspecified
    except ValueError:
        return host in {"", "*"}


def load_settings(env: Mapping[str, str]) -> Settings:
    """Build Settings from an environment mapping.

    BIND_HOST is any IP or hostname of the private-network interface to listen on
    (Tailscale, WireGuard, ZeroTier, Yggdrasil, LAN, or loopback behind a proxy).
    YGGDRASIL_IP is accepted as a deprecated alias. Raises ValueError on a wildcard
    bind without ALLOW_PUBLIC_BIND=1, or on invalid values.
    """
    host: str = (env.get("BIND_HOST") or env.get("YGGDRASIL_IP") or DEFAULT_BIND_HOST).strip().strip("[]")
    allow_public: bool = _flag(env.get("ALLOW_PUBLIC_BIND"))
    if _is_wildcard(host) and not allow_public:
        raise ValueError(
            f"Refusing to bind to wildcard address {host!r}: it listens on every interface. "
            "Set BIND_HOST to your private-network address, or ALLOW_PUBLIC_BIND=1 to override."
        )
    tls_cert: str | None = env.get("TLS_CERT") or None
    tls_key: str | None = env.get("TLS_KEY") or None
    if bool(tls_cert) != bool(tls_key):
        raise ValueError("TLS_CERT and TLS_KEY must be set together")
    return Settings(
        bind_host=host,
        port=int(env.get("API_PORT") or 8080),
        auto_lock_seconds=int(env.get("AUTO_LOCK_TIMEOUT") or 300),
        vault_path=env.get("VAULT_PATH") or None,
        allow_public_bind=allow_public,
        cookie_secure=_flag(env.get("COOKIE_SECURE")) or bool(tls_cert),
        trusted_proxy=_flag(env.get("TRUSTED_PROXY")),
        tls_cert=tls_cert,
        tls_key=tls_key,
    )
