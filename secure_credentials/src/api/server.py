#!/usr/bin/env python3
"""
Private-network password manager API with a small web UI.
Thin layer over KeePassHandler.

Security model:
- Unlock happens only through the web UI with the master password (never stored)
- Each unlock creates its own session (random HttpOnly cookie); all /api calls need it
- Sessions and the vault auto-lock after AUTO_LOCK_TIMEOUT seconds of inactivity
- Unlock and credential retrieval are throttled with exponential backoff
- A credential's own password is required to read its value
- Reachable only on the interface given by BIND_HOST (default: loopback)

Usage:
    python -m secure_credentials.src.api.server        (or: secure-credentials-api)
    Configure with environment variables / .env: see config.py
"""

import asyncio
import logging
import os
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from secure_credentials.src.api.auth import Clock, LoginThrottle, SessionStore
from secure_credentials.src.api.config import Settings, load_settings
from secure_credentials.src.api.vault import VaultGuard

logger = logging.getLogger("secure_credentials.api")

STATIC_DIR: Path = Path(__file__).parent / "static"
SESSION_COOKIE: str = "sc_session"
CSP: str = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class CredentialMetadata(BaseModel):
    name: str
    type: str
    created_at: Optional[str] = None
    last_accessed: Optional[str] = None


class Credential(BaseModel):
    name: str
    value: str
    type: str


class UnlockRequest(BaseModel):
    master_password: str = Field(min_length=1, max_length=1024)


class RetrieveRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    credential_password: str = Field(min_length=1, max_length=1024)


class VaultStatus(BaseModel):
    locked: bool
    timeout_seconds: int
    seconds_until_lock: Optional[int] = None


def _package_version() -> str:
    try:
        return version("secure_credentials")
    except PackageNotFoundError:
        return "0.0.0"


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_app(settings: Settings, clock: Clock = time.monotonic) -> FastAPI:
    """Build the application. All state (sessions, throttles, vault) lives in this closure."""
    vault = VaultGuard(settings.vault_path)
    sessions = SessionStore(settings.auto_lock_seconds, clock)
    unlock_client = LoginThrottle(free_attempts=3, clock=clock)
    unlock_global = LoginThrottle(free_attempts=12, max_delay=300.0, clock=clock)
    retrieve_client = LoginThrottle(free_attempts=5, clock=clock)
    unlock_serial = asyncio.Lock()
    unlocking: dict[str, bool] = {"active": False}
    static_files: dict[str, tuple[str, str]] = {
        "/": ("index.html", "text/html"),
        "/static/app.js": ("app.js", "application/javascript"),
        "/static/style.css": ("style.css", "text/css"),
    }
    static_cache: dict[str, tuple[str, str]] = {
        route: ((STATIC_DIR / fname).read_text(encoding="utf-8"), mime)
        for route, (fname, mime) in static_files.items()
    }

    def enforce_idle() -> None:
        if sessions.purge() == 0 and not unlocking["active"]:
            vault.close()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async def reaper() -> None:
            while True:
                await asyncio.sleep(2)
                enforce_idle()

        task = asyncio.create_task(reaper())
        try:
            yield
        finally:
            task.cancel()
            sessions.revoke_all()
            vault.close()

    app = FastAPI(
        title="Password Manager",
        version=_package_version(),
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def require_session(request: Request) -> str:
        enforce_idle()
        token: Optional[str] = request.cookies.get(SESSION_COOKIE)
        if not token or not sessions.touch(token):
            raise HTTPException(status_code=401, detail="Vault is locked")
        return token

    for route, (body, mime) in static_cache.items():

        def make_handler(content: str = body, media: str = mime):  # type: ignore[no-untyped-def]
            def serve() -> Response:
                return PlainTextResponse(content, media_type=media)

            return serve

        app.add_api_route(route, make_handler(), methods=["GET"], include_in_schema=False)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/status", response_model=VaultStatus)
    def status(request: Request) -> VaultStatus:
        enforce_idle()
        left: Optional[int] = sessions.seconds_left(request.cookies.get(SESSION_COOKIE))
        if left is None:
            return VaultStatus(locked=True, timeout_seconds=settings.auto_lock_seconds)
        return VaultStatus(
            locked=False, timeout_seconds=settings.auto_lock_seconds, seconds_until_lock=left
        )

    @app.post("/api/unlock")
    async def unlock(body: UnlockRequest, request: Request, response: Response) -> dict[str, object]:
        client: str = _client_key(request)
        async with unlock_serial:
            wait: int = max(unlock_client.retry_after(client), unlock_global.retry_after("*"))
            if wait > 0:
                raise HTTPException(
                    status_code=429,
                    detail="Too many failed attempts",
                    headers={"Retry-After": str(wait)},
                )
            unlocking["active"] = True
            try:
                opened: bool = await asyncio.to_thread(vault.open, body.master_password)
                token: str = sessions.create() if opened else ""
            finally:
                unlocking["active"] = False
            if not opened:
                unlock_client.record_failure(client)
                unlock_global.record_failure("*")
                logger.warning("Failed unlock attempt from %s", client)
                raise HTTPException(status_code=403, detail="Invalid master password")
            unlock_client.record_success(client)
            unlock_global.record_success("*")
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="strict",
            secure=settings.cookie_secure,
            path="/",
        )
        return {"status": "unlocked", "timeout_seconds": settings.auto_lock_seconds}

    @app.post("/api/lock")
    def lock(response: Response) -> dict[str, str]:
        sessions.revoke_all()
        vault.close()
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"status": "locked"}

    @app.get("/api/credentials", response_model=list[CredentialMetadata])
    def list_credentials(request: Request) -> list[CredentialMetadata]:
        require_session(request)
        creds = vault.list_metadata()
        if creds is None:
            raise HTTPException(status_code=401, detail="Vault is locked")
        return [
            CredentialMetadata(
                name=name,
                type=data.get("type", "other"),
                created_at=data.get("created_at"),
                last_accessed=data.get("last_accessed"),
            )
            for name, data in creds.items()
        ]

    @app.post("/api/credentials/retrieve", response_model=Credential)
    def retrieve_credential(body: RetrieveRequest, request: Request) -> Credential:
        require_session(request)
        client: str = _client_key(request)
        wait: int = retrieve_client.retry_after(client)
        if wait > 0:
            raise HTTPException(
                status_code=429,
                detail="Too many failed attempts",
                headers={"Retry-After": str(wait)},
            )
        is_open, cred = vault.retrieve(body.name, body.credential_password)
        if not is_open:
            raise HTTPException(status_code=401, detail="Vault is locked")
        if not cred:
            retrieve_client.record_failure(client)
            raise HTTPException(
                status_code=403, detail="Credential not found or incorrect credential password"
            )
        retrieve_client.record_success(client)
        return Credential(name=cred["name"], value=cred["value"], type=cred["type"])

    return app


def main() -> None:
    import uvicorn

    load_dotenv()
    try:
        settings: Settings = load_settings(os.environ)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        sys.exit(2)

    vault_file: Path = Path(VaultGuard(settings.vault_path).db_path)
    if not vault_file.exists():
        print(f"ERROR: vault not found at {vault_file}")
        print("Create it first with the GUI, or point VAULT_PATH at an existing .kdbx file.")
        sys.exit(1)

    scheme: str = "https" if settings.tls_cert else "http"
    host_display: str = f"[{settings.bind_host}]" if ":" in settings.bind_host else settings.bind_host
    print(f"Password Manager listening on {scheme}://{host_display}:{settings.port}/")
    print(f"Vault: {vault_file} | auto-lock: {settings.auto_lock_seconds}s | unlock via the web UI")
    if not settings.tls_cert and not settings.cookie_secure:
        print("Note: plain HTTP. Use an encrypted private network or set TLS_CERT/TLS_KEY.")

    uvicorn.run(
        create_app(settings),
        host=settings.bind_host,
        port=settings.port,
        log_level="warning",
        access_log=False,
        ssl_certfile=settings.tls_cert,
        ssl_keyfile=settings.tls_key,
    )


if __name__ == "__main__":
    main()
