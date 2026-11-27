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
import json
import logging
import logging.handlers
import os
import sys
import time
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from threading import RLock
from typing import NoReturn
from urllib.parse import urlparse
from uuid import UUID

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from pykeepass.entry import Entry
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from secure_credentials.src.api.activity import (
    AUDIT_BACKUPS,
    AUDIT_FILE_BYTES,
    AUDIT_LIMIT,
    AUDIT_MARKER,
    read_activity,
)
from secure_credentials.src.api.auth import Clock, LoginThrottle, SessionStore
from secure_credentials.src.api.config import Settings, load_settings
from secure_credentials.src.api.vault import VaultGuard
from secure_credentials.src.api.workspace import (
    DESKTOP_TYPES,
    VaultConflict,
    VaultWriteError,
    entry_metadata,
    find_entry,
    store_metadata,
)
from secure_credentials.src.keepass_backend import KeePassHandler, active_entries, invalid_name_reason

logger = logging.getLogger("secure_credentials.api")

STATIC_DIR: Path = Path(__file__).parent / "static"
SESSION_COOKIE: str = "sc_session"
MAX_BODY_BYTES: int = 16_384
CSP: str = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class BoundedBody:
    """Cap request bytes before FastAPI parses JSON, including chunked requests."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                await PlainTextResponse("Request too large", status_code=413)(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        pending: bytes | None = bytes(body)

        async def replay() -> Message:
            nonlocal pending
            if pending is None:
                return await receive()
            message = {"type": "http.request", "body": pending, "more_body": False}
            pending = None
            return message

        await self.app(scope, replay, send)


class CredentialMetadata(BaseModel):
    name: str
    type: str
    created_at: str | None = None
    last_accessed: str | None = None


class Credential(BaseModel):
    name: str
    value: str
    type: str


class UnlockRequest(BaseModel):
    master_password: str = Field(min_length=1, max_length=1024)


class RetrieveRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    credential_password: str = Field(min_length=1, max_length=1024)


class WorkspacePassword(BaseModel):
    credential_password: str = Field(min_length=1, max_length=1024)


class WorkspaceEntry(WorkspacePassword):
    name: str = Field(min_length=1, max_length=256)
    type: str = Field(min_length=1, max_length=100)
    account: str = Field(default="", max_length=256)
    tag: str = Field(default="", max_length=100)
    issue: str = Field(default="", max_length=150)
    secret: str | None = Field(default=None, min_length=1, max_length=8192)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("type", "account", "tag", "issue", "secret", "notes", "credential_password")
    @classmethod
    def valid_unicode(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("Invalid Unicode") from exc
        return value

    @field_validator("name")
    @classmethod
    def validate_name(cls, name: str) -> str:
        name = name.strip()
        if invalid_name_reason(name) or any(
            not (32 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD or ord(char) >= 0x10000)
            for char in name
        ):
            raise ValueError("Invalid entry name")
        return name


class FavoriteRequest(BaseModel):
    favorite: bool


class ImportRequest(BaseModel):
    entries: list[WorkspaceEntry] = Field(min_length=1, max_length=20)


class TimeoutRequest(BaseModel):
    seconds: int = Field(ge=10, le=86400)


class VaultStatus(BaseModel):
    locked: bool
    timeout_seconds: int
    seconds_until_lock: int | None = None


def _package_version() -> str:
    try:
        return version("secure_credentials")
    except PackageNotFoundError:
        return "0.0.0"


AUDIT_LOG_PATH: Path = Path.home() / ".secure_credentials" / "logs" / "api.log"


def configure_audit_log(path: Path) -> logging.Handler:
    """Attach a rotating file handler (1 MB x 3) to the API logger and return it.

    Only events are logged (unlock/lock, failures, lockouts, client address): never
    passwords, credential names or request bodies.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=AUDIT_FILE_BYTES, backupCount=AUDIT_BACKUPS, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return handler


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_app(
    settings: Settings, clock: Clock = time.monotonic, *, activity_log: Path | None = None
) -> FastAPI:
    """Build the application. All state (sessions, throttles, vault) lives in this closure."""
    vault = VaultGuard(settings.vault_path)
    sessions = SessionStore(settings.auto_lock_seconds, clock)
    unlock_client = LoginThrottle(free_attempts=3, clock=clock)
    unlock_global = LoginThrottle(free_attempts=12, max_delay=300.0, clock=clock)
    retrieve_client = LoginThrottle(free_attempts=5, clock=clock)
    operation = RLock()
    activity: deque[dict[str, str]] = deque(maxlen=AUDIT_LIMIT)
    activity_scope = ""
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
        with operation:
            if sessions.purge() == 0:
                vault.close()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async def reaper() -> None:
            while True:
                await asyncio.sleep(2)
                await asyncio.to_thread(enforce_idle)

        task = asyncio.create_task(reaper())
        try:
            yield
        finally:
            task.cancel()
            with operation:
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

    app.add_middleware(BoundedBody)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "Invalid request fields"}, status_code=422)

    @app.exception_handler(VaultConflict)
    async def changed_vault(_: Request, __: VaultConflict) -> JSONResponse:
        return JSONResponse({"detail": "Vault changed on disk. Lock and unlock before writing."}, status_code=409)

    @app.exception_handler(VaultWriteError)
    async def write_failed(_: Request, __: VaultWriteError) -> JSONResponse:
        logger.error("Vault write failed before commit")
        return JSONResponse({"detail": "Vault could not be saved. The live file was left intact."}, status_code=503)

    @app.middleware("http")
    async def reject_cross_origin_writes(request: Request, call_next):  # type: ignore[no-untyped-def]
        length: str | None = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return PlainTextResponse("Request too large", status_code=413)
        origin: str | None = request.headers.get("origin")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and origin:
            try:
                parsed = urlparse(origin)
                allowed = parsed.netloc == request.headers.get("host", "") and parsed.scheme == request.url.scheme
            except ValueError:
                allowed = False
            if not allowed:
                logger.warning("Rejected cross-origin request from %s", _client_key(request))
                return PlainTextResponse("Cross-origin request rejected", status_code=403)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        token = getattr(request.state, "vault_token", None)
        if token:
            left = sessions.seconds_left(token)
            if left is None:
                response = JSONResponse({"detail": "Vault is locked"}, status_code=401)
            else:
                response.headers["X-Vault-Idle"] = str(left)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def require_session(request: Request) -> str:
        enforce_idle()
        token: str | None = request.cookies.get(SESSION_COOKIE)
        if not token or not sessions.touch(token):
            raise HTTPException(status_code=401, detail="Vault is locked")
        request.state.vault_token = token
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

    def record(action: str) -> None:
        event = {"action": action, "at": datetime.now(timezone.utc).isoformat()}
        activity.appendleft(event)
        logger.info("%s%s", AUDIT_MARKER, json.dumps({**event, "scope": activity_scope}))

    @app.get("/api/status", response_model=VaultStatus)
    def status(request: Request) -> VaultStatus:
        with operation:
            enforce_idle()
            token = request.cookies.get(SESSION_COOKIE)
            left = sessions.seconds_left(token)
            timeout = sessions.timeout(token)
            return VaultStatus(locked=left is None, timeout_seconds=timeout, seconds_until_lock=left)

    @app.post("/api/unlock")
    def unlock(body: UnlockRequest, request: Request, response: Response) -> dict[str, object]:
        nonlocal activity_scope
        client = _client_key(request)
        with operation:
            wait = max(unlock_client.retry_after(client), unlock_global.retry_after("*"))
            if wait:
                logger.warning("Unlock refused (locked out %ss) for %s", wait, client)
                raise HTTPException(429, "Too many failed attempts", headers={"Retry-After": str(wait)})
            opened, changed = vault.open(body.master_password)
            if not opened:
                unlock_client.record_failure(client)
                unlock_global.record_failure("*")
                logger.warning("Failed unlock attempt from %s", client)
                raise HTTPException(403, "Invalid master password")
            if changed:
                sessions.revoke_all()
            scope = vault.activity_scope()
            if scope != activity_scope:
                activity.clear()
                if activity_log is not None:
                    activity.extend(read_activity(activity_log, scope))
                activity_scope = scope
            token = sessions.create()
            unlock_client.record_success(client)
            unlock_global.record_success("*")
            record("Vault unlocked")
            response.set_cookie(
                SESSION_COOKIE, token, httponly=True, samesite="strict", secure=settings.cookie_secure, path="/"
            )
        return {"status": "unlocked", "timeout_seconds": settings.auto_lock_seconds}

    @app.post("/api/lock")
    def lock(request: Request, response: Response) -> dict[str, str]:
        with operation:
            if sessions.seconds_left(request.cookies.get(SESSION_COOKIE)) is not None:
                sessions.revoke_all()
                vault.close()
                record("Vault locked manually")
            response.delete_cookie(
                SESSION_COOKIE, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict"
            )
        return {"status": "locked"}

    @app.get("/api/credentials", response_model=list[CredentialMetadata])
    def list_credentials(request: Request) -> list[CredentialMetadata]:
        with operation:
            require_session(request)
            return [
                CredentialMetadata(
                    name=name,
                    type=data.get("type", "other"),
                    created_at=data.get("created_at"),
                    last_accessed=data.get("last_accessed"),
                )
                for name, data in (vault.list_metadata() or {}).items()
            ]

    def check_entry_throttle(request: Request) -> str:
        client = _client_key(request)
        wait = retrieve_client.retry_after(client)
        if wait:
            raise HTTPException(429, "Too many failed attempts", headers={"Retry-After": str(wait)})
        return client

    def reject_entry_password(client: str) -> NoReturn:
        retrieve_client.record_failure(client)
        logger.warning("Failed credential retrieval or verification from %s", client)
        raise HTTPException(403, "Credential not found or incorrect credential password")

    @app.post("/api/credentials/retrieve", response_model=Credential)
    def retrieve_credential(body: RetrieveRequest, request: Request) -> Credential:
        with operation:
            require_session(request)
            client = check_entry_throttle(request)
            _, cred = vault.retrieve(body.name, body.credential_password)
            if cred is None:
                reject_entry_password(client)
            record("Credential retrieved")
            return Credential(name=cred["name"], value=cred["value"], type=cred["type"])

    def require_write(request: Request) -> None:
        require_session(request)
        if not settings.web_writes:
            raise HTTPException(403, "This server is configured for read-only vault access")
        match = request.headers.get("If-Match")
        if match is None:
            raise HTTPException(428, "A workspace revision is required")
        vault.snapshot()
        if match != vault.revision():
            raise HTTPException(409, "Workspace changed. Refresh before trying again.")

    def check_new_entries(entries: list[WorkspaceEntry]) -> None:
        if any(entry.secret is None or entry.type not in DESKTOP_TYPES for entry in entries):
            raise HTTPException(422, "New entries require a valid type and a secret")

    def wire_metadata(entry: WorkspaceEntry) -> dict[str, str | bool]:
        return {"type": entry.type, "account": entry.account, "tag": entry.tag, "issue": entry.issue}

    def write_notes(entry: Entry, handler: KeePassHandler, body: WorkspaceEntry) -> None:
        field = "Vaultroom protected notes"
        if body.notes:
            entry.set_custom_property(field, handler._encrypt_value(body.notes, body.credential_password), protect=True)
        elif body.notes == "" and entry.get_custom_property(field) is not None:
            entry.delete_custom_property(field)

    @app.get("/api/workspace")
    def workspace(request: Request) -> dict[str, object]:
        with operation:
            require_session(request)
            db = vault.database.kp
            assert db is not None
            return {
                "items": [entry_metadata(entry) for entry in active_entries(db)],
                "activity": list(activity),
                "writable": settings.web_writes,
                "revision": vault.revision() if settings.web_writes else None,
                "timeout_max": settings.auto_lock_seconds,
            }

    @app.post("/api/workspace/timeout")
    def change_timeout(body: TimeoutRequest, request: Request) -> dict[str, int]:
        with operation:
            token = require_session(request)
            if body.seconds > settings.auto_lock_seconds:
                raise HTTPException(422, "Timeout exceeds the configured maximum")
            sessions.set_timeout(token, body.seconds)
            return {"timeout_seconds": body.seconds}

    @app.post("/api/workspace/items/{entry_id}/retrieve")
    def retrieve_workspace_item(entry_id: UUID, body: WorkspacePassword, request: Request) -> dict[str, str]:
        with operation:
            require_session(request)
            client = check_entry_throttle(request)
            handler = vault.database
            assert handler.kp is not None
            entry = find_entry(handler.kp, entry_id)
            if entry is None:
                reject_entry_password(client)
            secret = handler.read_entry_secret(entry, body.credential_password)
            if secret is None:
                reject_entry_password(client)
            protected = entry.get_custom_property("Vaultroom protected notes")
            notes = handler._decrypt_value(protected, body.credential_password) if protected else ""
            record("Credential retrieved")
            return {"value": secret, "notes": notes or ""}

    def add_entries(entries: list[WorkspaceEntry], request: Request, action: str) -> dict[str, object]:
        with operation:
            require_write(request)
            check_new_entries(entries)
            with vault.transaction() as (handler, db):
                names = {(entry.title or "").casefold() for entry in active_entries(db)}
                created = []
                for body in entries:
                    name = body.name.casefold()
                    if name in names:
                        raise HTTPException(409, "An entry with that name already exists")
                    names.add(name)
                    assert body.secret is not None
                    entry = handler.build_protected_entry(
                        db, body.name, body.secret, DESKTOP_TYPES[body.type], body.credential_password
                    )
                    store_metadata(entry, wire_metadata(body))
                    write_notes(entry, handler, body)
                    created.append(str(entry.uuid))
            record(action)
            return {"ids": created, "revision": vault.revision()}

    @app.post("/api/workspace/items", status_code=201)
    def create_item(body: WorkspaceEntry, request: Request) -> dict[str, object]:
        return add_entries([body], request, "Credential created")

    @app.post("/api/workspace/import", status_code=201)
    def import_items(body: ImportRequest, request: Request) -> dict[str, object]:
        return add_entries(body.entries, request, "Credentials imported")

    @app.patch("/api/workspace/items/{entry_id}")
    def update_item(entry_id: UUID, body: WorkspaceEntry, request: Request) -> dict[str, str]:
        with operation:
            require_write(request)
            client = check_entry_throttle(request)
            with vault.transaction() as (handler, db):
                entry = find_entry(db, entry_id)
                if entry is None or not handler.verify_entry_password(entry, body.credential_password):
                    reject_entry_password(client)
                previous = entry_metadata(entry)
                if body.type != previous["type"] and body.type not in DESKTOP_TYPES:
                    raise HTTPException(422, "Unknown entry type")
                if body.name != entry.title and any(
                    other.uuid != entry_id and (other.title or "").casefold() == body.name.casefold()
                    for other in active_entries(db)
                ):
                    raise HTTPException(409, "An entry with that name already exists")
                entry.save_history()
                entry.title = body.name
                if body.secret is not None:
                    entry.password = handler._encrypt_value(body.secret, body.credential_password)
                if body.type != previous["type"]:
                    kind = DESKTOP_TYPES[body.type]
                    lines = [line for line in (entry.notes or "").splitlines() if not line.startswith("Type:")]
                    entry.notes = "\n".join([f"Type: {kind}", *lines])
                store_metadata(entry, {**wire_metadata(body), "favorite": previous["favorite"]})
                write_notes(entry, handler, body)
            record("Credential updated")
            return {"revision": vault.revision()}

    @app.post("/api/workspace/items/{entry_id}/favorite")
    def favorite_item(entry_id: UUID, body: FavoriteRequest, request: Request) -> dict[str, str]:
        with operation:
            require_write(request)
            with vault.transaction() as (_, db):
                entry = find_entry(db, entry_id)
                if entry is None:
                    raise HTTPException(404, "Entry not found")
                metadata = entry_metadata(entry)
                metadata["favorite"] = body.favorite
                store_metadata(entry, metadata)
            record("Favorite updated")
            return {"revision": vault.revision()}

    @app.delete("/api/workspace/items/{entry_id}")
    def delete_item(entry_id: UUID, body: WorkspacePassword, request: Request) -> dict[str, str]:
        with operation:
            require_write(request)
            client = check_entry_throttle(request)
            with vault.transaction() as (handler, db):
                entry = find_entry(db, entry_id)
                if entry is None or not handler.verify_entry_password(entry, body.credential_password):
                    reject_entry_password(client)
                db.trash_entry(entry)
            record("Credential moved to trash")
            return {"revision": vault.revision()}

    @app.get("/api/workspace/backup")
    def download_backup(request: Request) -> Response:
        with operation:
            require_session(request)
            snapshot = vault.snapshot()
            record("Encrypted backup downloaded")
            return Response(
                snapshot,
                media_type="application/octet-stream",
                headers={"Content-Disposition": 'attachment; filename="vault-backup.kdbx"'},
            )

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

    try:
        configure_audit_log(AUDIT_LOG_PATH)
    except OSError as exc:
        print(f"WARNING: audit log disabled ({exc})")
    uvicorn.run(
        create_app(settings, activity_log=AUDIT_LOG_PATH),
        host=settings.bind_host,
        port=settings.port,
        log_level="warning",
        access_log=False,
        proxy_headers=settings.trusted_proxy,
        forwarded_allow_ips="127.0.0.1" if settings.trusted_proxy else None,
        ssl_certfile=settings.tls_cert,
        ssl_keyfile=settings.tls_key,
    )


if __name__ == "__main__":
    main()
