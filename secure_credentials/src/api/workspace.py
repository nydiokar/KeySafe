"""KeePass workspace metadata, encrypted snapshots and atomic file replacement."""

import io
import json
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

from pykeepass import PyKeePass
from pykeepass.entry import Entry

from secure_credentials.src.keepass_backend import active_entries

METADATA = "Vaultroom metadata v1"
DISPLAY_TYPES = {"password": "login", "api_key": "key", "api": "key"}
DESKTOP_TYPES = {"login": "password", "key": "api_key", "note": "other", "recovery": "other", "other": "other"}


class VaultWriteError(Exception):
    """A commit failed before replacing the live vault."""


class VaultConflict(Exception):
    """The on-disk vault changed since it was opened."""


def find_entry(db: PyKeePass, entry_id: UUID) -> Entry | None:
    return next((entry for entry in active_entries(db) if entry.uuid == entry_id), None)


@contextmanager
def writer_lock(path: Path) -> Iterator[None]:
    """Serialize commits from Vaultroom processes targeting the same file."""
    lock_path = path.with_name(f"{path.name}.vaultroom.lock")
    with os.fdopen(os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600), "r+b") as lock:
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise VaultConflict from exc
        yield


def entry_metadata(entry: Entry) -> dict[str, str | bool]:
    notes = entry.notes or ""
    kind = next((line.partition(":")[2].strip() for line in notes.splitlines() if line.startswith("Type:")), "other")
    projection: dict[str, str | bool] = {
        "id": str(entry.uuid),
        "name": entry.title or "",
        "type": DISPLAY_TYPES.get(kind, kind),
        "account": "",
        "tag": "",
        "favorite": False,
        "issue": "",
    }
    try:
        extra = json.loads(entry.get_custom_property(METADATA) or "{}")
    except ValueError:
        return projection
    if isinstance(extra, dict):
        for key in ("type", "account", "tag", "favorite", "issue"):
            value = extra.get(key)
            if type(value) is type(projection[key]):
                projection[key] = value
    return projection


def store_metadata(entry: Entry, metadata: dict[str, str | bool]) -> None:
    entry.set_custom_property(METADATA, json.dumps(metadata, ensure_ascii=True), protect=True)


def open_snapshot(data: bytes, key: bytes) -> PyKeePass:
    return PyKeePass(io.BytesIO(data), transformed_key=key)


@contextmanager
def staged_file(path: Path, contents: bytes) -> Iterator[Path]:
    """Stage private, flushed bytes on the same filesystem as the live vault."""
    stage = tempfile.NamedTemporaryFile(dir=path.parent, prefix=".vaultroom-", delete=False)
    stage_path = Path(stage.name)
    try:
        with stage:
            stage.write(contents)
            stage.flush()
            os.fsync(stage.fileno())
        yield stage_path
    finally:
        stage_path.unlink(missing_ok=True)


def sync_directory(path: Path) -> None:
    if os.name != "nt":
        try:
            fd = os.open(path, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            # A filesystem may lack directory fsync; the replacement has already committed.
            pass


def save_snapshot(db: PyKeePass, path: Path, original: bytes, key: bytes) -> bytes:
    """Verify a staged KDBX, then retain its predecessor before committing it."""
    try:
        buffer = io.BytesIO()
        db.save(buffer, transformed_key=key)
        updated = buffer.getvalue()
        open_snapshot(updated, key)
    except Exception as exc:
        raise VaultWriteError from exc

    backup = path.with_name(f"{path.name}.previous.kdbx")
    try:
        with staged_file(path, updated) as candidate, staged_file(backup, original) as previous, writer_lock(path):
            if path.read_bytes() != original:
                raise VaultConflict
            os.replace(previous, backup)
            sync_directory(path.parent)
            if path.read_bytes() != original:
                raise VaultConflict
            os.replace(candidate, path)
            sync_directory(path.parent)
    except OSError as exc:
        raise VaultWriteError from exc
    return updated
