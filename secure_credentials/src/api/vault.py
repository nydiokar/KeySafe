"""Thread-safe holder for the opened KeePass database.

The master password is used only to open the database and is never stored.
"""

import hashlib
import io
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pykeepass import PyKeePass

from secure_credentials.src.api.workspace import VaultConflict, open_snapshot, save_snapshot
from secure_credentials.src.keepass_backend import KeePassHandler


class VaultGuard:
    def __init__(self, vault_path: str | None) -> None:
        self._vault_path: str | None = vault_path
        self._lock: threading.Lock = threading.Lock()
        self._kp: KeePassHandler | None = None
        self._snapshot: bytes | None = None
        self._resolved_path: Path | None = None

    @property
    def db_path(self) -> str:
        return str(KeePassHandler(vault_path=self._vault_path).db_path)

    def is_open(self) -> bool:
        with self._lock:
            return self._kp is not None

    def open(self, master_password: str) -> tuple[bool, bool]:
        """Return whether unlock succeeded and whether it loaded a different vault."""
        handler = KeePassHandler(vault_path=self._vault_path)
        try:
            path = handler.db_path.resolve(strict=True)
            snapshot = path.read_bytes()
            opened = PyKeePass(io.BytesIO(snapshot), password=master_password)
            handler.kp = open_snapshot(snapshot, opened.transformed_key)
        except Exception:
            return False, False
        with self._lock:
            changed = self._snapshot is not None and snapshot != self._snapshot
            self._kp = handler
            self._snapshot = snapshot
            self._resolved_path = path
        return True, changed

    def close(self) -> None:
        with self._lock:
            self._kp = None
            self._snapshot = None
            self._resolved_path = None

    def list_metadata(self) -> dict[str, dict[str, Any]] | None:
        with self._lock:
            return None if self._kp is None else self._kp.get_all_credentials()

    def retrieve(self, name: str, credential_password: str) -> tuple[bool, dict[str, Any] | None]:
        """Return (vault_open, credential). credential is None on wrong password or unknown name."""
        with self._lock:
            if self._kp is None:
                return False, None
            return True, self._kp.get_credential(name, credential_password, persist=False)

    @property
    def database(self) -> KeePassHandler:
        assert self._kp is not None
        return self._kp

    def snapshot(self) -> bytes:
        assert self._kp is not None and self._snapshot is not None
        try:
            path = self._kp.db_path.resolve(strict=True)
            if path != self._resolved_path or path.read_bytes() != self._snapshot:
                raise VaultConflict
        except OSError as exc:
            raise VaultConflict from exc
        return self._snapshot

    def activity_scope(self) -> str:
        """Identify a vault generation by its path and public KDBX derivation salt."""
        assert self._resolved_path is not None and self.database.kp is not None
        header = self.database.kp.kdbx.header.value
        dynamic = header.dynamic_header
        salt = dynamic.kdf_parameters.data.dict["S"].value if header.major_version >= 4 else dynamic.transform_seed.data
        return hashlib.sha256(os.fsencode(self._resolved_path) + b"\0" + salt).hexdigest()

    def revision(self) -> str:
        assert self._snapshot is not None
        return '"' + hashlib.sha256(self._snapshot).hexdigest() + '"'

    @contextmanager
    def transaction(self) -> Iterator[tuple[KeePassHandler, PyKeePass]]:
        assert self._kp is not None and self._kp.kp is not None
        original = self.snapshot()
        key = self._kp.kp.transformed_key
        candidate = open_snapshot(original, key)
        yield self._kp, candidate
        assert self._resolved_path is not None
        self._snapshot = save_snapshot(candidate, self._resolved_path, original, key)
        self._kp.kp = candidate
