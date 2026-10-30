"""Thread-safe holder for the opened KeePass database.

The master password is used only to open the database and is never stored.
"""

import threading
from typing import Any, Optional

from secure_credentials.src.keepass_backend import KeePassHandler


class VaultGuard:
    def __init__(self, vault_path: Optional[str]) -> None:
        self._vault_path: Optional[str] = vault_path
        self._lock: threading.Lock = threading.Lock()
        self._kp: Optional[KeePassHandler] = None

    @property
    def db_path(self) -> str:
        return str(KeePassHandler(vault_path=self._vault_path).db_path)

    def is_open(self) -> bool:
        with self._lock:
            return self._kp is not None

    def open(self, master_password: str) -> bool:
        handler = KeePassHandler(vault_path=self._vault_path)
        if not handler.open_database(master_password):
            return False
        with self._lock:
            self._kp = handler
        return True

    def close(self) -> None:
        with self._lock:
            self._kp = None

    def list_metadata(self) -> Optional[dict[str, dict[str, Any]]]:
        with self._lock:
            return None if self._kp is None else self._kp.get_all_credentials()

    def retrieve(self, name: str, credential_password: str) -> tuple[bool, Optional[dict[str, Any]]]:
        """Return (vault_open, credential). credential is None on wrong password or unknown name."""
        with self._lock:
            if self._kp is None:
                return False, None
            return True, self._kp.get_credential(name, credential_password)
