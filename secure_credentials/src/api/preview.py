"""Run Vaultroom against a disposable, localhost-only demo vault."""

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn

from secure_credentials.src.api.config import Settings
from secure_credentials.src.api.server import create_app
from secure_credentials.src.api.workspace import DESKTOP_TYPES, store_metadata
from secure_credentials.src.keepass_backend import KeePassHandler

MASTER_PASSWORD = "sandbox-vault"
ENTRY_PASSWORD = "sandbox-entry"
SAMPLE_ITEMS = [
    ("Cloud console", "login", "ops@example.test", "Infrastructure", "Review rotation date", True),
    ("Deployment token", "key", "Release automation", "Infrastructure", "Review issuer permissions", True),
    ("Design workspace", "login", "design@example.test", "Work", "", False),
    ("Device recovery", "recovery", "Laptop disk encryption", "Devices", "", True),
    ("Signing service", "key", "Release pipeline", "Infrastructure", "", False),
    ("Recovery contacts", "note", "Emergency checklist", "Personal", "", False),
    ("Source control", "login", "dev@example.test", "Work", "", False),
    ("Source control recovery", "recovery", "Offline backup codes", "Work", "", False),
    ("Wi-Fi setup", "note", "Workshop network", "Personal", "", False),
]


def seed(path: Path) -> None:
    handler = KeePassHandler(str(path))
    if not handler.create_database(MASTER_PASSWORD):
        raise RuntimeError("Could not create the disposable vault")
    database = handler.kp
    assert database is not None
    for index, (name, kind, account, tag, issue, favorite) in enumerate(SAMPLE_ITEMS, 1):
        entry = handler.build_protected_entry(
            database, name, f"FICTIONAL-ENTRY-{index}", DESKTOP_TYPES[kind], ENTRY_PASSWORD
        )
        store_metadata(entry, {"type": kind, "account": account, "tag": tag, "issue": issue, "favorite": favorite})
    database.save()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    with TemporaryDirectory(prefix="vaultroom-preview-") as directory:
        path = Path(directory) / "preview.kdbx"
        seed(path)
        settings = Settings(vault_path=str(path), port=args.port, web_writes=True)
        print(f"Vaultroom at http://127.0.0.1:{settings.port}/", flush=True)
        print(f"Master password: {MASTER_PASSWORD} | Entry password: {ENTRY_PASSWORD}", flush=True)
        uvicorn.run(create_app(settings), host=settings.bind_host, port=settings.port, access_log=False)


if __name__ == "__main__":
    main()
