"""Read recent Vaultroom events from the service's rotating audit log."""

import json
from pathlib import Path

AUDIT_MARKER = " Vaultroom "
AUDIT_LIMIT = 100
AUDIT_FILE_BYTES = 1_000_000
AUDIT_BACKUPS = 3


def read_activity(path: Path, scope: str) -> list[dict[str, str]]:
    matched = []
    for index in range(AUDIT_BACKUPS + 1):
        log = path if not index else path.with_name(f"{path.name}.{index}")
        try:
            with log.open("rb") as stream:
                stream.seek(max(0, log.stat().st_size - AUDIT_FILE_BYTES))
                lines = stream.read(AUDIT_FILE_BYTES).decode("utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            _, marker, payload = line.partition(AUDIT_MARKER)
            if not marker:
                continue
            try:
                event = json.loads(payload)
            except ValueError:
                continue
            if (
                isinstance(event, dict)
                and event.get("scope") == scope
                and isinstance(event.get("action"), str)
                and isinstance(event.get("at"), str)
            ):
                matched.append({"action": event["action"], "at": event["at"]})
                if len(matched) == AUDIT_LIMIT:
                    return matched
    return matched
