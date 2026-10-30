"""Print the CHANGELOG.md section for the version given as argv[1] (e.g. "1.3.0")."""

import re
import sys
from pathlib import Path


def section(changelog: str, version: str) -> str:
    match = re.search(rf"^## {re.escape(version)}\n(.*?)(?=^## |\Z)", changelog, re.S | re.M)
    return match.group(1).strip() if match else f"Release {version}"


if __name__ == "__main__":
    print(section(Path("CHANGELOG.md").read_text(encoding="utf-8"), sys.argv[1]))
