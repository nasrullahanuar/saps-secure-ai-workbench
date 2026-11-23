"""Create an encrypted Fernet backup of the SQLite database and local client data."""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

from app.backup_service import create_encrypted_backup
from app.config import get_settings


def main() -> int:
    settings = get_settings()
    key = os.getenv("SAPS_BACKUP_KEY", "")
    if not key or key == "generate-a-fernet-key-before-use":
        print("Set SAPS_BACKUP_KEY in your local .env before creating a backup.")
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or Path("backups") / f"saps-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.fernet"
    try:
        result = create_encrypted_backup(settings.database_url, settings.data_dir, output, key)
    except Exception as exc:
        print(f"FAIL: backup not created ({type(exc).__name__}: {exc})")
        return 1
    print(f"PASS: encrypted backup created at {result['path']} ({result['file_count']} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
