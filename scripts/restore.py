"""Restore a Fernet backup after verifying archive and file hashes."""

import argparse
import os
import sys
from pathlib import Path

from app.backup_service import restore_encrypted_backup
from app.config import get_settings


def main() -> int:
    settings = get_settings()
    key = os.getenv("SAPS_BACKUP_KEY", "")
    if not key or key == "generate-a-fernet-key-before-use":
        print("Set SAPS_BACKUP_KEY in your local .env before restoring a backup.")
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("backup", type=Path, help="Encrypted .fernet backup file")
    args = parser.parse_args()
    try:
        result = restore_encrypted_backup(settings.database_url, settings.data_dir, args.backup, key)
    except Exception as exc:
        print(f"FAIL: restore not verified ({type(exc).__name__}: {exc})")
        return 1
    print(f"PASS: backup hashes verified; {result['chain_message']}; {result['file_count']} files restored")
    return 0


if __name__ == "__main__":
    sys.exit(main())
