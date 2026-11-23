"""Authenticated encrypted backup and verified restore for the local lab."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import sqlite3
import tempfile
import zipfile

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select

from app.audit_chain import AuditChainError, verify_audit_chain
from app.database import initialize_database
from app.models import AuditLog


def _sqlite_path(database_url: str) -> Path:
    if not database_url.startswith("sqlite:///") or database_url == "sqlite:///:memory:":
        raise ValueError("Operational backup supports file-based SQLite databases only")
    path = Path(database_url.removeprefix("sqlite:///"))
    return path.resolve()


def _fernet(key: str | bytes) -> Fernet:
    encoded = key.encode("ascii") if isinstance(key, str) else key
    try:
        return Fernet(encoded)
    except (ValueError, TypeError) as exc:
        raise ValueError("SAPS_BACKUP_KEY must be a valid Fernet key") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def create_encrypted_backup(database_url: str, data_dir: Path | str,
                            output_path: Path | str, key: str | bytes) -> dict:
    fernet = _fernet(key)
    database_path = _sqlite_path(database_url)
    if not database_path.is_file():
        raise FileNotFoundError("SQLite database does not exist")
    data_root = Path(data_dir).resolve()
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    factory = initialize_database(database_url)
    with factory() as session:
        session.add(AuditLog(
            actor_user_id=None, event_type="backup_created",
            metadata_json=json.dumps({"format": "fernet_zip_v1"}, sort_keys=True),
        ))
        session.commit()
    factory.kw["bind"].dispose()

    with tempfile.TemporaryDirectory(prefix="saps-backup-") as temporary:
        staging = Path(temporary)
        backup_db = staging / "database" / "saps.db"
        backup_db.parent.mkdir(parents=True)
        source = sqlite3.connect(str(database_path))
        target = sqlite3.connect(str(backup_db))
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        for name in ("documents", "vectors"):
            source_dir = data_root / name
            if source_dir.is_dir():
                shutil.copytree(source_dir, staging / "data" / name)
        manifest = {
            "format": "saps-fernet-backup-v1",
            "files": {
                path.relative_to(staging).as_posix(): _sha256(path)
                for path in sorted(staging.rglob("*")) if path.is_file()
            },
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8",
        )
        archive = staging / "payload.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            for path in sorted(staging.rglob("*")):
                if path.is_file() and path != archive:
                    zipped.write(path, path.relative_to(staging).as_posix())
        encrypted = fernet.encrypt(archive.read_bytes())
        temporary_output = output.with_suffix(output.suffix + ".tmp")
        temporary_output.write_bytes(encrypted)
        os.replace(temporary_output, output)

    return {"path": str(output), "file_count": len(manifest["files"]), "manifest": manifest}


def restore_encrypted_backup(database_url: str, data_dir: Path | str,
                             backup_path: Path | str, key: str | bytes) -> dict:
    fernet = _fernet(key)
    backup = Path(backup_path).resolve()
    try:
        plaintext = fernet.decrypt(backup.read_bytes())
    except (InvalidToken, OSError) as exc:
        raise ValueError("Backup authentication failed; file or key is invalid") from exc
    database_path = _sqlite_path(database_url)
    data_root = Path(data_dir).resolve()

    with tempfile.TemporaryDirectory(prefix="saps-restore-") as temporary:
        staging = Path(temporary)
        archive = staging / "payload.zip"
        archive.write_bytes(plaintext)
        seen_names = set()
        try:
            with zipfile.ZipFile(archive) as zipped:
                for item in zipped.infolist():
                    name = item.filename
                    pure = PurePosixPath(name)
                    windows = PureWindowsPath(name)
                    if ("\\" in name or pure.is_absolute() or windows.is_absolute() or windows.drive or ".." in pure.parts or
                            name in seen_names):
                        raise ValueError("Backup archive contains an unsafe or duplicate path")
                    seen_names.add(name)
                zipped.extractall(staging / "payload")
        except zipfile.BadZipFile as exc:
            raise ValueError("Backup archive is invalid") from exc
        payload = staging / "payload"
        manifest_path = payload / "manifest.json"
        if not manifest_path.is_file():
            raise ValueError("Backup manifest is missing")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("format") != "saps-fernet-backup-v1" or not isinstance(manifest.get("files"), dict):
            raise ValueError("Backup manifest format is unsupported")
        actual_files = {
            path.relative_to(payload).as_posix(): path
            for path in payload.rglob("*") if path.is_file() and path != manifest_path
        }
        if set(actual_files) != set(manifest["files"]):
            raise ValueError("Backup file list does not match its manifest")
        for relative, expected in manifest["files"].items():
            if _sha256(actual_files[relative]) != expected:
                raise ValueError(f"Backup hash mismatch for {relative}")
        source_db = payload / "database" / "saps.db"
        if not source_db.is_file():
            raise ValueError("Backup database is missing")
        database_path.parent.mkdir(parents=True, exist_ok=True)
        staged_db = database_path.with_suffix(database_path.suffix + ".restore-tmp")
        shutil.copy2(source_db, staged_db)
        os.replace(staged_db, database_path)
        for name in ("documents", "vectors"):
            source_dir = payload / "data" / name
            target_dir = data_root / name
            if target_dir.resolve() == data_root or data_root not in target_dir.resolve().parents:
                raise ValueError("Unsafe restore target")
            if target_dir.exists():
                shutil.rmtree(target_dir)
            if source_dir.is_dir():
                shutil.copytree(source_dir, target_dir)

    factory = initialize_database(database_url)
    with factory() as session:
        valid, message = verify_audit_chain(session)
        if not valid:
            raise AuditChainError(f"Restored audit chain is invalid: {message}")
        session.add(AuditLog(
            actor_user_id=None, event_type="backup_restored",
            metadata_json=json.dumps({"file_count": len(manifest["files"]), "chain_before_restore_event": "valid"}, sort_keys=True),
        ))
        session.commit()
        valid, message = verify_audit_chain(session)
        if not valid:
            raise AuditChainError(f"Audit chain failed after restore event: {message}")
    factory.kw["bind"].dispose()
    return {"file_count": len(manifest["files"]), "chain_message": message}
