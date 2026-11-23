"""Append-only, SHA-256 hash chaining for audit events."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json

from sqlalchemy import event, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.models import AuditLog


class AuditChainError(RuntimeError):
    pass


def entry_hash_for(row: AuditLog) -> str:
    payload = {
        "id": row.id,
        "actor_user_id": row.actor_user_id,
        "event_type": row.event_type,
        "metadata_json": row.metadata_json,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "previous_hash": row.previous_hash,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _legacy_aware_timestamp_hash(row: AuditLog) -> str:
    """Read-only compatibility for rows created during the earlier UTC-aware encoding."""
    payload = {
        "id": row.id,
        "actor_user_id": row.actor_user_id,
        "event_type": row.event_type,
        "metadata_json": row.metadata_json,
        "created_at": row.created_at.replace(tzinfo=timezone.utc).isoformat() if row.created_at else None,
        "previous_hash": row.previous_hash,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@event.listens_for(Session, "before_flush")
def _chain_new_entries(session: Session, _flush_context, _instances) -> None:
    changed = [obj for obj in (*session.dirty, *session.deleted) if isinstance(obj, AuditLog)]
    if changed:
        raise AuditChainError("Audit log rows are append-only")
    pending = [obj for obj in session.new if isinstance(obj, AuditLog)]
    if not pending:
        return
    connection = session.connection()
    latest = connection.execute(text(
        "SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    )).first()
    last_id, previous_hash = (latest[0], latest[1]) if latest else (0, "")
    if latest and not previous_hash:
        raise AuditChainError("Existing audit chain is incomplete")
    for row in pending:
        last_id += 1
        row.id = last_id
        if row.created_at is None:
            # SQLite drops tzinfo from DateTime values, so hash its persisted UTC-naive form.
            row.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
        row.previous_hash = previous_hash
        row.entry_hash = entry_hash_for(row)
        previous_hash = row.entry_hash


def verify_audit_chain(session: Session) -> tuple[bool, str]:
    rows = session.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    previous_hash = ""
    previous_id = 0
    for row in rows:
        if row.id <= previous_id:
            return False, f"Non-increasing audit row id at row {row.id}"
        if row.previous_hash != previous_hash:
            return False, f"Previous-hash mismatch at audit row {row.id}"
        calculated = entry_hash_for(row)
        if row.entry_hash not in {calculated, _legacy_aware_timestamp_hash(row)}:
            return False, f"Entry-hash mismatch at audit row {row.id}"
        previous_hash = row.entry_hash
        previous_id = row.id
    return True, f"Audit chain valid ({len(rows)} entries)"


def initialize_audit_chain(engine: Engine) -> None:
    """Backfill only legacy rows with no hashes, verify, then forbid SQL mutations."""
    with engine.begin() as connection:
        migration_version = connection.exec_driver_sql("PRAGMA user_version").scalar_one()
        rows = connection.execute(text(
            "SELECT id, actor_user_id, event_type, metadata_json, created_at, previous_hash, entry_hash "
            "FROM audit_log ORDER BY id"
        )).all()
        if migration_version == 0 and rows and all(not row.previous_hash and not row.entry_hash for row in rows):
            previous_hash = ""
            for row in rows:
                created_text = row.created_at
                created_at = datetime.fromisoformat(created_text) if created_text else datetime.now(timezone.utc)
                record = AuditLog(
                    id=row.id, actor_user_id=row.actor_user_id, event_type=row.event_type,
                    metadata_json=row.metadata_json, created_at=created_at,
                    previous_hash=previous_hash,
                )
                record.entry_hash = entry_hash_for(record)
                connection.execute(text(
                    "UPDATE audit_log SET created_at=:created_at, previous_hash=:previous_hash, entry_hash=:entry_hash WHERE id=:id"
                ), {
                    "created_at": created_at.isoformat(), "previous_hash": previous_hash,
                    "entry_hash": record.entry_hash, "id": row.id,
                })
                previous_hash = record.entry_hash
        if migration_version == 0:
            connection.exec_driver_sql("PRAGMA user_version = 1")
        connection.exec_driver_sql(
            "CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log "
            "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END"
        )
        connection.exec_driver_sql(
            "CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log "
            "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END"
        )
    from sqlalchemy.orm import Session as OrmSession

    with OrmSession(engine) as session:
        valid, message = verify_audit_chain(session)
    if not valid:
        raise AuditChainError(message)
