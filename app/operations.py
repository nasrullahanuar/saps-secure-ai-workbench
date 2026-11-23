"""Privileged operational actions that never return client content."""

from pathlib import Path
import shutil

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Approval, AuditLog, Client, Document, Draft, DraftCitation, Engagement, utc_now


def secure_delete_client(session: Session, data_dir: Path | str, client_id: int, actor_user_id: int,
                         vector_store) -> dict:
    """Remove a client's stored files, vectors, drafts, and document rows, retaining a tombstone/log."""
    client = session.get(Client, client_id)
    if client is None:
        raise LookupError("Client not found")
    # Fetch only identifiers and storage paths. In particular, never materialize document or draft text.
    document_ids = session.scalars(select(Document.id).where(Document.client_id == client_id)).all()
    document_paths = session.scalars(select(Document.storage_path).where(Document.client_id == client_id)).all()
    draft_ids = session.scalars(select(Draft.id).where(Draft.client_id == client_id)).all()
    if document_ids:
        session.execute(DraftCitation.__table__.delete().where(DraftCitation.document_id.in_(document_ids)))
    if draft_ids:
        session.execute(Approval.__table__.delete().where(Approval.draft_id.in_(draft_ids)))
        session.execute(DraftCitation.__table__.delete().where(DraftCitation.draft_id.in_(draft_ids)))
    session.execute(Draft.__table__.delete().where(Draft.client_id == client_id))

    root = (Path(data_dir) / "documents").resolve()
    client_root = (root / str(client_id)).resolve()
    if client_root.parent != root:
        raise ValueError("Unsafe client document path")
    for storage_path in document_paths:
        stored = (Path(data_dir) / storage_path).resolve()
        if client_root == stored.parent or client_root in stored.parents:
            stored.unlink(missing_ok=True)
    if client_root.exists():
        shutil.rmtree(client_root)

    vector_removed = False
    remove_client = getattr(vector_store, "delete_client", None)
    if remove_client is not None:
        vector_removed = bool(remove_client(client_id))
    session.execute(Document.__table__.delete().where(Document.client_id == client_id))
    session.execute(Engagement.__table__.update().where(
        Engagement.client_id == client_id,
    ).values(status="deleted"))
    client.deleted_at = utc_now()
    session.add(AuditLog(
        actor_user_id=actor_user_id,
        event_type="client_data_deleted",
        metadata_json=(
            '{"client_id":' + str(client_id) + ',"document_count":' + str(len(document_paths)) +
            ',"draft_count":' + str(len(draft_ids)) + ',"vectors_removed":' + str(vector_removed).lower() + '}'
        ),
    ))
    session.commit()
    return {"document_count": len(document_paths), "draft_count": len(draft_ids), "vectors_removed": vector_removed}
