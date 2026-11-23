"""T2: Audit staff cannot retrieve another service line for the same client."""

import pyotp
import secrets
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.auth import hash_password
from app.database import initialize_database
from app.main import create_app
from app.models import AuditLog, Client, Document, Engagement, User


def save_evidence(name, excerpt):
    evidence_dir = Path(__file__).parents[1] / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    (evidence_dir / name).write_text(excerpt + "\n", encoding="utf-8")


class NoRetrievalStore:
    def __init__(self):
        self.calls = []

    def document_hash_matches(self, *args):
        self.calls.append("document_hash_matches")
        return False

    def remove_document(self, *args):
        self.calls.append("remove_document")

    def upsert_chunks(self, *args):
        self.calls.append("upsert_chunks")

    def search(self, *args, **kwargs):
        self.calls.append("search")
        return []


class NoModelCalls:
    def __init__(self):
        self.calls = []

    def embed(self, texts):
        self.calls.append("embed")
        return [[0.1, 0.2] for _ in texts]

    def chat(self, messages):
        self.calls.append("chat")
        return ""


def test_audit_user_cannot_access_accounting_store_for_assigned_client(tmp_path):
    db_url = f"sqlite:///{(tmp_path / 't2.db').as_posix()}"
    factory = initialize_database(db_url)
    password = secrets.token_urlsafe(24)
    totp_secret = pyotp.random_base32()
    with factory.begin() as session:
        client = Client(name="Client A (Fictional)", synthetic_code="SYNTH-A")
        session.add(client)
        session.flush()
        user = User(
            username="demo_audit",
            password_hash=hash_password(password),
            totp_secret=totp_secret,
            role="audit_staff",
        )
        session.add(user)
        session.flush()
        session.add(Engagement(user_id=user.id, client_id=client.id, service_line="audit"))
        session.add(Document(
            client_id=client.id,
            service_line="accounting",
            filename="accounting_only.txt",
            classification="internal",
            storage_path="documents/1/accounting/accounting_only.txt",
            content_hash="synthetic-hash",
            ingestion_status="accepted",
            created_by=user.id,
        ))
        client_id = client.id

    vectors, model = NoRetrievalStore(), NoModelCalls()
    app = create_app(
        db_url,
        session_secret=secrets.token_urlsafe(48),
        data_dir=tmp_path / "data",
        ollama_client=model,
        vector_store=vectors,
    )
    browser = TestClient(app)
    browser.post("/login", data={
        "username": "demo_audit",
        "password": password,
        "totp_code": pyotp.TOTP(totp_secret).now(),
    })

    response = browser.post("/search", data={
        "client_service": f"{client_id}:accounting",
        "prompt": "Summarize the assigned documents",
    })

    assert response.status_code == 403
    assert "Access denied" in response.text
    assert vectors.calls == []
    assert model.calls == []
    with factory() as session:
        denial = session.scalar(select(AuditLog).where(AuditLog.event_type == "retrieval_denied"))
        assert denial is not None
        assert '"reason": "no_active_engagement"' in denial.metadata_json
        event_metadata = denial.metadata_json
    save_evidence(
        "retrieval_t2_cross_service.txt",
        f"PASS: unassigned service-line retrieval denied before vector/model access; audit metadata={event_metadata}",
    )
    print("PASS: audit staff cannot retrieve accounting data without an assignment")
