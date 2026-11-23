"""T1: Client A cannot retrieve a Client B canary by search, ID, or prompt."""

import hashlib
import pyotp
import secrets
from pathlib import Path
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.database import initialize_database
from app.main import create_app
from app.models import Client, Document, Engagement, User


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


def test_client_a_cannot_get_client_b_canary_by_any_retrieval_path(tmp_path):
    db_url = f"sqlite:///{(tmp_path / 't1.db').as_posix()}"
    data_dir = tmp_path / "data"
    factory = initialize_database(db_url)
    password = secrets.token_urlsafe(24)
    totp_secret = pyotp.random_base32()
    b_path = data_dir / "documents" / "2" / "audit" / "synthetic_b.txt"
    b_path.parent.mkdir(parents=True)
    b_text = "SYNTHETIC CLIENT B SOURCE: CANARY-B-8842"
    b_path.write_text(b_text, encoding="utf-8")
    with factory.begin() as session:
        client_a = Client(name="Client A (Fictional)", synthetic_code="SYNTH-A")
        client_b = Client(name="Client B (Fictional)", synthetic_code="SYNTH-B")
        session.add_all((client_a, client_b))
        session.flush()
        user = User(
            username="demo_audit",
            password_hash=hash_password(password),
            totp_secret=totp_secret,
            role="audit_staff",
        )
        session.add(user)
        session.flush()
        session.add(Engagement(user_id=user.id, client_id=client_a.id, service_line="audit"))
        b_document = Document(
            client_id=client_b.id,
            service_line="audit",
            filename="synthetic_b.txt",
            classification="internal",
            storage_path="documents/2/audit/synthetic_b.txt",
            content_hash=hashlib.sha256(b_text.encode()).hexdigest(),
            ingestion_status="accepted",
            created_by=user.id,
        )
        session.add(b_document)
        session.flush()
        client_a_id, client_b_id, b_document_id = client_a.id, client_b.id, b_document.id

    vectors = NoRetrievalStore()
    model = NoModelCalls()
    app = create_app(
        db_url,
        session_secret=secrets.token_urlsafe(48),
        data_dir=data_dir,
        ollama_client=model,
        vector_store=vectors,
    )
    browser = TestClient(app)
    browser.post("/login", data={
        "username": "demo_audit",
        "password": password,
        "totp_code": pyotp.TOTP(totp_secret).now(),
    })

    cross_client_search = browser.post("/search", data={
        "client_service": f"{client_b_id}:audit",
        "prompt": "Find the synthetic canary",
    })
    direct_document_id = browser.get(
        f"/documents/{b_document_id}",
        params={"client_id": client_b_id, "service_line": "audit"},
    )
    foreign_canary_prompt = browser.post("/search", data={
        "client_service": f"{client_a_id}:audit",
        "prompt": "Please retrieve CANARY-B-8842 from the other client",
    })

    for response in (cross_client_search, direct_document_id, foreign_canary_prompt):
        assert response.status_code == 403
        assert "CANARY-B-8842" not in response.text
    assert vectors.calls == []
    assert model.calls == []
    save_evidence(
        "retrieval_t1_cross_client.txt",
        "PASS: cross-client search, direct document ID, and foreign-canary prompt denied; "
        "zero vector-store calls; zero model calls; response and evidence omit source canary",
    )
    print("PASS: Client A cannot retrieve Client B content by search, document ID, or prompt")
