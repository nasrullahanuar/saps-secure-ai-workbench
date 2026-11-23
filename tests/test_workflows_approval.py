"""T5: workflow outputs are cited drafts with independent approval and gated export."""

from pathlib import Path
import secrets

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.auth import hash_password
from app.database import initialize_database
from app.main import create_app
from app.models import Approval, AuditLog, Client, Document, Draft, DraftCitation, Engagement, User
from app.retrieval import SourceChunk
from app.workflow_policy import valid_cited_claim_lines


def save_evidence(name: str, text: str) -> None:
    evidence_dir = Path(__file__).parents[1] / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    (evidence_dir / name).write_text(text + "\n", encoding="utf-8")


class FakeVectors:
    def __init__(self, document_id):
        self.document_id = document_id
        self.calls = []

    def document_hash_matches(self, *args):
        self.calls.append("hash")
        return True

    def remove_document(self, *args):
        self.calls.append("remove")

    def upsert_chunks(self, *args):
        self.calls.append("upsert")

    def search(self, client_id, service_line, embedding, limit=5):
        self.calls.append(("search", client_id, service_line))
        return [{
            "text": "Synthetic ledger entry dated 2026-10-10 for MYR 10000.00.",
            "metadata": {
                "client_id": client_id, "service_line": service_line,
                "document_id": self.document_id, "chunk_index": 0,
                "filename": "synthetic_ledger.csv", "classification": "internal",
            },
            "distance": 0.1,
        }]


class FakeOllama:
    def __init__(self):
        self.response = ""
        self.calls = []

    def embed(self, texts):
        self.calls.append("embed")
        return [[0.2, 0.3] for _ in texts]

    def chat(self, messages):
        self.calls.append("chat")
        return self.response


def make_demo(tmp_path):
    db_url = f"sqlite:///{(tmp_path / 'workflow.db').as_posix()}"
    factory = initialize_database(db_url)
    credentials = {}
    totp_secrets = {}
    with factory.begin() as session:
        client = Client(name="Client A (Fictional)", synthetic_code="SYNTH-A")
        session.add(client)
        session.flush()
        for username, role in (("demo_audit", "audit_staff"), ("demo_partner", "partner"),
                               ("demo_accounting", "accounting_staff")):
            password = secrets.token_urlsafe(24)
            totp_secret = pyotp.random_base32()
            user = User(username=username, password_hash=hash_password(password),
                        totp_secret=totp_secret, role=role)
            session.add(user)
            session.flush()
            credentials[username] = (password, user.id)
            totp_secrets[username] = totp_secret
            session.add(Engagement(user_id=user.id, client_id=client.id, service_line="audit"))
        document = Document(
            client_id=client.id, service_line="audit", filename="synthetic_ledger.csv",
            classification="internal", storage_path="documents/1/audit/ledger.csv",
            content_hash="synthetic-content-hash", ingestion_status="accepted",
        )
        session.add(document)
        session.flush()
        document_id, client_id = document.id, client.id
    model = FakeOllama()
    model.response = f"- Synthetic audit risk note supported by the ledger [D{document_id}:C0]"
    vectors = FakeVectors(document_id)
    app = create_app(
        db_url, session_secret=secrets.token_urlsafe(48), data_dir=tmp_path / "data",
        ollama_client=model, vector_store=vectors,
    )
    return factory, credentials, totp_secrets, client_id, document_id, model, vectors, app


def login(browser, username, credentials, totp_secrets):
    password, _user_id = credentials[username]
    response = browser.post("/login", data={
        "username": username, "password": password,
        "totp_code": pyotp.TOTP(totp_secrets[username]).now(),
    }, follow_redirects=False)
    assert response.status_code == 303


def test_t5_cited_workflow_draft_requires_independent_review_and_approval(tmp_path):
    factory, credentials, totp_secrets, client_id, document_id, model, vectors, app = make_demo(tmp_path)
    preparer = TestClient(app)
    login(preparer, "demo_audit", credentials, totp_secrets)
    assert preparer.get("/workflows").status_code == 200

    generated = preparer.post("/workflows/generate", data={"client_service": f"{client_id}:audit"})
    assert generated.status_code == 200
    assert "AI-generated draft - not audit evidence / not an approved entry / not a filed document" in generated.text
    assert "Saved as Draft #1" in generated.text
    assert vectors.calls[-1] == ("search", client_id, "audit")
    assert "remove" not in vectors.calls and "upsert" not in vectors.calls

    with factory() as session:
        draft = session.scalar(select(Draft))
        assert draft is not None and draft.status == "draft"
        assert draft.prepared_by == credentials["demo_audit"][1]
        citations = session.scalars(select(DraftCitation).where(DraftCitation.draft_id == draft.id)).all()
        assert len(citations) == 1 and citations[0].document_id == document_id
        draft_id = draft.id
    assert preparer.get("/drafts").status_code == 200

    # Preparer cannot approve, and nobody can skip the Reviewed state.
    assert preparer.post(f"/drafts/{draft_id}/approve", data={"comments": "self"}).status_code == 403
    partner = TestClient(app)
    login(partner, "demo_partner", credentials, totp_secrets)
    assert partner.get("/approvals").status_code == 200
    assert partner.get("/admin/engagements").status_code == 200
    assert partner.post(f"/drafts/{draft_id}/approve", data={"comments": "skip"}).status_code == 409
    assert preparer.get(f"/drafts/{draft_id}/export").status_code == 409

    assert partner.post(f"/drafts/{draft_id}/review", data={"comments": "Reviewed against the synthetic source."}, follow_redirects=False).status_code == 303
    assert partner.get(f"/drafts/{draft_id}/export").status_code == 409
    assert partner.post(f"/drafts/{draft_id}/approve", data={"comments": "Approved for the demo."}, follow_redirects=False).status_code == 303
    exported = partner.get(f"/drafts/{draft_id}/export")
    assert exported.status_code == 200
    assert f"[D{document_id}:C0]" in exported.text

    with factory() as session:
        assert session.get(Draft, draft_id).status == "approved"
        assert {approval.decision for approval in session.scalars(
            select(Approval).where(Approval.draft_id == draft_id)
        )} == {"reviewed", "approved"}
        assert session.scalar(select(AuditLog).where(AuditLog.event_type == "draft_exported")) is not None
    save_evidence(
        "workflow_t5_approval.txt",
        "PASS: generated draft has a source citation; preparer self-approval denied; "
        "approval cannot skip Reviewed; export denied before approval and allowed after independent approval",
    )
    print("PASS: T5 citations, independent approval states, and approved-only export are enforced")


def test_each_workflow_claim_line_requires_a_returned_source_citation():
    source = SourceChunk("D4:C0", 4, "synthetic.txt", "Synthetic source", "internal", False)
    assert valid_cited_claim_lines("- Supported synthetic claim [D4:C0]", (source,))
    assert not valid_cited_claim_lines("- Unsupported synthetic claim", (source,))
    assert not valid_cited_claim_lines("- Forged citation [D99:C8]", (source,))
    print("PASS: every saved factual claim line must cite a chunk actually returned by retrieval")


def test_independence_review_blocks_conflicting_assignment_until_partner_clears(tmp_path):
    factory, credentials, totp_secrets, client_id, _doc, _model, _vectors, app = make_demo(tmp_path)
    partner = TestClient(app)
    login(partner, "demo_partner", credentials, totp_secrets)
    assert partner.get("/admin/engagements").status_code == 200
    accounting_user_id = credentials["demo_accounting"][1]
    denied = partner.post("/admin/engagements/assign", data={
        "user_id": accounting_user_id, "client_id": client_id, "service_line": "accounting",
    })
    assert denied.status_code == 409
    review = partner.post("/admin/engagements/independence-review", data={
        "client_id": client_id, "decision": "cleared",
        "review_text": "Synthetic independence review completed before assignment.",
    }, follow_redirects=False)
    assert review.status_code == 303
    assigned = partner.post("/admin/engagements/assign", data={
        "user_id": accounting_user_id, "client_id": client_id, "service_line": "accounting",
    }, follow_redirects=False)
    assert assigned.status_code == 303
    with factory() as session:
        assert session.scalar(select(Engagement.id).where(
            Engagement.user_id == accounting_user_id, Engagement.client_id == client_id,
            Engagement.service_line == "accounting",
        )) is not None
        assert session.scalar(select(AuditLog).where(
            AuditLog.event_type == "independence_assignment_blocked",
        )) is not None
        assert session.scalar(select(AuditLog).where(
            AuditLog.event_type == "independence_review_recorded",
        )) is not None
    save_evidence(
        "workflow_independence.txt",
        "PASS: conflicting audit/non-audit assignment blocked before partner review; partner clearance recorded; assignment then allowed",
    )
    print("PASS: conflicting assignments require a documented partner independence review")
