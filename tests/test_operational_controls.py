"""T4/T6 operational controls: chained admin logs, privileged boundaries, encrypted restore."""

from pathlib import Path
from io import BytesIO
import secrets
import zipfile

import pyotp
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.audit_chain import AuditChainError, verify_audit_chain
from app.auth import hash_password
from app.backup_service import create_encrypted_backup, restore_encrypted_backup
from app.database import initialize_database
from app.main import create_app
from app.models import (
    Approval, AuditLog, Client, Document, Draft, DraftCitation, Engagement, User,
)
from app.operations import secure_delete_client
from app.retrieval import AccessDenied, RetrievalService
from app.vector_store import ChromaVectorStore


def evidence(name, message):
    path = Path(__file__).parents[1] / "evidence"
    path.mkdir(exist_ok=True)
    (path / name).write_text(message + "\n", encoding="utf-8")


def new_user(session, username, role):
    secret = pyotp.random_base32()
    password = secrets.token_urlsafe(24)
    user = User(username=username, role=role, password_hash=hash_password(password), totp_secret=secret)
    session.add(user)
    session.flush()
    return user, password, secret


def login(browser, username, password, totp_secret):
    response = browser.post("/login", data={
        "username": username, "password": password,
        "totp_code": pyotp.TOTP(totp_secret).now(),
    }, follow_redirects=False)
    assert response.status_code == 303


def test_t4_it_admin_can_manage_users_and_logs_but_never_read_client_content(tmp_path):
    db_url = f"sqlite:///{(tmp_path / 'privileged.db').as_posix()}"
    factory = initialize_database(db_url)
    with factory.begin() as session:
        client = Client(name="Client A (Fictional)", synthetic_code="SYNTH-A")
        session.add(client)
        session.flush()
        admin, password, totp_secret = new_user(session, "demo_it_admin", "it_admin")
        session.add(Engagement(user_id=admin.id, client_id=client.id, service_line="audit"))
        document_path = tmp_path / "data" / "documents" / str(client.id) / "audit" / "private.txt"
        document_path.parent.mkdir(parents=True)
        document_path.write_text("SYNTHETIC CONTENT CANARY-ADMIN-PRIVATE", encoding="utf-8")
        document = Document(
            client_id=client.id, service_line="audit", filename="private.txt",
            classification="internal", storage_path=document_path.relative_to(tmp_path / "data").as_posix(),
            content_hash="fake-hash", ingestion_status="accepted",
        )
        session.add(document)
        session.flush()
        document_id, client_id = document.id, client.id
        client_draft = Draft(
            client_id=client.id, service_line="audit", draft_type="synthetic_test",
            content="SYNTHETIC OUTPUT CANARY-ADMIN-PRIVATE", status="draft", prepared_by=admin.id,
        )
        session.add(client_draft)
        session.flush()
        draft_id = client_draft.id

    class NoCalls:
        calls = []
        def embed(self, texts):
            self.calls.append("embed")
            return [[0.1, 0.2] for _ in texts]
        def chat(self, messages):
            self.calls.append("chat")
            return "should not run"

    class NoVectors:
        calls = []
        def search(self, *args, **kwargs):
            self.calls.append("search")
            return []

    model, vectors = NoCalls(), NoVectors()
    browser = TestClient(create_app(
        db_url, session_secret=secrets.token_urlsafe(48), data_dir=tmp_path / "data",
        ollama_client=model, vector_store=vectors,
    ))
    login(browser, "demo_it_admin", password, totp_secret)
    dashboard = browser.get("/dashboard")
    assert dashboard.status_code == 200
    assert "private.txt" not in dashboard.text and "CANARY-ADMIN-PRIVATE" not in dashboard.text
    assert browser.get("/documents/upload").status_code == 200
    assert "Client A (Fictional)" not in browser.get("/documents/upload").text
    assert browser.get(f"/documents/{document_id}", params={
        "client_id": client_id, "service_line": "audit",
    }).status_code == 403
    denied_search = browser.post("/search", data={
        "client_service": f"{client_id}:audit", "prompt": "Read the client file",
    })
    assert denied_search.status_code == 403
    assert "PRIVILEGED-PROMPT-CANARY" not in denied_search.text
    assert "PRIVILEGED-PROMPT-CANARY" not in browser.get("/admin/logs").text
    assert model.calls == [] and vectors.calls == []
    drafts_page = browser.get("/drafts")
    assert drafts_page.status_code == 200 and "CANARY-ADMIN-PRIVATE" not in drafts_page.text
    assert browser.get(f"/drafts/{draft_id}/export").status_code == 403
    assert "CANARY-ADMIN-PRIVATE" not in browser.get("/admin/logs").text
    assert browser.get("/admin/logs").status_code == 200
    assert browser.get("/admin/users").status_code == 200

    created = browser.post("/admin/users", data={"username": "new_audit", "role": "audit_staff"})
    assert created.status_code == 200
    assert "Demo password" in created.text and "TOTP secret" in created.text
    with factory() as session:
        new_account = session.scalar(select(User).where(User.username == "new_audit"))
        assert new_account is not None and "new_audit" in created.text
        assert created.text.find("Demo password") < created.text.find("Accounts")
        valid, message = verify_audit_chain(session)
        assert valid, message
    evidence(
        "operational_t4_privileged_access.txt",
        "PASS: IT admin user/log pages allowed; document, prompt, search, and draft content denied; "
        "zero vector/model calls; user creation logged; audit chain valid",
    )
    print("PASS: T4 IT admin manages accounts and reads metadata logs without client content access")


def test_audit_chain_detects_row_tampering_and_blocks_orm_mutation(tmp_path):
    factory = initialize_database(f"sqlite:///{(tmp_path / 'chain.db').as_posix()}")
    with factory.begin() as session:
        session.add(AuditLog(actor_user_id=None, event_type="synthetic_test_event", metadata_json='{"safe":true}'))
    with factory() as session:
        valid, message = verify_audit_chain(session)
        assert valid, message
        row = session.scalar(select(AuditLog))
        row.event_type = "silently_changed"
        with pytest.raises(AuditChainError, match="append-only"):
            session.flush()
        session.rollback()

    with factory.begin() as session:
        session.connection().exec_driver_sql("DROP TRIGGER audit_log_no_update")
        session.connection().exec_driver_sql("UPDATE audit_log SET metadata_json='{}' WHERE id=(SELECT MIN(id) FROM audit_log)")
    with factory() as session:
        valid, message = verify_audit_chain(session)
        assert not valid and "hash mismatch" in message.lower()
    evidence("operational_t4_tamper_detection.txt", "PASS: audit modification trigger blocks ORM mutation; verifier detects raw database edit")
    print("PASS: audit log rows are append-only and the verifier detects tampering")


def test_t6_encrypted_backup_delete_restore_chain_and_isolation(tmp_path):
    db_path = tmp_path / "data" / "saps.db"
    db_url = f"sqlite:///{db_path.as_posix()}"
    data_dir = tmp_path / "data"
    factory = initialize_database(db_url)
    with factory.begin() as session:
        client_a = Client(name="Client A (Fictional)", synthetic_code="SYNTH-A")
        client_b = Client(name="Client B (Fictional)", synthetic_code="SYNTH-B")
        session.add_all((client_a, client_b))
        session.flush()
        user_a, _pw_a, _totp_a = new_user(session, "audit_a", "audit_staff")
        user_b, _pw_b, _totp_b = new_user(session, "audit_b", "audit_staff")
        session.add_all((
            Engagement(user_id=user_a.id, client_id=client_a.id, service_line="audit"),
            Engagement(user_id=user_b.id, client_id=client_b.id, service_line="audit"),
        ))
        docs = []
        for client, user, letter in ((client_a, user_a, "A"), (client_b, user_b, "B")):
            path = data_dir / "documents" / str(client.id) / "audit" / "synthetic.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"SYNTHETIC CANARY-{letter}-RESTORE", encoding="utf-8")
            doc = Document(
                client_id=client.id, service_line="audit", filename="synthetic.txt",
                classification="internal", storage_path=path.relative_to(data_dir).as_posix(),
                content_hash=f"hash-{letter}", ingestion_status="accepted", created_by=user.id,
            )
            session.add(doc)
            docs.append((client, user, doc))
        session.flush()
        draft = Draft(
            client_id=client_a.id, service_line="audit", draft_type="test_note",
            content="Synthetic claim [D1:C0]", status="approved", prepared_by=user_a.id,
        )
        session.add(draft)
        session.flush()
        session.add(DraftCitation(
            draft_id=draft.id, document_id=docs[0][2].id, chunk_id="D1:C0",
            source_excerpt="Synthetic source excerpt",
        ))
        session.add(Approval(draft_id=draft.id, reviewer_id=user_b.id, decision="approved", comments=""))
        session.add(AuditLog(actor_user_id=user_a.id, event_type="synthetic_fixture_loaded", metadata_json='{"fixture":true}'))
        client_a_id, client_b_id, document_a_id, user_a_id = client_a.id, client_b.id, docs[0][2].id, user_a.id

    vectors = ChromaVectorStore(data_dir / "vectors")
    vectors.upsert_chunks(client_a_id, "audit", document_a_id, "hash-A", "synthetic.txt", "internal", ["SYNTHETIC CANARY-A-RESTORE"], [[0.1, 0.2]])
    doc_b_id = docs[1][2].id
    vectors.upsert_chunks(client_b_id, "audit", doc_b_id, "hash-B", "synthetic.txt", "internal", ["SYNTHETIC CANARY-B-RESTORE"], [[0.2, 0.1]])
    key = Fernet.generate_key()
    backup_file = tmp_path / "backups" / "synthetic.fernet"
    created = create_encrypted_backup(db_url, data_dir, backup_file, key)
    assert backup_file.is_file()
    assert b"CANARY-A-RESTORE" not in backup_file.read_bytes()
    assert created["file_count"] >= 5
    encrypted = Fernet(key).decrypt(backup_file.read_bytes())
    tampered_zip = BytesIO()
    with zipfile.ZipFile(BytesIO(encrypted), "r") as original, zipfile.ZipFile(tampered_zip, "w") as changed:
        for item in original.infolist():
            payload = original.read(item.filename)
            if item.filename.startswith("data/documents/"):
                payload += b"tampered"
            changed.writestr(item, payload)
    tampered_backup = tmp_path / "backups" / "tampered.fernet"
    tampered_backup.write_bytes(Fernet(key).encrypt(tampered_zip.getvalue()))
    with pytest.raises(ValueError, match="hash mismatch"):
        restore_encrypted_backup(db_url, data_dir, tampered_backup, key)

    with factory.begin() as session:
        deleted = secure_delete_client(session, data_dir, client_a_id, user_a_id, vectors)
    assert deleted["document_count"] == 1 and deleted["draft_count"] == 1
    assert not (data_dir / "documents" / str(client_a_id)).exists()
    assert not (data_dir / "vectors" / str(client_a_id)).exists()
    with factory() as session:
        assert session.scalar(select(Document).where(Document.client_id == client_a_id)) is None
        assert session.scalar(select(Draft).where(Draft.client_id == client_a_id)) is None
        valid, message = verify_audit_chain(session)
        assert valid, message

    vectors.close()
    factory.kw["bind"].dispose()
    restored = restore_encrypted_backup(db_url, data_dir, backup_file, key)
    assert "valid" in restored["chain_message"].lower()
    assert (data_dir / "documents" / str(client_a_id) / "audit" / "synthetic.txt").is_file()
    assert (data_dir / "vectors" / str(client_a_id) / "audit").is_dir()
    with initialize_database(db_url)() as session:
        assert session.scalar(select(Document).where(Document.client_id == client_a_id)) is not None
        assert session.scalar(select(Draft).where(Draft.client_id == client_a_id)) is not None
        assert session.scalar(select(AuditLog).where(AuditLog.event_type == "backup_restored")) is not None
        valid, message = verify_audit_chain(session)
        assert valid, message

    class NoModel:
        def embed(self, texts):
            raise AssertionError("unauthorized cross-client query reached model")
        def chat(self, messages):
            raise AssertionError("unauthorized cross-client query reached model")
    class NoSearch:
        calls = []
        def document_hash_matches(self, *args):
            self.calls.append("index")
            return True
        def search(self, *args, **kwargs):
            self.calls.append("search")
            return []

    denied_vectors = NoSearch()
    service = RetrievalService(data_dir, denied_vectors, NoModel())
    with initialize_database(db_url)() as session:
        with pytest.raises(AccessDenied):
            service.chat(session, user_a_id, client_b_id, "audit", "Find the other synthetic client")
        assert denied_vectors.calls == []
        valid, message = verify_audit_chain(session)
        assert valid, message
    evidence(
        "operational_t6_backup_restore.txt",
        "PASS: encrypted backup created; client A documents, vectors, drafts and citations removed; "
        "manifest hashes and restored audit chain verified; client A user denied client B after restore before vector access",
    )
    print("PASS: T6 encrypted backup, client wipe, verified restore, and post-restore isolation")
