"""Ingestion redacts synthetic identifiers and secrets before storage or logging."""

import pyotp
import secrets
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.auth import hash_password
from app.database import initialize_database
from app.main import create_app
from app.models import AuditLog, Client, Document, Engagement, User
from app.scanner import scan_text

FAKE_SECRET = "FAKE-DEMO-ONLY-0000"
FAKE_NRIC = "900101-14-5678"


def save_evidence(name, excerpt):
    evidence_dir = Path(__file__).parents[1] / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    (evidence_dir / name).write_text(excerpt + "\n", encoding="utf-8")


def make_client(tmp_path):
    db_url = f"sqlite:///{(tmp_path / 'ingestion.db').as_posix()}"
    factory = initialize_database(db_url)
    password = secrets.token_urlsafe(24)
    totp_secret = pyotp.random_base32()
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
        client_a_id, client_b_id = client_a.id, client_b.id
    app = create_app(
        db_url, session_secret=secrets.token_urlsafe(48), data_dir=tmp_path / "data"
    )
    client = TestClient(app)
    code = pyotp.TOTP(totp_secret).now()
    login = client.post("/login", data={
        "username": "demo_audit", "password": password, "totp_code": code,
    }, follow_redirects=False)
    assert login.status_code == 303
    return client, db_url, client_a_id, client_b_id


def test_scanner_detects_common_synthetic_secret_and_identifier_patterns():
    source = (
        f"NRIC {FAKE_NRIC}; passport P12345678; bank account: 0000000000001234; "
        "Tax ID: C0000000000; API_KEY=FAKE-API-DEMO-0001; "
        "Authorization: Bearer FAKE.BEARER.TOKEN-0000; password=FAKE-PASS-0000; "
        f"MyInvois_Client_Secret={FAKE_SECRET}; SSM_PASSWORD=FAKE-SSM-DEMO-0000"
    )
    result = scan_text(source)
    assert {
        "mykad", "passport", "bank_account", "tax_identifier", "api_key",
        "bearer_token", "password", "client_secret",
    }.issubset(set(result.categories))
    assert FAKE_NRIC not in result.redacted_text
    assert FAKE_SECRET not in result.redacted_text
    assert result.classification == "restricted"
    save_evidence(
        "ingestion_scanner.txt",
        f"PASS: scanner categories={','.join(result.categories)}; classification={result.classification}; raw values omitted",
    )
    print("PASS: scanner identifies the synthetic ID and credential patterns and redacts matched values")


def test_sensitive_upload_is_redacted_before_storage_and_not_written_to_logs(tmp_path):
    client, db_url, client_a_id, _ = make_client(tmp_path)
    upload_page = client.get("/documents/upload")
    assert upload_page.status_code == 200
    assert "Client A (Fictional) - Audit" in upload_page.text
    assert "Client B (Fictional)" not in upload_page.text
    payload = (
        f"Synthetic demo only\nMYINVOIS_CLIENT_SECRET={FAKE_SECRET}\n"
        f"NRIC-pattern {FAKE_NRIC}\n"
    )
    response = client.post(
        "/documents/upload",
        data={"client_service": f"{client_a_id}:audit"},
        files={"file": ("private-looking-name.txt", payload, "text/plain")},
    )
    assert response.status_code == 200
    assert "restricted" in response.text
    assert "Client secret detected - redacted" in response.text
    assert "NRIC / MyKad pattern detected - redacted" in response.text
    assert FAKE_SECRET not in response.text and FAKE_NRIC not in response.text

    factory = initialize_database(db_url)
    with factory() as session:
        document = session.scalar(select(Document))
        assert document is not None
        stored_text = (tmp_path / "data" / document.storage_path).read_text(encoding="utf-8")
        assert FAKE_SECRET not in stored_text
        assert FAKE_NRIC not in stored_text
        logs = session.scalars(select(AuditLog)).all()
        log_text = " ".join(row.metadata_json for row in logs)
        assert FAKE_SECRET not in log_text
        assert FAKE_NRIC not in log_text
        assert "client_secret" in log_text and "mykad" in log_text
        safe_excerpt = "\n".join(row.metadata_json for row in logs if row.event_type.startswith("ingestion_"))
        save_evidence("ingestion_redaction.txt", f"PASS: stored redacted text; metadata only\n{safe_excerpt}")
    print("PASS: fake secret and NRIC are absent from stored content and audit logs")


def test_unassigned_upload_is_denied_logged_and_not_stored(tmp_path):
    client, db_url, _, client_b_id = make_client(tmp_path)
    response = client.post(
        "/documents/upload",
        data={"client_service": f"{client_b_id}:audit"},
        files={"file": ("synthetic.txt", "CANARY-B-8842", "text/plain")},
    )
    assert response.status_code == 403
    factory = initialize_database(db_url)
    with factory() as session:
        assert session.scalar(select(Document)) is None
        denied = session.scalar(select(AuditLog).where(AuditLog.event_type == "upload_denied"))
        assert denied is not None
        assert "CANARY-B-8842" not in denied.metadata_json
        safe_excerpt = denied.metadata_json
    storage_dir = tmp_path / "data" / "documents"
    assert not storage_dir.exists() or not any(storage_dir.rglob("*"))
    save_evidence("ingestion_denial.txt", f"PASS: unassigned pair denied before storage\n{safe_excerpt}")
    print("PASS: upload to an unassigned client/service pair is denied and logged without file content")
