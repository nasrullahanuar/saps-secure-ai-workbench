"""Authentication checks for password, TOTP, and the protected dashboard."""

import pyotp
import secrets
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.database import initialize_database
from app.main import create_app
from app.models import Client, Engagement, User


def make_client(tmp_path):
    db_url = f"sqlite:///{(tmp_path / 'auth.db').as_posix()}"
    factory = initialize_database(db_url)
    password = secrets.token_urlsafe(24)
    totp_secret = pyotp.random_base32()
    with factory.begin() as session:
        client = Client(name="Client A (Fictional)", synthetic_code="SYNTH-A")
        session.add(client)
        user = User(
            username="demo_audit",
            password_hash=hash_password(password),
            totp_secret=totp_secret,
            role="audit_staff",
        )
        session.add(user)
        session.flush()
        session.add(Engagement(user_id=user.id, client_id=client.id, service_line="audit"))
    app = create_app(db_url, session_secret=secrets.token_urlsafe(48), session_timeout_seconds=1800)
    return TestClient(app), password, totp_secret


def test_dashboard_requires_login(tmp_path):
    client, _, _ = make_client(tmp_path)
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_valid_password_and_totp_open_assigned_dashboard(tmp_path):
    client, password, totp_secret = make_client(tmp_path)
    code = pyotp.TOTP(totp_secret).now()
    response = client.post("/login", data={
        "username": "demo_audit", "password": password, "totp_code": code,
    }, follow_redirects=True)
    assert response.status_code == 200
    assert "Role:" in response.text and "audit_staff" in response.text
    assert "Client A (Fictional)" in response.text and "Audit" in response.text


def test_invalid_password_or_totp_is_denied(tmp_path):
    client, password, _ = make_client(tmp_path)
    response = client.post("/login", data={
        "username": "demo_audit", "password": password, "totp_code": "abcdef",
    })
    assert response.status_code == 401
    assert "Login failed" in response.text
