"""Seed fictional clients, role accounts, and isolated demo engagements."""

import secrets

import pyotp
from sqlalchemy import select

from app.auth import hash_password
from app.database import initialize_database
from app.models import Client, Engagement, User

DEMO_USERS = (
    ("demo_partner", "partner", (("A", "audit"), ("B", "accounting"), ("C", "cosec"))),
    ("demo_audit", "audit_staff", (("A", "audit"),)),
    ("demo_accounting", "accounting_staff", (("B", "accounting"),)),
    ("demo_cosec", "cosec_staff", (("C", "cosec"),)),
    ("demo_it_admin", "it_admin", ()),
)


def seed(database_url: str | None = None) -> None:
    factory = initialize_database(database_url)
    with factory.begin() as session:
        clients = {}
        for letter in "ABC":
            code = f"SYNTH-{letter}"
            client = session.scalar(select(Client).where(Client.synthetic_code == code))
            if client is None:
                client = Client(name=f"Client {letter} (Fictional)", synthetic_code=code)
                session.add(client)
                session.flush()
            clients[letter] = client

        for username, role, assignments in DEMO_USERS:
            if session.scalar(select(User).where(User.username == username)):
                print(f"{username}: already exists; skipped (no password printed).")
                continue

            password = secrets.token_urlsafe(18)
            totp_secret = pyotp.random_base32()
            user = User(
                username=username,
                password_hash=hash_password(password),
                totp_secret=totp_secret,
                role=role,
            )
            session.add(user)
            session.flush()
            for letter, service_line in assignments:
                session.add(Engagement(user_id=user.id, client_id=clients[letter].id, service_line=service_line))

            provisioning_uri = pyotp.TOTP(totp_secret).provisioning_uri(
                name=username, issuer_name="SAPS Local Lab"
            )
            print(f"\n{username} ({role})")
            print(f"  Demo password: {password}")
            print(f"  TOTP secret: {totp_secret}")
            print(f"  Authenticator URI: {provisioning_uri}")
    print("\nDemo assignments: partner has one isolated service per client; each staff role has one engagement; IT admin has none.")


if __name__ == "__main__":
    seed()
