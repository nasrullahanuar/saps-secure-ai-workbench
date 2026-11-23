"""Demo seed creates role accounts with generated credentials and isolated access."""

from sqlalchemy import select

from app.database import initialize_database
from app.models import Engagement, User
from scripts.seed_demo_users import seed


def test_seed_creates_demo_roles_and_prints_generated_setup(tmp_path, capsys):
    database_url = f"sqlite:///{(tmp_path / 'seed.db').as_posix()}"
    seed(database_url)
    output = capsys.readouterr().out

    for role in ("partner", "audit_staff", "accounting_staff", "cosec_staff", "it_admin"):
        assert role in output
    assert "Demo password:" in output
    assert "TOTP secret:" in output

    factory = initialize_database(database_url)
    with factory() as session:
        users = session.scalars(select(User)).all()
        assert {user.role for user in users} == {
            "partner", "audit_staff", "accounting_staff", "cosec_staff", "it_admin",
        }
        admin = next(user for user in users if user.role == "it_admin")
        assert session.scalar(select(Engagement).where(Engagement.user_id == admin.id)) is None
