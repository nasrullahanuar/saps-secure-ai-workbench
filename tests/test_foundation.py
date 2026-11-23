"""Readable foundation checks for schema and synthetic fixture generation."""

from pathlib import Path

from sqlalchemy import create_engine, inspect

from app.database import initialize_database
from scripts.generate_synthetic_data import generate


def test_database_initialization_creates_required_tables(tmp_path: Path):
    db_path = tmp_path / "foundation.db"
    initialize_database(f"sqlite:///{db_path.as_posix()}")
    inspector = inspect(create_engine(f"sqlite:///{db_path.as_posix()}"))
    expected = {
        "users", "clients", "engagements", "independence_reviews", "documents",
        "drafts", "draft_citations", "approvals", "audit_log",
    }
    assert expected.issubset(set(inspector.get_table_names()))


def test_synthetic_generator_creates_all_service_lines_and_markers(tmp_path: Path):
    created = generate(tmp_path / "documents")
    assert len(created) == 15
    for letter, marker in (("A", "CANARY-A-7731"), ("B", "CANARY-B-8842"), ("C", "CANARY-C-9953")):
        client_files = list((tmp_path / "documents" / f"client_{letter}").rglob("*.txt"))
        assert any(marker in path.read_text(encoding="utf-8") for path in client_files)
    assert "MYINVOIS_CLIENT_SECRET=FAKE-DEMO-ONLY-0000" in (
        tmp_path / "documents/client_B/accounting/fake_secret.txt"
    ).read_text(encoding="utf-8")
