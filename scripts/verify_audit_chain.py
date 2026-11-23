"""Verify every audit event's previous-link and row digest."""

import sys

from app.audit_chain import AuditChainError, verify_audit_chain
from app.config import get_settings
from app.database import initialize_database


def main() -> int:
    try:
        factory = initialize_database(get_settings().database_url)
        with factory() as session:
            valid, message = verify_audit_chain(session)
        factory.kw["bind"].dispose()
    except Exception as exc:
        print(f"FAIL: audit chain could not be verified ({type(exc).__name__}: {exc})")
        return 1
    print(("PASS: " if valid else "FAIL: ") + message)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
