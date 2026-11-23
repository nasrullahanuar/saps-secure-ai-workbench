"""Templates and local assets must not reference remote web resources."""

from pathlib import Path
import re

PROJECT_ROOT = Path(__file__).parents[1]
CHECKED_DIRS = (PROJECT_ROOT / "app" / "templates", PROJECT_ROOT / "app" / "static")
REMOTE_URL = re.compile(
    r"(?i)https?://(?:(?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?"
)


def test_templates_and_static_assets_do_not_reference_external_urls():
    violations = []
    for directory in CHECKED_DIRS:
        for path in directory.rglob("*"):
            if path.is_file():
                content = path.read_text(encoding="utf-8", errors="ignore")
                if REMOTE_URL.search(content):
                    violations.append(path.relative_to(PROJECT_ROOT).as_posix())
    assert not violations, f"External URL references found in: {', '.join(violations)}"
