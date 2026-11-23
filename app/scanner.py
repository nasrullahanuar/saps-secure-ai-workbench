"""Small text scanner used before synthetic documents enter persistent storage."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Finding:
    category: str
    start: int
    end: int


@dataclass(frozen=True)
class ScanResult:
    redacted_text: str
    findings: tuple[Finding, ...]

    @property
    def categories(self) -> list[str]:
        return sorted({finding.category for finding in self.findings})

    @property
    def finding_count(self) -> int:
        return len({(finding.start, finding.end) for finding in self.findings})

    @property
    def classification(self) -> str:
        categories = set(self.categories)
        if categories.intersection({"api_key", "bearer_token", "password", "client_secret"}):
            return "restricted"
        if categories.intersection({"mykad", "passport", "bank_account", "tax_identifier"}):
            return "confidential"
        if self.redacted_text.lstrip().upper().startswith("PUBLIC:"):
            return "public"
        return "internal"


# For labelled values, only the value is replaced so useful field labels remain.
_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("mykad", re.compile(r"(?<!\d)\d{6}-?\d{2}-?\d{4}(?!\d)"), 0),
    ("passport", re.compile(r"(?<![A-Z0-9])[A-Z]{1,2}\d{6,9}(?![A-Z0-9])", re.IGNORECASE), 0),
    (
        "bank_account",
        re.compile(r"\b(?:bank\s*account|account\s*(?:number|no\.?))\s*(?:number|no\.?)?\s*[:=#-]?\s*(\d(?:[ -]?\d){8,19})", re.IGNORECASE),
        1,
    ),
    ("bank_account", re.compile(r"(?<!\d)\d{10,18}(?!\d)"), 0),
    (
        "tax_identifier",
        re.compile(r"\b(?:tax\s*(?:identifier|id|number|no\.?)|TIN)\s*[:=#-]?\s*([A-Z0-9][A-Z0-9-]{7,17})", re.IGNORECASE),
        1,
    ),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE),
        1,
    ),
    (
        "client_secret",
        re.compile(r"\b(?:myinvois[_ -]?(?:client[_ -]?)?secret|client[_ -]?secret|ssm[_ -]?(?:username|user|password|credential|login))\s*[:=]\s*([^\s,;]+)", re.IGNORECASE),
        1,
    ),
    (
        "api_key",
        re.compile(r"\bapi[_ -]?key\s*[:=]\s*([^\s,;]+)", re.IGNORECASE),
        1,
    ),
    (
        "api_key",
        re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|AIza[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b"),
        0,
    ),
    (
        "password",
        re.compile(r"\b(?:ssm[_ -]?(?:password|credential|login)|password|passwd|pwd)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE),
        1,
    ),
    (
        "api_key",
        re.compile(r"\b(?:access[_ -]?token|refresh[_ -]?token|api[_ -]?token)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE),
        1,
    ),
)


def scan_text(text: str) -> ScanResult:
    """Find sensitive-looking spans and redact them without returning their values."""
    findings: list[Finding] = []
    spans: list[tuple[int, int]] = []
    seen: set[tuple[str, int, int]] = set()
    for category, pattern, group in _PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span(group)
            key = (category, start, end)
            if start < end and key not in seen:
                seen.add(key)
                findings.append(Finding(category, start, end))
                spans.append((start, end))

    # Merge overlapping matches so every suspicious character is removed once.
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    redacted = text
    for start, end in reversed(merged):
        redacted = redacted[:start] + "[REDACTED]" + redacted[end:]
    return ScanResult(redacted_text=redacted, findings=tuple(findings))
