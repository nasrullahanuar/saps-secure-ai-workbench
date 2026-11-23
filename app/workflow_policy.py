"""Workflow prompts and simple citation checks for saved AI drafts."""

from __future__ import annotations

import re

from app.retrieval import SourceChunk


WORKFLOWS = {
    "audit": {
        "type": "audit_risk_note",
        "title": "Audit exception risk note",
        "prompt": (
            "Review the synthetic general-ledger source chunks. Draft concise risk-note bullets and flag only "
            "source-supported round amounts, weekend postings, and duplicate entries. Each factual claim must be "
            "on its own line and end with an exact source citation such as [D12:C0]. Do not infer unsupported facts."
        ),
    },
    "accounting": {
        "type": "accounting_journal_proposal",
        "title": "Accounting invoice extraction and journal proposal",
        "prompt": (
            "From the synthetic invoice source chunks, extract supplier, invoice date, amount, and tax, then propose "
            "a draft journal classification. Put each field or factual claim on its own line and end every line with "
            "an exact source citation such as [D12:C0]. Mark missing fields as not stated. This is a proposal only; "
            "never post or imply that anything was posted."
        ),
    },
    "cosec": {
        "type": "cosec_resolution_checklist",
        "title": "Company secretarial resolution and deadline checklist",
        "prompt": (
            "Using only the synthetic register and minutes source chunks, draft a clearly marked resolution template "
            "and a checklist of dates or statutory-deadline reminders explicitly stated in those sources. Do not invent "
            "legal requirements or calculate statutory deadlines. Put each factual claim on its own line and end it "
            "with an exact source citation such as [D12:C0]. Use placeholders for unsupported template details."
        ),
    },
}

_CITATION = re.compile(r"\[D(\d+):C(\d+)\]")


def valid_cited_claim_lines(content: str, sources: tuple[SourceChunk, ...]) -> bool:
    """Every non-heading claim line must cite a source that retrieval actually returned."""
    valid_references = {source.reference for source in sources}
    cited_any = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or (line.endswith(":") and not _CITATION.search(line)):
            continue
        references = [f"D{doc}:C{chunk}" for doc, chunk in _CITATION.findall(line)]
        if not references or any(reference not in valid_references for reference in references):
            return False
        cited_any = True
    return cited_any


def cited_references(content: str) -> set[str]:
    return {match.group(0)[1:-1] for match in _CITATION.finditer(content)}
