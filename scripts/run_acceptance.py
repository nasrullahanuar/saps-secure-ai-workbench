"""Run T1-T8 acceptance checks and write timestamped, secret-safe evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
ACCEPTANCE = [
    ("T1", "Cross-client denial: search, direct document ID, and foreign canary prompt",
     ["tests/test_t1_cross_client_retrieval.py"],
     "Synthetic fixtures; verifies no vector-store or model calls on denial."),
    ("T2", "Cross-service denial before retrieval",
     ["tests/test_t2_cross_service_retrieval.py"],
     "Synthetic fixtures; verifies denial is logged and model/vector adapters are untouched."),
    ("T3", "Non-loopback TCP, DNS and UDP blocked; app upload/search path has zero blocked attempts",
     ["tests/test_local_ai_security.py::test_egress_guard_allows_loopback_and_fails_on_non_loopback_attempts",
      "tests/test_acceptance_controls.py::test_t3_full_mocked_upload_and_search_flow_has_zero_non_loopback_attempts"],
     "Meaningful for the installed socket guard and stubbed app flow; not an OS packet capture or live Ollama test."),
    ("T4", "IT admin content boundary, account/log activity, append-only chain and tamper detection",
     ["tests/test_operational_controls.py::test_t4_it_admin_can_manage_users_and_logs_but_never_read_client_content",
      "tests/test_operational_controls.py::test_audit_chain_detects_row_tampering_and_blocks_orm_mutation"],
     "Exercises HTTP role boundaries and test-only direct SQLite tampering in temporary databases."),
    ("T5", "Cited claims, independent review/approval, and approved-only export",
     ["tests/test_workflows_approval.py::test_t5_cited_workflow_draft_requires_independent_review_and_approval",
      "tests/test_workflows_approval.py::test_each_workflow_claim_line_requires_a_returned_source_citation"],
     "Workflow AI adapter is mocked; tests verify the saved output/citation and status gates."),
    ("T6", "Encrypted backup, deletion, verified restore, and post-restore isolation",
     ["tests/test_operational_controls.py::test_t6_encrypted_backup_delete_restore_chain_and_isolation"],
     "Uses temporary SQLite, real local Chroma directories, a generated Fernet key, and synthetic rows."),
    ("T7", "Synthetic secret and ID absent from storage, model inputs, vector documents, response and logs",
     ["tests/test_acceptance_controls.py::test_t7_synthetic_secret_and_nric_absent_from_storage_embeddings_vectors_prompts_and_logs"],
     "Uses a real local Chroma store and a capturing model stub; fixture values are fake only."),
    ("T8", "Poisoned source detected, escaped, wrapped as untrusted and paired with defense instructions",
     ["tests/test_acceptance_controls.py::test_t8_poisoned_source_is_untrusted_and_system_defense_reaches_model_adapter"],
     "Mechanism test only. Actual prompt-injection resistance of a live Ollama model is not established by a mock."),
]


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_excerpt(output: str) -> list[str]:
    """Keep only outcome lines; never persist raw pytest tracebacks or fixture payloads."""
    excerpts = []
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("PASS:"):
            excerpts.append(line[:500])
        elif line.startswith("FAILED "):
            node = line.removeprefix("FAILED ").split(" - ", 1)[0]
            excerpts.append("FAILED " + node[:300])
        elif line.startswith("ERROR "):
            excerpts.append("ERROR: pytest reported a collection or execution error")
        elif re.fullmatch(r"\d+ (?:failed|passed|error|errors|skipped|xfailed|xpassed|deselected)(?:, \d+ (?:failed|passed|error|errors|skipped|xfailed|xpassed|deselected))* in .+", line):
            excerpts.append(line[:300])
        elif re.fullmatch(r"=+\s+\d+ (?:failed|passed|error|errors|skipped|xfailed|xpassed|deselected).*=+", line):
            excerpts.append(line[:300])
    return excerpts


def run_group(label: str, description: str, nodes: list[str], limit_note: str, log_lines: list[str]) -> dict:
    started = timestamp()
    log_lines.append(f"[{started}] START {label}: {description}")
    command = [sys.executable, "-m", "pytest", "-q", "-s", "--tb=no", *nodes]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    output = completed.stdout + "\n" + completed.stderr
    excerpts = safe_excerpt(output)
    status = "PASS" if completed.returncode == 0 else "FAIL"
    test_summary = next((line for line in excerpts if re.match(r"\d+ (?:failed|passed|error|errors)", line)), "")
    if status == "FAIL" and not any(line.startswith("FAILED ") or line.startswith("ERROR:") for line in excerpts):
        excerpts.append(f"FAIL: pytest exited with status {completed.returncode}; traceback omitted from evidence")
    for excerpt in excerpts:
        log_lines.append(f"[{timestamp()}] {label} {excerpt}")
    log_lines.append(f"[{timestamp()}] END {label}: {status}; exit={completed.returncode}")
    return {
        "id": label, "description": description, "status": status,
        "return_code": completed.returncode, "started": started,
        "finished": timestamp(), "note": limit_note, "excerpts": excerpts,
        "test_summary": test_summary,
        "command": " ".join(command[2:]),
    }


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_lines = [f"SAPS FINAL ACCEPTANCE RUN {run_id}", "Synthetic fixtures only; outcome lines are filtered to avoid logging test payloads."]
    results = [run_group(*spec, log_lines) for spec in ACCEPTANCE]
    full_suite = run_group(
        "FULL", "Complete pytest suite", ["tests"],
        "Full repository suite after the focused T1-T8 checks.", log_lines,
    )
    results.append(full_suite)
    overall = "PASS" if all(item["status"] == "PASS" for item in results) else "FAIL"
    report_path = EVIDENCE / f"acceptance_report_{run_id}.md"
    log_path = EVIDENCE / f"acceptance_log_{run_id}.txt"

    report = [
        f"# SAPS final acceptance report — {run_id}", "",
        f"**Overall: {overall}**", "",
        "| Test | Result | Check | Meaning and limits |",
        "|---|---|---|---|",
    ]
    for item in results:
        report.append(
            f"| {item['id']} | {item['status']}{' — ' + item['test_summary'] if item['test_summary'] else ''} | {item['description']} | {item['note']} |"
        )
    report.extend(["", "## Test commands", ""])
    for item in results:
        report.append(f"- **{item['id']}** (`{item['started']}`): `{item['command']}` (exit {item['return_code']}).")
    report.extend(["", "## Safe log excerpts", "", f"Full filtered log: `{log_path.name}`", ""])
    for item in results:
        report.append(f"### {item['id']} — {item['status']}")
        report.append("")
        report.extend(f"- {excerpt}" for excerpt in item["excerpts"])
        if not item["excerpts"]:
            report.append("- No PASS line was emitted; see result and exit code above.")
        report.append("")
    report.extend([
        "## Interpretation", "",
        "A passing T8 result verifies that the injection detector, source escaping/wrapping, and system instruction reach the model adapter. It does not prove that a particular live model will resist every injection. T3 checks the socket guard and exercises the app with local test adapters; it is not an OS-level packet capture.",
        "",
    ])
    report_path.write_text("\n".join(report), encoding="utf-8")
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print("\nFINAL ACCEPTANCE SUMMARY")
    print("| Test | Result |")
    print("|---|---|")
    for item in results:
        print(f"| {item['id']} | {item['status']}{' — ' + item['test_summary'] if item['test_summary'] else ''} |")
    print(f"\nOverall: {overall}")
    print(f"Report: {report_path}")
    print(f"Filtered log: {log_path}")
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
