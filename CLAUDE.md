# Seri Aman Professional Services (SAPS) Lab Demonstrator — Hard Rules

1. **Synthetic data only.** Never use real client data, real MyKad/passport numbers, tokens, or passwords. Generate fictional data with clearly fake identifiers.
2. **100% local.** The only model endpoint is exactly `http://127.0.0.1:11434`. The app must make no calls to OpenAI, Anthropic, or any cloud API. Add an egress guard and a test that fails if the app attempts any non-loopback network connection.
3. **No secrets in code.** Use a `.env` file (gitignored) and `.env.example`. Generate demo credentials at seed time; never commit them.
4. **Enforce security controls server-side.** Never rely on the UI alone.
5. **Make only verified claims.** Do not claim test results you have not run. Every claim must be backed by a test the student can run and screenshot.
6. **Keep it simple and readable.** The student must be able to explain every file in a 5–7 minute presentation and Q&A defence. Prefer clear code over clever code.
7. **Work in small phases.** After each phase, run its tests, summarise changes, and wait for the student's explicit `continue` before starting the next phase.

These five hard rules (synthetic data only, exact local Ollama endpoint, server-side enforcement, no secrets in code, and no invented test results) are mandatory and are duplicated in `AGENTS.md`.

## Assignment context

Build a secure, locally-run AI lab demonstrator for the fictitious Malaysian professional services firm Seri Aman Professional Services (SAPS), for BKASK3083 Information Systems Control and Audit (UUM). Service lines: Audit & Assurance, Accounting & Bookkeeping, and Company Secretarial.

## Roles and access model

Roles: `partner`, `audit_staff`, `accounting_staff`, `cosec_staff`, `it_admin`.

Core tables: `users`, `clients`, `engagements(user_id, client_id, service_line)`, `documents`, `drafts`, `approvals`, `audit_log`.

- A user may query only client/service-line pairs assigned in `engagements`. Authorize before retrieval; deny and log otherwise.
- Physically separate vector stores at `data/vectors/<client_id>/<service_line>/`; also apply a retrieval metadata filter.
- `it_admin` may manage users and see system logs, but may not read client documents, prompts, or outputs. Cover this separation in a test.
- If a client has both an audit engagement and a non-audit engagement, flag independence risk. Block the assignment until a partner records a documented independence review, and log the event. Platform access does not imply permission to share client information.

## Security features

1. Password plus TOTP MFA login and session timeout.
2. Ingestion gate scans Malaysian NRIC/MyKad-pattern numbers, passport-like IDs, bank account numbers, tax identifiers, API keys/tokens/bearer strings/passwords (including synthetic MyInvois and SSM credential examples). Block or redact; classify as `public`, `internal`, `confidential`, or `restricted`; log the decision.
3. Prompt gate runs the same scanner before model submission. Never write raw secrets to logs.
4. Prompt-injection defense wraps retrieved text as untrusted data with delimiters; system instructions tell the model to ignore instructions inside documents. Add a heuristic detector and a synthetic poisoned document test.
5. Save every AI output as a DRAFT with source citations and visible banner: **AI-generated draft - not audit evidence / not an approved entry / not a filed document**. Flow: Draft → Reviewed → Approved. A different, authorized user must approve. Only Approved items may be exported.
6. Append-only, hash-chained audit log (each row stores previous row hash). Provide a verify-chain command that detects tampering. Log logins, denials, ingestion decisions, query metadata (not content), approvals, admin actions, backups, and restores.
7. Fernet-encrypted backup/restore script and restore verification check.
8. Per-client secure deletion removes documents, vectors, and drafts, then records a deletion certificate in the log.

## Demo workflows

- **Audit:** summarize synthetic general-ledger CSV and flag round amounts, weekend postings, and duplicate entries as draft risk notes.
- **Accounting:** extract supplier, date, amount, and tax from synthetic invoice text; propose a draft journal classification; never post anything.
- **Company secretarial:** search synthetic registers/minutes and draft a resolution template and statutory-deadline checklist.

## Synthetic data

`scripts/generate_synthetic_data.py` must produce three fictional clients (Client A, B, C) and documents for each service line. Plant a unique canary per client (for example `CANARY-A-7731`) for cross-client leakage tests. Include a fake API secret, a fake NRIC-pattern number, and a prompt-injection document.

## Acceptance tests

- **T1 Cross-client negative:** Client A-authorized user cannot retrieve Client B canary via search, direct document ID, or a prompt asking for it.
- **T2 Cross-service negative:** `audit_staff` cannot access Accounting or Company Secretarial stores for the same client unless assigned.
- **T3 Data egress:** network monitoring/mocking proves zero non-loopback connections during ingestion, retrieval, and generation.
- **T4 Privileged access logging:** `it_admin` actions are logged; `it_admin` cannot read client content; chain verifies and tampering is detected.
- **T5 Output accuracy/human approval:** preparer cannot approve own draft; unapproved draft cannot be exported; every claim has a source-chunk citation.
- **T6 Backup restoration:** backup, wipe, restore, then verify hashes and that isolation still holds.
- **T7 Secret/ID leakage:** fake secrets and NRIC patterns never appear in model prompts, vector stores, or logs.
- **T8 Prompt injection:** poisoned document does not change system behavior.

Each test file must print clear PASS/FAIL criteria and save evidence (log excerpts) under `evidence/` for screenshots.
