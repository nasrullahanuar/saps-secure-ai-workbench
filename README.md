# SAPS Secure AI Workbench — local lab demonstrator

## Purpose

This is a university lab demonstrator for the fictional Seri Aman Professional Services (SAPS) firm. It illustrates controls around client/service-line authorization, sensitive-data ingestion, local retrieval, AI-generated drafts, human approval, operational logging, backup, and deletion. All built-in clients and documents are synthetic. Do not upload real client data or credentials.

The app is a teaching prototype, not a production audit, accounting, company-secretarial, or records-management system. See [LIMITATIONS.md](LIMITATIONS.md) before presenting what the controls establish.

## Architecture

- **Web app:** FastAPI routes with Jinja2 templates, local CSS/JavaScript, and locally vendored HTMX. The server binds to `127.0.0.1:8000`.
- **Authentication:** SQLite and SQLAlchemy store users and assignments. Login uses Argon2 password hashes, TOTP MFA, and an idle session timeout.
- **Ingestion:** UTF-8 `.txt`, `.csv`, and `.md` uploads are scanned server-side. Sensitive-looking values are redacted before document storage; only finding categories and metadata are logged.
- **Retrieval and AI:** Chroma persists separately under `data/vectors/<client_id>/<service_line>/`. Queries also apply client and service metadata filters. Ollama is restricted to exactly `http://127.0.0.1:11434`; the app's socket guard blocks non-loopback egress attempts.
- **Drafts:** Audit, accounting, company-secretarial, and search outputs require source-chunk citations before being saved as Drafts. A different user with the same active engagement must review and approve. Only Approved drafts can be exported.
- **Operations:** Audit events are append-only and hash-chained. Fernet backup/restore scripts verify archive hashes and the audit chain. Per-client deletion removes document files, vectors, drafts, citations, and approvals, then retains a client tombstone and deletion log event.

The code and templates are organized under `app/`; synthetic fixtures and user seeding are in `scripts/`; tests are in `tests/`; timestamped acceptance evidence is written under `evidence/`. Hard project rules are recorded in both `CLAUDE.md` and `AGENTS.md`.

## Requirements

- Python 3.11 or newer.
- Ollama installed and running locally.
- The configured local models installed in Ollama. Defaults are `qwen2.5:3b` for chat and `nomic-embed-text` for embeddings.
- An authenticator app for TOTP.

If Ollama is not already serving, start it with `ollama serve` in a separate terminal. The application rejects any model endpoint other than `http://127.0.0.1:11434`.

## Setup

Run the commands from the project directory.

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -c "from pathlib import Path; import secrets; from cryptography.fernet import Fernet; p=Path('.env'); s=p.read_text(encoding='utf-8-sig'); s=s.replace('replace-with-a-random-value-before-use', secrets.token_urlsafe(48)); s=s.replace('generate-a-fernet-key-before-use', Fernet.generate_key().decode()); p.write_text(s, encoding='utf-8')"
python -m scripts.generate_synthetic_data
python -m scripts.seed_demo_users
ollama pull qwen2.5:3b
ollama pull nomic-embed-text
```

### macOS and Linux

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example .env
python -c 'from pathlib import Path; import secrets; from cryptography.fernet import Fernet; p=Path(".env"); s=p.read_text(encoding="utf-8-sig"); s=s.replace("replace-with-a-random-value-before-use", secrets.token_urlsafe(48)); s=s.replace("generate-a-fernet-key-before-use", Fernet.generate_key().decode()); p.write_text(s, encoding="utf-8")'
python -m scripts.generate_synthetic_data
python -m scripts.seed_demo_users
ollama pull qwen2.5:3b
ollama pull nomic-embed-text
```

`.env` is gitignored. The setup command generates a session secret and Fernet backup key locally without printing either. Keep the backup key safe and separate from backup files. The seed command prints each newly created demo password, TOTP secret, and authenticator URI once. Store the generated login setup locally; rerunning the seed skips existing accounts and does not reveal their credentials.

## Run and verify

Run the full test suite and the focused acceptance suite:

```powershell
python -m pytest -q
python -m scripts.run_acceptance
```

The acceptance runner executes T1–T8 and the complete pytest suite. It writes timestamped reports and filtered log excerpts to `evidence/`. The filter keeps test payloads out of those evidence files. T3 is a socket-guard and stubbed app-flow test, not an OS packet capture. T8 verifies the injection defense reaches the model adapter; it does not prove live-model resistance.

Start the app:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** and sign in with a seeded username, its generated password, and a current six-digit authenticator code. Ollama must be running with both configured models for live search and workflow generation.

To check the audit chain:

```powershell
python -m scripts.verify_audit_chain
```

## Demo users

The seed script creates generated credentials for these accounts and gives them separated client/service assignments:

| Username | Role | Seeded assignment |
|---|---|---|
| `demo_partner` | Partner | Client A / Audit; Client B / Accounting; Client C / Company Secretarial |
| `demo_audit` | Audit staff | Client A / Audit |
| `demo_accounting` | Accounting staff | Client B / Accounting |
| `demo_cosec` | Company secretarial staff | Client C / Company Secretarial |
| `demo_it_admin` | IT admin | No client engagement; user management and metadata-only system logs |

Passwords and TOTP setup are generated when an account is first seeded; there are no default passwords in source code. The database stores password hashes. IT admin access does not grant access to client documents, prompts, or draft outputs.

## Browser workflows

- **Dashboard:** assignment-scoped engagements, documents, counts, and activity.
- **Upload:** select an assigned client/service line and upload a synthetic text, CSV, or Markdown file up to 1 MiB. Findings show categories and whether values were redacted; raw matches are not shown.
- **Search / Chat:** query an assigned engagement. Retrieved source chunks are expandable citations. Outputs that do not cite authorized chunks are not saved or displayed as AI answers.
- **Workflows:** generate an audit risk note, invoice extraction and proposed journal classification, or company-secretarial resolution/checklist. No journal entry is posted. Each factual claim line must cite retrieved material.
- **Drafts and Approvals:** status sequence is Draft → Reviewed → Approved. The preparer cannot review or approve their own draft; the second user must be assigned to the same client/service line. Only Approved drafts can be exported.
- **Independence:** partners record a documented decision before assigning audit and non-audit work to the same client. A latest Prohibited review continues to block the conflicting assignment.
- **User management and System logs:** IT admin can create/suspend users and see metadata-only system events. Server checks prevent client-content reads.
- **Secure deletion:** partner or IT admin can remove a client's workspace content. Back up first if the data may be needed again.

Fixtures useful for the browser demo are created by `python -m scripts.generate_synthetic_data`:

- `data/documents/client_A/audit/synthetic_ledger.csv`
- `data/documents/client_B/accounting/synthetic_invoice.txt`
- `data/documents/client_C/cosec/synthetic_minutes.txt`
- `data/documents/client_B/accounting/fake_secret.txt` (synthetic credential value for redaction demonstration)

For a ready-to-upload audit walkthrough file with weekend, round-amount, and duplicate examples, use [`demo_uploads/demo_audit_walkthrough.csv`](demo_uploads/demo_audit_walkthrough.csv). It is synthetic and contains no sensitive values.

Use **Upload** to add each fixture to the matching assigned engagement before running its workflow. See [DEMO_SCRIPT.md](DEMO_SCRIPT.md) for a timed presentation script.

## Backup and restore

Backups contain the SQLite database and the local `documents/` and `vectors/` trees. They are Fernet-encrypted and include SHA-256 hashes for every archived file. `SAPS_BACKUP_KEY` is read from `.env`.

```powershell
python -m scripts.backup --output backups/demo.fernet
```

Stop the app before restoring so SQLite and Chroma files are closed. Then:

```powershell
python -m scripts.restore backups/demo.fernet
python -m scripts.verify_audit_chain
```

The restore command authenticates the encrypted archive, verifies each manifest hash, checks the restored audit chain, appends a restore event, and checks the chain again. The commands and controls are demonstration-grade; see [LIMITATIONS.md](LIMITATIONS.md).

## Feature-to-control and test map

| Feature | Control demonstrated | Relevant test(s) |
|---|---|---|
| Login and MFA | Password plus TOTP, unauthenticated redirect, invalid credential denial | `tests/test_login_mfa.py` |
| Synthetic fixture/schema setup | Required tables and generated fictional clients/documents | `tests/test_foundation.py`, `tests/test_seed_demo_users.py` |
| Sensitive-data scanner and upload | MyKad-pattern/credential detection; redaction before storage; no raw match in logs; unauthorized upload denied | `tests/test_ingestion_gate.py` |
| T1 cross-client retrieval | Client A cannot retrieve Client B by search, document ID, or foreign canary prompt | `tests/test_t1_cross_client_retrieval.py` |
| T2 cross-service retrieval | Audit assignment cannot access Accounting for the same client | `tests/test_t2_cross_service_retrieval.py` |
| T3 egress guard | Non-loopback TCP/DNS/UDP attempts are rejected; stubbed upload/search flow records no blocked egress attempts | `tests/test_local_ai_security.py::test_egress_guard_allows_loopback_and_fails_on_non_loopback_attempts`, `tests/test_acceptance_controls.py::test_t3_full_mocked_upload_and_search_flow_has_zero_non_loopback_attempts` |
| Chroma isolation and local AI privacy | Separate persistent directories, client/service metadata filter, prompt secret blocked before model/store | `tests/test_local_ai_security.py` |
| T4 privileged access and audit integrity | IT admin content boundary, user/system-log access, append-only writes, hash tamper detection | `tests/test_operational_controls.py::test_t4_it_admin_can_manage_users_and_logs_but_never_read_client_content`, `tests/test_operational_controls.py::test_audit_chain_detects_row_tampering_and_blocks_orm_mutation` |
| T5 citations and approval | Cited claims, different preparer/reviewer, Draft → Reviewed → Approved, approved-only export | `tests/test_workflows_approval.py::test_t5_cited_workflow_draft_requires_independent_review_and_approval`, `tests/test_workflows_approval.py::test_each_workflow_claim_line_requires_a_returned_source_citation` |
| Independence gate | Conflicting audit/non-audit assignment blocked until partner clearance is recorded | `tests/test_workflows_approval.py::test_independence_review_blocks_conflicting_assignment_until_partner_clears` |
| T6 encrypted backup, deletion, restore | Manifest tamper rejection; file/vector/draft removal; restore verification and isolation afterward | `tests/test_operational_controls.py::test_t6_encrypted_backup_delete_restore_chain_and_isolation` |
| T7 secret/ID containment | Fake secret and MyKad-pattern value absent from persisted text, embeddings/model messages, Chroma text, response, and logs | `tests/test_acceptance_controls.py::test_t7_synthetic_secret_and_nric_absent_from_storage_embeddings_vectors_prompts_and_logs` |
| T8 injection defense | Heuristic detection, escaped source delimiter, untrusted-source wrapper, system defense passed to model adapter | `tests/test_acceptance_controls.py::test_t8_poisoned_source_is_untrusted_and_system_defense_reaches_model_adapter`, `tests/test_local_ai_security.py::test_prompt_injection_text_is_detected_and_delimiter_cannot_be_forged` |
| Local UI assets | No external HTTP(S) references in templates/static files | `tests/test_no_external_assets.py` |

Acceptance suite entry point: `python -m scripts.run_acceptance`. It reports each T1–T8 result and then runs the complete test suite.
