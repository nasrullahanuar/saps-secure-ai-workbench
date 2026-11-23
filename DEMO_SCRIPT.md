# Five-minute presentation script

## Before presenting

1. Complete the README setup. Keep generated demo credentials local; use the seed output for usernames, passwords, and TOTP setup.
2. Confirm Ollama is running at the configured local address and both configured models are installed. Search and AI workflows need these models; tests use local stubs instead.
3. Generate the synthetic documents with `python -m scripts.generate_synthetic_data`.
4. Start the app with `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`, then open **http://127.0.0.1:8000**.
5. Keep this project directory open in a terminal. Seeded demo usernames are `demo_audit`, `demo_accounting`, `demo_cosec`, `demo_partner`, and `demo_it_admin`.

## Live walkthrough

### 0:00–0:40 — Sign in with MFA

1. At `/login`, sign in as `demo_audit` with its generated demo password.
2. Enter the current six-digit TOTP from the authenticator configured from the seed output.
3. Point out the logged-in role, **LAB DEMO - SYNTHETIC DATA ONLY** badge, and the Client A / Audit assignment on the dashboard.

### 0:40–1:15 — Show the Client A boundary

1. Open **Search / Chat**. The selector lists only Client A / Audit for `demo_audit`.
2. Explain that hiding Client B in the selector is a convenience; the server checks every requested client/service pair before retrieval.
3. In the terminal, run:

   ```powershell
   python -m pytest -q -s tests/test_t1_cross_client_retrieval.py
   ```

4. Point to the PASS line: the test tries cross-client search, direct document ID, and a prompt requesting Client B's canary. All three are denied before vector or model calls.

### 1:15–2:00 — Redact a synthetic credential at ingestion

1. Sign out and sign in as `demo_accounting` with its generated password and TOTP.
2. Open **Upload**. Choose Client B / Accounting and upload `data/documents/client_B/accounting/fake_secret.txt`.
3. Show that the scanner reports the client-secret finding and redaction. Explain that the synthetic credential value is not stored in the uploaded text or written to audit logs.
4. If time allows, run `python -m pytest -q -s tests/test_ingestion_gate.py::test_sensitive_upload_is_redacted_before_storage_and_not_written_to_logs` to show the storage/log assertion.

### 2:00–3:20 — Create a cited draft and require another user

1. Sign in as `demo_audit` again. In **Upload**, add `data/documents/client_A/audit/synthetic_ledger.csv` to Client A / Audit.
2. Open **Workflows** and generate the Audit risk note. Show that each factual claim has a source citation and that the persistent banner says it is not audit evidence.
3. Open **Drafts** and point out its Draft status and citation.
4. Sign out. Sign in as `demo_partner`, who is assigned to Client A / Audit. Open **Approvals**, mark the draft Reviewed, then approve it.
5. Return to **Drafts** and show that export becomes available only after approval. The preparer account cannot approve its own draft.

### 3:20–4:00 — Show the IT admin boundary

1. Sign out and sign in as `demo_it_admin`.
2. Open **User management** and **System logs**. Explain that logs show metadata, not document text, prompts, or AI output.
3. Enter `/documents/upload` directly in the address bar. The page has no client assignments; server-side checks deny a direct document/search request even if the UI is bypassed.
4. If needed, run `python -m pytest -q -s tests/test_operational_controls.py::test_t4_it_admin_can_manage_users_and_logs_but_never_read_client_content` for the direct-request proof.

### 4:00–5:00 — Show backup, deletion, and restore

1. Create a local encrypted backup:

   ```powershell
   python -m scripts.backup --output backups/demo.fernet
   ```

2. As partner or IT admin, open **Secure deletion** and delete one synthetic client's workspace using the confirmation field. The audit log keeps a metadata-only deletion record.
3. Stop uvicorn with **Ctrl+C** in its terminal. Restore the saved backup and verify the audit chain:

   ```powershell
   python -m scripts.restore backups/demo.fernet
   python -m scripts.verify_audit_chain
   ```

4. Restart uvicorn and confirm the restored client documents and vectors are present. The T6 acceptance test also verifies that post-restore client isolation still holds:

   ```powershell
   python -m pytest -q -s tests/test_operational_controls.py::test_t6_encrypted_backup_delete_restore_chain_and_isolation
   ```

The backup key must already be configured in the gitignored `.env`. For a shorter presentation, prepare the backup before the session and show the T6 test's PASS output; explain that the live restore requires stopping the app.

## Closing statement

“This is a synthetic local lab. The tests demonstrate the specific authorization, redaction, citation, approval, logging, and restore checks shown. They do not establish production security or prove how every live language model will respond to every prompt injection.”
