# Limitations and claims this lab does not prove

This project is a synthetic university demonstrator. A passing test proves only the behavior exercised by that test in its local environment. It does not certify the application, host, model, or organization as secure or compliant.

## Host and deployment

- It does not harden Windows, macOS, Linux, Python, Ollama, SQLite, Chroma, the browser, or the host account.
- It does not provide disk encryption, encrypted swap, endpoint protection, secure boot, OS access-control policy, container isolation, or protection from another process running as the same user.
- It does not provide firewall policy, network segmentation, packet capture, DNS filtering, or a host-level egress control. The egress guard patches Python socket APIs in this process; other processes and lower-level paths are outside its scope.
- The local-only bind and model endpoint do not prove the computer is disconnected from a network. Ollama model installation may download model files separately from app runtime requests.
- The demo web server does not configure production TLS, reverse-proxy headers, hardened cookie settings, rate limiting, CSRF protection, or a production deployment topology.

## Identity, keys, and permissions

- Demo passwords and TOTP secrets are locally generated. TOTP secrets are stored by the demo app without a hardware-backed secret manager. User administration is not an enterprise identity provider, SSO, or lifecycle-management system.
- Fernet backup keys come from `.env`; the lab does not establish key custody, access separation, rotation, escrow, recovery, hardware protection, or safe key destruction. A lost key makes a backup unreadable; a stolen key can decrypt it.
- SQLite append-only triggers and hash links detect the tested row mutations, but a person with filesystem/database-owner access can alter the database, remove triggers, or replace the entire database. There is no external trusted timestamp, remote anchor, or independent log collector.
- The role and engagement model is a small demonstration. It does not model every legal entity, conflict rule, partner delegation, temporary assignment, or revocation process used by a real firm.

## Data handling and deletion

- All included clients and documents are fictional. The tests do not establish safe handling of real MyKad numbers, passports, credentials, bank details, tax identifiers, or client records.
- Pattern scanning is heuristic. It can miss secrets and identifiers, flag ordinary text, or behave differently on formats not covered by tests.
- Secure deletion removes selected app files and rows and deletes the Chroma client directory. It is not forensic media sanitization and cannot erase prior copies in backups, filesystem snapshots, journals/WAL files, endpoint backups, SSD wear-leveling, or copies made outside the app.
- The backup includes the configured SQLite database and local document/vector trees. It does not back up the host, Ollama model binaries, `.env`, backup key, or unrelated files. Stop the app before restore; restore replaces the configured database and document/vector trees.

## AI behavior and evidence

- T3 tests the Python socket guard and a stubbed app flow; it is not a packet-level observation of every dependency or an OS-wide guarantee.
- T8 verifies the injection detector, source escaping/wrapping, and system instruction passed to a mocked model adapter. It does not demonstrate actual prompt-injection resistance for Ollama, any particular model/version, or every attack.
- Model outputs can be wrong, incomplete, biased, or unsupported even when they cite a retrieved chunk. Citations establish which chunks were supplied, not that a claim is correct or complete.
- Citation validation checks the demonstrator's claim-line format and that references point to returned chunks. It is not an audit opinion, independent evidence validation, or legal review.
- Search and workflow tests use mocked model adapters. Live model quality, latency, availability, memory use, and behavior under load were not established by those tests.
- Company-secretarial dates are synthetic exercise data. The application does not determine current statutory deadlines or provide legal advice. Accounting output is a proposal only and is never posted.

## Testing scope

- Pytest uses temporary SQLite databases, synthetic fixtures, local Chroma directories, mocked model adapters, and local test clients. It does not prove production multi-user concurrency, recovery from every crash point, dependency supply-chain integrity, or security under hostile OS-level access.
- The no-external-URL test checks references in templates and static assets. It does not analyze every Python dependency for hidden network behavior.
- Acceptance evidence under `evidence/` records the observed test runs. Read the T3 and T8 notes in each report; do not present either as broader proof than its test provides.
