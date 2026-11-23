# Mandatory project rules

Follow these rules in every change to this repository:

1. **Synthetic data only.** Never use real client data, real MyKad/passport numbers, tokens, or passwords. Generate fictional records with clearly fake identifiers.
2. **100% local.** The only model endpoint is exactly `http://127.0.0.1:11434`. The app must not call OpenAI, Anthropic, or any cloud API. Add an egress guard and a test that fails on any attempted non-loopback connection.
3. **No secrets in code.** Use a gitignored `.env` and committed `.env.example`. Generate demo credentials at seed time; never commit them.
4. **Server-side enforcement.** Enforce security controls on the server; UI checks are never sufficient.
5. **No invented test results.** Report tests as passing only after running them and observing the result. Tie claims to runnable tests.

Keep this lab readable and local. Complete one approved phase at a time, run its tests, report the observed results, and wait for the student's `continue` before starting another phase.
