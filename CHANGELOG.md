# Changelog

## 0.1.0 — 2026-08-12

Initial draft. The oversight-certificate primitive: a DSSE-wrapped, RFC-8785-canonical,
Ed25519-signed record of an oversight decision (DECIDED / ESCALATED / ABSTAINED) with a named legal
basis and evidence; `verify` re-checks it offline and enforces credential-validity **at decision
time**. Composes on `cryptography`, `rfc8785`, and the in-toto DSSE envelope (all injected).
