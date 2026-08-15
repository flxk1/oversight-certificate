# Changelog

## 0.2.0 — 2026-08-15

`Assistance` — a certificate may now declare **how the judgement was formed**: unaided, aided by a
deterministic check, or aided by a generative model, and if a model, whether it was of the same
family as the system under review. `verify` reports `Report.independence` over six states.

The point is correlated failure, not over-reliance: a check drawn from the same model family as its
subject may inherit the subject's blind spot, and a check that is not independent is not oversight.
Declaring it **never invalidates a certificate**, MODEL_CORRELATED included — a disclosure that can
be used against the discloser stops being made (ASRS non-punitive principle). Independence is
reported, never a `Finding`, and never affects `ok`.

Silence reads as `UNDECLARED`, not `UNAIDED`; an unstated family relationship reads as
`MODEL_UNDETERMINED`, not `MODEL_INDEPENDENT`. Fully back-compatible: a certificate without
`assistance` canonicalises byte-identically, so 0.1.0 signatures still verify, and 0.2.0 adds no
finding 0.1.0 did not have. Both pinned by tests.

## 0.1.0 — 2026-08-12

Initial draft. The oversight-certificate primitive: a DSSE-wrapped, RFC-8785-canonical,
Ed25519-signed record of an oversight decision (DECIDED / ESCALATED / ABSTAINED) with a named legal
basis and evidence; `verify` re-checks it offline and enforces credential-validity **at decision
time**. Composes on `cryptography`, `rfc8785`, and the in-toto DSSE envelope (all injected).
