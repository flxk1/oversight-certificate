# Usage and API


When an AI system escalates a consequential decision to a human, *"a human approved it"* is, on
its own, an unfalsifiable claim. This is the primitive that turns it into a **re-checkable proof**:
a signed, portable certificate recording *what was decided or refused, which qualified human took
responsibility, on what evidence, and under which legal obligation* — re-verifiable **offline** by a
third party (an auditor, a regulator) from the certificate and a public key alone, without trusting
the system that produced it.

It **computes and checks; it does not judge.** `verify` proves a qualified human decided at a given
time and locates every structural or cryptographic defect — but whether that oversight was *legally
sufficient* stays with the auditor. **Refusal is first-class**: a decision is `DECIDED`, `ESCALATED`
(routed to a human, pending, with evidence), or `ABSTAINED` (recorded, not forced).

## Install

```bash
pip install "oversight-certificate[recommended] @ git+https://github.com/flxk1/oversight-certificate"
```

Stdlib-only core; FOSS primitives are injected, not bundled. The `recommended` extra pulls
`cryptography` and `rfc8785`, which the examples use — the core needs neither.

Distributed from this repository; there is no package-index release. Tests:
`pip install ".[test]"` from a clone.

## Usage

```python
from dataclasses import replace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rfc8785 import dumps  # RFC 8785 canonical JSON — the composed FOSS primitive
from oversight_certificate import OversightCertificate, Human, Disposition, issue, verify

key = Ed25519PrivateKey.from_private_bytes(bytes(32))          # fixed seed for a reproducible demo
pub = key.public_key()
sign = lambda b: key.sign(b)
def verify_sig(b, s):
    try: pub.verify(s, b); return True
    except Exception: return False

cert = OversightCertificate(
    id="decision-42",
    action="approve high-risk model deployment",
    disposition=Disposition.DECIDED,
    at="2026-08-12T10:00:00Z",
    basis="eu-ai-act-2024-1689-art-14",
    evidence=("sha256:of-what-the-reviewer-saw",),
    human=Human("reviewer-7", "notified-body-reviewer", credential_not_after="2027-01-01T00:00:00Z"),
)
envelope = issue(cert, canonicalize=dumps, sign=sign).to_dict()

# A third party re-checks it offline — years later — from the envelope + public key alone:
report = verify(envelope, canonicalize=dumps, verify_sig=verify_sig, now="2030-01-01T00:00:00Z")
print("valid:", report.ok)

# Had the reviewer's credential lapsed BEFORE the decision, verify locates exactly that:
lapsed = replace(cert, human=replace(cert.human, credential_not_after="2026-01-01T00:00:00Z"))
bad = verify(issue(lapsed, canonicalize=dumps, sign=sign).to_dict(),
             canonicalize=dumps, verify_sig=verify_sig, now="2030-01-01T00:00:00Z")
print("valid:", bad.ok, "->", [f.code for f in bad.findings])
```

Output (behaviour proven by the test suite; the printed values are canonicaliser-independent):

```
valid: True
valid: False -> ['unqualified-at-decision']
```

The second line is the distinctive rule: the credential is checked **at decision time**, so a
credential that lapses *after* a valid decision does not retroactively void the record — while one
that had already lapsed *before* it is caught.

## API

- `issue(cert, *, canonicalize, sign, keyid="") -> Envelope` — canonicalise, wrap in a DSSE
  envelope, sign the PAE. Refuses to mint a structurally-incoherent certificate
  (`InvalidCertificate`). The signing key is never read — `sign` is your closed function.
- `verify(envelope, *, canonicalize, verify_sig, now, required_basis=None) -> Report` — re-check
  from the envelope + a public verify function alone. Returns `Report(ok, findings, independence)`; each `Finding`
  names *what* is wrong (bad-signature, non-canonical-payload, decided-without-human,
  escalated-without-target, unqualified-at-decision, wrong-basis, …). It never rules on legal
  sufficiency.
- `OversightCertificate`, `Human`, `Disposition` (DECIDED / ESCALATED / ABSTAINED), `Envelope`
  (DSSE), `Report`, `Finding`, `InvalidCertificate`.
