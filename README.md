# oversight-certificate

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

Stdlib-only core; you inject the FOSS primitives (closed I/O). The `recommended` extra pulls `cryptography` and `rfc8785`, which the examples use — the core
needs neither. Without the extra:

```bash
pip install "git+https://github.com/flxk1/oversight-certificate"
```

Tests: `pip install ".[test]"` from a clone. **Not yet on PyPI**, so the git URL is the install.

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
  from the envelope + a public verify function alone. Returns `Report(ok, findings)`; each `Finding`
  names *what* is wrong (bad-signature, non-canonical-payload, decided-without-human,
  escalated-without-target, unqualified-at-decision, wrong-basis, …). It never rules on legal
  sufficiency.
- `OversightCertificate`, `Human`, `Disposition` (DECIDED / ESCALATED / ABSTAINED), `Envelope`
  (DSSE), `Report`, `Finding`, `InvalidCertificate`.

## How the judgement was formed (0.2.0)

A certificate may declare how the reviewer reached the decision. Art. 14 requires oversight by
natural persons, and the standard oversight record captures who reviewed what, when, and under
what information — where "information" means what was shown to the reviewer, not what the reviewer
consulted. A reviewer who read the file and one who asked a model produce identical records.

The concern is not only over-reliance. Where the aid comes from the same model family as the
system under review, the check may share the subject's failure modes.

```python
from oversight_certificate import Aid, Assistance, Independence

cert = replace(cert, assistance=Assistance(Aid.MODEL, "some-llm", same_model_family=True))
report = verify(issue(cert, canonicalize=dumps, sign=sign).to_dict(),
                canonicalize=dumps, verify_sig=verify_sig, now="2026-08-15T00:00:00Z")
print(report.ok, report.independence.value)
```

```
True model-correlated
```

| `Report.independence` | meaning |
|---|---|
| `UNDECLARED` | no claim made — every 0.1.0 record, and the default |
| `UNAIDED` | unassisted human judgement |
| `DETERMINISTIC` | calculator, checklist or rule engine; no generative model |
| `MODEL_INDEPENDENT` | model aid, declared a different family from the subject |
| `MODEL_CORRELATED` | model aid, declared the same family |
| `MODEL_UNDETERMINED` | model aid, relationship not stated |

Three rules govern the field:

- **Declaring never invalidates a certificate**, `MODEL_CORRELATED` included. Independence is
  reported on the `Report`, never as a `Finding`, and never affects `ok`. A disclosure that can be
  used against the discloser stops being made (ASRS non-punitive principle).
- **Silence reads `UNDECLARED`, not `UNAIDED`.** An absent field is not a claim of unassisted
  judgement. An unstated family relationship reads `MODEL_UNDETERMINED`.
- **Back-compatible.** A certificate without `assistance` canonicalises to byte-identical payload,
  so 0.1.0 signatures still verify, and 0.2.0 adds no finding 0.1.0 did not have. Both are pinned
  by tests.

## Limitations

- **Single signature.** One DSSE signature per envelope in this version; threshold/multi-sig is not
  modelled.
- **You supply canonicalisation and the key.** Pass an RFC 8785 canonicaliser (`rfc8785.dumps`) and
  an Ed25519 `sign`/`verify_sig`; the library bundles neither, by design (closed I/O).
- **It does not fetch credential status.** Validity-at-decision-time is checked from the
  `credential_not_after` recorded in the certificate; it does not call a revocation service. A
  for-cause revocation effective *before* the decision is out of scope for this version.
- **It does not judge sufficiency.** `verify` locates structural and cryptographic defects; whether
  the oversight was legally adequate is the auditor's call, not the tool's.
- **Assistance is self-declared and unverifiable.** A reviewer's own tooling is outside any
  enforcement boundary, so this records a claim, not an observation. Its value is that the
  independence question can be asked, not that the answer is enforced.
- **`same_model_family` is a proxy** for correlated failure modes. Two unrelated families can
  still share a blind spot.

## Origin & prior art

Composed, not reinvented. Signing envelope = the in-toto **DSSE** standard (its PAE encoding);
canonical bytes = **RFC 8785** (pass `rfc8785.dumps`); signatures = **`cryptography`** (Ed25519);
it interoperates with the DSSE/Sigstore ecosystem. What this package owns — and what no FOSS tool
packages — is the **oversight semantic**: refuse-to-decide as a first-class disposition, credential
validity checked *at decision time*, evidence bound into the signed payload, and a named legal
basis, yielding a re-checkable certificate of *meaningful human oversight*. Grounded in EU AI Act
(Reg. 2024/1689) Art. 14 (human oversight) and Art. 12 (record-keeping).

```
PRIOR-ART:
  incumbent(s):      in-toto/DSSE (signing envelope) · RFC 8785 (canonical JSON) ·
                     cryptography (Ed25519) · Sigstore/Rekor (transparency)
  distinctive layer: the oversight-decision semantic — disposition incl. refuse/escalate,
                     qualification-valid-at-decision-time, evidence-bound, named legal basis,
                     offline re-verifiable from the certificate alone
  decision:          build-distinctive (composes on the above; owns the oversight certificate)
```

## Related

One of four narrow governance primitives, each usable alone:

- [`enforcement-posture`](https://github.com/flxk1/enforcement-posture) — binds evidence to the
  controls that were in force while it was recorded
- [`norm-freshness`](https://github.com/flxk1/norm-freshness) — whether the rule a gate applies
  still matches the text it was compiled from
- [`effect-reconciliation`](https://github.com/flxk1/effect-reconciliation) — permissions granted
  against effects observed
- [`oversight-certificate`](https://github.com/flxk1/oversight-certificate) — re-checkable proof
  that a qualified human decided

They answer different questions about the same decision: *who decided* (oversight-certificate),
*under what regime* (enforcement-posture), *against which version of the rule* (norm-freshness),
and *did the permission produce the effect* (effect-reconciliation).

## License

MIT. See `LICENSE`. Copyright 2026 flxk1.
