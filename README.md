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
pip install .
```

Stdlib-only core — you inject the FOSS primitives (closed I/O): the test suite needs `pytest`
(`pip install ".[test]"`); the usage example needs `pip install ".[recommended]"` (`cryptography`
for Ed25519, `rfc8785` for canonical bytes).

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

Art. 14 requires oversight by *natural persons*, and the settled audit schema records who reviewed
what, when, **under what information** — which is what was *shown to* the reviewer, never what the
reviewer *consulted*. A reviewer who read the file and one who pasted it into a chatbot produce
identical records. In 2026 that is no longer a hypothetical distinction.

The concern is not only over-reliance, which is well studied. It is **correlated failure**: where
the aid belongs to the same model family as the system under review, the check may inherit the
subject's blind spot — and a check that is not independent of what it checks is not oversight.

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

**That output is the design.** A reviewer who declares they used a model of the same family as the
subject has disclosed a real weakness in their own check — and it costs them nothing. Independence
is reported on the `Report`, **never** as a `Finding`, and never affects `ok`. A disclosure that
can be used against the discloser stops being made; this follows the ASRS non-punitive principle
rather than the compliance instinct.

| `Report.independence` | meaning |
|---|---|
| `UNDECLARED` | the certificate makes no claim — every 0.1.0 record, and the default |
| `UNAIDED` | unassisted human judgement |
| `DETERMINISTIC` | a calculator, checklist or rule engine; no generative model |
| `MODEL_INDEPENDENT` | a model aid, declared to be a different family from the subject |
| `MODEL_CORRELATED` | a model aid, declared to be the same family — the check may not be independent |
| `MODEL_UNDETERMINED` | a model aid, relationship not stated; not assumed independent |

Two refusals worth naming. **Silence is `UNDECLARED`, not `UNAIDED`** — reading an absent field as
"unassisted" would manufacture the exact reassurance the field exists to withhold. And an unstated
family relationship is `MODEL_UNDETERMINED`, never `MODEL_INDEPENDENT`.

**Fully back-compatible.** A certificate without `assistance` canonicalises to byte-identical
payload, so signatures minted under 0.1.0 still verify; 0.2.0 introduces no finding that 0.1.0 did
not have. Both are pinned by tests.

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
- **Assistance is self-declared and unverifiable.** A reviewer's own browser tab is outside any
  enforcement boundary, so this records a claim, never an observation — and an overseer who does
  not declare is indistinguishable from one who was unaided, which is why silence reads as
  `UNDECLARED`. Its value is that the independence question can be asked at all, not that the
  answer is enforced.
- **`same_model_family` is a proxy.** The real property is correlated failure modes; shared family
  is the observable stand-in for it, and two unrelated families can still share a blind spot.

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

## License

MIT. See `LICENSE`. Copyright 2026 flxk1.
