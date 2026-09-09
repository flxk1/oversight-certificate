# Origin, prior art, related

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
