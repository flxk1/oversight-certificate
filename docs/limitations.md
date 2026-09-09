# Limitations

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
