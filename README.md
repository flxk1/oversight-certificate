# oversight-certificate

Signed, offline-verifiable certificate that a qualified human decided, escalated or abstained on one action, on named evidence and legal basis.

## Problem

"A human approved it" is a log line. A signed, offline-verifiable certificate of who decided, on what, under which basis.

## Install

`pip install "oversight-certificate[recommended] @ git+https://github.com/flxk1/oversight-certificate"`

## Usage

```python
envelope = issue(cert, canonicalize=dumps, sign=sign).to_dict()
report = verify(envelope, canonicalize=dumps, verify_sig=verify_sig, now="2030-01-01T00:00:00Z")
```

## Example

```
in : issue(OversightCertificate("oc-1", "data_transfer:t1", Disposition.DECIDED, "2026-09-09T10:00:00Z", basis="gdpr-2016-679-art-44",
       evidence=("sha256:4da8b3468ad57b8a4e6c6d2a741876e1b3f00eb8c974df29e540c9517e2a88d2",), human=Human("dpo-01", "dpo")), canonicalize=dumps, sign=key.sign).to_dict()
     verify(envelope, canonicalize=dumps, verify_sig=verify_sig, now="2026-09-09T10:00:01Z")
out: {"payloadType": "application/vnd.oversight-certificate+json", "payload": "eyJhY3Rpb24iOiJkYXRhX3RyYW5zZmVyOnQx…
     Report(ok=True, findings=[], independence=<Independence.UNDECLARED: 'undeclared'>)
```

## Interface

- `OversightCertificate(id, action, disposition, at, basis, evidence=(), human=None, escalated_to=None, assistance=None)`; `Disposition`: DECIDED, ESCALATED, ABSTAINED; `Human(id, qualification, credential_not_after=None)`
- `issue(cert, *, canonicalize, sign, keyid="") -> Envelope` (DSSE); raises `InvalidCertificate`
- `verify(envelope, *, canonicalize, verify_sig, now, required_basis=None) -> Report(ok, findings, independence)`; `Finding.code`, e.g. `unqualified-at-decision`
- limits: one signature per envelope; caller supplies RFC 8785 canonicaliser and Ed25519 keys; credential validity read from the certificate; sufficiency left to the auditor ([docs/limitations.md](docs/limitations.md))

## Family

Assurance artifact, pillar "oversight" of [governance-certification](https://github.com/flxk1/governance-certification); embeds as its `overseen` sub-attestation. Docs: [docs/](docs/).

## Status

0.2.0 · 19 tests · 14 conformance vectors · Python ≥ 3.10

## How this is made

The code and documentation are written with Loomground agents. The maintainer reads and corrects all of it.

## License

MIT — [LICENSES/MIT.txt](LICENSES/MIT.txt)
