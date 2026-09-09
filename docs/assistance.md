# How the judgement was formed

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
