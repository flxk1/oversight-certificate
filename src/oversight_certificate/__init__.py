"""A re-checkable certificate that a qualified human exercised meaningful oversight.

When an AI system escalates a consequential decision to a human, "a human
approved it" is, on its own, an unfalsifiable claim. This package turns it into a
proof: a signed, portable record of *what was decided or refused, which qualified
human took responsibility, on what evidence, and under which legal obligation* —
re-verifiable offline by a third party from the certificate and a public key
alone, without trusting the system that produced it.

It computes and checks; it does not judge. :func:`verify` proves a qualified
human decided at a given time and locates every structural or cryptographic
defect, but whether that oversight was *legally sufficient* stays with the
auditor. Refusal is first-class: a decision is DECIDED, ESCALATED (routed to a
human, pending, with evidence), or ABSTAINED (recorded, not forced).

Since 0.2.0 a certificate may also declare **how the judgement was formed**
(:class:`Assistance`). Art. 14 requires oversight by *natural persons*, and the
settled audit schema records who reviewed what, when, under what information — but
"under what information" is what was *shown to* the reviewer, never what the
reviewer *consulted*. A reviewer who asked a model is indistinguishable from one
who read the file. The concern is not only over-reliance: where the aid belongs to
the same model family as the system under review, the check may inherit the
subject's blind spot, and a check that is not independent is not oversight.

Declaring it **never invalidates a certificate** — not even
:attr:`Independence.MODEL_CORRELATED`. That is deliberate and load-bearing: a
disclosure that can be used against the discloser stops being made (the ASRS
non-punitive principle). Independence is *reported* on the :class:`Report`, never
a :class:`Finding`, and an undeclared certificate stays exactly as valid as it was
in 0.1.0.

Composed, not reinvented — the caller injects the FOSS primitives (closed I/O):
canonical bytes via RFC 8785 (pass ``rfc8785.dumps``), signatures via
``cryptography`` (Ed25519), wrapped in the in-toto DSSE envelope. This module owns
only the oversight semantic; see the README's Origin section.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

__all__ = [
    "Disposition", "Human", "Aid", "Assistance", "Independence",
    "OversightCertificate", "Envelope",
    "Finding", "Report", "issue", "verify", "InvalidCertificate",
]
from ._version import __version__

DSSE_PAYLOAD_TYPE = "application/vnd.oversight-certificate+json"


class InvalidCertificate(ValueError):
    """Raised by :func:`issue` when asked to sign a structurally-incoherent
    certificate (findings attached as ``.findings``)."""

    def __init__(self, findings: "list[Finding]") -> None:
        super().__init__("; ".join(f.code for f in findings))
        self.findings = findings


class Disposition(str, Enum):
    DECIDED = "decided"      # a qualified human ruled
    ESCALATED = "escalated"  # the machine refused; routed to a human, pending, with evidence
    ABSTAINED = "abstained"  # no decision in scope; recorded, not forced


@dataclass(frozen=True)
class Human:
    """The person who took responsibility. ``credential_not_after`` is when their
    qualifying credential lapses (ISO 8601); a lapse *after* the decision does not
    void the record — see :func:`verify`."""
    id: str
    qualification: str
    credential_not_after: Optional[str] = None


class Aid(str, Enum):
    """What the overseer used to form the judgement. Self-declared."""
    UNAIDED = "unaided"              # unassisted human judgement
    DETERMINISTIC = "deterministic"  # a calculator, checklist, rule engine — no generative model
    MODEL = "model"                  # a generative model assisted the judgement


@dataclass(frozen=True)
class Assistance:
    """How the judgement was formed.

    ``same_model_family`` is a proxy for *correlated failure* — an aid drawn from
    the same family as the system under review may share its blind spot. ``None``
    means the reviewer did not state the relationship, which is honest and common;
    it yields :attr:`Independence.MODEL_UNDETERMINED` rather than a guess."""
    aid: Aid
    system: str = ""                            # optional identifier of the aid used
    same_model_family: Optional[bool] = None     # only meaningful when aid is MODEL


class Independence(str, Enum):
    """Whether the check was independent of what it checked. Reported, never a finding."""
    UNDECLARED = "undeclared"                    # the certificate makes no claim (all 0.1.0 records)
    UNAIDED = "unaided"
    DETERMINISTIC = "deterministic"
    MODEL_INDEPENDENT = "model-independent"      # model aid, declared a different family
    MODEL_CORRELATED = "model-correlated"        # model aid, declared the same family
    MODEL_UNDETERMINED = "model-undetermined"    # model aid, relationship not stated


@dataclass(frozen=True)
class OversightCertificate:
    id: str
    action: str                       # what was under oversight
    disposition: Disposition
    at: str                           # ISO 8601 decision time
    basis: str                        # the named legal obligation, e.g. "eu-ai-act-2024-1689-art-14"
    evidence: tuple[str, ...] = ()     # content hashes of what the overseer was shown
    human: Optional[Human] = None      # who took responsibility (DECIDED)
    escalated_to: Optional[str] = None  # who a decision was routed to (ESCALATED)
    assistance: Optional[Assistance] = None  # how the judgement was formed (0.2.0; optional)

    def to_payload(self) -> dict:
        d: dict = {
            "id": self.id, "action": self.action,
            "disposition": self.disposition.value, "at": self.at,
            "basis": self.basis, "evidence": list(self.evidence),
        }
        if self.human is not None:
            d["human"] = {
                "id": self.human.id, "qualification": self.human.qualification,
                "credential_not_after": self.human.credential_not_after,
            }
        if self.escalated_to is not None:
            d["escalated_to"] = self.escalated_to
        if self.assistance is not None:
            a: dict = {"aid": self.assistance.aid.value}
            if self.assistance.system:
                a["system"] = self.assistance.system
            if self.assistance.same_model_family is not None:
                a["same_model_family"] = self.assistance.same_model_family
            d["assistance"] = a
        return d


@dataclass(frozen=True)
class Envelope:
    """A DSSE (in-toto Dead-Simple-Signing-Envelope) wrapper. Interoperable with
    the DSSE ecosystem; single-signature in this version."""
    payload_type: str
    payload_b64: str
    sig_b64: str
    keyid: str = ""

    def to_dict(self) -> dict:
        return {
            "payloadType": self.payload_type, "payload": self.payload_b64,
            "signatures": [{"sig": self.sig_b64, "keyid": self.keyid}],
        }


@dataclass
class Finding:
    code: str
    detail: str


@dataclass
class Report:
    ok: bool
    findings: "list[Finding]"
    #: Whether the check was independent of what it checked. Never affects ``ok``.
    independence: Independence = Independence.UNDECLARED


def _pae(payload_type: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (the in-toto DSSE spec's signed-bytes rule)."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(pt), pt, len(body), body)


def _shape_findings(cert: OversightCertificate) -> "list[Finding]":
    f: list[Finding] = []
    if not cert.basis:
        f.append(Finding("no-legal-basis", "a certificate must name the legal obligation it discharges"))
    if cert.disposition == Disposition.DECIDED:
        if cert.human is None:
            f.append(Finding("decided-without-human", "a DECIDED certificate must name the human who took responsibility"))
        if not cert.evidence:
            f.append(Finding("decided-without-evidence", "a DECIDED certificate must record the evidence the overseer was shown"))
    elif cert.disposition == Disposition.ESCALATED:
        if not cert.escalated_to:
            f.append(Finding("escalated-without-target", "an ESCALATED certificate must name who it was routed to"))
        if cert.human is not None:
            f.append(Finding("escalated-with-decision", "an ESCALATED certificate is pending; it must not carry a human decision"))
        if not cert.evidence:
            f.append(Finding("escalated-without-evidence", "an ESCALATED certificate must carry the evidence routed to the human"))
    return f


def _independence(cert: OversightCertificate) -> Independence:
    """Map a declared assistance onto the independence question. Pure; no findings.

    An undeclared certificate is UNDECLARED, not UNAIDED — silence is not a claim
    of unassisted judgement, and reading it as one would manufacture the very
    reassurance this field exists to withhold."""
    a = cert.assistance
    if a is None:
        return Independence.UNDECLARED
    if a.aid is Aid.UNAIDED:
        return Independence.UNAIDED
    if a.aid is Aid.DETERMINISTIC:
        return Independence.DETERMINISTIC
    if a.same_model_family is None:
        return Independence.MODEL_UNDETERMINED
    return Independence.MODEL_CORRELATED if a.same_model_family else Independence.MODEL_INDEPENDENT


def issue(cert: OversightCertificate, *,
          canonicalize: Callable[[dict], bytes],
          sign: Callable[[bytes], bytes],
          keyid: str = "") -> Envelope:
    """Canonicalise the certificate (pass ``rfc8785.dumps``), wrap it in a DSSE
    envelope, and sign the PAE with ``sign`` (Ed25519). The signing key is never
    read here — ``sign`` is the caller's closed function. Refuses to mint a
    structurally-incoherent certificate (raises :class:`InvalidCertificate`)."""
    findings = _shape_findings(cert)
    if findings:
        raise InvalidCertificate(findings)
    body = canonicalize(cert.to_payload())
    sig = sign(_pae(DSSE_PAYLOAD_TYPE, body))
    return Envelope(DSSE_PAYLOAD_TYPE,
                    base64.b64encode(body).decode("ascii"),
                    base64.b64encode(sig).decode("ascii"), keyid)


def _from_payload(payload: dict) -> Optional[OversightCertificate]:
    try:
        h = payload.get("human")
        human = Human(h["id"], h["qualification"], h.get("credential_not_after")) if h else None
        a = payload.get("assistance")
        assistance = Assistance(
            Aid(a["aid"]), a.get("system", ""), a.get("same_model_family"),
        ) if a else None
        return OversightCertificate(
            id=payload["id"], action=payload["action"],
            disposition=Disposition(payload["disposition"]),
            at=payload["at"], basis=payload.get("basis", ""),
            evidence=tuple(payload.get("evidence", ())),
            human=human, escalated_to=payload.get("escalated_to"),
            assistance=assistance,
        )
    except (KeyError, ValueError, TypeError):
        return None


def verify(envelope: dict, *,
           canonicalize: Callable[[dict], bytes],
           verify_sig: Callable[[bytes, bytes], bool],
           now: str,
           required_basis: Optional[str] = None) -> Report:
    """Re-check a certificate from the envelope and a public verify function
    ALONE — offline, third-party, no trust in the issuer. Locates defects; it does
    NOT rule whether the oversight was legally sufficient (that stays with the
    auditor). ``now`` and the credential's validity window are inputs, never
    fetched here.

    Checks: the DSSE signature; that the payload is in canonical form (signed bytes
    reproducible); shape coherence for the disposition; and — the distinctive one —
    that the overseer's credential was valid *at the decision time*, so a credential
    that lapses *after* a valid decision does not retroactively void the record.

    Also reports :attr:`Report.independence` — whether the check was independent of
    what it checked. It is **never** a finding and never affects ``ok``, including
    MODEL_CORRELATED: a disclosure that can be used against the discloser stops
    being made."""
    findings: list[Finding] = []
    try:
        ptype = envelope["payloadType"]
        body = base64.b64decode(envelope["payload"])
        sig = base64.b64decode(envelope["signatures"][0]["sig"])
        payload = json.loads(body)
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        return Report(False, [Finding("malformed-envelope", str(exc))])

    if not verify_sig(_pae(ptype, body), sig):
        findings.append(Finding("bad-signature", "the DSSE signature does not verify"))

    if canonicalize(payload) != body:
        findings.append(Finding("non-canonical-payload",
                                "payload is not in canonical form; the signed bytes are not reproducible"))

    cert = _from_payload(payload)
    if cert is None:
        findings.append(Finding("unparseable-payload", "the payload is not a well-formed oversight certificate"))
        return Report(False, findings)

    # Reported, never a finding: a declared correlation must not cost the discloser
    # anything, or the declaration stops being made.
    independence = _independence(cert)

    findings.extend(_shape_findings(cert))

    if (cert.disposition == Disposition.DECIDED and cert.human is not None
            and cert.human.credential_not_after is not None
            and cert.human.credential_not_after < cert.at):
        findings.append(Finding(
            "unqualified-at-decision",
            f"the overseer's credential lapsed at {cert.human.credential_not_after}, "
            f"before the decision at {cert.at}"))

    if required_basis is not None and cert.basis != required_basis:
        findings.append(Finding("wrong-basis", f"expected basis {required_basis!r}, got {cert.basis!r}"))

    return Report(not findings, findings, independence)
