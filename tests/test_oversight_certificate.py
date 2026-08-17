"""Tests for oversight_certificate. Runs under both `pytest` and
`python -m unittest discover -s tests`. Signatures use a real Ed25519 key via
`cryptography`; canonicalisation uses a deterministic in-test stub (production
passes `rfc8785.dumps`), which is all these tests need to exercise the oversight
semantic (issue/verify/disposition/qualification-at-time)."""
from __future__ import annotations

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from oversight_certificate import (  # noqa: E402
    Disposition, Human, OversightCertificate, InvalidCertificate, issue, verify,
    Aid, Assistance, Independence,
)


def canon(d: dict) -> bytes:
    # Deterministic test canonicaliser. Production: pass rfc8785.dumps instead.
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.priv = Ed25519PrivateKey.generate()
        self.pub = self.priv.public_key()
        self.sign = lambda b: self.priv.sign(b)

    def verify_sig(self, body: bytes, sig: bytes) -> bool:
        try:
            self.pub.verify(sig, body)
            return True
        except Exception:
            return False

    def issued(self, cert: OversightCertificate):
        return issue(cert, canonicalize=canon, sign=self.sign).to_dict()

    def check(self, env, *, now="2026-08-12T00:00:00Z", required_basis=None):
        return verify(env, canonicalize=canon, verify_sig=self.verify_sig,
                      now=now, required_basis=required_basis)


DECIDED = OversightCertificate(
    id="d-1", action="publish-model-card", disposition=Disposition.DECIDED,
    at="2026-08-12T10:00:00Z", basis="eu-ai-act-2024-1689-art-14",
    evidence=("sha256:aa",), human=Human("u-7", "notified-body-reviewer",
                                          credential_not_after="2027-01-01T00:00:00Z"))


class TestRoundTrip(Base):
    def test_valid_decided_verifies(self):
        r = self.check(self.issued(DECIDED))
        self.assertTrue(r.ok, [f.code for f in r.findings])
        self.assertEqual(r.findings, [])

    def test_required_basis_match_and_mismatch(self):
        env = self.issued(DECIDED)
        self.assertTrue(self.check(env, required_basis="eu-ai-act-2024-1689-art-14").ok)
        bad = self.check(env, required_basis="gdpr-art-17")
        self.assertFalse(bad.ok)
        self.assertIn("wrong-basis", [f.code for f in bad.findings])


class TestTamperEvidence(Base):
    def test_flipped_payload_fails(self):
        env = self.issued(DECIDED)
        payload = json.loads(__import__("base64").b64decode(env["payload"]))
        payload["action"] = "publish-something-else"
        env["payload"] = __import__("base64").b64encode(canon(payload)).decode()
        r = self.check(env)  # signed bytes no longer match the payload
        self.assertFalse(r.ok)
        self.assertIn("bad-signature", [f.code for f in r.findings])

    def test_non_canonical_payload_detected(self):
        env = self.issued(DECIDED)
        # re-encode the same payload in a NON-canonical byte form; signature is over the canonical body
        payload = json.loads(__import__("base64").b64decode(env["payload"]))
        loose = json.dumps(payload, sort_keys=False, indent=2).encode()
        env["payload"] = __import__("base64").b64encode(loose).decode()
        r = self.check(env)
        self.assertFalse(r.ok)
        codes = [f.code for f in r.findings]
        self.assertTrue("non-canonical-payload" in codes or "bad-signature" in codes)


class TestDispositionCoherence(Base):
    def test_decided_without_human_refused_at_issue(self):
        bad = OversightCertificate("d-2", "act", Disposition.DECIDED,
                                   "2026-08-12T10:00:00Z", "eu-ai-act-2024-1689-art-14",
                                   evidence=("sha256:aa",))
        with self.assertRaises(InvalidCertificate) as cm:
            self.issued(bad)
        self.assertIn("decided-without-human", [f.code for f in cm.exception.findings])

    def test_escalated_roundtrips_and_requires_target_and_evidence(self):
        esc = OversightCertificate("e-1", "high-risk-classification", Disposition.ESCALATED,
                                   "2026-08-12T10:00:00Z", "eu-ai-act-2024-1689-art-14",
                                   evidence=("sha256:bb",), escalated_to="human-reviewer-pool")
        self.assertTrue(self.check(self.issued(esc)).ok)
        with self.assertRaises(InvalidCertificate):
            self.issued(OversightCertificate("e-2", "x", Disposition.ESCALATED,
                                              "2026-08-12T10:00:00Z", "b", evidence=("sha256:bb",)))

    def test_abstained_minimal_ok(self):
        ab = OversightCertificate("a-1", "out-of-scope-request", Disposition.ABSTAINED,
                                  "2026-08-12T10:00:00Z", "eu-ai-act-2024-1689-art-14")
        self.assertTrue(self.check(self.issued(ab)).ok)


class TestQualificationAtDecisionTime(Base):
    def test_credential_lapsed_before_decision_is_a_finding(self):
        cert = OversightCertificate(
            "d-3", "act", Disposition.DECIDED, at="2026-08-12T10:00:00Z",
            basis="eu-ai-act-2024-1689-art-14", evidence=("sha256:aa",),
            human=Human("u-7", "reviewer", credential_not_after="2026-01-01T00:00:00Z"))
        r = self.check(self.issued(cert))
        self.assertFalse(r.ok)
        self.assertIn("unqualified-at-decision", [f.code for f in r.findings])

    def test_credential_lapsing_after_decision_leaves_record_standing(self):
        # The distinctive rule: valid AT decision time; a later lapse does not void it,
        # even when re-verified long after (now is well past not_after).
        cert = OversightCertificate(
            "d-4", "act", Disposition.DECIDED, at="2026-08-12T10:00:00Z",
            basis="eu-ai-act-2024-1689-art-14", evidence=("sha256:aa",),
            human=Human("u-7", "reviewer", credential_not_after="2026-09-01T00:00:00Z"))
        r = self.check(self.issued(cert), now="2030-01-01T00:00:00Z")
        self.assertTrue(r.ok, [f.code for f in r.findings])



class TestAssistance(Base):
    """How the judgement was formed (0.2.0). Declaring it must never cost anything."""

    def cert(self, assistance):
        return OversightCertificate(
            id="d-1", action="publish-model-card", disposition=Disposition.DECIDED,
            at="2026-08-12T10:00:00Z", basis="eu-ai-act-2024-1689-art-14",
            evidence=("sha256:aa",),
            human=Human("u-7", "notified-body-reviewer", credential_not_after="2027-01-01T00:00:00Z"),
            assistance=assistance)

    def test_an_undeclared_certificate_is_byte_identical_to_0_1_0(self):
        """The load-bearing back-compat guarantee: signatures minted before 0.2.0
        must still verify, which requires the canonical bytes to be unchanged."""
        payload = DECIDED.to_payload()
        self.assertNotIn("assistance", payload)
        self.assertEqual(
            canon(payload),
            canon({"id": "d-1", "action": "publish-model-card", "disposition": "decided",
                   "at": "2026-08-12T10:00:00Z", "basis": "eu-ai-act-2024-1689-art-14",
                   "evidence": ["sha256:aa"],
                   "human": {"id": "u-7", "qualification": "notified-body-reviewer",
                             "credential_not_after": "2027-01-01T00:00:00Z"}}))
        self.assertTrue(self.check(self.issued(DECIDED)).ok)

    def test_silence_is_undeclared_not_unaided(self):
        """Reading an absent field as 'unassisted' would manufacture the exact
        reassurance the field exists to withhold."""
        r = self.check(self.issued(DECIDED))
        self.assertIs(r.independence, Independence.UNDECLARED)
        self.assertIsNot(r.independence, Independence.UNAIDED)

    def test_each_aid_maps_to_its_independence(self):
        cases = [
            (Assistance(Aid.UNAIDED), Independence.UNAIDED),
            (Assistance(Aid.DETERMINISTIC, "actuarial-table-v3"), Independence.DETERMINISTIC),
            (Assistance(Aid.MODEL, "some-llm", same_model_family=False), Independence.MODEL_INDEPENDENT),
            (Assistance(Aid.MODEL, "some-llm", same_model_family=True), Independence.MODEL_CORRELATED),
            (Assistance(Aid.MODEL, "some-llm"), Independence.MODEL_UNDETERMINED),
        ]
        for assistance, expected in cases:
            with self.subTest(aid=assistance.aid.value, same=assistance.same_model_family):
                r = self.check(self.issued(self.cert(assistance)))
                self.assertIs(r.independence, expected)
                self.assertTrue(r.ok, [f.code for f in r.findings])

    def test_a_correlated_check_is_reported_and_still_valid(self):
        """The non-punitive rule, pinned. A reviewer who declares they used a model
        of the same family as the subject has told the truth about a real weakness;
        penalising that would end the disclosure. Reported, never a finding."""
        r = self.check(self.issued(self.cert(Assistance(Aid.MODEL, "same-family-llm", True))))
        self.assertIs(r.independence, Independence.MODEL_CORRELATED)
        self.assertTrue(r.ok)
        self.assertEqual(r.findings, [])

    def test_an_unstated_family_relationship_is_undetermined_not_assumed_independent(self):
        r = self.check(self.issued(self.cert(Assistance(Aid.MODEL, "some-llm"))))
        self.assertIs(r.independence, Independence.MODEL_UNDETERMINED)

    def test_assistance_is_inside_the_signed_payload(self):
        """It is a claim about the decision, so it must be bound into the signature —
        not carried alongside where it could be stripped."""
        env = self.issued(self.cert(Assistance(Aid.MODEL, "some-llm", True)))
        payload = json.loads(base64.b64decode(env["payload"]))
        self.assertEqual(payload["assistance"],
                         {"aid": "model", "system": "some-llm", "same_model_family": True})

        payload["assistance"]["same_model_family"] = False        # launder the correlation away
        env["payload"] = base64.b64encode(canon(payload)).decode("ascii")
        r = self.check(env)
        self.assertFalse(r.ok)
        self.assertIn("bad-signature", [f.code for f in r.findings])

    def test_round_trip_recovers_the_declaration(self):
        env = self.issued(self.cert(Assistance(Aid.MODEL, "some-llm", False)))
        payload = json.loads(base64.b64decode(env["payload"]))
        self.assertEqual(payload["assistance"]["system"], "some-llm")
        self.assertIs(self.check(env).independence, Independence.MODEL_INDEPENDENT)

    def test_declaring_assistance_adds_no_new_failure_mode(self):
        """0.2.0 introduces no finding that 0.1.0 did not have."""
        for assistance in (None, Assistance(Aid.UNAIDED), Assistance(Aid.MODEL, "x", True)):
            with self.subTest(assistance=assistance):
                self.assertTrue(self.check(self.issued(self.cert(assistance))).ok)



class TestDSSEInterop(unittest.TestCase):
    """Checks the README's interoperability claim against securesystemslib, the
    in-toto/TUF reference implementation, rather than against our own verifier.
    Skips when absent so the core suite stays dependency-free."""

    def setUp(self):
        try:
            from securesystemslib.dsse import Envelope  # noqa: F401
        except ImportError:
            self.skipTest("securesystemslib not installed")

    def test_a_third_party_implementation_parses_our_envelope(self):
        from securesystemslib.dsse import Envelope

        priv = Ed25519PrivateKey.from_private_bytes(bytes(32))
        envelope = issue(DECIDED, canonicalize=canon, sign=priv.sign).to_dict()
        theirs = Envelope.from_dict(envelope)
        self.assertEqual(theirs.payload_type, "application/vnd.oversight-certificate+json")
        self.assertEqual(json.loads(theirs.payload)["id"], DECIDED.id)

    def test_their_pae_is_byte_identical_to_ours(self):
        """PAE is what gets signed. A one-byte difference makes every signature we
        produce unverifiable to the ecosystem."""
        from securesystemslib.dsse import Envelope
        from oversight_certificate import _pae, DSSE_PAYLOAD_TYPE

        priv = Ed25519PrivateKey.from_private_bytes(bytes(32))
        envelope = issue(DECIDED, canonicalize=canon, sign=priv.sign).to_dict()
        payload = base64.b64decode(envelope["payload"])
        self.assertEqual(Envelope.from_dict(envelope).pae(), _pae(DSSE_PAYLOAD_TYPE, payload))


if __name__ == "__main__":
    unittest.main()
