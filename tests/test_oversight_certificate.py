"""Tests for oversight_certificate. Runs under both `pytest` and
`python -m unittest discover -s tests`. Signatures use a real Ed25519 key via
`cryptography`; canonicalisation uses a deterministic in-test stub (production
passes `rfc8785.dumps`), which is all these tests need to exercise the oversight
semantic (issue/verify/disposition/qualification-at-time)."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from oversight_certificate import (  # noqa: E402
    Disposition, Human, OversightCertificate, InvalidCertificate, issue, verify,
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


if __name__ == "__main__":
    unittest.main()
