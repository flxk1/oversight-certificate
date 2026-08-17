#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 flxk1
"""Check an implementation against the published conformance vectors.

``vectors.json`` specifies the certificate SEMANTICS — disposition shape,
qualification-at-decision-time, and the assistance/independence mapping. Signature
bytes are deliberately out of scope: DSSE is specified elsewhere, and the
distinctive layer here is the oversight semantic. This runner therefore stubs
signature verification and exercises the rest.

Usage:
    python3 conformance/check_vectors.py [path-to-vectors.json]

Exit 0 = conformant · 1 = a vector failed · 2 = the suite could not be run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from oversight_certificate import (  # noqa: E402
    Aid, Assistance, Disposition, Human, OversightCertificate,
    InvalidCertificate, issue, verify,
)


def canon(d) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _cert(d: dict) -> OversightCertificate:
    h = d.get("human")
    a = d.get("assistance")
    return OversightCertificate(
        id=d["id"], action=d["action"], disposition=Disposition(d["disposition"]),
        at=d["at"], basis=d.get("basis", ""), evidence=tuple(d.get("evidence", ())),
        human=Human(h["id"], h["qualification"], h.get("credential_not_after")) if h else None,
        escalated_to=d.get("escalated_to"),
        assistance=Assistance(Aid(a["aid"]), a.get("system", ""), a.get("same_model_family")) if a else None,
    )


def _check(v: dict, now: str) -> list[str]:
    cert = _cert(v["certificate"])
    try:
        envelope = issue(cert, canonicalize=canon, sign=lambda b: b"sig").to_dict()
    except InvalidCertificate as exc:
        # issue() refuses structurally-incoherent certificates; that IS the finding.
        codes = [f.code for f in exc.findings]
        want = v["expect"].get("findings", [])
        missing = [c for c in want if c not in codes]
        errs = [f"findings: {c!r} not raised (got {codes})" for c in missing]
        if v["expect"].get("ok") is True:
            errs.append(f"ok: expected True, but issue() refused with {codes}")
        return errs

    report = verify(envelope, canonicalize=canon, verify_sig=lambda b, s: True,
                    now=now, required_basis=v.get("options", {}).get("required_basis"))
    codes = [f.code for f in report.findings]
    errs = []
    if "ok" in v["expect"] and report.ok != v["expect"]["ok"]:
        errs.append(f"ok: expected {v['expect']['ok']}, got {report.ok} (findings {codes})")
    for want in v["expect"].get("findings", []):
        if want not in codes:
            errs.append(f"findings: expected {want!r} present, got {codes}")
    if "independence" in v["expect"] and report.independence.value != v["expect"]["independence"]:
        errs.append(f"independence: expected {v['expect']['independence']!r}, got {report.independence.value!r}")
    return errs


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent / "vectors.json"
    try:
        doc = json.loads(path.read_text())
    except Exception as exc:
        print(f"cannot read vectors: {exc}", file=sys.stderr)
        return 2
    vectors = doc.get("vectors") or []
    if not vectors:
        # Zero vectors passing is the silent-skip failure; refuse rather than report success.
        print("no vectors found — refusing to report conformance", file=sys.stderr)
        return 2

    failed = 0
    for v in vectors:
        try:
            errs = _check(v, doc["now"])
        except Exception as exc:
            errs = [f"<raised {type(exc).__name__}: {exc}>"]
        if errs:
            failed += 1
            print(f"FAIL {v['id']}")
            for e in errs:
                print(f"     {e}")
            print(f"     {v['note']}")
    print(f"{len(vectors) - failed}/{len(vectors)} vectors conformant"
          f"{'' if not failed else f' — {failed} FAILED'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
