"""Response envelopes (SPEC 5.5): every vector, wrong HTTP statuses, and edge cases."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest

from util import env_keys, vectors_of

import datumesh
from datumesh import EnvelopeResult, check_envelope

STATUS = {"ok": [200], "stale": [200], "not_covered": [404], "unlicensed": [403], "payment_required": [402],
          "rate_limited": [429], "error": list(range(500, 600))}
PROBE_STATUSES = [100, 200, 201, 204, 301, 302, 304, 400, 401, 402, 403, 404, 409, 429, 499, 500, 503, 599, 600, 0, -200]

PRIMARY = next(v for v in vectors_of("envelope", True) if v["id"] == "envelope/ok-primary")
KEYS = env_keys(PRIMARY["keys"])
R = json.loads(PRIMARY["input"])["receipt"]
R_HASH = PRIMARY["receipt_hash"]
SB = "f670bbe9ced52884b8187be1b2c1df15470079356998eb291bed9910432ca5c9"
QUOTE = {"amount": "0.05", "authorise": "https://mesh.example/pay", "currency": "EUR"}


def ok(**kw) -> dict:
    return dict({"outcome": "ok", "receipt": R, "trust": "primary"}, **kw)


def stale(**kw) -> dict:
    return dict({"outcome": "stale", "receipt": R, "trust": "primary", "age_seconds": 1}, **kw)


def quote(**kw) -> dict:
    return {"outcome": "payment_required", "quote": dict(QUOTE, **kw)}


def raw_with(member: str, literal: str, outcome: str = "stale") -> str:
    """An envelope body whose ``member`` is the JSON number text ``literal``."""
    if outcome == "stale":
        return '{"outcome":"stale","receipt":%s,"trust":"primary","%s":%s}' % (json.dumps(R), member, literal)
    return '{"outcome":"%s","%s":%s}' % (outcome, member, literal)


class EnvelopeVectorTest(unittest.TestCase):
    """Contract test 4."""

    def test_every_vector(self) -> None:
        n = 0
        for v in vectors_of("envelope"):
            with self.subTest(v["id"]):
                res = check_envelope(v["status"], v["input"], env_keys(v["keys"]))
                if v["valid"]:
                    self.assertEqual((res.ok, res.code, res.outcome, res.trust, res.receipt_hash),
                                     (True, "OK", v["outcome"], v.get("trust"), v.get("receipt_hash")))
                else:
                    self.assertEqual((res.ok, res.code), (False, v["error"]))
                n += 1
        self.assertEqual(n, 35)

    def test_valid_bodies_with_wrong_status(self) -> None:
        total = 0
        for v in vectors_of("envelope", True):
            keys = env_keys(v["keys"])
            right = STATUS[v["outcome"]]
            self.assertIn(v["status"], right)
            for status in PROBE_STATUSES:
                if status in right:
                    continue
                with self.subTest(v["id"], status=status):
                    res = check_envelope(status, v["input"], keys)
                    self.assertEqual((res.ok, res.code), (False, "E_ENVELOPE"))
                    self.assertEqual(res.path, "status")
                    total += 1
        print(f"\nvalid envelopes with a wrong HTTP status: {total} run, {total} rejected with E_ENVELOPE",
              file=sys.stderr)

    def test_status_must_be_an_int(self) -> None:
        for status in ("200", 200.0, None, True):
            with self.subTest(status=status):
                self.assertEqual(check_envelope(status, PRIMARY["input"], KEYS).code, "E_ENVELOPE")  # type: ignore


class EnvelopeRulesTest(unittest.TestCase):
    # Every expected code here was confirmed against the reference tool, used as a black box.
    CASES = [
        # integral JSON numbers (SPEC 5.5: "JSON numbers with integral values, at most 2^53 - 1")
        (200, raw_with("age_seconds", "0"), "OK"),
        (200, raw_with("age_seconds", "30.0"), "OK"),
        (200, raw_with("age_seconds", "3e1"), "OK"),
        (200, raw_with("age_seconds", "1.0e0"), "OK"),
        (200, raw_with("age_seconds", "-0"), "OK"),
        (200, raw_with("age_seconds", "9007199254740991"), "OK"),
        (200, raw_with("age_seconds", "9007199254740992"), "E_ENVELOPE"),
        (200, raw_with("age_seconds", "-1"), "E_ENVELOPE"),
        (200, raw_with("age_seconds", "1.5"), "E_ENVELOPE"),
        (200, raw_with("age_seconds", "true"), "E_ENVELOPE"),
        (200, raw_with("age_seconds", '"30"'), "E_ENVELOPE"),
        (200, raw_with("age_seconds", "null"), "E_ENVELOPE"),
        (200, raw_with("age_seconds", "1e400"), "E_PARSE_JSON"),
        (429, raw_with("retry_after_seconds", "30.0", "rate_limited"), "OK"),
        (429, raw_with("retry_after_seconds", "-1", "rate_limited"), "E_ENVELOPE"),
        (429, raw_with("retry_after_seconds", "9007199254740992", "rate_limited"), "E_ENVELOPE"),
        # superseded_by and reason
        (200, ok(superseded_by=SB, reason="x"), "OK"),
        (200, stale(superseded_by=SB, reason="x"), "OK"),
        (200, ok(superseded_by=SB, reason=""), "E_ENVELOPE"),
        (200, ok(superseded_by=SB, reason="Zürich"), "E_ENVELOPE"),
        (200, ok(superseded_by=SB, reason="a\nb"), "E_ENVELOPE"),
        (200, ok(superseded_by=SB, reason="͸"), "E_ENVELOPE"),
        (200, ok(superseded_by=SB, reason="a" * 1024), "OK"),
        (200, ok(superseded_by=SB, reason="a" * 1025), "E_ENVELOPE"),
        (200, ok(superseded_by=SB, reason=5), "E_ENVELOPE"),
        (200, ok(reason="x"), "E_ENVELOPE"),
        (200, ok(superseded_by=SB.upper()), "E_ENVELOPE"),
        (200, ok(superseded_by=SB[:-1]), "E_ENVELOPE"),
        (200, ok(superseded_by=R_HASH), "E_ENVELOPE"),
        # quotes
        (402, quote(), "OK"),
        (402, quote(amount="0"), "E_ENVELOPE"),
        (402, quote(amount="-1"), "E_ENVELOPE"),
        (402, quote(amount="1e2"), "E_ENVELOPE"),
        (402, quote(amount="0.50"), "E_ENVELOPE"),
        (402, quote(amount=1), "E_ENVELOPE"),
        (402, quote(amount="1" * 129), "E_ENVELOPE"),
        (402, quote(x=1), "E_ENVELOPE"),
        (402, {"outcome": "payment_required", "quote": {"amount": "1", "currency": "EUR"}}, "E_ENVELOPE"),
        (402, {"outcome": "payment_required", "quote": "1 EUR"}, "E_ENVELOPE"),
        (402, quote(authorise="http://mesh.example/pay"), "E_ENVELOPE"),
        (402, quote(authorise="HTTPS://mesh.example/pay"), "E_ENVELOPE"),
        (402, quote(authorise="https://"), "E_ENVELOPE"),
        (402, quote(authorise="https://mesh.example/p ay"), "E_ENVELOPE"),
        (402, quote(authorise="https://" + "a" * 504), "OK"),
        (402, quote(authorise="https://" + "a" * 505), "E_ENVELOPE"),
        (402, quote(currency="GRD"), "OK"),
        (402, quote(currency="XXX"), "E_ENVELOPE"),
        (402, quote(currency="kg"), "E_ENVELOPE"),
        (402, quote(currency="eur"), "E_ENVELOPE"),
        (402, quote(currency={"arg": "x"}), "E_ENVELOPE"),
        # error codes
        (500, {"outcome": "error", "error": "E_ENVELOPE"}, "OK"),
        (500, {"outcome": "error", "error": "E_BLOB_MISMATCH"}, "OK"),
        (500, {"outcome": "error", "error": "OK"}, "E_ENVELOPE"),
        (500, {"outcome": "error", "error": "E_PROBE"}, "E_ENVELOPE"),
        (500, {"outcome": "error", "error": 5}, "E_ENVELOPE"),
        (599, {"outcome": "error", "error": "E_SIGNATURE"}, "OK"),
        (600, {"outcome": "error", "error": "E_SIGNATURE"}, "E_ENVELOPE"),
        (499, {"outcome": "error", "error": "E_SIGNATURE"}, "E_ENVELOPE"),
        # outcomes and members
        (404, {}, "E_ENVELOPE"),
        (404, {"outcome": 1}, "E_ENVELOPE"),
        (404, {"outcome": "not_covered", "x": 1}, "E_ENVELOPE"),
        (200, ok(age_seconds=1), "E_ENVELOPE"),
        (200, ok(trust=None), "E_ENVELOPE"),
        (200, ok(receipt="x"), "E_ENVELOPE"),
        (200, ok(receipt=[]), "E_ENVELOPE"),
        (404, "[]", "E_ENVELOPE"),
        (404, "null", "E_ENVELOPE"),
        (404, '"not_covered"', "E_ENVELOPE"),
        (404, "not json", "E_PARSE_JSON"),
        (404, "", "E_PARSE_JSON"),
        (404, "﻿{\"outcome\":\"not_covered\"}", "E_PARSE_JSON"),
        (404, '{"outcome":"not_covered","outcome":"not_covered"}', "E_PARSE_DUPLICATE_KEY"),
        # the embedded receipt keeps its own codes; member and status checks come first
        (200, ok(receipt={k: v for k, v in R.items() if k != "summary"}), "E_SCHEMA"),
        (200, ok(receipt=dict(R, x=1)), "E_SCHEMA"),
        (200, ok(receipt=dict(R, value="1.50")), "E_CANON_NUMBER"),
        (200, ok(receipt=dict(R, cell=dict(R["cell"], args=dict(R["cell"]["args"], base="*")))), "E_SLICE"),
        (200, ok(receipt=dict(R, summary="x")), "E_SIGNATURE"),
        (200, ok(receipt=dict(R, summary="x"), trust="trusted"), "E_ENVELOPE"),
        (404, ok(receipt=dict(R, summary="x")), "E_ENVELOPE"),
        (200, ok(receipt=dict(R, summary="x"), superseded_by=R_HASH), "E_SIGNATURE"),
        (200, ok(trust="verified", superseded_by=R_HASH), "E_ENVELOPE"),
        (200, '{"outcome":"ok","trust":"primary","receipt":%s}' % json.dumps(R).replace('{"', '{"proto":"x","', 1),
         "E_PARSE_DUPLICATE_KEY"),
    ]

    def test_cases(self) -> None:
        for status, body, code in self.CASES:
            text = body if isinstance(body, str) else json.dumps(body)
            with self.subTest(text[:100], status=status):
                res = check_envelope(status, text, KEYS)
                self.assertEqual(res.code, code, res)
                self.assertEqual(res.ok, code == "OK")

    def test_no_keys_for_the_signer(self) -> None:
        self.assertEqual(check_envelope(200, json.dumps(ok()), []).code, "E_KEY_UNAVAILABLE")
        self.assertEqual(check_envelope(200, json.dumps(ok()), {}).code, "E_KEY_UNKNOWN")  # {} maps no key ids

    def test_result(self) -> None:
        res = check_envelope(200, PRIMARY["input"], KEYS)
        self.assertEqual(res, EnvelopeResult(True, "OK", "ok", "primary", R_HASH, res.detail, None))
        self.assertEqual(R_HASH, hashlib.sha256(datumesh.receipt_payload(R)).hexdigest())
        res = check_envelope(404, '{"outcome":"not_covered"}', {})
        self.assertEqual((res.ok, res.outcome, res.trust, res.receipt_hash), (True, "not_covered", None, None))
        res = check_envelope(200, json.dumps(ok(trust="trusted")), KEYS)
        self.assertEqual((res.ok, res.code, res.path), (False, "E_ENVELOPE", "$.trust"))
        res = check_envelope(200, json.dumps(ok(receipt=dict(R, value="1.50"))), KEYS)
        self.assertEqual((res.code, res.path), ("E_CANON_NUMBER", "$.receipt.value"))

    def test_never_raises_on_bad_input(self) -> None:
        bodies = [b"\xff", b"{", b"[" * 100000, "{\"outcome\": \"ok\", \"receipt\": {}}", json.dumps(ok(receipt={}))]
        for body in bodies:
            for status in (200, 404):
                self.assertIsInstance(check_envelope(status, body, KEYS), EnvelopeResult)

    def test_wrong_argument_types(self) -> None:
        with self.assertRaises(TypeError):
            check_envelope(200, {"outcome": "not_covered"}, {})  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            check_envelope(200, '{"outcome":"not_covered"}', 5)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
