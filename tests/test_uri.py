"""Test 3: cell URI round trips, plus URI edge cases."""

from __future__ import annotations

import unittest

from util import vectors_of

import datumesh
from datumesh import DatumeshError, format_uri, parse_uri

FX = {"args": {"base": {"type": "string", "valid": False}, "date": {"type": "date", "valid": True},
               "quote": {"type": "string", "valid": False}},
      "returns": {"type": "number", "unit": {"of": {"arg": "quote"}, "per": {"arg": "base"}}}}


def _decl(t: str) -> dict:
    return {"type": t, "unit": "1", "valid": False} if t == "number" else {"type": t, "valid": False}


class UriTest(unittest.TestCase):
    def test_round_trip_every_valid_vector(self) -> None:
        n = 0
        for v in vectors_of("uri", True):
            with self.subTest(v["id"]):
                ref = parse_uri(v["input"], v["signature"])
                self.assertEqual(ref, v["object"])
                self.assertEqual(format_uri(ref), v["input"])
                self.assertEqual(parse_uri(format_uri(v["object"]), v["signature"]), v["object"])
                n += 1
        self.assertEqual(n, 11)
        self.assertEqual(len(vectors_of("uri", False)), 32)

    def test_invalid_vectors(self) -> None:
        for v in vectors_of("uri", False):
            with self.subTest(v["id"]), self.assertRaises(DatumeshError) as cm:
                parse_uri(v["input"], v["signature"])
            self.assertEqual(cm.exception.code, v["error"])

    def test_format_encodes_everything_but_literals(self) -> None:
        ref = {"args": {"base": {"type": "string", "value": "a b+c/é*~:._-"}, "date": "*",
                        "quote": {"type": "string", "value": ""}}, "fn": "fx_rate", "ns": "rates.example.org",
               "asof": "2024-03-16T09:00:00.000000Z"}
        uri = format_uri(ref)
        self.assertEqual(uri, "cell://rates.example.org/fx_rate?base=a%20b%2Bc%2F%C3%A9%2A~:._-&date=*&quote="
                              "&asof=2024-03-16T09:00:00.000000Z")
        self.assertEqual(parse_uri(uri, FX), ref)

    def test_format_validates(self) -> None:
        with self.assertRaises(DatumeshError) as cm:
            format_uri({"args": {}, "fn": "Pi", "ns": "math.example"})
        self.assertEqual(cm.exception.code, "E_CANON_NAME")

    def test_parse_takes_signature_as_given(self) -> None:
        # SPEC 5.4 (2a77580): the signature comes from a checked descriptor and is not checked again.
        lax = {"args": {"n": {"type": "number", "valid": True}}, "returns": "number"}
        self.assertEqual(parse_uri("cell://math.example/f?n=1", lax),
                         {"args": {"n": {"type": "number", "value": "1"}}, "fn": "f", "ns": "math.example"})
        # A type outside the six still cannot type a value.
        with self.assertRaises(DatumeshError) as cm:
            parse_uri("cell://math.example/f?n=1", {"args": {"n": {"type": "decimal", "valid": False}}})
        self.assertEqual(cm.exception.code, "E_CANON_TYPE")
        # A signature whose argument types cannot be read is E_SCHEMA (SPEC 5.4 step 5, spec-0.2.1).
        for bad in (None, {}, {"args": []}, {"args": {"n": {}}}, {"args": {"n": {"type": 5}}}):
            with self.subTest(bad=bad), self.assertRaises(DatumeshError) as cm:
                parse_uri("cell://math.example/f?n=1", bad)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "E_SCHEMA")
        with self.assertRaises(TypeError):
            parse_uri(b"cell://math.example/pi", {"args": {}, "returns": "boolean"})  # type: ignore[arg-type]


    def test_https_mapping(self) -> None:
        u = "cell://rates.example.org/fx_rate?base=EUR&date=*&quote=USD"
        self.assertEqual(datumesh.uri_to_https(u, "mesh.example"),
                         "https://mesh.example/cell/rates.example.org/fx_rate?base=EUR&date=*&quote=USD")

    # Codes below were confirmed against spec/tools/canon.py used as a black box
    # (except where marked as a deliberate divergence in DEFECTS.md).
    CASES = [
        ("cell://math.example", {}, "E_CANON_NAME"),
        ("cell://user@math.example/pi", {}, "E_PARSE_URI"),
        ("cell://math.example:443/pi", {}, "E_PARSE_URI"),
        # Userinfo and ports are outer-grammar failures (SPEC 5.1; DEFECTS.md DEF-02).
        ("cell://user@rates.example.org/fx_rate?base=EUR", {"base": "string"}, "E_PARSE_URI"),
        ("cell://rates.example.org:443/fx_rate?base=EUR", {"base": "string"}, "E_PARSE_URI"),
        ("cell://rates.example.org:/fx_rate", {}, "E_PARSE_URI"),
        ("cell://rates.example.org:https/fx_rate", {}, "E_PARSE_URI"),
        ("cell://user:pw@rates.example.org:443/fx_rate", {}, "E_PARSE_URI"),
        ("cell://rates.example.org:443", {}, "E_PARSE_URI"),
        ("cell://a@b.example?x=1", {"x": "number"}, "E_PARSE_URI"),
        ("cell://User@X.example/F?c", {}, "E_PARSE_URI"),
        # ':' and '@' after the authority are not userinfo or ports: names and values decide.
        ("cell://x.example/f:g", {}, "E_CANON_NAME"),
        ("cell://x.example/f?a=b@c", {"a": "string"}, "E_CANON_PERCENT"),
        ("cell://x.example/f?a=2024-01-01T00:00:00.000000Z", {"a": "instant"}, None),
        ("cell://math.example/pi/", {}, "E_CANON_NAME"),
        ("cell:/math.example/pi", {}, "E_PARSE_URI"),
        ("CELL://math.example/pi", {}, "E_PARSE_URI"),
        ("cell://x.example/f?a=1#", {"a": "number"}, "E_PARSE_URI"),
        ("cell://x.example/f?a=1&&b=2", {"a": "number", "b": "number"}, "E_PARSE_URI"),
        ("cell://x.example/f?a=1&", {"a": "number"}, "E_PARSE_URI"),
        ("cell://x.example/f?=1", {"a": "number"}, "E_CANON_ARG_NAME"),
        ("cell://x.example/f?a=b=c", {"a": "string"}, "E_CANON_PERCENT"),
        ("cell://x.example/f?b=1&a=1&a=2", {"a": "number", "b": "number"}, "E_CANON_ARG_ORDER"),
        ("cell://x.example/f?a=1&b=2&a=3", {"a": "number", "b": "number"}, "E_CANON_ARG_ORDER"),
        ("cell://x.example/f?a=1&a=1&dm_x=1", {"a": "number"}, "E_CANON_ARG_DUPLICATE"),
        ("cell://x.example/f?b=1&a=1&dm_x=1", {"a": "number", "b": "number"}, "E_CANON_ARG_ORDER"),
        ("cell://x.example/f?a=1&asof=2024-01-01T00:00:00.000000Z&b=1", {"a": "number", "b": "number"}, "E_CANON_ARG_ORDER"),
        ("cell://x.example/f?asof=2024-01-01T00:00:00.000000Z&asof=2024-01-01T00:00:00.000000Z&a=1", {"a": "number"},
         "E_CANON_ARG_ORDER"),
        ("cell://x.example/f?asof=2024-01-01T00:00:00.000000Z&a=1&asof=2024-01-01T00:00:00.000000Z", {"a": "number"},
         "E_CANON_ARG_DUPLICATE"),
        ("cell://x.example/f?a=%4", {"a": "string"}, "E_CANON_PERCENT"),
        ("cell://x.example/f?a=%2a", {"a": "string"}, "E_CANON_PERCENT"),
        ("cell://x.example/f?a=%2A", {"a": "number"}, "E_CANON_NUMBER"),
        ("cell://x.example/f?a=%74rue", {"a": "boolean"}, "E_CANON_PERCENT"),
        ("cell://x.example/f?a=*", {"a": "boolean"}, None),
        ("cell://x.example/f?asof=", {}, "E_CANON_INSTANT"),
        ("cell://x.example/f?asof=*", {}, "E_CANON_PERCENT"),
        ("cell://x.example/f?asof=2024-01-01T00%3A00:00.000000Z", {}, "E_CANON_PERCENT"),
        ("cell://x.example/f?" + "a" * 65 + "=1", {"a": "number"}, "E_CANON_LIMIT"),
        ("cell://x.example/" + "a" * 65, {}, "E_CANON_LIMIT"),
        ("cell://x.example/" + ("a" * 60 + "/") * 9 + "f", {}, "E_CANON_LIMIT"),
        ("cell://x.example/" + ("a" * 60 + "/") * 9 + "F", {}, "E_CANON_NAME"),
        ("cell://x.example/f?a=1&z=1", {"a": "number", "b": "number"}, "E_ARG_UNKNOWN"),
        ("cell://x.example/f?" + "&".join("a%02d=1" % i for i in range(33)),
         {"a%02d" % i: "number" for i in range(32)}, "E_CANON_LIMIT"),
        ("cell://x.example/f?a=%ED%A0%80", {"a": "string"}, "E_CANON_PERCENT"),
        ("cell://x.example/f?a=%00", {"a": "string"}, "E_CANON_STRING"),
        ("cell://x.example/f?a=%zz&asof=x", {"a": "string"}, "E_CANON_PERCENT"),
        ("cell://x.example/f?a=%zz", {"a": "number", "b": "number"}, "E_ARG_MISSING"),
        ("cell://10.0.0.1/f", {}, "E_CANON_NAME"),
        ("cell:///f", {}, "E_CANON_NAME"),
        ("cell://x.example/f?B=1&c", {"a": "number"}, "E_PARSE_URI"),
        # The outer grammar is checked entirely before any name (SPEC 5.4 step 1; DEFECTS.md DEF-01).
        ("cell://X.example/f?c", {"a": "number"}, "E_PARSE_URI"),
        # spec-0.2.0 blobs (SPEC 3.7, 5.2): ':' is literal, '/' and '+' are percent-encoded.
        # Codes confirmed against the reference tool.
        ("cell://f.example/d?file=" + "a" * 64 + ":17:text%2Fplain", {"file": "blob"}, None),
        ("cell://f.example/d?file=" + "a" * 64 + "%3A17%3Atext%2Fplain", {"file": "blob"}, "E_CANON_PERCENT"),
        ("cell://f.example/d?file=" + "a" * 64 + ":17:text/plain", {"file": "blob"}, "E_CANON_PERCENT"),
        ("cell://f.example/d?file=" + "a" * 64 + ":17:application/ld+json", {"file": "blob"}, "E_CANON_PERCENT"),
        ("cell://f.example/d?file=*", {"file": "blob"}, None),
        ("cell://f.example/d?file=%2A", {"file": "blob"}, "E_CANON_BLOB"),
        ("cell://f.example/d?file=", {"file": "blob"}, "E_CANON_BLOB"),
        ("cell://f.example/d?file=" + "A" * 64 + ":17:text%2Fplain", {"file": "blob"}, "E_CANON_BLOB"),
    ]

    def test_edge_cases(self) -> None:
        for uri, types, code in self.CASES:
            sig = {"args": {k: _decl(t) for k, t in types.items()}, "returns": "boolean"}
            with self.subTest(uri[:80]):
                if code is None:
                    parse_uri(uri, sig)
                else:
                    with self.assertRaises(DatumeshError) as cm:
                        parse_uri(uri, sig)
                    self.assertEqual(cm.exception.code, code, cm.exception)


if __name__ == "__main__":
    unittest.main()
