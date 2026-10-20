"""Test 3: cell URI round trips, plus URI edge cases."""

from __future__ import annotations

import unittest

from util import vectors_of

import datumesh
from datumesh import DatumeshError, format_uri, parse_uri

FX = {"args": {"base": {"type": "string", "valid": False}, "date": {"type": "date", "valid": True},
               "quote": {"type": "string", "valid": False}}, "returns": "number"}


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
        self.assertEqual(n, 10)

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

    def test_parse_validates_signature(self) -> None:
        bad = {"args": {"n": {"type": "number", "valid": True}}, "returns": "number"}
        with self.assertRaises(DatumeshError) as cm:
            parse_uri("cell://math.example/f?n=1", bad)
        self.assertEqual(cm.exception.code, "E_CANON_TYPE")
        with self.assertRaises(TypeError):
            parse_uri(b"cell://math.example/pi", {"args": {}, "returns": "number"})  # type: ignore[arg-type]

    def test_https_mapping(self) -> None:
        u = "cell://rates.example.org/fx_rate?base=EUR&date=*&quote=USD"
        self.assertEqual(datumesh.uri_to_https(u, "mesh.example"),
                         "https://mesh.example/cell/rates.example.org/fx_rate?base=EUR&date=*&quote=USD")

    # Codes below were confirmed against spec/tools/canon.py used as a black box
    # (except where marked as a deliberate divergence in DEFECTS.md).
    CASES = [
        ("cell://math.example", {}, "E_CANON_NAME"),
        ("cell://user@math.example/pi", {}, "E_CANON_NAME"),
        ("cell://math.example:443/pi", {}, "E_CANON_NAME"),
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
        # Deliberate divergence (DEFECTS.md, URI-1): the outer grammar is checked before names,
        # as SPEC 5.4 orders it; the reference tool reports E_CANON_NAME here.
        ("cell://X.example/f?c", {"a": "number"}, "E_PARSE_URI"),
    ]

    def test_edge_cases(self) -> None:
        for uri, types, code in self.CASES:
            sig = {"args": {k: {"type": t, "valid": False} for k, t in types.items()}, "returns": "number"}
            with self.subTest(uri[:80]):
                if code is None:
                    parse_uri(uri, sig)
                else:
                    with self.assertRaises(DatumeshError) as cm:
                        parse_uri(uri, sig)
                    self.assertEqual(cm.exception.code, code, cm.exception)


if __name__ == "__main__":
    unittest.main()
