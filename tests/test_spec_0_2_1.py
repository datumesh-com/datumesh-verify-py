"""Statements written down in spec-0.2.1 (a text-only revision): each is tested here.

Codes were confirmed against the reference tool, used as a black box.
"""

from __future__ import annotations

import copy
import json
import unittest

from util import env_keys, vectors_of

import datumesh
from datumesh import DatumeshError, canonicalize, parse_uri, verify

STORED = next(v for v in vectors_of("receipt", True) if v["id"] == "receipt/stored-number")
R = json.loads(STORED["input"])


def code_of(fn, *args):
    try:
        fn(*args)
        return None
    except DatumeshError as e:
        return e.code


def receipt_code(**changes) -> object:
    r = copy.deepcopy(R)
    for k, v in changes.items():
        r[k] = v
    return code_of(canonicalize, r, "receipt")


class JsonParsingTest(unittest.TestCase):
    """SPEC 6.1: nesting at most 64 levels, and the order in which parse failures are reported."""

    CASES = [
        ("[" * 64 + "]" * 64, None),
        ("[" * 65 + "]" * 65, "E_PARSE_JSON"),
        ('{"a":' * 63 + "[]" + "}" * 63, None),  # 63 objects + 1 array = 64
        ('{"a":' * 64 + "[]" + "}" * 64, "E_PARSE_JSON"),
        ("[" * 65, "E_PARSE_JSON"),  # unclosed, too deep
        ("[" * 100000, "E_PARSE_JSON"),
        # brackets inside strings, escaped quotes included, do not count
        ('{"a": "' + "[" * 100 + '", "a": 2}', "E_PARSE_DUPLICATE_KEY"),
        ('["\\"' + "[" * 100 + '", 1]', None),
        ('["\\\\", ' + "[" * 63 + "]" * 63 + "]", None),
        ('["\\\\", ' + "[" * 64 + "]" * 64 + "]", "E_PARSE_JSON"),
        # depth before anything else in the text
        ('{"a": 1, "a": 2, "b": ' + "[" * 64 + "]" * 64 + "}", "E_PARSE_JSON"),
        ('{"a": 1, "a": 2, "b": ' + "[" * 63 + "]" * 63 + "}", "E_PARSE_DUPLICATE_KEY"),
        # then the first in text order of syntax error, NaN/Infinity, overflow, duplicate (at its close)
        ('[{"a": 1, "a": 2}, NaN]', "E_PARSE_DUPLICATE_KEY"),
        ('[NaN, {"a": 1, "a": 2}]', "E_PARSE_JSON"),
        ('[1e400, {"a": 1, "a": 2}]', "E_PARSE_JSON"),
        ('[{"a": 1, "a": 2}, 1e400]', "E_PARSE_DUPLICATE_KEY"),
        ('[{"a": 1, "a": 2}, x]', "E_PARSE_DUPLICATE_KEY"),
        ('{"a": 1, "a": 2, x}', "E_PARSE_JSON"),
        ('{"a": {"b": 1, "b": 2}, "a": 3}', "E_PARSE_DUPLICATE_KEY"),
        # lone surrogates last
        ('{"a": "\\ud800", "a": 1}', "E_PARSE_DUPLICATE_KEY"),
        ('["\\ud800", NaN]', "E_PARSE_JSON"),
        ("[1e-400]", None),  # underflow is not an error
    ]

    def test_cases(self) -> None:
        for text, code in self.CASES:
            with self.subTest(text[:60]):
                self.assertEqual(code_of(datumesh.jcs, text), code)
                self.assertEqual(code_of(datumesh.jcs, text.encode()), code)

    def test_bom_and_utf8_come_first(self) -> None:
        deep = "[" * 70 + "]" * 70
        self.assertEqual(code_of(datumesh.jcs, b"\xef\xbb\xbf" + deep.encode()), "E_PARSE_JSON")
        self.assertEqual(code_of(datumesh.jcs, b'["\xff"' + deep.encode() + b"]"), "E_PARSE_JSON")

    def test_depth_through_verify_and_envelopes(self) -> None:
        self.assertEqual(verify("[" * 65 + "]" * 65, {}).code, "E_PARSE_JSON")
        body = '{"outcome": "not_covered", "x": ' + "[" * 64 + "]" * 64 + "}"
        res = datumesh.check_envelope(404, body, [], {"cell_id": "0" * 64})
        self.assertEqual(res.code, "E_PARSE_JSON")

    def test_parsed_values_too_deep(self) -> None:
        # A parsed value that would be more than 64 levels deep as text is refused the same way.
        v: list = []
        for _ in range(64):
            v = [v]
        self.assertEqual(code_of(datumesh.jcs, v), "E_PARSE_JSON")
        self.assertIsNone(code_of(datumesh.jcs, v[0]))


class UriSignatureTest(unittest.TestCase):
    """SPEC 5.4 step 5: an unreadable signature is E_SCHEMA, after steps 1-4."""

    def test_unreadable(self) -> None:
        uri = "cell://m.example/f?n=1"
        for sig, path in [
            (None, "signature"), ([], "signature"), ("x", "signature"), ({}, "signature"),
            ({"args": []}, "signature.args"), ({"args": {"n": 5}}, "signature.args.n"),
            ({"args": {"n": {}}}, "signature.args.n"), ({"args": {"n": {"type": 5}}}, "signature.args.n"),
            ({"args": {"z": {"type": "number"}, "b": 5, "a": {}}}, "signature.args.a"),  # JCS order
        ]:
            with self.subTest(sig=sig):
                with self.assertRaises(DatumeshError) as cm:
                    parse_uri(uri, sig)  # type: ignore[arg-type]
                self.assertEqual((cm.exception.code, cm.exception.path), ("E_SCHEMA", path))

    def test_steps_1_to_4_first(self) -> None:
        for uri, code in [("cell://m.example/f#x", "E_PARSE_URI"), ("cell://M.example/f", "E_CANON_NAME"),
                          ("cell://m.example/f?b=1&a=1", "E_CANON_ARG_ORDER"),
                          ("cell://m.example/f?" + "&".join("a%02d=1" % i for i in range(33)), "E_CANON_LIMIT")]:
            with self.subTest(uri[:40]):
                self.assertEqual(code_of(parse_uri, uri, None), code)
        self.assertEqual(code_of(parse_uri, "cell://m.example/f?n=1", {"args": {"n": {"type": "decimal"}}}),
                         "E_CANON_TYPE")
        self.assertIsNone(code_of(parse_uri, "cell://m.example/f?n=*", {"args": {"n": {"type": "decimal"}}}))

    def test_asof_and_repeats(self) -> None:
        sig = {"args": {"a": {"type": "number"}, "b": {"type": "number"}}}
        self.assertEqual(code_of(parse_uri, "cell://m.example/f?a=1&b=1&a=1", sig), "E_CANON_ARG_ORDER")
        self.assertEqual(code_of(parse_uri, "cell://m.example/f?a=1&b=1&asof=*", sig), "E_CANON_PERCENT")


class ReceiptStatementsTest(unittest.TestCase):
    def test_licence_grammar(self) -> None:
        for lic, code in [("CC-BY-4.0", None), ("Not-A-Real-Licence", None), ("a.b+c", None),
                          ("-x", "E_CANON_LICENCE"), ("CC BY", "E_CANON_LICENCE"), ("", "E_CANON_LICENCE"),
                          ("a" * 64, None), ("a" * 65, "E_CANON_LIMIT"), ("-" * 65, "E_CANON_LICENCE"),
                          ("https://x.example/l", None), ("https://", "E_CANON_LICENCE"),
                          ("HTTPS://x.example/l", "E_CANON_LICENCE"), ("https://x.example/a b", "E_CANON_LICENCE"),
                          ("https://" + "a" * 504, None), ("https://" + "a" * 505, "E_CANON_LIMIT"),
                          ("https://" + "a" * 600 + " ", "E_CANON_LICENCE"), ("http://x.example", "E_CANON_LICENCE")]:
            with self.subTest(lic[:40]):
                self.assertEqual(receipt_code(licence=lic), code)

    def test_key_reference_codes(self) -> None:
        for ref, code in [("rates.example.org", "E_CANON_NAME"), ("Rates.example.org#d712b32a2cc5cb7c", "E_CANON_NAME"),
                          ("rates#d712b32a2cc5cb7c", "E_CANON_NAME"), ("rates.example.org#D712B32A2CC5CB7C", "E_CANON_HEX"),
                          ("rates.example.org#d712b32a2cc5cb7", "E_CANON_HEX"),
                          ("rates.example.org#d712b32a2cc5cb7c#x", "E_CANON_HEX")]:
            with self.subTest(ref):
                self.assertEqual(receipt_code(computed_by=ref), code)

    def test_instant_failures(self) -> None:
        for t in ("2023-02-29T00:00:00.000000Z", "2024-13-01T00:00:00.000000Z", "2024-03-15T23:59:60.000000Z",
                  "0000-01-01T00:00:00.000000Z"):
            with self.subTest(t):
                self.assertEqual(receipt_code(issued=t), "E_CANON_INSTANT")

    def test_value_json_types(self) -> None:
        self.assertEqual(receipt_code(value=1.0892), "E_SCHEMA")
        self.assertEqual(receipt_code(value=None), "E_SCHEMA")
        self.assertEqual(receipt_code(value=[]), "E_SCHEMA")
        self.assertEqual(receipt_code(value=True), "E_CANON_TYPE")
        s = {"type": "boolean", "value": "true"}
        self.assertEqual(code_of(canonicalize, s, "scalar"), "E_CANON_TYPE")
        self.assertEqual(code_of(canonicalize, {"type": "string", "value": 1}, "scalar"), "E_SCHEMA")

    def test_consistency_order(self) -> None:
        # Step 4 runs in the listed order: slices, publisher, valid, time.
        args = dict(R["cell"]["args"], base="*")
        later = "2025-01-01T00:00:00.000000Z"
        self.assertEqual(receipt_code(cell=dict(R["cell"], args=args), publisher="other.example.org"), "E_SLICE")
        self.assertEqual(receipt_code(publisher="other.example.org", valid={"date": {"type": "date", "value": "2024-01-01"}}),
                         "E_PUBLISHER_MISMATCH")
        self.assertEqual(receipt_code(valid={"date": {"type": "date", "value": "2024-01-01"}}, tx=later),
                         "E_VALID_MISMATCH")

    def test_container_order(self) -> None:
        r_inputs = ["f" * 64, "0" * 64]
        self.assertEqual(receipt_code(inputs=r_inputs), "E_CANON_SET")
        self.assertEqual(receipt_code(inputs=["F" * 64, "0" * 64]), "E_CANON_HEX")
        self.assertEqual(receipt_code(inputs=["%064x" % i for i in range(4097)][::-1]), "E_CANON_SET")
        self.assertEqual(receipt_code(inputs=["%064x" % i for i in range(4097)]), "E_CANON_LIMIT")
        args = {"a%02d" % i: {"type": "string", "value": "x"} for i in range(33)}
        args["A"] = {"type": "string", "value": "x"}
        self.assertEqual(code_of(canonicalize, {"args": args, "fn": "f", "ns": "m.example"}, "ref"), "E_CANON_LIMIT")

    def test_stored_convention_not_enforced(self) -> None:
        d = {"code": {"body": "x + 1\n", "lang": "stored"}, "inputs": ["m.example/f"],
             "signature": {"args": {}, "returns": "boolean"}}
        self.assertIsNone(code_of(datumesh.function_hash, d))

    def test_ed25519_vectors(self) -> None:
        names = {v["id"]: v for v in vectors_of("receipt") if "ed25519" in v["id"]}
        self.assertEqual(sorted(names), ["invalid/receipt-ed25519-negative-zero-r", "invalid/receipt-ed25519-non-canonical-r",
                                         "invalid/receipt-ed25519-s-not-reduced", "invalid/receipt-ed25519-small-order-key",
                                         "invalid/receipt-ed25519-small-order-r", "receipt/ed25519-mixed-order-key"])
        for vid, v in names.items():
            with self.subTest(vid):
                res = verify(v["input"], env_keys(v["keys"]))
                self.assertEqual(res.code, "OK" if v["valid"] else v["error"])


if __name__ == "__main__":
    unittest.main()
