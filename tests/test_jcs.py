"""Test 5: the RFC 8785 serialiser passes every sample of RFC 8785 Appendix B and the main examples."""

from __future__ import annotations

import json
import math
import struct
import unittest

from util import vectors_of

import datumesh
from datumesh import DatumeshError, jcs
from datumesh._json import format_number

# RFC 8785 Appendix B: IEEE 754 bit pattern -> expected serialisation (None: must be rejected).
APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("7fffffffffffffff", None),  # NaN
    ("7ff0000000000000", None),  # Infinity
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]

# RFC 8785 section 3.2.2 (the main example) and 3.2.3 (sorting), input and output verbatim.
# "~" stands for a backslash: these are JSON texts with escapes, copied from the RFC.
MAIN_INPUT = '''{
  "numbers": [333333333.33333329, 1E30, 4.50,
              2e-3, 0.000000000000000000000000001],
  "string": "~u20ac$~u000F~u000aA'~u0042~u0022~u005c~~~"~/",
  "literals": [null, true, false]
}'''.replace("~", chr(92))
MAIN_OUTPUT = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' \
              '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
MAIN_OUTPUT_HEX = (
    "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72 75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 "
    "22 3a 5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31 65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 "
    "65 2d 32 37 5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30 30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c "
    "22 2f 22 7d"
)
SORT_INPUT = '''{
  "~u20ac": "Euro Sign",
  "~r": "Carriage Return",
  "~ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "~ud83d~ude00": "Emoji: Grinning Face",
  "~u0080": "Control",
  "~u00f6": "Latin Small Letter O With Diaeresis"
}'''.replace("~", chr(92))
SORT_ORDER = ["\r", "1", chr(0x80), chr(0xF6), chr(0x20AC), chr(0x1F600), chr(0xFB33)]
SORT_OUTPUT = ('{"' + chr(92) + 'r":"Carriage Return","1":"One","' + chr(0x80) + '":"Control","' + chr(0xF6) + '":"Latin Small Letter O With Diaeresis","' + chr(0x20AC) + '":"Euro Sign","' + chr(0x1F600) + '":"Emoji: Grinning Face","' + chr(0xFB33) + '":"Hebrew Letter Dalet With Dagesh"}')


class JcsTest(unittest.TestCase):
    def test_appendix_b(self) -> None:
        for bits, expected in APPENDIX_B:
            value = struct.unpack(">d", bytes.fromhex(bits))[0]
            with self.subTest(bits):
                if expected is None:
                    self.assertFalse(math.isfinite(value))
                    with self.assertRaises(DatumeshError):
                        format_number(value)
                    with self.assertRaises(DatumeshError):
                        jcs([value])
                else:
                    self.assertEqual(format_number(value), expected)
                    self.assertEqual(jcs([value]), f"[{expected}]".encode())
                    # and through the parser, from the expected text itself
                    self.assertEqual(jcs(expected), expected.encode())
        self.assertEqual(len(APPENDIX_B), 26)

    def test_main_example(self) -> None:
        out = jcs(MAIN_INPUT)
        self.assertEqual(out.decode("utf-8"), MAIN_OUTPUT)
        self.assertEqual(out, bytes.fromhex(MAIN_OUTPUT_HEX.replace(" ", "")))

    def test_sorting_example(self) -> None:
        out = jcs(SORT_INPUT)
        self.assertEqual(list(json.loads(out)), SORT_ORDER)
        self.assertEqual(out.decode("utf-8"), SORT_OUTPUT)

    def test_jcs_vectors(self) -> None:
        for v in vectors_of("jcs"):
            with self.subTest(v["id"]):
                if v["valid"]:
                    self.assertEqual(jcs(v["input"]).decode("utf-8"), v["canonical"])
                else:
                    with self.assertRaises(DatumeshError) as cm:
                        jcs(v["input"])
                    self.assertEqual(cm.exception.code, v["error"])

    def test_strict_parsing(self) -> None:
        cases = {
            "[1,]": "E_PARSE_JSON", "[1E400]": "E_PARSE_JSON", "[-1e400]": "E_PARSE_JSON", "[NaN]": "E_PARSE_JSON",
            "[Infinity]": "E_PARSE_JSON", '{"\\udc00":1}': "E_PARSE_JSON", '["\\ud800"]': "E_PARSE_JSON",
            '{"a":1,"a":2}': "E_PARSE_DUPLICATE_KEY", '{"a":1,"\\u0061":2}': "E_PARSE_DUPLICATE_KEY",
            "﻿[]": "E_PARSE_JSON", "\f[1]": "E_PARSE_JSON", "[01]": "E_PARSE_JSON", "'a'": "E_PARSE_JSON",
            '["a\tb"]': "E_PARSE_JSON", "[] x": "E_PARSE_JSON", "": "E_PARSE_JSON",
        }
        for text, code in cases.items():
            with self.subTest(text), self.assertRaises(DatumeshError) as cm:
                jcs(text)
            self.assertEqual(cm.exception.code, code)
        for raw in (b"\xef\xbb\xbf[]", b'["\xc0\xaf"]', b'["\xed\xa0\x80"]', '[]'.encode("utf-16")):
            with self.assertRaises(DatumeshError) as cm:
                jcs(raw)
            self.assertEqual(cm.exception.code, "E_PARSE_JSON")
        # Underflow is not out of range: 1e-400 is the double 0.
        self.assertEqual(jcs("[1e-400, -0, 0e999999]"), b"[0,0,0]")
        self.assertEqual(jcs("[" * 64 + "]" * 64), b"[" * 64 + b"]" * 64)  # SPEC 6.1: at most 64 levels
        self.assertEqual(jcs('"\\u00e9\\/"'), '"é/"'.encode())
        self.assertEqual(jcs("123456789012345678901234567890"), b"1.2345678901234568e+29")

    def test_parsed_values(self) -> None:
        self.assertEqual(jcs({"b": [1, 2.5, True, None], "a": "x"}), b'{"a":"x","b":[1,2.5,true,null]}')
        for bad in ({1: "x"}, {"a": float("nan")}, {"a": (1, 2)}, {"a": {1}}, ["\ud800"], [10 ** 400]):
            with self.subTest(repr(bad)[:30]), self.assertRaises(DatumeshError) as cm:
                jcs(bad)
            self.assertEqual(cm.exception.code, "E_PARSE_JSON")

    def test_canonicalize_examples(self) -> None:
        # canonicalize is JCS after validation: compare with the vectors' canonical forms.
        for kind in ("scalar", "cell", "ref", "function"):
            for v in vectors_of(kind, True):
                self.assertEqual(datumesh.canonicalize(v["input"], kind).decode(), v["canonical"])


if __name__ == "__main__":
    unittest.main()
