"""Test 6: string validity does not depend on the runtime's Unicode version (SPEC 3.5 pins 15.1)."""

from __future__ import annotations

import json
import sys
import unicodedata
import unittest

from util import FIXTURES, ROOT, SPEC

import datumesh
from datumesh import DatumeshError, canonicalize
from datumesh import _unicode

ON_15_1 = unicodedata.unidata_version == "15.1.0"


def scalar(s: str) -> dict:
    return {"type": "string", "value": s}


def code_of(s: str):
    try:
        canonicalize(scalar(s), "scalar")
        return None
    except DatumeshError as e:
        return e.code


class UnicodeTablesTest(unittest.TestCase):
    def test_shipped_version(self) -> None:
        self.assertEqual(_unicode.UNIDATA_VERSION, "15.1.0")
        print(f"\nruntime Python {sys.version.split()[0]}, runtime unicodedata {unicodedata.unidata_version}, "
              f"datumesh tables {_unicode.UNIDATA_VERSION}", file=sys.stderr)

    def test_package_never_uses_unicodedata(self) -> None:
        for f in (ROOT / "src" / "datumesh").glob("*.py"):
            text = f.read_text(encoding="utf-8")
            self.assertNotIn("import unicodedata", text, f.name)
            self.assertNotIn("from unicodedata", text, f.name)
            self.assertNotIn("__import__", text, f.name)

    def test_assigned_matches_spec_file(self) -> None:
        ranges = []
        for line in (SPEC / "tools" / "unicode-15.1-assigned.txt").read_text().splitlines():
            if line and not line.startswith("#"):
                a, b = line.split("..")
                ranges.append((int(a, 16), int(b, 16)))
        expected = bytearray(0x110000)
        for a, b in ranges:
            expected[a:b + 1] = b"\x01" * (b - a + 1)
        mismatches = [cp for cp in range(0x110000) if bool(expected[cp]) != _unicode.is_assigned(cp)]
        self.assertEqual(mismatches, [])

    def test_nfc_fixtures_from_15_1(self) -> None:
        data = json.loads((FIXTURES / "unicode15.json").read_text(encoding="ascii"))
        self.assertEqual(data["unidata_version"], "15.1.0")
        bad = [(s, exp) for s, exp in data["nfc"] if _unicode.is_nfc(s) != exp]
        self.assertEqual(bad[:5], [])
        self.assertGreater(len(data["nfc"]), 20000)

    @unittest.skipUnless(ON_15_1, "needs a runtime whose unicodedata is 15.1.0 (Python 3.13)")
    def test_exhaustive_against_runtime_15_1(self) -> None:
        for cp in range(0x110000):
            ch = chr(cp)
            if (unicodedata.category(ch) != "Cn") != _unicode.is_assigned(cp):
                self.fail(f"assigned mismatch U+{cp:04X}")
            if 0xD800 <= cp <= 0xDFFF or not _unicode.is_assigned(cp):
                continue
            if _unicode.combining_class(cp) != unicodedata.combining(ch):
                self.fail(f"ccc mismatch U+{cp:04X}")
            nfd = unicodedata.normalize("NFD", ch)
            for s in (ch, nfd, nfd + chr(0x0301), chr(0x0041) + nfd):
                if _unicode.nfc(s) != unicodedata.normalize("NFC", s):
                    self.fail(f"NFC mismatch for {ascii(s)}")
                if _unicode.is_nfc(s) != unicodedata.is_normalized("NFC", s):
                    self.fail(f"is_nfc mismatch for {ascii(s)}")


class VersionDependentStringsTest(unittest.TestCase):
    """Strings whose verdict differs between the Unicode 13 of Python 3.10 and Unicode 15.1."""

    def test_assigned_after_13(self) -> None:
        # Assigned in Unicode 14 or 15 (valid under 15.1, unassigned in Python 3.10's tables).
        for cp in (0x0870, 0x1E030, 0x1F6DD, 0x11F00, 0x31350, 0x2EBF0):
            with self.subTest(f"U+{cp:04X}"):
                self.assertIsNone(code_of(chr(cp)))

    def test_assigned_after_15_1(self) -> None:
        # Assigned in Unicode 16.0: rejected by the 15.1 pin on every runtime.
        for cp in (0x1C89, 0x0897, 0x1611E, 0x11383):
            with self.subTest(f"U+{cp:04X}"):
                self.assertEqual(code_of(chr(cp)), "E_CANON_STRING")

    def test_nfc_with_newer_combining_marks(self) -> None:
        # U+1E08F (Unicode 15.0) has combining class 230; U+0316 has 220. Canonical order is 0316 first.
        self.assertEqual(code_of("a" + chr(0x1E08F) + chr(0x0316)), "E_CANON_STRING")
        self.assertIsNone(code_of("a" + chr(0x0316) + chr(0x1E08F)))

    def test_vectors_unicode_16(self) -> None:
        self.assertEqual(code_of(chr(0x1C89)), "E_CANON_STRING")


class StringRulesTest(unittest.TestCase):
    def test_rules(self) -> None:
        cases = {
            "": None, "Zu" + chr(0x308) + "rich": "E_CANON_STRING", "Z" + chr(0xFC) + "rich": None,
            chr(0x1100) + chr(0x1161): "E_CANON_STRING", chr(0xAC00): None, chr(0x344): "E_CANON_STRING",
            chr(0xFEFF): None, chr(0xE000) + chr(0xF0000): None, chr(0x10FFFF): "E_CANON_STRING",
            chr(0xFFFF): "E_CANON_STRING", chr(0x2028): None, chr(0x7F): "E_CANON_STRING", chr(0x85): "E_CANON_STRING",
            "a\tb": "E_CANON_STRING", chr(0x200D): None, chr(0x202E): None,
            "a" * 1024: None, "a" * 1025: "E_CANON_LIMIT", chr(0xE9) * 512: None, chr(0xE9) * 513: "E_CANON_LIMIT",
            chr(0x1F600) * 256: None, chr(0x1F600) * 257: "E_CANON_LIMIT",
            chr(7) + "a" * 2000: "E_CANON_STRING", ("u" + chr(0x308)) * 600: "E_CANON_STRING",
        }
        for s, code in cases.items():
            with self.subTest(ascii(s)[:40]):
                self.assertEqual(code_of(s), code)

    def test_surrogate_in_parsed_object(self) -> None:
        with self.assertRaises(DatumeshError) as cm:
            canonicalize(scalar(chr(0xD800)), "scalar")
        self.assertEqual(cm.exception.code, "E_PARSE_JSON")

    def test_body_rules(self) -> None:
        desc = {"code": {"body": "", "lang": "expr"}, "inputs": [], "signature": {"args": {}, "returns": "string"}}
        for body, code in {"a\tb\n": None, "a\r\nb": "E_CANON_STRING", "a" * 1048576: None,
                           "a" * 1048577: "E_CANON_LIMIT", "u" + chr(0x308): "E_CANON_STRING"}.items():
            d = json.loads(json.dumps(desc))
            d["code"]["body"] = body
            with self.subTest(ascii(body)[:20]):
                try:
                    datumesh.function_hash(d)
                    got = None
                except DatumeshError as e:
                    got = e.code
                self.assertEqual(got, code)


if __name__ == "__main__":
    unittest.main()
