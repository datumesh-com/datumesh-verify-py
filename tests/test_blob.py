"""Blob values (SPEC 3.7) and blob content (SPEC 10.1 step 7.7)."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest

from util import env_keys, vectors_of

import datumesh
from datumesh import DatumeshError, canonicalize, verify

BLOB = next(v for v in vectors_of("receipt", True) if v["id"] == "receipt/blob-value")
CONTENT = bytes.fromhex(BLOB["blob_hex"])
KEYS = env_keys(BLOB["keys"])
STORED = next(v for v in vectors_of("receipt", True) if v["id"] == "receipt/stored-number")
DESCRIPTOR = json.loads(next(v for v in vectors_of("function", True) if v["id"] == "function/blob-return")["input"])
H = "9dc30a40021f1f79d8dd9437ec9014ce134138326b72fcb9696485ab3d69330a"


def scalar_code(value: object):
    try:
        canonicalize({"type": "blob", "value": value}, "scalar")
        return None
    except DatumeshError as e:
        return e.code


class BlobContentTest(unittest.TestCase):
    """Contract test 2 for blobs: every corruption of the content fails with E_BLOB_MISMATCH."""

    def test_vector_is_what_we_think(self) -> None:
        r = json.loads(BLOB["input"])
        digest, length, media = r["value"].split(":", 2)
        self.assertEqual((r["type"], hashlib.sha256(CONTENT).hexdigest(), int(length), media),
                         ("blob", digest, len(CONTENT), "text/csv"))

    def test_unmodified_content_passes(self) -> None:
        res = verify(BLOB["input"], KEYS, blob=CONTENT)
        self.assertEqual((res.ok, res.code, res.level, res.hash, res.blob_checked),
                         (True, "OK", "signed", BLOB["sha256"], True))
        for form in (bytearray(CONTENT), memoryview(CONTENT)):
            self.assertTrue(verify(BLOB["input"], KEYS, blob=form).blob_checked)
        # Without content, step 7.7 does not run.
        res = verify(BLOB["input"], KEYS)
        self.assertEqual((res.ok, res.blob_checked), (True, False))

    def test_every_bit_flip_of_the_content(self) -> None:
        total = 0
        for i in range(len(CONTENT)):
            for bit in range(8):
                flipped = bytearray(CONTENT)
                flipped[i] ^= 1 << bit
                res = verify(BLOB["input"], KEYS, blob=bytes(flipped))
                total += 1
                self.assertEqual(res.code, "E_BLOB_MISMATCH", f"byte {i} bit {bit}")
                self.assertFalse(res.ok)
                self.assertIsNone(res.level)
                self.assertFalse(res.blob_checked)
                self.assertEqual(res.hash, BLOB["sha256"])
        print(f"\nbit flips of blob content: {total} run, {total} rejected with E_BLOB_MISMATCH", file=sys.stderr)

    def test_removing_or_adding_one_byte(self) -> None:
        variants = []
        for i in range(len(CONTENT)):
            variants.append(CONTENT[:i] + CONTENT[i + 1:])  # remove byte i
        for i in range(len(CONTENT) + 1):
            for b in (0x00, 0x0A, 0x41, 0xFF):
                variants.append(CONTENT[:i] + bytes([b]) + CONTENT[i:])  # add one byte at i
        variants += [b"", CONTENT * 2]
        for content in variants:
            self.assertEqual(verify(BLOB["input"], KEYS, blob=content).code, "E_BLOB_MISMATCH", content)

    def test_signature_is_checked_before_content(self) -> None:
        r = json.loads(BLOB["input"])
        r["summary"] = "Tampered."
        self.assertEqual(verify(r, KEYS, blob=b"x").code, "E_SIGNATURE")
        self.assertEqual(verify(BLOB["input"], [], blob=b"x").code, "E_KEY_UNAVAILABLE")
        self.assertEqual(verify(BLOB["input"], {}, blob=b"x").code, "E_KEY_UNKNOWN")  # {} maps no key ids

    def test_content_for_a_value_that_is_not_a_blob(self) -> None:
        # SPEC 10.1 step 7.7 (2a77580): content supplied for a value that is not a blob is E_SCHEMA.
        keys = env_keys(STORED["keys"])
        for content in (b"\x00", b"", CONTENT):
            res = verify(STORED["input"], keys, blob=content)
            self.assertEqual((res.ok, res.code, res.path, res.blob_checked, res.hash),
                             (False, "E_SCHEMA", "$.type", False, STORED["sha256"]))
        # Earlier steps still come first.
        self.assertEqual(verify(STORED["input"], [], blob=b"x").code, "E_KEY_UNAVAILABLE")
        # With recomputation, 7.1-7.6 come first, then 7.7.
        lin = next(v for v in vectors_of("receipt", True) if v["id"] == "receipt/computed-with-lineage")
        lk = env_keys(lin["keys"])
        self.assertEqual(verify(lin["input"], lk, lin["recompute"], b"x").code, "E_SCHEMA")
        wrong = dict(lin["recompute"], value={"type": "number", "value": "1"})
        self.assertEqual(verify(lin["input"], lk, wrong, b"x").code, "E_VALUE_MISMATCH")

    def test_with_recompute(self) -> None:
        value = json.loads(BLOB["input"])["value"]
        rc = {"descriptor": DESCRIPTOR, "value": {"type": "blob", "value": value}}
        res = verify(BLOB["input"], KEYS, rc, CONTENT)
        self.assertEqual((res.level, res.blob_checked), ("recomputed", True))
        res = verify(BLOB["input"], KEYS, rc)
        self.assertEqual((res.level, res.blob_checked), ("recomputed", False))
        # Steps 7.1-7.6 come before 7.7 (reference tool agrees).
        self.assertEqual(verify(BLOB["input"], KEYS, rc, b"x").code, "E_BLOB_MISMATCH")
        wrong = dict(rc, value={"type": "blob", "value": "0" * 64 + ":0:text/csv"})
        self.assertEqual(verify(BLOB["input"], KEYS, wrong, b"x").code, "E_VALUE_MISMATCH")
        self.assertEqual(verify(BLOB["input"], KEYS, {"value": rc["value"]}, b"x").code, "E_FN_UNAVAILABLE")

    def test_blob_argument_type(self) -> None:
        for bad in ("text", 5, [1, 2], bytes.hex(CONTENT)):
            with self.subTest(bad=type(bad).__name__), self.assertRaises(TypeError):
                verify(BLOB["input"], KEYS, blob=bad)  # type: ignore[arg-type]


class BlobValueTest(unittest.TestCase):
    """The lexical form of SPEC 3.7. Codes confirmed against the reference tool."""

    CASES = {
        H + ":17:text/plain": None,
        H + ":0:application/octet-stream": None,
        H + ":9007199254740991:a/b": None,
        H + ":9007199254740992:a/b": "E_CANON_BLOB",
        H + ":10000000000000000:a/b": "E_CANON_BLOB",
        H + ":" + "1" * 1000 + ":a/b": "E_CANON_BLOB",
        H + ":00:a/b": "E_CANON_BLOB",
        H + ":017:a/b": "E_CANON_BLOB",
        H + ":-1:a/b": "E_CANON_BLOB",
        H + ":1.0:a/b": "E_CANON_BLOB",
        H + ": 1:a/b": "E_CANON_BLOB",
        H + ":1:a/b:": "E_CANON_BLOB",
        H + ":1:a!#$&-^_.+/0!#$&-^_.+": None,
        H + ":1:+a/b": "E_CANON_BLOB",
        H + ":1:.a/b": "E_CANON_BLOB",
        H + ":1:a/b/c": "E_CANON_BLOB",
        H + ":1:/b": "E_CANON_BLOB",
        H + ":1:a/": "E_CANON_BLOB",
        H + ":1:a": "E_CANON_BLOB",
        H + ":1:a/é": "E_CANON_BLOB",
        H + ":1:a/b~c": "E_CANON_BLOB",
        H + ":1:a/b%20": "E_CANON_BLOB",
        H + ":1:Text/plain": "E_CANON_BLOB",
        H + ":1:text/plain;charset=utf-8": "E_CANON_BLOB",
        H + ":1:text/plain ": "E_CANON_BLOB",
        H + ":1:a/" + "b" * 126: None,  # media type of 128 characters
        H + ":1:a/" + "b" * 127: "E_CANON_BLOB",  # 129
        H + ":1:a/" + "b" * 2000: "E_CANON_BLOB",  # not E_CANON_LIMIT
        H.upper() + ":1:a/b": "E_CANON_BLOB",
        H[:-1] + ":1:a/b": "E_CANON_BLOB",
        H + "a:1:a/b": "E_CANON_BLOB",
        H + ":1:a/b\n": "E_CANON_BLOB",
        "*": "E_CANON_BLOB",
        "": "E_CANON_BLOB",
        True: "E_CANON_TYPE",
    }

    def test_lexical_form(self) -> None:
        for value, code in self.CASES.items():
            with self.subTest(ascii(value)[:60]):
                self.assertEqual(scalar_code(value), code)

    def test_blob_in_a_receipt_value(self) -> None:
        r = json.loads(BLOB["input"])
        r["value"] = r["value"].upper()
        res = verify(r, KEYS)
        self.assertEqual((res.code, res.path), ("E_CANON_BLOB", "$.value"))

    def test_blob_is_not_a_valid_time_type(self) -> None:
        desc = {"code": {"body": "", "lang": "stored"}, "inputs": [],
                "signature": {"args": {"file": {"type": "blob", "valid": True}}, "returns": "boolean"}}
        with self.assertRaises(DatumeshError) as cm:
            datumesh.function_hash(desc)
        self.assertEqual(cm.exception.code, "E_CANON_TYPE")
        # In a receipt, a blob echoed in valid fails step 4.
        r = json.loads(BLOB["input"])
        r["cell"]["args"]["file"] = r["valid"]["file"] = {"type": "blob", "value": r["value"]}
        self.assertEqual(verify(r, KEYS).code, "E_VALID_MISMATCH")


if __name__ == "__main__":
    unittest.main()
