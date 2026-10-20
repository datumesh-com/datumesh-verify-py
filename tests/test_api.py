"""API behaviour: kinds, errors, robustness of verify, package metadata."""

from __future__ import annotations

import copy
import json
import random
import unittest

from util import ROOT, env_keys, vectors_of

import datumesh
from datumesh import DatumeshError, VerifyResult, canonicalize, verify

STORED = next(v for v in vectors_of("receipt", True) if v["id"] == "receipt/stored-number")
LINEAGE = next(v for v in vectors_of("receipt", True) if v["id"] == "receipt/computed-with-lineage")


class ApiTest(unittest.TestCase):
    def test_constants(self) -> None:
        self.assertEqual(datumesh.SPEC_VERSION, "spec-0.2.0")
        self.assertEqual(datumesh.__version__, "0.2.0")
        self.assertEqual(len(datumesh.ERROR_CODES), 41)
        self.assertEqual(len(set(datumesh.ERROR_CODES)), 41)
        for code in ("E_CANON_UNIT", "E_CANON_BLOB", "E_BLOB_MISMATCH", "E_ENVELOPE"):
            self.assertIn(code, datumesh.ERROR_CODES)
        for name in ("resolved_unit", "check_envelope", "EnvelopeResult", "UNITS"):
            self.assertIn(name, datumesh.__all__)
        for name in datumesh.__all__:
            self.assertTrue(hasattr(datumesh, name), name)

    def test_error_codes_match_spec_table(self) -> None:
        text = (ROOT / "spec" / "SPEC.md").read_text(encoding="utf-8")
        table = text[text.index("### 10.2 Error codes"):text.index("## 11.")]
        import re
        self.assertEqual(tuple(re.findall(r"^\| `(E_[A-Z_]+)` \|", table, re.M)), datumesh.ERROR_CODES)

    def test_error_attributes(self) -> None:
        with self.assertRaises(DatumeshError) as cm:
            canonicalize('{"type":"number","value":"1.50"}', "scalar")
        e = cm.exception
        self.assertEqual((e.code, e.path), ("E_CANON_NUMBER", "$.value"))
        self.assertIsInstance(e, ValueError)
        self.assertIn("E_CANON_NUMBER", str(e))

    def test_kind_inference(self) -> None:
        for kind in ("scalar", "cell", "ref", "function"):
            for v in vectors_of(kind, True):
                with self.subTest(v["id"]):
                    self.assertEqual(canonicalize(v["input"]).decode(), v["canonical"])
        r = json.loads(STORED["input"])
        self.assertEqual(json.loads(canonicalize(r)), r)  # receipt, sig included
        self.assertEqual(canonicalize(r, "receipt"), canonicalize(STORED["input"]))
        with self.assertRaises(DatumeshError) as cm:
            canonicalize({"x": 1})
        self.assertEqual(cm.exception.code, "E_SCHEMA")
        with self.assertRaises(DatumeshError) as cm:
            canonicalize([])
        self.assertEqual(cm.exception.code, "E_SCHEMA")
        with self.assertRaises(ValueError):
            canonicalize({}, "jcs")

    def test_canonicalize_receipt_checks_consistency(self) -> None:
        r = json.loads(STORED["input"])
        r["publisher"] = "other.example.org"
        with self.assertRaises(DatumeshError) as cm:
            canonicalize(r, "receipt")
        self.assertEqual(cm.exception.code, "E_PUBLISHER_MISMATCH")
        with self.assertRaises(DatumeshError) as cm:
            datumesh.receipt_hash(r)
        self.assertEqual(cm.exception.code, "E_PUBLISHER_MISMATCH")

    def test_hash_reported_when_canonical(self) -> None:
        r = json.loads(STORED["input"])
        r["value"] = "1.0893"
        res = verify(r, env_keys(STORED["keys"]))
        self.assertEqual(res.code, "E_SIGNATURE")
        self.assertEqual(res.hash, datumesh.receipt_hash(r))
        r["value"] = "1.50"
        res = verify(r, env_keys(STORED["keys"]))
        self.assertEqual((res.code, res.hash, res.path), ("E_CANON_NUMBER", None, "$.value"))

    def test_recompute_argument(self) -> None:
        keys = env_keys(LINEAGE["keys"])
        rc = copy.deepcopy(LINEAGE["recompute"])
        self.assertEqual(verify(LINEAGE["input"], keys, rc).level, "recomputed")
        self.assertEqual(verify(LINEAGE["input"], keys).level, "signed")
        # descriptor as JSON text
        rc2 = dict(rc, descriptor=json.dumps(rc["descriptor"]))
        self.assertEqual(verify(LINEAGE["input"], keys, rc2).level, "recomputed")
        # descriptor None or absent
        self.assertEqual(verify(LINEAGE["input"], keys, dict(rc, descriptor=None)).code, "E_FN_UNAVAILABLE")
        self.assertEqual(verify(LINEAGE["input"], keys, {"value": rc["value"]}).code, "E_FN_UNAVAILABLE")
        # inputs missing, given as parsed objects, or tampered
        self.assertEqual(verify(LINEAGE["input"], keys, dict(rc, inputs={})).code, "E_INPUT_UNAVAILABLE")
        parsed = {h: json.loads(t) for h, t in rc["inputs"].items()}
        self.assertEqual(verify(LINEAGE["input"], keys, dict(rc, inputs=parsed)).level, "recomputed")
        # boolean vs string values are different
        self.assertEqual(verify(LINEAGE["input"], keys, dict(rc, value={"type": "number", "value": "108.920"})).code,
                         "E_VALUE_MISMATCH")
        for bad in ([], {"descriptor": rc["descriptor"]}, {"value": "108.92"}, dict(rc, inputs=[])):
            with self.subTest(bad=str(bad)[:40]), self.assertRaises(TypeError):
                verify(LINEAGE["input"], keys, bad)  # type: ignore[arg-type]

    def test_verify_never_raises_on_bad_receipts(self) -> None:
        rnd = random.Random(20261020)
        keys = env_keys(STORED["keys"])
        base = STORED["input"].encode()
        pool = [None, True, 1, 1.5, "", "*", [], {}, "x" * 2000, {"type": "number", "value": "1"}, "2024-03-15"]
        for i in range(3000):
            kind = i % 3
            if kind == 0:
                data = bytearray(base)
                for _ in range(rnd.randint(1, 8)):
                    data[rnd.randrange(len(data))] = rnd.randrange(256)
                arg = bytes(data)
            elif kind == 1:
                arg = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 64)))
            else:
                r = json.loads(STORED["input"])
                target = r
                path = []
                while isinstance(target, dict) and target and rnd.random() < 0.6:
                    k = rnd.choice(list(target))
                    path.append(k)
                    if not isinstance(target[k], dict):
                        break
                    target = target[k]
                if isinstance(target, dict) and target:
                    target[rnd.choice(list(target))] = rnd.choice(pool)
                arg = r
            res = verify(arg, keys)
            self.assertIsInstance(res, VerifyResult)
            self.assertIn(res.code, datumesh.ERROR_CODES + ("OK",))
            if res.ok:
                self.assertEqual(res.hash, STORED["sha256"])

    def test_deep_nesting(self) -> None:
        deep = "[" * 100000 + "]" * 100000
        res = verify(deep, {})
        self.assertEqual(res.code, "E_PARSE_JSON")
        with self.assertRaises(DatumeshError):
            datumesh.jcs(deep)

    def test_cell_hash_of_slice(self) -> None:
        v = next(v for v in vectors_of("cell", True) if v["id"] == "cell/slice")
        self.assertEqual(datumesh.cell_hash(json.loads(v["input"])), v["sha256"])


if __name__ == "__main__":
    unittest.main()
