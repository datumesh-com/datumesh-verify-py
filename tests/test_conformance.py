"""Test 1: conformance over every vector in spec/vectors (through the API and the runner)."""

from __future__ import annotations

import collections
import json
import subprocess
import sys
import unittest

from util import (FORMULA_KINDS, ROOT, blob_of, env_keys, expected_output, load_vectors, recompute_of, runner,
                  runner_output, vectors_of, verifier_vectors)

import datumesh


class ConformanceTest(unittest.TestCase):
    def test_vector_count(self) -> None:
        counts = collections.Counter(v["kind"] for v in load_vectors())
        # spec-0.4.0 (SPEC 14): 978 vectors; 432 for verifier libraries, the rest for formula evaluators
        self.assertEqual(sum(counts.values()), 978, counts)
        self.assertEqual(len(verifier_vectors()), 432, counts)
        self.assertEqual(sum(counts[k] for k in FORMULA_KINDS), 546, counts)
        self.assertEqual(counts["unit"], 13, counts)
        self.assertEqual(counts["envelope"], 63, counts)
        self.assertEqual(counts["slice"], 18, counts)
        self.assertEqual(counts["function"], 48 + 16, counts)
        # 30 slice-lineage receipt vectors (13 valid, 17 invalid); invalid/receipt-slice is from spec-0.1
        lineage = [v for v in vectors_of("receipt") if v["id"].startswith(("receipt/slice-", "invalid/receipt-slice-"))]
        self.assertEqual((len(lineage), sum(v["valid"] for v in lineage)), (30, 13), counts)
        # every kind is one the runner knows (or skips)
        for v in load_vectors():
            self.assertIn(v["kind"], ("jcs", "scalar", "cell", "ref", "function", "uri", "keyid", "keys",
                                      "receipt", "unit", "envelope", "slice") + FORMULA_KINDS, v["id"])

    def test_every_vector_in_process(self) -> None:
        run = runner().run_vector
        tally = collections.Counter()
        for v in verifier_vectors():
            with self.subTest(v["id"]):
                got = run(v)
                self.assertEqual(got, expected_output(v))
                tally[(v["kind"], "valid" if v["valid"] else "invalid")] += 1
        print("\nconformance (in-process): " + ", ".join(f"{k[0]}/{k[1]} {n}" for k, n in sorted(tally.items())),
              file=sys.stderr)

    def test_runner_script(self) -> None:
        vectors = load_vectors()
        feed = "\n".join(json.dumps(v) for v in vectors) + "\n"
        proc = subprocess.run([sys.executable, str(ROOT / "tools" / "run_vectors.py")], input=feed.encode(),
                              capture_output=True, check=True)
        lines = proc.stdout.decode("ascii").split("\n")
        self.assertEqual(lines[-1], "")
        self.assertEqual(len(lines) - 1, len(vectors))
        passed = collections.Counter()
        failed = collections.Counter()
        for v, line in zip(vectors, lines):
            got = json.loads(line)
            key = (v["kind"], "valid" if v["valid"] else "invalid")
            if v["kind"] in FORMULA_KINDS:
                key = ("skipped " + v["kind"], key[1])
            if got == runner_output(v):
                passed[key] += 1
            else:
                failed[key] += 1
                self.fail(f"{v['id']}: expected {runner_output(v)}, got {got}")
        print("\nconformance (runner): " + ", ".join(f"{k[0]}/{k[1]} {n} pass" for k, n in sorted(passed.items()))
              + f"; failures {sum(failed.values())}", file=sys.stderr)

    def test_runner_keeps_alignment_on_garbage(self) -> None:
        feed = b'{"id": "x/garbage", "kind": "receipt", "valid": false, "input": 5}\nnot json\n'
        proc = subprocess.run([sys.executable, str(ROOT / "tools" / "run_vectors.py")], input=feed,
                              capture_output=True, check=True)
        lines = proc.stdout.decode().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["id"], "x/garbage")

    def test_receipts_through_verify(self) -> None:
        for v in vectors_of("receipt"):
            with self.subTest(v["id"]):
                rc = recompute_of(v)
                res = datumesh.verify(v["input"], env_keys(v["keys"]), rc, blob_of(v))
                if v["valid"]:
                    self.assertTrue(res.ok, res)
                    # SPEC 10.1 step 7.6: E_EVAL_UNAVAILABLE (spec-0.3.0) at $.value and E_INPUT_SUPERSEDED
                    # (spec-0.4.0) at $.inputs are reported with success
                    self.assertEqual(res.code, v.get("code", "OK"))
                    self.assertEqual(res.level, v["level"])
                    self.assertEqual(res.hash, v["sha256"])
                    self.assertEqual(res.blob_checked, "blob_hex" in v)
                    self.assertEqual(res.key, json.loads(v["input"])["computed_by"])
                    self.assertEqual(res.path, {None: None, "E_EVAL_UNAVAILABLE": "$.value",
                                                "E_INPUT_SUPERSEDED": "$.inputs"}[v.get("code")])
                    # bytes input and parsed input give the same result
                    self.assertEqual(datumesh.verify(v["input"].encode(), env_keys(v["keys"]), rc, blob_of(v)), res)
                    self.assertEqual(datumesh.verify(json.loads(v["input"]), env_keys(v["keys"]), rc, blob_of(v)), res)
                    self.assertEqual(datumesh.receipt_hash(v["input"]), v["sha256"])
                    self.assertEqual(datumesh.receipt_payload(v["input"]).decode(), v["canonical"])
                else:
                    self.assertFalse(res.ok)
                    self.assertEqual(res.code, v["error"])
                    self.assertIsNone(res.level)
                    self.assertIsNone(res.key)
                    self.assertFalse(res.blob_checked)

    def test_hash_helpers(self) -> None:
        for v in vectors_of("cell", True):
            self.assertEqual(datumesh.cell_hash(v["input"]), v["sha256"])
        for v in vectors_of("function", True):
            self.assertEqual(datumesh.function_hash(v["input"]), v["sha256"])
        for v in vectors_of("cell", False):
            with self.subTest(v["id"]), self.assertRaises(datumesh.DatumeshError) as cm:
                datumesh.cell_hash(v.get("input") if "input" in v else bytes.fromhex(v["input_hex"]))
            self.assertEqual(cm.exception.code, v["error"])

    def test_unit_vectors_through_resolved_unit(self) -> None:
        for v in vectors_of("unit"):
            obj = json.loads(v["input"])
            with self.subTest(v["id"]):
                if v["valid"]:
                    self.assertEqual(datumesh.resolved_unit(obj["descriptor"], obj["cell"]), v["unit"])
                    # JSON text works too
                    self.assertEqual(datumesh.resolved_unit(json.dumps(obj["descriptor"]), json.dumps(obj["cell"])),
                                     v["unit"])
                else:
                    with self.assertRaises(datumesh.DatumeshError) as cm:
                        datumesh.resolved_unit(obj["descriptor"], obj["cell"])
                    self.assertEqual(cm.exception.code, v["error"])

    def test_envelope_vectors_through_check_envelope(self) -> None:
        for v in vectors_of("envelope"):
            with self.subTest(v["id"]):
                res = datumesh.check_envelope(v["status"], v["input"], env_keys(v["keys"]), v["request"])
                self.assertIsInstance(res, datumesh.EnvelopeResult)
                self.assertEqual(datumesh.check_envelope(v["status"], v["input"].encode(), env_keys(v["keys"]),
                                                         v["request"]), res)
                if v["valid"]:
                    self.assertTrue(res.ok, res)
                    self.assertEqual((res.code, res.outcome, res.trust, res.receipt_hash, res.path),
                                     ("OK", v["outcome"], v.get("trust"), v.get("receipt_hash"), None))
                else:
                    self.assertFalse(res.ok)
                    self.assertEqual(res.code, v["error"])
                    self.assertEqual((res.outcome, res.trust, res.receipt_hash), (None, None, None))

    def test_slice_vectors_through_the_api(self) -> None:
        for v in vectors_of("slice"):
            with self.subTest(v["id"]):
                obj = json.loads(v["input"])
                kind = "manifest" if isinstance(obj, dict) and "members" in obj else "slice"
                if v["valid"]:
                    self.assertEqual(datumesh.canonicalize(v["input"], kind).decode(), v["canonical"])
                    if kind == "manifest":
                        self.assertEqual(datumesh.slice_id(obj["slice"]), v["slice_id"])
                        self.assertEqual(datumesh.members_hash(obj["members"]), v["members_hash"])
                        self.assertEqual(datumesh.slice_entry(v["input"]), v["entry"])
                    else:
                        self.assertEqual(datumesh.slice_id(v["input"]), v["slice_id"])
                        self.assertEqual(v["slice_id"], v["sha256"])
                else:
                    with self.assertRaises(datumesh.DatumeshError) as cm:
                        datumesh.canonicalize(v["input"], kind)
                    self.assertEqual(cm.exception.code, v["error"])

    def test_invalid_vectors_raise_exact_code(self) -> None:
        for v in load_vectors():
            if v["valid"] or v["kind"] not in ("scalar", "cell", "ref", "function"):
                continue
            with self.subTest(v["id"]):
                data = v["input"] if "input" in v else bytes.fromhex(v["input_hex"])
                with self.assertRaises(datumesh.DatumeshError) as cm:
                    datumesh.canonicalize(data, v["kind"])
                self.assertEqual(cm.exception.code, v["error"])


if __name__ == "__main__":
    unittest.main()
