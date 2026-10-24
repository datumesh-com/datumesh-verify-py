"""The changes of spec-0.3.0, each tested through the API (the vectors are run by test_conformance).

- D17 revised (8.2, 10.1 step 7.5): an input receipt's asof is at or before the receipt's.
- D31 revised (5.5 step 5): for ok as for stale, the receipt's asof is at or before the requested one.
- E_EVAL_UNAVAILABLE (10.1 step 7.6, 10.2, 11): success at level signed, with the code at $.value.
- 10.1 step 7.1 / 11 (DEF-17): a null descriptor is a descriptor offered (E_FN_HASH_MISMATCH).
- 9.3 / 11 (DEF-16(b)): only the integer 200 is a retrieved key document.
- 3.7: the 128-character media type limit is on the whole media type.
"""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from typing import Any, Dict

from nacl.signing import SigningKey

from util import ROOT, env_keys, recompute_of, runner, vectors_of

import datumesh
from datumesh import DatumeshError, canonicalize, check_envelope, keys_from_response, verify


def vector(vid: str) -> Dict[str, Any]:
    v: Dict[str, Any] = json.loads((ROOT / "spec" / "vectors" / f"{vid}.json").read_text(encoding="utf-8"))
    return v


EARLIER = vector("receipt/computed-inputs-earlier-asof")
EVAL_STORED = vector("receipt/eval-unavailable-stored")
EVAL_COMPUTED = vector("receipt/eval-unavailable-computed")
EVAL_BLOB = vector("receipt/eval-unavailable-blob-checked")
STORED = vector("receipt/stored-number")
LINEAGE = vector("receipt/computed-with-lineage")


def resign(v: Dict[str, Any], **changes: Any) -> str:
    """The vector's receipt with ``changes``, signed again with the vector's keypair."""
    r = json.loads(v["input"])
    r.update(changes)
    payload = datumesh.jcs({k: x for k, x in r.items() if k != "sig"})
    r["sig"] = SigningKey(bytes.fromhex(v["keypair"]["seed"])).sign(payload).signature.hex()
    return json.dumps(r)


def without_value(v: Dict[str, Any]) -> Dict[str, Any]:
    rc = copy.deepcopy(v["recompute"])
    rc.pop("value", None)
    return rc


class InputAsofTest(unittest.TestCase):
    """D17 revised: an input's asof at or before the receipt's; only a later one is E_TIME_ORDER."""

    def test_boundaries(self) -> None:
        keys = env_keys(EARLIER["keys"])
        rc = EARLIER["recompute"]
        latest_input_asof = max(json.loads(t)["asof"] for t in rc["inputs"].values())
        self.assertEqual(latest_input_asof, "2024-03-16T09:00:00.000000Z")
        # the vector as it is: inputs at earlier asofs
        self.assertEqual(verify(EARLIER["input"], keys, rc).level, "recomputed")
        # the receipt's asof equal to the latest input asof
        res = verify(resign(EARLIER, asof=latest_input_asof), keys, rc)
        self.assertEqual((res.ok, res.code, res.level), (True, "OK", "recomputed"))
        # one microsecond earlier: that input is later than the receipt
        res = verify(resign(EARLIER, asof="2024-03-16T08:59:59.999999Z"), keys, rc)
        self.assertEqual((res.ok, res.code, res.path), (False, "E_TIME_ORDER", "$.inputs[0]"))
        # still reported when evaluation is unavailable: 7.5 comes before 7.6
        res = verify(resign(EARLIER, asof="2024-03-16T08:59:59.999999Z"), keys, without_value(EARLIER))
        self.assertEqual((res.ok, res.code), (False, "E_TIME_ORDER"))

    def test_tx_is_still_the_latest_input_tx(self) -> None:
        keys = env_keys(EARLIER["keys"])
        res = verify(resign(EARLIER, tx="2024-03-15T16:00:00.000000Z"), keys, EARLIER["recompute"])
        self.assertEqual((res.code, res.path), ("E_TIME_ORDER", "$.tx"))


class EvalUnavailableTest(unittest.TestCase):
    """E_EVAL_UNAVAILABLE: recompute without value, after 7.1-7.5 pass."""

    def test_error_code_list(self) -> None:
        codes = datumesh.ERROR_CODES
        self.assertIn("E_EVAL_UNAVAILABLE", codes)
        i = codes.index("E_EVAL_UNAVAILABLE")
        # spec-0.4.0 put E_INPUT_SUPERSEDED after it
        self.assertEqual((codes[i - 1], codes[i + 1]), ("E_VALUE_MISMATCH", "E_INPUT_SUPERSEDED"))
        self.assertEqual(DatumeshError("E_EVAL_UNAVAILABLE").code, "E_EVAL_UNAVAILABLE")

    def test_stored_and_computed(self) -> None:
        for v in (EVAL_STORED, EVAL_COMPUTED):
            with self.subTest(v["id"]):
                res = verify(v["input"], env_keys(v["keys"]), v["recompute"])
                self.assertEqual(
                    (res.ok, res.code, res.level, res.hash, res.key, res.path, res.blob_checked),
                    (True, "E_EVAL_UNAVAILABLE", "signed", v["sha256"], json.loads(v["input"])["computed_by"],
                     "$.value", False))
                self.assertIn("not evaluated", res.detail)

    def test_existing_vectors_without_value(self) -> None:
        # Every valid recomputed vector, with value removed, is signed with E_EVAL_UNAVAILABLE.
        for v in vectors_of("receipt", True):
            if v.get("level") != "recomputed":
                continue
            with self.subTest(v["id"]):
                blob = bytes.fromhex(v["blob_hex"]) if "blob_hex" in v else None
                res = verify(v["input"], env_keys(v["keys"]), without_value(v), blob)
                self.assertEqual((res.ok, res.code, res.level, res.path, res.blob_checked),
                                 (True, "E_EVAL_UNAVAILABLE", "signed", "$.value", blob is not None))

    def test_failures_before_7_6_are_reported_instead(self) -> None:
        keys = env_keys(LINEAGE["keys"])
        rc = without_value(LINEAGE)
        self.assertEqual(verify(LINEAGE["input"], keys, {}).code, "E_FN_UNAVAILABLE")
        self.assertEqual(verify(LINEAGE["input"], keys, dict(rc, inputs={})).code, "E_INPUT_UNAVAILABLE")
        self.assertEqual(verify(LINEAGE["input"], keys, dict(rc, descriptor=None)).code, "E_FN_HASH_MISMATCH")
        # a receipt that is not signature-valid fails as before
        r = json.loads(LINEAGE["input"])
        r["summary"] = "changed"
        res = verify(r, keys, rc)
        self.assertEqual((res.ok, res.code, res.level), (False, "E_SIGNATURE", None))

    def test_blob_after_eval_unavailable(self) -> None:
        keys = env_keys(EVAL_BLOB["keys"])
        content = bytes.fromhex(EVAL_BLOB["blob_hex"])
        rc = EVAL_BLOB["recompute"]
        res = verify(EVAL_BLOB["input"], keys, rc, content)
        self.assertEqual((res.ok, res.code, res.level, res.path, res.blob_checked),
                         (True, "E_EVAL_UNAVAILABLE", "signed", "$.value", True))
        # 7.7 fails: an ordinary failure replaces the code
        res = verify(EVAL_BLOB["input"], keys, rc, content + b"x")
        self.assertEqual((res.ok, res.code, res.level, res.blob_checked), (False, "E_BLOB_MISMATCH", None, False))
        # content for a value that is not a blob: E_SCHEMA, also after E_EVAL_UNAVAILABLE
        res = verify(EVAL_STORED["input"], env_keys(EVAL_STORED["keys"]), EVAL_STORED["recompute"], b"x")
        self.assertEqual((res.ok, res.code), (False, "E_SCHEMA"))
        # no content: the code, and blob_checked false
        res = verify(EVAL_BLOB["input"], keys, rc)
        self.assertEqual((res.ok, res.code, res.blob_checked), (True, "E_EVAL_UNAVAILABLE", False))

    def test_value_none_is_a_caller_error(self) -> None:
        # Only an absent value means unavailable; a value that is not {"type", "value"} is a TypeError.
        for bad in (None, "1.0892", {"type": "number"}):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                verify(EVAL_STORED["input"], env_keys(EVAL_STORED["keys"]), dict(EVAL_STORED["recompute"], value=bad))

    def test_runner_reports_code_only_with_it(self) -> None:
        run = runner().run_vector
        for v in vectors_of("receipt"):
            with self.subTest(v["id"]):
                out = run(v)
                if v["valid"] and v.get("code"):
                    # E_EVAL_UNAVAILABLE, or since spec-0.4.0 E_INPUT_SUPERSEDED
                    self.assertEqual(out.get("code"), v["code"])
                    self.assertEqual(out["level"], "signed")
                else:
                    self.assertNotIn("code", out)

    def test_envelope_error_may_carry_it(self) -> None:
        body = json.dumps({"outcome": "error", "error": "E_EVAL_UNAVAILABLE"})
        res = check_envelope(503, body, [], {"cell_id": "0" * 64})
        self.assertEqual((res.ok, res.outcome), (True, "error"))
        body = json.dumps({"outcome": "bad_request", "error": "E_EVAL_UNAVAILABLE"})
        self.assertEqual(check_envelope(400, body, [], {"cell_id": "0" * 64}).code, "E_ENVELOPE")


class DescriptorOfferedTest(unittest.TestCase):
    """10.1 step 7.1: what is obtained is a JSON value; only obtaining nothing is E_FN_UNAVAILABLE."""

    def test_forms(self) -> None:
        keys = env_keys(STORED["keys"])
        rc = STORED["recompute"]
        desc = rc["descriptor"]
        cases = [
            ({"inputs": {}, "value": rc["value"]}, "E_FN_UNAVAILABLE", "$.cell.fn_hash"),  # nothing obtained
            (dict(rc, descriptor=None), "E_FN_HASH_MISMATCH", "$.cell.fn_hash"),  # JSON null
            (dict(rc, descriptor=0), "E_FN_HASH_MISMATCH", "$.cell.fn_hash"),
            (dict(rc, descriptor=[]), "E_FN_HASH_MISMATCH", "$.cell.fn_hash"),
            (dict(rc, descriptor="null"), "E_FN_HASH_MISMATCH", "$.cell.fn_hash"),  # text of null
            # a JSON string value holding the descriptor's text, given as JSON text: a string
            (dict(rc, descriptor=json.dumps(json.dumps(desc))), "E_FN_HASH_MISMATCH", "$.cell.fn_hash"),
            # bytes or text are parsed strictly first, with the parse codes
            (dict(rc, descriptor=b"{"), "E_PARSE_JSON", None),
            (dict(rc, descriptor='{"a":1,"a":1}'), "E_PARSE_DUPLICATE_KEY", None),
        ]
        for recompute, code, path in cases:
            with self.subTest(recompute=str(recompute.get("descriptor", "<absent>"))[:30]):
                res = verify(STORED["input"], keys, recompute)
                self.assertEqual(res.code, code)
                if path is not None:
                    self.assertEqual(res.path, path)
        # the descriptor as a parsed value, as text, and as bytes
        for d in (desc, json.dumps(desc), json.dumps(desc).encode()):
            self.assertEqual(verify(STORED["input"], keys, dict(rc, descriptor=d)).level, "recomputed")

    def test_vectors(self) -> None:
        for vid in ("invalid/receipt-descriptor-null", "invalid/receipt-descriptor-text"):
            v = vector(vid)
            with self.subTest(vid):
                self.assertEqual(verify(v["input"], env_keys(v["keys"]), recompute_of(v)).code, "E_FN_HASH_MISMATCH")


class OkAsofTest(unittest.TestCase):
    """D31 revised: ok binds to an asof at or before the requested one, like stale."""

    def test_ok_and_stale(self) -> None:
        v = vector("envelope/served-ok")
        s = vector("envelope/served-stale")
        req = v["request"]
        receipt = json.loads(v["input"])["receipt"]
        keys = env_keys(v["keys"])
        self.assertLess(receipt["asof"], req["asof"])
        for body in (v["input"], s["input"]):
            env = json.loads(body)
            for asof, ok in ((req["asof"], True), (receipt["asof"], True), (None, True),
                             ("2024-03-16T08:59:59.999999Z", False), ("2020-01-01T00:00:00.000000Z", False)):
                request = {"cell_id": req["cell_id"]} if asof is None else {"cell_id": req["cell_id"], "asof": asof}
                with self.subTest(outcome=env["outcome"], asof=asof):
                    res = check_envelope(200, body, keys, request)
                    self.assertEqual(res.ok, ok, res)
                    if not ok:
                        self.assertEqual((res.code, res.path), ("E_ENVELOPE", "$.receipt.asof"))

    def test_age_seconds_still_tells_them_apart(self) -> None:
        v = vector("envelope/served-ok")
        env = json.loads(v["input"])
        keys = env_keys(v["keys"])
        self.assertEqual(check_envelope(200, json.dumps(dict(env, age_seconds=5)), keys, v["request"]).code,
                         "E_ENVELOPE")
        self.assertEqual(check_envelope(200, json.dumps(dict(env, outcome="stale")), keys, v["request"]).code,
                         "E_ENVELOPE")


class KeyStatusTest(unittest.TestCase):
    """9.3 / 11: only the integer 200 is a retrieved document."""

    def test_status_forms(self) -> None:
        body = json.loads(next(v for v in vectors_of("keys", True))["env"]["https"]["body"])
        host = body["host"]
        text = json.dumps(body)
        self.assertTrue(keys_from_response(host, 200, text).ok)
        for status in ("200", 200.0, True, None, b"200", [200]):
            with self.subTest(status=status):
                res = keys_from_response(host, status, text)  # type: ignore[arg-type]
                self.assertEqual((res.ok, res.code), (False, "E_KEY_UNAVAILABLE"))


class MediaTypeLengthTest(unittest.TestCase):
    """3.7: 128 characters for the whole media type; no per-name limit."""

    def test_limits(self) -> None:
        h = hashlib.sha256(b"").hexdigest()

        def code(media: str) -> Any:
            try:
                canonicalize({"type": "blob", "value": f"{h}:0:{media}"}, "scalar")
                return None
            except DatumeshError as e:
                return e.code

        self.assertIsNone(code("a/" + "b" * 126))
        self.assertEqual(code("a/" + "b" * 127), "E_CANON_BLOB")
        self.assertIsNone(code("a" * 126 + "/b"))
        self.assertEqual(code("a" * 127 + "/b"), "E_CANON_BLOB")
        self.assertIsNone(code("a" * 63 + "/" + "b" * 64))


if __name__ == "__main__":
    unittest.main()
