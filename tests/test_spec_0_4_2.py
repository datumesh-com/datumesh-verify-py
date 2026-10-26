"""The changes of spec-0.4.2 for a verifier library, each tested through the API (the vectors are run by
test_conformance):

- 2.4, 4.3, 5.1-5.4: the pin ``fn_hash=`` in cell URIs and references; ``fn_hash`` reserved as an argument name;
- 5.5: the ``fn_hash`` echo; ``not_covered`` with ``E_NAME_UNBOUND``; the new ``bad_request`` codes; trust
  ``computed``; the request description's ``fn_hash`` and ``mesh``;
- 5.6: pages of the slice endpoint, checked against ``{slice_id, asof?, fn_hash?, mesh?, after?}``;
- 5.7: batches;
- 9.6: the optional ``versions`` endpoint;
- 10.2: ``E_SLICE_AT_CELL`` and ``E_NAME_UNBOUND`` after ``E_MESH_DOC``.

Expected codes for the hand-made envelope and batch cases are those the reference tool gives on the same
inputs (run as a black box).
"""

from __future__ import annotations

import copy
import json
import unittest
from typing import Any, Dict, List, Optional

from util import ROOT, env_keys, runner

import datumesh
from datumesh import DatumeshError, canonicalize, check_batch, check_envelope, format_uri, parse_uri


def vector(vid: str) -> Dict[str, Any]:
    v: Dict[str, Any] = json.loads((ROOT / "spec" / "vectors" / f"{vid}.json").read_text(encoding="utf-8"))
    return v


PIN = "7b58ecb8fd23b644c87951d0bd609790ff547cbb23fed27186c669ce2ce0aa80"
OTHER = "0" * 64
URI = vector("uri/pinned")
SIG = URI["signature"]
BASE = "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD"
ASOF = "2024-03-16T09:00:00.000000Z"


def uri_code(uri: str, sig: Any = SIG) -> Optional[str]:
    try:
        parse_uri(uri, sig)
        return None
    except DatumeshError as e:
        return e.code


class PinTest(unittest.TestCase):
    def test_parse_and_format(self) -> None:
        ref = parse_uri(f"{BASE}&fn_hash={PIN}&asof={ASOF}", SIG)
        self.assertEqual((ref["fn_hash"], ref["asof"]), (PIN, ASOF))
        self.assertEqual(format_uri(ref), f"{BASE}&fn_hash={PIN}&asof={ASOF}")
        ref = parse_uri(f"{BASE}&fn_hash={PIN}", SIG)
        self.assertEqual(format_uri(ref), f"{BASE}&fn_hash={PIN}")
        self.assertNotIn("fn_hash", parse_uri(BASE, SIG))
        self.assertEqual(format_uri(parse_uri(f"cell://a.example/f?fn_hash={PIN}", {"args": {}})),
                         f"cell://a.example/f?fn_hash={PIN}")
        # a reference carries it, checked as 64 lowercase hex in JCS order (after fn, before ns)
        canonicalize(ref, "ref")
        for bad in (PIN[:-1], PIN.upper(), "*", 5):
            with self.subTest(bad), self.assertRaises(DatumeshError) as cm:
                canonicalize(dict(ref, fn_hash=bad), "ref")
            self.assertEqual(cm.exception.code, "E_SCHEMA" if bad == 5 else "E_CANON_HEX")
        with self.assertRaises(DatumeshError) as cm:
            canonicalize(dict(ref, fn_hash=PIN[:-1], ns="Bad"), "ref")
        self.assertEqual(cm.exception.code, "E_CANON_HEX")
        with self.assertRaises(DatumeshError) as cm:
            canonicalize(dict(ref, fn_hash=PIN[:-1], fn="Bad"), "ref")
        self.assertEqual(cm.exception.code, "E_CANON_NAME")

    def test_parse_codes(self) -> None:
        cases = [
            (f"{BASE}&asof={ASOF}&fn_hash={PIN}", "E_CANON_ARG_ORDER"),
            (f"cell://rates.example.org/fx_rate?base=EUR&fn_hash={PIN}&date=2024-03-15&quote=USD", "E_CANON_ARG_ORDER"),
            (f"{BASE}&fn_hash={PIN}&fn_hash={PIN}", "E_CANON_ARG_DUPLICATE"),
            (f"{BASE}&fn_hash={PIN}&fn_hash={PIN}&asof={ASOF}", "E_CANON_ARG_DUPLICATE"),
            (f"{BASE}&fn_hash={PIN.upper()}", "E_CANON_HEX"),
            (f"{BASE}&fn_hash=*", "E_CANON_HEX"),
            (f"{BASE}&fn_hash={PIN[:-1]}", "E_CANON_HEX"),
            (f"{BASE}&fn_hash=", "E_CANON_HEX"),
            # the pin after the values, before asof
            (f"cell://rates.example.org/fx_rate?base=EUR&date=2024-13-15&quote=USD&fn_hash=x", "E_CANON_DATE"),
            (f"{BASE}&fn_hash=x&asof=bad", "E_CANON_HEX"),
            (f"{BASE}&fn_hash={PIN}&asof=bad", "E_CANON_INSTANT"),
        ]
        for uri, want in cases:
            with self.subTest(uri):
                self.assertEqual(uri_code(uri), want)
        self.assertIsNone(uri_code(f"cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=*&fn_hash={PIN}"))

    def test_reserved_argument_name(self) -> None:
        d = {"code": {"body": "", "lang": "stored"}, "inputs": [],
             "signature": {"args": {"fn_hash": {"type": "string", "valid": False}}, "returns": "boolean"}}
        with self.assertRaises(DatumeshError) as cm:
            canonicalize(d, "function")
        self.assertEqual(cm.exception.code, "E_CANON_ARG_NAME")
        cell = {"args": {"fn_hash": {"type": "string", "value": "x"}}, "fn": "f", "fn_hash": PIN, "ns": "a.example"}
        with self.assertRaises(DatumeshError) as cm:
            canonicalize(cell, "cell")
        self.assertEqual(cm.exception.code, "E_CANON_ARG_NAME")
        self.assertEqual(uri_code(f"cell://a.example/f?fn_hash=x&z=1", {"args": {"z": {"type": "number"}}}),
                         "E_CANON_ARG_ORDER")


# ---------------------------------------------------------------- envelopes

OKP = vector("envelope/ok-pinned")
PAGE = vector("envelope/slice-page")
COMP = vector("envelope/ok-computed")
CELL = OKP["request"]["cell_id"]
REQP = {"cell_id": CELL, "asof": ASOF, "fn_hash": PIN}
J = "a" * 32
PEND = {"outcome": "pending", "job": J, "estimate_seconds": 1, "poll": "https://m.example/jobs/" + J,
        "request": {"cell_id": CELL, "asof": ASOF, "fn_hash": PIN}}
PB = json.loads(PAGE["input"])
RECEIPT = json.loads(OKP["input"])["receipt"]


def member(i: int, **changes: Any) -> Dict[str, Any]:
    m = copy.deepcopy(PB)
    for k, x in changes.items():
        if x is None:
            del m["members"][i][k]
        else:
            m["members"][i][k] = x
    return m


def ecode(base: Dict[str, Any], body: Any, status: int, request: Optional[Dict[str, Any]] = None) -> str:
    res = check_envelope(status, json.dumps(body), env_keys(base["keys"]),
                         request if request is not None else base["request"])
    return res.code


class EchoAndCodesTest(unittest.TestCase):
    def test_cases(self) -> None:
        E = "E_ENVELOPE"
        cases = [
            (OKP, {"outcome": "rate_limited", "retry_after_seconds": 1, "fn_hash": OTHER}, 429, REQP, E),
            (OKP, {"outcome": "bad_request", "error": "E_PARSE_URI", "fn_hash": OTHER}, 400, REQP, E),
            (OKP, {"outcome": "bad_request", "error": "E_PARSE_URI"}, 400, REQP, "OK"),
            (OKP, {"outcome": "not_covered", "fn_hash": OTHER}, 404, {"cell_id": CELL}, "OK"),
            (OKP, {"outcome": "not_covered", "error": "E_NAME_UNBOUND", "fn_hash": PIN}, 404, REQP, "OK"),
            (OKP, {"outcome": "not_covered", "error": "E_NAME_UNBOUND"}, 404, REQP, E),
            (OKP, {"outcome": "unlicensed"}, 403, REQP, E),
            (OKP, {"outcome": "error", "error": "E_EVAL_UNAVAILABLE"}, 500, REQP, E),
            (OKP, dict(PEND, fn_hash=PIN), 202, REQP, E),
            (OKP, PEND, 202, {"cell_id": CELL, "asof": ASOF}, E),
            (OKP, PEND, 202, REQP, "OK"),
            (OKP, dict(PEND, request={"cell_id": CELL, "asof": ASOF}), 202, REQP, E),
            (OKP, dict(PEND, request={"cell_id": CELL, "asof": ASOF, "fn_hash": OTHER}), 202, REQP, E),
            (OKP, dict(PEND, request={"cell_id": CELL, "asof": ASOF, "fn_hash": PIN.upper()}), 202, REQP, E),
            (OKP, dict(json.loads(OKP["input"]), members=[]), 200, {"cell_id": CELL, "asof": ASOF}, E),
            (OKP, PB, 200, {"cell_id": CELL, "asof": ASOF}, E),
            (OKP, {"outcome": "bad_request", "error": "E_CANON_HEX"}, 400, {"cell_id": CELL}, "OK"),
            (OKP, {"outcome": "bad_request", "error": "E_SLICE_AT_CELL"}, 400, {"cell_id": CELL}, "OK"),
            (OKP, {"outcome": "bad_request", "error": "E_NAME_UNBOUND"}, 400, {"cell_id": CELL}, E),
            (OKP, {"outcome": "error", "error": "E_MESH_DOC"}, 500, {"cell_id": CELL}, "OK"),
            (OKP, {"outcome": "error", "error": "E_SLICE_AT_CELL"}, 500, {"cell_id": CELL}, E),
            (OKP, {"outcome": "error", "error": "E_NAME_UNBOUND"}, 500, {"cell_id": CELL}, E),
            (OKP, {"outcome": "not_covered", "error": "E_EVAL_UNAVAILABLE"}, 404, {"cell_id": CELL}, E),
            (OKP, {"outcome": "not_covered", "error": "E_NAME_UNBOUND", "fault": "E_FORMULA_DOMAIN"}, 404,
             {"cell_id": CELL}, E),
            (OKP, {"outcome": "ok", "trust": "primary", "receipt": RECEIPT, "fn_hash": "A" * 64}, 200,
             {"cell_id": CELL, "asof": ASOF}, E),
            (OKP, {"outcome": "ok", "trust": "primary", "receipt": RECEIPT, "fn_hash": OTHER}, 200,
             {"cell_id": CELL, "asof": ASOF}, E),
            (OKP, {"outcome": "ok", "trust": "primary", "receipt": RECEIPT, "fn_hash": PIN}, 200,
             {"cell_id": CELL, "asof": ASOF}, "OK"),
            (OKP, {"outcome": "ok", "trust": "primary", "receipt": RECEIPT, "fn_hash": 5}, 200,
             {"cell_id": CELL, "asof": ASOF}, E),
            (COMP, json.loads(COMP["input"]), 200, dict(COMP["request"], mesh="calc.example.net"), "OK"),
            (OKP, {"outcome": "pending", "job": J, "estimate_seconds": 1, "poll": "https://m.example/jobs/" + J,
                   "request": {"cell_id": CELL}}, 202, {"cell_id": CELL, "mesh": "m.example"}, "OK"),
            (OKP, {"outcome": "pending", "job": J, "estimate_seconds": 1, "poll": "https://m.example/jobs/" + J,
                   "request": {"cell_id": CELL}}, 202, {"cell_id": CELL, "mesh": "n.example"}, E),
        ]
        for base, body, status, req, want in cases:
            with self.subTest(json.dumps(body)[:150], request=req):
                self.assertEqual(ecode(base, body, status, req), want)

    def test_echo_exposed(self) -> None:
        res = check_envelope(200, OKP["input"], env_keys(OKP["keys"]), OKP["request"])
        self.assertEqual((res.ok, res.fn_hash), (True, PIN))
        res = check_envelope(404, '{"outcome": "not_covered", "error": "E_NAME_UNBOUND"}', [], {"cell_id": CELL})
        self.assertEqual((res.ok, res.error), (True, "E_NAME_UNBOUND"))

    def test_trust_rules(self) -> None:
        # computed: not primary; with mesh, signed by it. verified and unverified: with mesh, signed by another.
        body = json.loads(COMP["input"])
        signer = body["receipt"]["computed_by"].split("#")[0]
        keys = env_keys(COMP["keys"])
        for trust, mesh, want in (("computed", None, "OK"), ("computed", signer, "OK"),
                                  ("computed", "other.example.net", "E_ENVELOPE"),
                                  ("verified", None, "OK"), ("verified", signer, "E_ENVELOPE"),
                                  ("verified", "other.example.net", "OK"),
                                  ("unverified", signer, "E_ENVELOPE"), ("unverified", "other.example.net", "OK"),
                                  ("primary", None, "E_ENVELOPE"), ("primary", signer, "E_ENVELOPE")):
            req = dict(COMP["request"], **({"mesh": mesh} if mesh else {}))
            with self.subTest(trust=trust, mesh=mesh):
                self.assertEqual(check_envelope(200, json.dumps(dict(body, trust=trust)), keys, req).code, want)
        # a primary receipt is never computed, whatever the mesh
        b = json.loads(OKP["input"])
        for mesh in (None, "rates.example.org", "m.example"):
            req = dict(OKP["request"], **({"mesh": mesh} if mesh else {}))
            self.assertEqual(check_envelope(200, json.dumps(dict(b, trust="computed")), env_keys(OKP["keys"]),
                                            req).code, "E_ENVELOPE")
            self.assertEqual(check_envelope(200, OKP["input"], env_keys(OKP["keys"]), req).code, "OK")

    def test_request_description(self) -> None:
        body = '{"outcome": "not_covered"}'
        for bad in ({"cell_id": CELL, "fn_hash": PIN.upper()}, {"cell_id": CELL, "fn_hash": 5},
                    {"cell_id": CELL, "mesh": "Mesh.example"}, {"cell_id": CELL, "mesh": "localhost"},
                    {"cell_id": CELL, "mesh": 5}, {"cell_id": CELL, "after": {}},
                    {"slice_id": "a" * 64, "job": J}, {"slice_id": "A" * 64}, {"slice_id": "a" * 64, "cell_id": CELL},
                    {"slice_id": "a" * 64, "after": []}, {"slice_id": "a" * 64, "after": {"q": "*"}},
                    {"slice_id": "a" * 64, "after": {"q": {"type": "string", "value": "\u0007"}}}):
            with self.subTest(bad), self.assertRaises((ValueError, TypeError)):
                check_envelope(404, body, [], bad)


class SlicePageTest(unittest.TestCase):
    def test_cases(self) -> None:
        E = "E_ENVELOPE"
        req = PAGE["request"]
        cases = [
            ({"outcome": "bad_request", "error": "E_SLICE_AT_CELL"}, 400, req, "OK"),
            ({"outcome": "stale", "receipt": RECEIPT, "trust": "primary", "age_seconds": 1}, 200, req, E),
            (PB, 200, dict(req, fn_hash=PIN), E),
            (dict(PB, fn_hash=OTHER), 200, req, E),
            (dict(PB, fn_hash=PIN), 200, dict(req, fn_hash=PIN), "OK"),
            (member(0, fn_hash=OTHER), 200, req, E),
            (member(0, trust=None), 200, req, E),
            (member(0, receipt=dict(PB["members"][0]["receipt"], sig="0" * 128)), 200, req, "E_SIGNATURE"),
            (dict(PB, next="https://mesh.example:443/x"), 200, req, E),
            (dict(PB, next="https://mesh.example"), 200, req, E),
            (dict(PB, next="https://other.example.net/x"), 200, req, "OK"),
            (member(0, members=[]), 200, req, E),
            (dict(PB, slice=5), 200, req, E),
            (member(0, fn_hash=PIN), 200, req, "OK"),
            (PB, 200, {"slice_id": req["slice_id"]}, "OK"),
            ({"outcome": "pending", "job": J, "estimate_seconds": 1, "poll": "https://m.example/jobs/" + J,
              "request": {"cell_id": CELL}}, 202, req, E),
            (dict(PB, members=[{"outcome": "not_covered"}]), 200, req, E),
            ({"outcome": "not_covered", "error": "E_NAME_UNBOUND"}, 404, req, "OK"),
            (dict(PB, next="https://mesh.example/x y"), 200, req, E),
            (dict(PB, next="https://mesh.example/" + "x" * 600), 200, req, E),
            (dict(PB, next="http://mesh.example/x"), 200, req, E),
            (dict(PB, next=5), 200, req, E),
            (member(0, outcome="stale"), 200, req, E),
            (dict(PB, members={}), 200, req, E),
            ({"outcome": "not_covered", "fn_hash": OTHER}, 404, dict(req, fn_hash=PIN), E),
            (dict(PB, next="https://mesh.example/x"), 200, dict(req, mesh="mesh.example"), "OK"),
            (dict(PB, next="https://mesh.example/x"), 200, dict(req, mesh="other.example"), E),
            (dict(PB, members=[]), 200, req, "OK"),
            (dict(PB, members=PB["members"][::-1]), 200, req, E),
            (dict(PB, members=PB["members"][:1] * 2), 200, req, E),
            (PB, 200, dict(req, after={"quote": {"type": "string", "value": "CHF"}}), E),
            (PB, 200, dict(req, after={"quote": {"type": "string", "value": "BRL"}}), "OK"),
            (PB, 200, dict(req, asof="2024-03-16T08:59:59.999999Z"), E),
            (PB, 200, dict(req, slice_id=OTHER), E),
        ]
        for body, status, request, want in cases:
            with self.subTest(json.dumps(body)[:150], request=request):
                self.assertEqual(ecode(PAGE, body, status, request), want)

    def test_page_result(self) -> None:
        res = check_envelope(200, PAGE["input"], env_keys(PAGE["keys"]), PAGE["request"])
        self.assertEqual((res.ok, res.outcome, res.trust, res.receipt_hash, res.next), (True, "ok", None, None, PB["next"]))
        self.assertEqual([(m.outcome, m.trust, m.receipt_hash) for m in res.members],
                         [(r["outcome"], r["trust"], r["receipt_hash"]) for r in PAGE["results"]])
        self.assertTrue(all(isinstance(m, datumesh.MemberResult) for m in res.members))


# ---------------------------------------------------------------- batches

BATCH = vector("batch/in-order")
ITEMS = json.loads(BATCH["input"])


def bres(body: Any, status: int = 200, requests: Optional[List[Dict[str, Any]]] = None) -> datumesh.BatchResult:
    text = body if isinstance(body, str) else json.dumps(body)
    return check_batch(status, text, env_keys(BATCH["keys"]), BATCH["requests"] if requests is None else requests)


def items(**changes: Any) -> List[Any]:
    it = copy.deepcopy(ITEMS)
    for key, x in changes.items():
        i, member_name = key.split("_", 1)
        idx = int(i[1:])
        if member_name == "item":
            it[idx] = x
        elif x is None:
            del it[idx][member_name]
        else:
            it[idx][member_name] = x
    return it


class BatchTest(unittest.TestCase):
    def test_whole(self) -> None:
        E = "E_ENVELOPE"
        cases = [
            ({"outcome": "not_covered"}, 404, None, E),
            (ITEMS[2]["envelope"], 202, None, E),
            (items(i0_status=600), 200, None, E),
            (items(i0_status=99), 200, None, E),
            (items(i0_status=None), 200, None, E),
            ([], 200, [], "OK"),
            ({"outcome": "ok"}, 200, None, E),
            ("[", 200, None, "E_PARSE_JSON"),
            ({"outcome": "bad_request", "error": "E_JOB_UNKNOWN"}, 400, None, E),
            ({"outcome": "error", "error": "E_EVAL_UNAVAILABLE"}, 503, None, "OK"),
            (items(i0_envelope=5), 200, None, "OK"),
            (items(i0_item=5), 200, None, E),
            (items(i0_status=True), 200, None, E),
            (json.dumps(ITEMS).replace('"status": 200', '"status": 2e2', 1), 200, None, E),
            (json.dumps(ITEMS).replace('"status": 200', '"status": 200, "status": 200', 1), 200, None,
             "E_PARSE_DUPLICATE_KEY"),
            (ITEMS + ITEMS[:1], 200, None, E),
            ({"outcome": "payment_required", "quote": {"amount": "1", "currency": "EUR",
                                                        "authorise": "https://x.example/p"}}, 402, None, "OK"),
            ({"outcome": "not_covered", "fn_hash": OTHER}, 404, None, E),
            ({"outcome": "rate_limited", "retry_after_seconds": 1}, 200, None, E),
        ]
        for body, status, requests, want in cases:
            with self.subTest(str(body)[:120], status=status):
                res = bres(body, status, requests)
                self.assertEqual(res.code, want)
                self.assertEqual(res.ok, want == "OK")

    def test_items(self) -> None:
        res = bres(ITEMS)
        self.assertEqual([i.outcome for i in res.items], ["ok", "ok", "pending"])
        self.assertIsNone(res.outcome)
        it = items(i1_envelope=dict(ITEMS[1]["envelope"], age_seconds=1))
        res = bres(it)
        self.assertTrue(res.ok)
        self.assertEqual([i.code for i in res.items], ["OK", "E_ENVELOPE", "OK"])
        res = bres(items(i0_envelope=5))
        self.assertEqual([i.code for i in res.items], ["E_ENVELOPE", "OK", "OK"])
        # an item's integer members keep the integer text rule
        text = json.dumps(items(i1_envelope=dict(ITEMS[1]["envelope"], outcome="stale", age_seconds=1)))
        self.assertEqual([i.code for i in bres(text).items], ["OK", "OK", "OK"])
        self.assertEqual([i.code for i in bres(text.replace('"age_seconds": 1', '"age_seconds": 1.0')).items],
                         ["OK", "E_ENVELOPE", "OK"])
        # each item against its own request
        reqs = copy.deepcopy(BATCH["requests"])
        reqs[0], reqs[1] = reqs[1], reqs[0]
        self.assertEqual([i.code for i in bres(ITEMS, 200, reqs).items], ["E_ENVELOPE", "E_ENVELOPE", "OK"])

    def test_arguments(self) -> None:
        with self.assertRaises(TypeError):
            check_batch(200, "[]", [], {"cell_id": CELL})
        with self.assertRaises(ValueError):
            check_batch(200, "[]", [], [{"cell_id": "x"}])


# ---------------------------------------------------------------- mesh, codes, runner


class MeshVersionsTest(unittest.TestCase):
    def test_versions_endpoint(self) -> None:
        v = vector("mesh/versions")
        env = v["env"]
        res = datumesh.resolve_mesh(v["host"], (200, env["keys"]["https"]["body"]),
                                    (200, env["mesh"]["https"]["body"]))
        self.assertTrue(res.ok)
        self.assertIn("versions", res.endpoints)
        self.assertEqual(datumesh.MESH_ENDPOINTS["versions"], (("cell",), False))


class CodesTest(unittest.TestCase):
    def test_codes(self) -> None:
        codes = datumesh.ERROR_CODES
        self.assertEqual(codes[codes.index("E_MESH_DOC") + 1:], ("E_SLICE_AT_CELL", "E_NAME_UNBOUND"))

    def test_version(self) -> None:
        self.assertEqual(datumesh.SPEC_VERSION, "spec-0.4.2")
        self.assertEqual(datumesh.__version__, "0.4.2")
        for name in ("check_batch", "BatchResult", "MemberResult"):
            self.assertIn(name, datumesh.__all__)
        self.assertIn("computed", datumesh.TRUST)


class RunnerTest(unittest.TestCase):
    def test_kinds(self) -> None:
        run = runner().run_vector
        v = vector("batch/item-failures")
        self.assertEqual(run(v), {"id": v["id"], "error": None, "results": v["results"]})
        v = vector("batch/refused")
        self.assertEqual(run(v), {"id": v["id"], "error": None, "outcome": "rate_limited"})
        v = vector("envelope/slice-page")
        self.assertEqual(run(v), {"id": v["id"], "error": None, "outcome": "ok", "results": v["results"]})
        self.assertEqual(run({"id": "x/y", "kind": "call", "valid": True}), {"id": "x/y", "error": None,
                                                                             "skipped": "call"})


if __name__ == "__main__":
    unittest.main()
