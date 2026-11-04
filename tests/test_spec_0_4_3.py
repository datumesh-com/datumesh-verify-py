"""The changes of spec-0.4.3 for a verifier library, each tested through the API (the vectors are run by
test_conformance):

- 9.2, 4.5: the optional ``declarations`` member of the key document, checked whole (``E_KEY_DOC``) and exposed;
  a document with them verifies every receipt as one without them;
- 5.5, 10.2: ``E_FOREIGN_UNAVAILABLE``, outcome ``error`` with HTTP 502 and the closed ``detail``;
- 8.5: licence inheritance as a pure function;
- 10.3: the entitlement check, and the input-licence helper;
- 2.5: unrooted namespaces.
"""

from __future__ import annotations

import copy
import json
import unittest
from typing import Any, Dict, List

from util import ROOT, env_keys

import datumesh
from datumesh import (Declaration, DatumeshError, check_batch, check_entitlement, check_envelope, inherit_licence,
                      input_licences, is_unrooted, keys_from_response, verify)


def vector(vid: str) -> Dict[str, Any]:
    v: Dict[str, Any] = json.loads((ROOT / "spec" / "vectors" / f"{vid}.json").read_text(encoding="utf-8"))
    return v


HOST = "rates.example.org"
DOC: Dict[str, Any] = json.loads(vector("keys/declarations")["env"]["https"]["body"])
PLAIN: Dict[str, Any] = {k: v for k, v in DOC.items() if k != "declarations"}
URL = "https://rates.example.org/licences/restricted"
T0, T1, T2 = "2020-01-01T00:00:00.000000Z", "2024-03-16T09:00:00.000000Z", "2025-01-01T00:00:00.000000Z"
FN = "calc.example.net/convert"


def doc_with(declarations: Any) -> str:
    d = copy.deepcopy(PLAIN)
    d["declarations"] = declarations
    return json.dumps(d)


def doc_code(declarations: Any, host: str = HOST) -> str:
    return keys_from_response(host, 200, doc_with(declarations)).code


class DeclarationsTest(unittest.TestCase):
    def test_exposed(self) -> None:
        r = keys_from_response(HOST, 200, json.dumps(DOC))
        self.assertEqual(r.code, "OK")
        self.assertIsNotNone(r.declarations)
        assert r.declarations is not None
        self.assertEqual(sorted(r.declarations), ["rates.example.org/cross_rate", "rates.example.org/stats/mean_rate"])
        self.assertEqual(r.declarations["rates.example.org/cross_rate"],
                         (Declaration(URL, T0, "2024-06-01T00:00:00.000000Z"), Declaration(URL, T2)))
        self.assertEqual(r.declarations_json(), DOC["declarations"])
        self.assertTrue(Declaration(URL, T0, T2).open_at(T1))
        self.assertTrue(Declaration(URL, T1).open_at(T1))
        self.assertFalse(Declaration(URL, T0, T1).open_at(T1))
        self.assertFalse(Declaration(URL, T2).open_at(T1))
        hash(r)  # still hashable

    def test_absent(self) -> None:
        r = keys_from_response(HOST, 200, json.dumps(PLAIN))
        self.assertEqual((r.code, r.declarations, r.declarations_json()), ("OK", None, None))

    def test_same_keys_either_way(self) -> None:
        a = keys_from_response(HOST, 200, json.dumps(DOC))
        b = keys_from_response(HOST, 200, json.dumps(PLAIN))
        self.assertEqual(a.keys, b.keys)

    def test_rejected_whole(self) -> None:
        entry = {"licence": URL, "valid_from": T0}
        cases = {
            "not an object": [],
            "empty object": {},
            "empty array": {"rates.example.org/f": []},
            "not an array": {"rates.example.org/f": entry},
            "other host": {"calc.example.net/f": [entry]},
            "subdomain": {"eu.rates.example.org/f": [entry]},
            "parent": {"example.org/f": [entry]},
            "bare host": {"rates.example.org": [entry]},
            "bad function": {"rates.example.org/Fx": [entry]},
            "bad path": {"rates.example.org/a-b/f": [entry]},
            "trailing slash": {"rates.example.org/f/": [entry]},
            "bad licence": {"rates.example.org/f": [{"licence": "CC BY", "valid_from": T0}]},
            "long licence": {"rates.example.org/f": [{"licence": "A" * 65, "valid_from": T0}]},
            "number licence": {"rates.example.org/f": [{"licence": 1, "valid_from": T0}]},
            "bad instant": {"rates.example.org/f": [{"licence": URL, "valid_from": "2020-01-01T00:00:00Z"}]},
            "valid_to equal": {"rates.example.org/f": [{"licence": URL, "valid_from": T0, "valid_to": T0}]},
            "valid_to before": {"rates.example.org/f": [{"licence": URL, "valid_from": T1, "valid_to": T0}]},
            "missing licence": {"rates.example.org/f": [{"valid_from": T0}]},
            "missing valid_from": {"rates.example.org/f": [{"licence": URL}]},
            "extra member": {"rates.example.org/f": [dict(entry, note="x")]},
            "null valid_to": {"rates.example.org/f": [dict(entry, valid_to=None)]},
            "entry not an object": {"rates.example.org/f": [URL]},
            "17 entries": {"rates.example.org/f": [entry] * 17},
            "65 names": {f"rates.example.org/f{i}": [entry] for i in range(65)},
        }
        for name, decl in cases.items():
            with self.subTest(name):
                self.assertEqual(doc_code(decl), "E_KEY_DOC")
        # at the limits
        self.assertEqual(doc_code({"rates.example.org/f": [entry] * 16}), "OK")
        self.assertEqual(doc_code({f"rates.example.org/f{i}": [entry] for i in range(64)}), "OK")
        self.assertEqual(doc_code({"rates.example.org/a/b/f": [entry, entry]}), "OK")

    def test_through_verify_and_key_document_dicts(self) -> None:
        v = vector("receipt/stored-number")
        self.assertTrue(verify(v["input"], DOC).ok)
        self.assertTrue(verify(v["input"], PLAIN).ok)
        bad = copy.deepcopy(PLAIN)
        bad["declarations"] = {}
        self.assertEqual(verify(v["input"], bad).code, "E_KEY_DOC")
        self.assertEqual(verify(v["input"], keys_from_response(HOST, 200, doc_with({}))).code, "E_KEY_DOC")

    def test_mesh_resolution(self) -> None:
        mesh = vector("mesh/keydoc-declarations")
        res = datumesh.resolve_mesh(mesh["host"], (200, mesh["env"]["keys"]["https"]["body"]),
                                    (200, mesh["env"]["mesh"]["https"]["body"]))
        self.assertEqual(res.code, "OK")


ENV_KEYS = vector("envelope/error-foreign-unavailable")["keys"]
REQ = {"cell_id": "f566f2838815a8649fe467b7a41876c5d2b4deca9afb974b8c50caafd4633ca5"}


class ForeignUnavailableTest(unittest.TestCase):
    def check(self, body: Dict[str, Any], status: int = 502) -> datumesh.EnvelopeResult:
        return check_envelope(status, json.dumps(body), env_keys(ENV_KEYS), REQ)

    def test_code(self) -> None:
        self.assertEqual(datumesh.ERROR_CODES[-1], "E_FOREIGN_UNAVAILABLE")
        self.assertEqual(datumesh.FOREIGN_DETAILS, ("offline", "network", "dns", "tls", "timeout", "refused"))
        self.assertNotIn("E_FOREIGN_UNAVAILABLE", datumesh.SUCCESS_CODES)

    def test_valid(self) -> None:
        for d in datumesh.FOREIGN_DETAILS:
            with self.subTest(d):
                r = self.check({"outcome": "error", "error": "E_FOREIGN_UNAVAILABLE", "detail": d})
                self.assertEqual((r.ok, r.outcome, r.error, r.error_detail), (True, "error", "E_FOREIGN_UNAVAILABLE", d))
        r = self.check({"outcome": "error", "error": "E_FOREIGN_UNAVAILABLE", "detail": "dns", "fn_hash": "0" * 64})
        self.assertTrue(r.ok, r.detail)
        r = self.check({"outcome": "error", "error": "E_EVAL_UNAVAILABLE"}, 500)
        self.assertEqual((r.ok, r.error_detail), (True, None))

    def test_invalid(self) -> None:
        cases = [
            ({"outcome": "error", "error": "E_FOREIGN_UNAVAILABLE"}, 502),
            ({"outcome": "error", "error": "E_FOREIGN_UNAVAILABLE", "detail": "Offline"}, 502),
            ({"outcome": "error", "error": "E_FOREIGN_UNAVAILABLE", "detail": "other"}, 502),
            ({"outcome": "error", "error": "E_FOREIGN_UNAVAILABLE", "detail": None}, 502),
            ({"outcome": "error", "error": "E_FOREIGN_UNAVAILABLE", "detail": "offline"}, 500),
            ({"outcome": "error", "error": "E_FOREIGN_UNAVAILABLE", "detail": "offline"}, 503),
            ({"outcome": "error", "error": "E_EVAL_UNAVAILABLE", "detail": "offline"}, 502),
            ({"outcome": "error", "error": "E_INPUT_UNAVAILABLE", "detail": "timeout"}, 500),
            ({"outcome": "not_covered", "error": "E_FOREIGN_UNAVAILABLE"}, 404),
            ({"outcome": "not_covered", "detail": "offline"}, 404),
            ({"outcome": "bad_request", "error": "E_FOREIGN_UNAVAILABLE", "detail": "offline"}, 400),
            ({"outcome": "unlicensed", "detail": "offline"}, 403),
        ]
        for body, status in cases:
            with self.subTest(body=body, status=status):
                r = self.check(body, status)
                self.assertEqual(r.code, "E_ENVELOPE", r.detail)

    def test_other_codes_keep_any_5xx(self) -> None:
        for status in (500, 502, 503, 599):
            self.assertTrue(self.check({"outcome": "error", "error": "E_INPUT_UNAVAILABLE"}, status).ok)

    def test_batch_refusal(self) -> None:
        body = json.dumps({"outcome": "error", "error": "E_FOREIGN_UNAVAILABLE", "detail": "refused"})
        self.assertEqual(check_batch(502, body, [], [REQ]).outcome, "error")
        self.assertEqual(check_batch(500, body, [], [REQ]).code, "E_ENVELOPE")

    def test_never_a_verification_result(self) -> None:
        for v in (vector("receipt/stored-number"),):
            self.assertNotEqual(verify(v["input"], env_keys(v["keys"])).code, "E_FOREIGN_UNAVAILABLE")


def inherit(licences: List[str], declarations: Any = None, issued: str = T1,
            mesh: str = "CC-BY-4.0") -> tuple:
    r = inherit_licence(licences, declarations, FN, issued, mesh)
    return r.licence, r.reason


class InheritanceTest(unittest.TestCase):
    def test_no_inputs(self) -> None:
        self.assertEqual(inherit([]), ("CC-BY-4.0", "no_inputs"))
        self.assertEqual(inherit([], mesh=URL), (URL, "no_inputs"))

    def test_open(self) -> None:
        self.assertEqual(inherit(["CC0-1.0"]), ("CC0-1.0", "open"))
        self.assertEqual(inherit(["PDDL-1.0", "CC0-1.0"]), ("PDDL-1.0", "open"))
        self.assertEqual(inherit(["CC-BY-4.0", "MIT"]), ("CC-BY-4.0", "open"))
        self.assertEqual(inherit(["OGL-UK-3.0", "MIT", "Apache-2.0", "CC-BY-4.0", "CC0-1.0"]), ("OGL-UK-3.0", "open"))
        self.assertEqual(inherit(["Apache-2.0", "MIT"]), ("Apache-2.0", "open"))
        self.assertEqual(inherit(["ODbL-1.0", "MIT", "PDDL-1.0", "ODbL-1.0"]), ("ODbL-1.0", "open"))
        self.assertEqual(inherit(["CC-BY-SA-4.0", "OGL-UK-3.0"]), ("CC-BY-SA-4.0", "open"))

    def test_share_alike_conflict_first(self) -> None:
        self.assertEqual(inherit(["CC-BY-SA-4.0", "ODbL-1.0"]), (None, "share_alike_conflict"))
        decl = {FN: [{"licence": URL, "valid_from": T0}]}
        self.assertEqual(inherit(["CC-BY-SA-4.0", URL], decl), (None, "share_alike_conflict"))
        self.assertEqual(inherit(["ODbL-1.0", URL, "CC-BY-NC-4.0"]), (None, "share_alike_conflict"))

    def test_restricted(self) -> None:
        open_decl = {FN: [{"licence": URL, "valid_from": T0}]}
        self.assertEqual(inherit([URL]), (None, "not_declared"))
        self.assertEqual(inherit([URL], {}), (None, "not_declared"))
        self.assertEqual(inherit([URL, "MIT", URL], open_decl), (URL, "declared"))
        self.assertEqual(inherit([URL, "CC-BY-NC-4.0"], open_decl), (None, "restricted_conflict"))
        self.assertEqual(inherit(["cc0-1.0"]), (None, "not_declared"))  # compared byte for byte
        # another function's declaration, or another licence's
        self.assertEqual(inherit([URL], {"calc.example.net/other": [{"licence": URL, "valid_from": T0}]}),
                         (None, "not_declared"))
        self.assertEqual(inherit([URL], {FN: [{"licence": "CC-BY-NC-4.0", "valid_from": T0}]}),
                         (None, "not_declared"))
        # closed before issued, closing at issued, opening at issued, opening after
        self.assertEqual(inherit([URL], {FN: [{"licence": URL, "valid_from": T0, "valid_to": T1}]}),
                         (None, "declaration_not_open"))
        self.assertEqual(inherit([URL], {FN: [{"licence": URL, "valid_from": T1}]}), (URL, "declared"))
        self.assertEqual(inherit([URL], {FN: [{"licence": URL, "valid_from": T2}]}), (None, "declaration_not_open"))
        reopened = {FN: [{"licence": URL, "valid_from": T0, "valid_to": "2021-01-01T00:00:00.000000Z"},
                         {"licence": URL, "valid_from": "2023-01-01T00:00:00.000000Z"}]}
        self.assertEqual(inherit([URL], reopened), (URL, "declared"))
        # Declaration objects and a KeysResult's declarations are accepted as well
        self.assertEqual(inherit([URL], {FN: (Declaration(URL, T0),)}), (URL, "declared"))

    def test_tiers(self) -> None:
        self.assertEqual([datumesh.licence_tier(x) for x in ("CC0-1.0", "PDDL-1.0", "MIT", "Apache-2.0", "CC-BY-4.0",
                                                             "OGL-UK-3.0", "CC-BY-SA-4.0", "ODbL-1.0", "CC-BY-NC-4.0",
                                                             URL, "mit")],
                         [1, 1, 2, 2, 2, 2, 3, 3, 4, 4, 4])

    def test_caller_errors(self) -> None:
        with self.assertRaises(TypeError):
            inherit_licence("MIT", None, FN, T1, "MIT")
        with self.assertRaises(DatumeshError):
            inherit_licence(["not a licence"], None, FN, T1, "MIT")
        with self.assertRaises(DatumeshError):
            inherit_licence(["MIT"], None, "convert", T1, "MIT")
        with self.assertRaises(DatumeshError):
            inherit_licence(["MIT"], None, FN, "2024-03-16", "MIT")
        with self.assertRaises((TypeError, ValueError)):
            inherit_licence([URL], {FN: [{"licence": URL}]}, FN, T1, "MIT")

    def test_every_licence_vector(self) -> None:
        for path in sorted((ROOT / "spec" / "vectors" / "licence").glob("*.json")):
            v = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(v["id"]):
                r = inherit_licence(v["licences"], v.get("declarations"), v["fn"], v["issued"], v["mesh_licence"])
                self.assertEqual((r.licence, r.reason), (v["licence"], v["reason"]))
                self.assertEqual(r.refused, v["licence"] is None)


class EntitlementTest(unittest.TestCase):
    def parts(self, vid: str) -> tuple:
        v = vector(vid)
        r = json.loads(v["input"])
        host = r["cell"]["ns"].split("/")[0]
        k = env_keys({host: v["keys"][host]})[0]
        return v, r, k

    def test_every_entitlement_vector(self) -> None:
        for path in sorted((ROOT / "spec" / "vectors" / "entitlement").glob("*.json")):
            vid = f"entitlement/{path.stem}"
            v, r, k = self.parts(vid)
            with self.subTest(vid):
                keys = env_keys(v["keys"])
                self.assertTrue(verify(v["input"], keys).ok)
                lic = input_licences(v["input"], v["receipts"], v.get("manifests"), keys)
                self.assertEqual(lic, input_licences(v["input"], v["receipts"], v.get("manifests")))
                res = check_entitlement(v["input"], lic, k)
                self.assertEqual((res.entitled, res.reason), (v["entitled"], v["reason"]))
                # the key document as a parsed dict works the same
                doc = json.loads(v["keys"][r["cell"]["ns"].split("/")[0]]["https"]["body"])
                self.assertEqual(check_entitlement(r, lic, doc).reason, v["reason"])

    def test_slice_members_count(self) -> None:
        v = vector("entitlement/slice-members")
        self.assertEqual(sorted(input_licences(v["input"], v["receipts"], v["manifests"])),
                         ["CC-BY-SA-4.0", "CC0-1.0"])

    def test_wrong_host_is_the_callers_error(self) -> None:
        v, r, _ = self.parts("entitlement/open-inherited")
        other = env_keys({"rates.example.org": vector("keys/declarations")["env"]})[0]
        if r["cell"]["ns"].split("/")[0] == "rates.example.org":  # pragma: no cover - the vector is calc.example.net
            self.skipTest("vector is under rates.example.org")
        with self.assertRaises(ValueError):
            check_entitlement(v["input"], ["MIT"], other)
        with self.assertRaises(ValueError):
            check_entitlement(v["input"], ["MIT"], keys_from_response("calc.example.net", 404, None))
        with self.assertRaises(TypeError):
            check_entitlement(v["input"], ["MIT"], {"f7ec60a92abf4774": "00" * 32})

    def test_mismatch_and_stored(self) -> None:
        v, r, k = self.parts("entitlement/open-inherited")
        self.assertEqual(check_entitlement(r, [r["licence"]], k).reason, "open")
        other = "MIT" if r["licence"] != "MIT" else "CC0-1.0"
        res = check_entitlement(r, [other, other], k)
        self.assertEqual((res.entitled, res.reason, res.licence), (False, "licence_mismatch", other))
        res = check_entitlement(r, [], k)
        self.assertEqual((res.entitled, res.reason), (True, "no_inputs"))

    def test_input_licence_helper_errors(self) -> None:
        v = vector("entitlement/slice-members")
        with self.assertRaises(DatumeshError) as cm:
            input_licences(v["input"], {}, v["manifests"])
        self.assertEqual(cm.exception.code, "E_INPUT_UNAVAILABLE")
        with self.assertRaises(DatumeshError) as cm:
            input_licences(v["input"], v["receipts"], {})
        self.assertEqual(cm.exception.code, "E_INPUT_UNAVAILABLE")
        swapped = dict(zip(v["receipts"], reversed(list(v["receipts"].values()))))
        with self.assertRaises(DatumeshError) as cm:
            input_licences(v["input"], swapped, v["manifests"])
        self.assertEqual(cm.exception.code, "E_INPUT_UNAVAILABLE")
        with self.assertRaises(DatumeshError) as cm:
            input_licences(v["input"], v["receipts"], v["manifests"], [])
        self.assertEqual(cm.exception.code, "E_INPUT_INVALID")


class UnrootedTest(unittest.TestCase):
    def test_is_unrooted(self) -> None:
        for name in ("local.invalid", "agent-7.local.invalid", "local.invalid/notes", "a.b.invalid/x/y"):
            self.assertTrue(is_unrooted(name), name)
        for name in ("rates.example.org", "invalid.example", "local.invalid.example", "rates.example.org/invalid"):
            self.assertFalse(is_unrooted(name), name)
        for bad in ("invalid", "Local.invalid", "local.invalid/", ""):
            with self.assertRaises(DatumeshError):
                is_unrooted(bad)
        with self.assertRaises(TypeError):
            is_unrooted(None)  # type: ignore[arg-type]

    def test_grammar_unchanged(self) -> None:
        self.assertEqual(datumesh.canonicalize(vector("cell/unrooted-namespace")["input"], "cell").decode(),
                         vector("cell/unrooted-namespace")["canonical"])
        v = vector("receipt/unrooted-key-supplied")
        self.assertTrue(verify(v["input"], env_keys(v["keys"])).ok)
        v = vector("invalid/receipt-unrooted-no-key-document")
        self.assertEqual(verify(v["input"], env_keys(v.get("keys") or {})).code, "E_KEY_UNAVAILABLE")


class VersionTest(unittest.TestCase):
    def test_versions(self) -> None:
        self.assertEqual(datumesh.SPEC_VERSION, "spec-0.4.3")
        self.assertEqual(datumesh.__version__, "0.4.3")


if __name__ == "__main__":
    unittest.main()
