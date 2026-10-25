"""The changes of spec-0.4.1 for a verifier library, each tested through the API (the vectors are run by
test_conformance):

- 5.5: the ninth outcome ``pending`` (202) with exactly ``estimate_seconds``, ``job``, ``poll`` and ``request``;
  step 5 for it (the echoed request equals the request made, and the job polled); a job's result bound to the
  original request; ``E_JOB_UNKNOWN`` in ``bad_request`` at a job URL only, never in ``error``;
- 9.6: the mesh document and cross-mesh resolution (``resolve_mesh``), in its six-step order, with
  ``E_MESH_DOC``; unknown members dropped;
- 10.2: ``E_JOB_UNKNOWN`` and ``E_MESH_DOC`` after ``E_ENVELOPE``.
"""

from __future__ import annotations

import copy
import json
import unittest
from typing import Any, Dict, Optional, Tuple

from util import ROOT, env_keys, mesh_outputs, runner, vectors_of

import datumesh
from datumesh import check_envelope, resolve_mesh


def vector(vid: str) -> Dict[str, Any]:
    v: Dict[str, Any] = json.loads((ROOT / "spec" / "vectors" / f"{vid}.json").read_text(encoding="utf-8"))
    return v


PENDING = vector("envelope/pending")
JOB_OK = vector("envelope/job-result-ok")
CELL = PENDING["request"]["cell_id"]
ASOF = PENDING["request"]["asof"]
JOB = "4f9c2a7e1b3d5f60817a9c2e4b6d8f01"
OTHER_JOB = "0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a"


def pending(**changes: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = {"estimate_seconds": 5, "job": JOB, "outcome": "pending",
                            "poll": f"https://mesh.example/jobs/{JOB}", "request": {"cell_id": CELL, "asof": ASOF}}
    for k, x in changes.items():
        if x is None:
            body.pop(k, None)
        else:
            body[k] = x
    return body


def env_code(body: Any, request: Optional[Dict[str, str]] = None, status: int = 202) -> str:
    text = body if isinstance(body, str) else json.dumps(body)
    res = check_envelope(status, text, [], request if request is not None else {"cell_id": CELL, "asof": ASOF})
    return res.code


class PendingMembersTest(unittest.TestCase):
    def test_valid(self) -> None:
        res = check_envelope(202, json.dumps(pending()), [], {"cell_id": CELL, "asof": ASOF})
        self.assertEqual((res.ok, res.outcome, res.trust, res.receipt_hash), (True, "pending", None, None))
        self.assertEqual((res.job, res.estimate_seconds, res.poll), (JOB, 5, f"https://mesh.example/jobs/{JOB}"))
        # no asof requested, none echoed
        self.assertEqual(env_code(pending(request={"cell_id": CELL}), {"cell_id": CELL}), "OK")
        # 64 hex digits, estimate 0 and 2^53 - 1, poll of 512 characters
        j64 = "a" * 64
        self.assertEqual(env_code(pending(job=j64, poll=f"https://mesh.example/jobs/{j64}")), "OK")
        self.assertEqual(env_code(pending(estimate_seconds=0)), "OK")
        self.assertEqual(env_code(json.dumps(pending())[:-1] + "}"), "OK")
        self.assertEqual(env_code(json.dumps(pending(estimate_seconds=None))[:-1] + ', "estimate_seconds": 9007199254740991}'),
                         "OK")
        path = "https://mesh.example/" + "p" * (512 - len("https://mesh.example/") - len(f"/jobs/{JOB}")) + f"/jobs/{JOB}"
        self.assertEqual(len(path), 512)
        self.assertEqual(env_code(pending(poll=path)), "OK")
        # the other outcomes have no job members
        res = check_envelope(404, '{"outcome": "not_covered"}', [], {"cell_id": CELL})
        self.assertEqual((res.job, res.estimate_seconds, res.poll), (None, None, None))

    def test_status(self) -> None:
        for status in (200, 201, 203, 204, 400, 404, 500):
            with self.subTest(status):
                self.assertEqual(env_code(pending(), status=status), "E_ENVELOPE")
        # and no other outcome is 202
        self.assertEqual(env_code('{"outcome": "not_covered"}', status=202), "E_ENVELOPE")

    def test_members(self) -> None:
        bad = [
            dict(job=None), dict(estimate_seconds=None), dict(poll=None), dict(request=None),
            dict(job="a" * 31, poll="https://mesh.example/jobs/" + "a" * 31),
            dict(job="a" * 65, poll="https://mesh.example/jobs/" + "a" * 65),
            dict(job=JOB.upper(), poll="https://mesh.example/jobs/" + JOB.upper()),
            dict(job="g" * 32, poll="https://mesh.example/jobs/" + "g" * 32),
            dict(job=5), dict(estimate_seconds="5"), dict(estimate_seconds=-1), dict(estimate_seconds=True),
            dict(estimate_seconds=2 ** 53),
            dict(poll=f"http://mesh.example/jobs/{JOB}"), dict(poll=f"https://mesh.example/jobs/{OTHER_JOB}"),
            dict(poll=f"https://mesh.example/jobs/{JOB}/"), dict(poll=f"https://mesh.example/job{JOB}"),
            dict(poll=f"https://mesh example/jobs/{JOB}"), dict(poll=5),
            dict(poll="https://mesh.example/" + "p" * 512 + f"/jobs/{JOB}"),
            dict(request=[]), dict(request={"asof": ASOF}), dict(request={"cell_id": CELL, "asof": ASOF, "job": JOB}),
            dict(request={"cell_id": CELL.upper(), "asof": ASOF}), dict(request={"cell_id": CELL, "asof": "2024-03-16"}),
            dict(request={"cell_id": CELL, "asof": None}), dict(request={"cell_id": 5}),
            dict(trust="primary"), dict(receipt={}), dict(age_seconds=1), dict(error="E_JOB_UNKNOWN"),
        ]
        for changes in bad:
            with self.subTest(changes):
                self.assertEqual(env_code(pending(**changes)), "E_ENVELOPE")
        # integer text rule: 5.0, 5e0, -0
        for text in ("5.0", "5e0", "-0"):
            with self.subTest(text):
                body = json.dumps(pending(estimate_seconds=None))[:-1] + f', "estimate_seconds": {text}}}'
                self.assertEqual(env_code(body), "E_ENVELOPE")


class BindingTest(unittest.TestCase):
    def test_pending_binds_to_the_request(self) -> None:
        req, req_job = {"cell_id": CELL, "asof": ASOF}, {"cell_id": CELL, "asof": ASOF, "job": JOB}
        self.assertEqual(env_code(pending(), req), "OK")
        self.assertEqual(env_code(pending(), req_job), "OK")
        other = "5" * 64
        self.assertEqual(env_code(pending(request={"cell_id": other, "asof": ASOF}), req), "E_ENVELOPE")
        self.assertEqual(env_code(pending(request={"cell_id": CELL}), req), "E_ENVELOPE")  # asof dropped
        self.assertEqual(env_code(pending(), {"cell_id": CELL}), "E_ENVELOPE")  # asof added
        self.assertEqual(env_code(pending(request={"cell_id": CELL, "asof": "2024-03-16T09:00:00.000001Z"}), req),
                         "E_ENVELOPE")  # another asof, even a later one
        self.assertEqual(env_code(pending(request={"cell_id": CELL, "asof": "2024-03-16T08:59:59.999999Z"}), req),
                         "E_ENVELOPE")  # or an earlier one: the echo is equal, not at-or-before
        # polled: the job polled
        polled_other = pending(job=OTHER_JOB, poll=f"https://mesh.example/jobs/{OTHER_JOB}")
        self.assertEqual(env_code(polled_other, req), "OK")
        self.assertEqual(env_code(polled_other, req_job), "E_ENVELOPE")

    def test_job_result_binds_to_the_original_request(self) -> None:
        keys = env_keys(JOB_OK["keys"])
        res = check_envelope(200, JOB_OK["input"], keys, JOB_OK["request"])
        self.assertEqual((res.ok, res.outcome, res.trust), (True, "ok", "primary"))
        self.assertEqual(res, check_envelope(200, JOB_OK["input"], keys,
                                             {k: x for k, x in JOB_OK["request"].items() if k != "job"}))
        # the original request's asof before the receipt's: E_ENVELOPE, whatever the job
        r = json.loads(json.loads(JOB_OK["input"])["receipt"]) if isinstance(json.loads(JOB_OK["input"])["receipt"], str) \
            else json.loads(JOB_OK["input"])["receipt"]
        early = dict(JOB_OK["request"], asof="2024-03-15T15:59:59.999999Z")
        self.assertLess(early["asof"], r["asof"])
        self.assertEqual(check_envelope(200, JOB_OK["input"], keys, early).code, "E_ENVELOPE")
        self.assertEqual(check_envelope(200, JOB_OK["input"], keys, dict(JOB_OK["request"], cell_id="5" * 64)).code,
                         "E_ENVELOPE")

    def test_job_unknown(self) -> None:
        body = '{"outcome": "bad_request", "error": "E_JOB_UNKNOWN"}'
        res = check_envelope(400, body, [], {"cell_id": CELL, "job": JOB})
        self.assertEqual((res.ok, res.outcome), (True, "bad_request"))
        self.assertEqual(env_code(body, {"cell_id": CELL}, 400), "E_ENVELOPE")
        self.assertEqual(env_code(body, {"cell_id": CELL, "asof": ASOF}, 400), "E_ENVELOPE")
        # error never carries it, job or not
        body = '{"outcome": "error", "error": "E_JOB_UNKNOWN"}'
        self.assertEqual(env_code(body, {"cell_id": CELL, "job": JOB}, 500), "E_ENVELOPE")
        self.assertEqual(env_code(body, {"cell_id": CELL}, 500), "E_ENVELOPE")
        # error may carry E_MESH_DOC (any code of 10.2 but E_ENVELOPE and E_JOB_UNKNOWN); bad_request may not
        self.assertEqual(env_code('{"outcome": "error", "error": "E_MESH_DOC"}', {"cell_id": CELL}, 502), "OK")
        self.assertEqual(env_code('{"outcome": "bad_request", "error": "E_MESH_DOC"}', {"cell_id": CELL, "job": JOB},
                                  400), "E_ENVELOPE")
        # a parse code at a job URL is still accepted
        self.assertEqual(env_code('{"outcome": "bad_request", "error": "E_PARSE_URI"}', {"cell_id": CELL, "job": JOB},
                                  400), "OK")

    def test_request_description(self) -> None:
        for bad in ({"cell_id": CELL, "job": "a" * 31}, {"cell_id": CELL, "job": JOB.upper()},
                    {"cell_id": CELL, "job": 5}, {"cell_id": CELL, "job": None}, {"cell_id": CELL, "jobs": JOB}):
            with self.subTest(bad), self.assertRaises((ValueError, TypeError)):
                check_envelope(202, json.dumps(pending()), [], bad)


# ---------------------------------------------------------------- the mesh document


FULL = vector("mesh/full")
KEY_ENV = FULL["env"]["keys"]
MESH_DOC = json.loads(FULL["env"]["mesh"]["https"]["body"])
KEY_DOC = json.loads(KEY_ENV["https"]["body"])
HOST = "mesh.example.org"


def ok(doc: Any) -> Tuple[int, str]:
    return 200, doc if isinstance(doc, str) else json.dumps(doc)


def resp(env: Any) -> Tuple[Optional[int], Optional[str]]:
    if env is None:
        return None, None
    https = env.get("https") or {}
    status = https.get("status", "error")
    return (None if status == "error" else status), https.get("body")


def mesh_code(keys: Any, mesh: Any, host: str = HOST) -> str:
    return resolve_mesh(host, keys, mesh).code


def endpoints(**changes: Any) -> Tuple[int, str]:
    doc = copy.deepcopy(MESH_DOC)
    for k, x in changes.items():
        if x is None:
            doc["endpoints"].pop(k, None)
        else:
            doc["endpoints"][k] = x
    return ok(doc)


KEYS_OK = resp(KEY_ENV)


class MeshVectorsTest(unittest.TestCase):
    def test_vectors(self) -> None:
        n = 0
        for v in vectors_of("mesh"):
            with self.subTest(v["id"]):
                env = v["env"]
                res = resolve_mesh(v["host"], resp(env.get("keys")), resp(env.get("mesh")))
                if v["valid"]:
                    self.assertEqual((res.ok, res.code, res.host), (True, "OK", v["host"]))
                    out = mesh_outputs(v)
                    self.assertEqual((res.bindings, res.endpoints), (out["bindings"], out["endpoints"]))
                    self.assertIsNotNone(res.keys)
                    assert res.keys is not None
                    self.assertEqual(res.keys.key_ids, ("f7ec60a92abf4774",))
                else:
                    self.assertEqual((res.ok, res.code, res.bindings, res.endpoints, res.keys),
                                     (False, v["error"], None, {}, None))
                n += 1
        self.assertEqual(n, 20)

    def test_unknown_members_dropped(self) -> None:
        res = resolve_mesh(HOST, KEYS_OK, ok(dict(MESH_DOC, x_status=5, endpoints=dict(MESH_DOC["endpoints"], x=[1]))))
        self.assertTrue(res.ok)
        self.assertNotIn("x", res.endpoints)
        self.assertEqual(set(res.endpoints), set(MESH_DOC["endpoints"]))
        res = resolve_mesh(HOST, KEYS_OK, endpoints(blob=None, cells=None, explain=None, find=None, slice=None,
                                                     verify=None))
        self.assertEqual(sorted(res.endpoints), ["cell", "descriptor", "jobs", "manifest", "receipt"])


class MeshOrderTest(unittest.TestCase):
    """SPEC 9.6's six steps, first failure reported. Expected codes agree with the reference tool, run as a black
    box on these inputs."""

    def test_retrieval(self) -> None:
        self.assertEqual(mesh_code((404, None), (404, None)), "E_KEY_UNAVAILABLE")
        self.assertEqual(mesh_code((None, None), ok(MESH_DOC)), "E_KEY_UNAVAILABLE")
        self.assertEqual(mesh_code((301, None), ok(MESH_DOC)), "E_KEY_UNAVAILABLE")
        self.assertEqual(mesh_code(("200", KEYS_OK[1]), ok(MESH_DOC)), "E_KEY_UNAVAILABLE")
        # a 200 without a key document is E_KEY_DOC at retrieval, as in 9.3, before the mesh document
        self.assertEqual(mesh_code((200, None), (404, None)), "E_KEY_DOC")
        self.assertEqual(mesh_code(KEYS_OK, (404, None)), "E_MESH_DOC")
        self.assertEqual(mesh_code(KEYS_OK, (None, None)), "E_MESH_DOC")
        self.assertEqual(mesh_code(KEYS_OK, ("200", json.dumps(MESH_DOC))), "E_MESH_DOC")
        self.assertEqual(mesh_code(KEYS_OK, (200, None)), "E_MESH_DOC")
        # the key document's parse failure is step 3, after the mesh document's retrieval
        self.assertEqual(mesh_code(ok("{x"), (404, None)), "E_MESH_DOC")
        # retrieval does not look at the host: a host that is not a DNS name fails later
        self.assertEqual(mesh_code(KEYS_OK, (404, None), host="localhost"), "E_MESH_DOC")

    def test_parse(self) -> None:
        self.assertEqual(mesh_code(ok("{x"), ok("{y")), "E_KEY_DOC")
        self.assertEqual(mesh_code(ok('{"host":"a.example","host":"a.example"}'), ok(MESH_DOC)), "E_KEY_DOC")
        self.assertEqual(mesh_code(KEYS_OK, ok("")), "E_MESH_DOC")
        self.assertEqual(mesh_code(KEYS_OK, ok("[]")), "E_MESH_DOC")
        self.assertEqual(mesh_code(ok([]), ok("{")), "E_MESH_DOC")

    def test_identity(self) -> None:
        self.assertEqual(mesh_code(KEYS_OK, ok(dict(MESH_DOC, host="other.example.org"))), "E_MESH_DOC")
        self.assertEqual(mesh_code(KEYS_OK, ok({k: x for k, x in MESH_DOC.items() if k != "host"})), "E_MESH_DOC")
        self.assertEqual(mesh_code(KEYS_OK, ok(dict(MESH_DOC, host=5))), "E_MESH_DOC")
        self.assertEqual(mesh_code(ok(dict(KEY_DOC, host="other.example.org")), ok(MESH_DOC)), "E_MESH_DOC")
        self.assertEqual(mesh_code(ok(dict(KEY_DOC, proto="datumesh/2")), ok(MESH_DOC)), "E_MESH_DOC")
        self.assertEqual(mesh_code(ok(dict(KEY_DOC, proto=1)), ok(MESH_DOC)), "E_MESH_DOC")
        self.assertEqual(mesh_code(ok({k: x for k, x in KEY_DOC.items() if k != "proto"}), ok(MESH_DOC)), "E_MESH_DOC")
        self.assertEqual(mesh_code(KEYS_OK, ok({k: x for k, x in MESH_DOC.items() if k != "proto"})), "E_MESH_DOC")
        self.assertEqual(mesh_code(ok(dict(KEY_DOC, proto="datumesh/2")), ok(dict(MESH_DOC, proto="datumesh/2"))),
                         "E_MESH_DOC")
        # identity before the key document's own rules, and before the mesh document's members
        self.assertEqual(mesh_code(ok(dict(KEY_DOC, keys=[], proto="datumesh/2")), ok(MESH_DOC)), "E_MESH_DOC")
        # a key document whose host is not a string, or that is not an object, is left to step 5 (DEF-49)
        self.assertEqual(mesh_code(ok({k: x for k, x in KEY_DOC.items() if k != "host"}), ok(MESH_DOC)), "E_KEY_DOC")
        self.assertEqual(mesh_code(ok(dict(KEY_DOC, host=5)), ok(MESH_DOC)), "E_KEY_DOC")
        self.assertEqual(mesh_code(ok([]), ok(MESH_DOC)), "E_KEY_DOC")
        self.assertEqual(mesh_code(ok([]), ok(dict(MESH_DOC, host="other.example.org"))), "E_MESH_DOC")

    def test_key_document_rules(self) -> None:
        self.assertEqual(mesh_code(ok(dict(KEY_DOC, keys=[])), ok(dict(MESH_DOC, bindings="http://x"))), "E_KEY_DOC")
        # a host that is not a DNS name, named consistently everywhere: the key document's rule (9.2)
        up = "MESH.example.org"
        self.assertEqual(mesh_code(ok(dict(KEY_DOC, host=up)), ok(dict(MESH_DOC, host=up)), host=up), "E_KEY_DOC")

    def test_mesh_members(self) -> None:
        cases = [
            (ok({k: x for k, x in MESH_DOC.items() if k != "bindings"}), "E_MESH_DOC"),
            (ok(dict(MESH_DOC, bindings=5)), "E_MESH_DOC"),
            (ok(dict(MESH_DOC, bindings="https://mesh.example.org/bindings/{x}")), "OK"),  # no placeholder rule
            (ok(dict(MESH_DOC, bindings="https://mesh.example.org?x=1")), "E_MESH_DOC"),  # a path
            (ok(dict(MESH_DOC, bindings="https://other.example.org/bindings")), "E_MESH_DOC"),
            (ok(dict(MESH_DOC, endpoints=[])), "E_MESH_DOC"),
            (ok({k: x for k, x in MESH_DOC.items() if k != "endpoints"}), "E_MESH_DOC"),
            (endpoints(jobs=None), "E_MESH_DOC"),
            (endpoints(cell=None), "E_MESH_DOC"),
            (endpoints(blob=None), "OK"),
            (endpoints(cell=5), "E_MESH_DOC"),
            (endpoints(x_y=5), "OK"),
            (endpoints(cells="https://mesh.example.org"), "E_MESH_DOC"),
            (endpoints(cells="https://mesh.example.org#x"), "E_MESH_DOC"),
            (endpoints(cells="https://mesh.example.org:443/cells"), "E_MESH_DOC"),
            (endpoints(cells="https://u@mesh.example.org/cells"), "E_MESH_DOC"),
            (endpoints(cells="https://mesh.example.org.evil.com/cells"), "E_MESH_DOC"),
            (endpoints(cells="https://mesh.example.org\\@evil/x"), "E_MESH_DOC"),
            (endpoints(cells="http://mesh.example.org/cells"), "E_MESH_DOC"),
            (endpoints(cells="https://mesh.example.org/" + "a" * 600), "E_MESH_DOC"),
            (endpoints(cells="https://mesh.example.org/" + "a" * (512 - 25)), "OK"),
            (endpoints(cells="https://mesh.example.org/c ells"), "E_MESH_DOC"),
            (endpoints(cells="https://mesh.example.org/cells}"), "OK"),
            (endpoints(cells="https://mesh.example.org/cells?x={"), "E_MESH_DOC"),
            (endpoints(cells="https://mesh.example.org/cells/{cell}"), "E_MESH_DOC"),
            (endpoints(cell="https://mesh.example.org/cell/{cell}{cell}"), "E_MESH_DOC"),
            (endpoints(cell="https://mesh.example.org/cell/{cell}?v={version}"), "E_MESH_DOC"),
            (endpoints(cell="https://mesh.example.org/cell/{Cell}"), "E_MESH_DOC"),
            (endpoints(cell="https://mesh.example.org/cell"), "E_MESH_DOC"),
            (endpoints(manifest="https://mesh.example.org/m/{members_hash}/{slice_id}"), "OK"),
            (endpoints(manifest="https://mesh.example.org/m/{slice_id}"), "E_MESH_DOC"),
            (endpoints(receipt="https://mesh.example.org/r/{sha256}"), "E_MESH_DOC"),
        ]
        self.assertEqual(len("https://mesh.example.org/" + "a" * (512 - 25)), 512)
        for mesh, want in cases:
            with self.subTest(mesh[1][:300]):
                self.assertEqual(mesh_code(KEYS_OK, mesh), want)

    def test_never_raises(self) -> None:
        for args in ((HOST, None, None), (HOST, (200, b"\xff"), ok(MESH_DOC)), (5, KEYS_OK, ok(MESH_DOC)),
                     (HOST, KEYS_OK, (200, 5)), (HOST, (True, KEYS_OK[1]), ok(MESH_DOC))):
            with self.subTest(args):
                res = resolve_mesh(*args)
                self.assertFalse(res.ok)
        self.assertEqual(resolve_mesh(HOST, KEYS_OK, (200, json.dumps(MESH_DOC).encode())).code, "OK")


class CodesAndVersionTest(unittest.TestCase):
    def test_codes(self) -> None:
        codes = datumesh.ERROR_CODES
        i = codes.index("E_ENVELOPE")
        self.assertEqual(codes[i + 1:], ("E_JOB_UNKNOWN", "E_MESH_DOC"))
        for c in ("E_JOB_UNKNOWN", "E_MESH_DOC"):
            self.assertEqual(datumesh.DatumeshError(c).code, c)
            self.assertNotIn(c, datumesh.SUCCESS_CODES)

    def test_version_and_names(self) -> None:
        self.assertEqual(datumesh.SPEC_VERSION, "spec-0.4.1")
        self.assertEqual(datumesh.__version__, "0.4.1")
        for name in ("resolve_mesh", "MeshResult", "MESH_ENDPOINTS"):
            self.assertIn(name, datumesh.__all__)
        self.assertEqual({k for k, (_, req) in datumesh.MESH_ENDPOINTS.items() if req},
                         {"cell", "descriptor", "jobs", "manifest", "receipt"})


class RunnerTest(unittest.TestCase):
    def test_mesh_kind(self) -> None:
        run = runner().run_vector
        out = run(FULL)
        self.assertEqual(out, dict({"id": FULL["id"], "error": None}, **mesh_outputs(FULL)))
        self.assertEqual(run(vector("invalid/mesh-unavailable")), {"id": "invalid/mesh-unavailable", "error": "E_MESH_DOC"})
        # absent env members behave as a failed retrieval
        self.assertEqual(run({"id": "x/y", "kind": "mesh", "valid": False, "host": HOST, "env": {"keys": KEY_ENV}}),
                         {"id": "x/y", "error": "E_MESH_DOC"})
        self.assertEqual(run({"id": "x/y", "kind": "mesh", "valid": False, "host": HOST, "env": {}}),
                         {"id": "x/y", "error": "E_KEY_UNAVAILABLE"})

    def test_envelope_job_passed(self) -> None:
        run = runner().run_vector
        v = vector("envelope/pending-polled")
        self.assertEqual(run(v), {"id": v["id"], "error": None, "outcome": "pending"})
        v = vector("invalid/envelope-pending-polled-other-job")
        self.assertEqual(run(v), {"id": v["id"], "error": "E_ENVELOPE"})


if __name__ == "__main__":
    unittest.main()
