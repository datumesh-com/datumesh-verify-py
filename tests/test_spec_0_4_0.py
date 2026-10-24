"""The changes of spec-0.4.0 for a verifier library, each tested through the API (the vectors are run by
test_conformance). SPEC 10.1, "What verifier libraries of spec-0.4.0 must do":

- step 3: an inputs entry is a receipt hash or a slice entry slice:<64 hex>:<64 hex> (E_CANON_HEX), ascending,
  one entry each for the 4,096 limit; nothing else changes at level signed;
- descriptors (7): optional signature.order and argument extent, with their canonical-form checks and order;
- step 7.5: slice entries, through manifests and members (E_SLICE_MEMBER, new), and the tx rule over input
  receipts and members together (no constraint when there is no input receipt);
- step 7.6: E_INPUT_SUPERSEDED, success at level signed at $.inputs, when a lineage replaces an input;
- envelopes (5.5): not_covered may carry fault, a formula evaluation fault;
- units.md: min, h, d, km, deg; limits (4.5): extent 4096, members 1048576.
"""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

from nacl.signing import SigningKey

from util import ROOT, env_keys, recompute_of, runner

import datumesh
from datumesh import DatumeshError, canonicalize, check_envelope, verify


def vector(vid: str) -> Dict[str, Any]:
    v: Dict[str, Any] = json.loads((ROOT / "spec" / "vectors" / f"{vid}.json").read_text(encoding="utf-8"))
    return v


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- a small world signed with one key

SEED = bytes(range(32))
KEY = SigningKey(SEED)
PUB = KEY.verify_key.encode().hex()
KID = datumesh.key_id(PUB)
KEYS = {KID: PUB}  # a bare mapping covers any host

NS = "weather.example.org"
STORED = {
    "code": {"body": "", "lang": "stored"},
    "inputs": [],
    "signature": {"args": {"date": {"type": "date", "valid": True}, "station": {"type": "string", "valid": False}},
                  "returns": {"type": "number", "unit": "degC"}},
}
STORED_HASH = datumesh.function_hash(STORED)
MEAN = {
    "code": {"body": "mean(weather.example.org/temp(date: date, station: *))\n", "lang": "formula"},
    "inputs": [f"{NS}/temp"],
    "signature": {"args": {"date": {"type": "date", "valid": True}}, "order": ["date"],
                  "returns": {"type": "number", "unit": "degC"}},
}
MEAN_HASH = datumesh.function_hash(MEAN)


def sign(r: Dict[str, Any]) -> Dict[str, Any]:
    r = dict(r)
    r.pop("sig", None)
    r["sig"] = KEY.sign(datumesh.jcs(r)).signature.hex()
    return r


def rhash(r: Dict[str, Any]) -> str:
    return datumesh.receipt_hash(r)


def stored(date: str, station: str, value: str, tx: str, asof: Optional[str] = None,
           fn_hash: str = STORED_HASH, fn: str = "temp") -> Dict[str, Any]:
    args = {"date": {"type": "date", "value": date}, "station": {"type": "string", "value": station}}
    return sign({
        "asof": asof or tx, "cell": {"args": args, "fn": fn, "fn_hash": fn_hash, "ns": NS},
        "computed_by": f"{NS}#{KID}", "inputs": [], "issued": asof or tx, "licence": "CC0-1.0",
        "proto": "datumesh/1", "publisher": NS, "summary": "A daily temperature.", "tx": tx, "type": "number",
        "valid": {"date": args["date"]}, "value": value})


def manifest(members: List[Dict[str, Any]], slice_obj: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if slice_obj is None:
        slice_obj = {"args": {"date": {"type": "date", "value": "2026-03-01"}, "station": "*"},
                     "fn": "temp", "fn_hash": STORED_HASH, "ns": NS}
    return {"members": sorted(rhash(m) for m in members), "slice": slice_obj}


def entry_of(m: Dict[str, Any]) -> str:
    return f"slice:{sha(datumesh.jcs(m['slice']))}:{sha(datumesh.jcs(m['members']))}"


def computed(inputs: List[str], value: str, tx: str, asof: str, date: str = "2026-03-01") -> Dict[str, Any]:
    ns = "calc.example.net"
    args = {"date": {"type": "date", "value": date}}
    return sign({
        "asof": asof, "cell": {"args": args, "fn": "mean_temp", "fn_hash": MEAN_HASH, "ns": ns},
        "computed_by": f"mesh.example.net#{KID}", "inputs": sorted(inputs), "issued": asof, "licence": "CC0-1.0",
        "proto": "datumesh/1", "publisher": ns, "summary": "A mean temperature.", "tx": tx, "type": "number",
        "valid": args, "value": value})


T1, T2, T3 = "2026-03-01T18:00:00.000000Z", "2026-03-01T19:00:00.000000Z", "2026-03-01T20:00:00.000000Z"


def world(members: Optional[List[Dict[str, Any]]] = None, m: Optional[Dict[str, Any]] = None,
          value: str = "11", tx: Optional[str] = None, asof: str = T3,
          extra: Tuple[Dict[str, Any], ...] = ()) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """A computed receipt over one slice entry, and the recompute object for it."""
    if members is None:
        members = [stored("2026-03-01", "kew", "10", T1), stored("2026-03-01", "soho", "12", T2)]
    if m is None:
        m = manifest(members)
    e = entry_of(m)
    txs = [x["tx"] for x in members if rhash(x) in m["members"]]
    r = computed([e], value, tx or (max(txs) if txs else "0001-01-01T00:00:00.000000Z"), asof)
    rc = {"descriptor": MEAN, "inputs": {rhash(x): json.dumps(x) for x in list(members) + list(extra)},
          "manifests": {e: json.dumps(m)}, "value": {"type": "number", "value": value}}
    return r, rc


def code(r: Any, rc: Any = None, keys: Any = None) -> Tuple[bool, str, Optional[str], Optional[str]]:
    res = verify(json.dumps(r) if isinstance(r, dict) else r, KEYS if keys is None else keys, rc)
    return res.ok, res.code, res.level, res.path


# ---------------------------------------------------------------- step 3


def signed_only() -> Dict[str, Any]:
    """The receipt of receipt/slice-signed-only, to be signed again with this module's key."""
    r: Dict[str, Any] = json.loads(vector("receipt/slice-signed-only")["input"])
    r["computed_by"] = f"mesh.example.net#{KID}"
    return r


class InputEntryFormTest(unittest.TestCase):
    """Step 3: an entry is 64 lowercase hex digits or slice:<64>:<64> (135 characters), else E_CANON_HEX."""

    def test_slice_entry_accepted_at_level_signed(self) -> None:
        r, _ = world()
        self.assertEqual(code(r), (True, "OK", "signed", None))
        v = vector("receipt/slice-signed-only")
        res = verify(v["input"], env_keys(v["keys"]))
        self.assertEqual((res.ok, res.level, res.code, res.hash), (True, "signed", "OK", v["sha256"]))
        self.assertEqual(len(json.loads(v["input"])["inputs"][0]), 135)

    def test_malformed_entries(self) -> None:
        h = "a" * 64
        good = f"slice:{h}:{'b' * 64}"
        for bad in (f"Slice:{h}:{h}", f"slice:{h}:{h[:-1]}", f"slice:{h[:-1]}:{h}0", f"slice:{h.upper()}:{h}",
                    f"slice:{h}:{h}:", f"slice:{h}{h}", f"slice:{h};{h}", f"slices:{h}:{h}", f"slice::{h}{h}",
                    f"{h}:{h}", "slice:", " " + good, good + "0", h[:-1], h.upper()):
            with self.subTest(bad):
                r = sign(dict(signed_only(), inputs=[bad]))
                ok, c, _, path = code(r)
                self.assertEqual((ok, c, path), (False, "E_CANON_HEX", "$.inputs[0]"))

    def test_order_and_uniqueness(self) -> None:
        h, s = "f" * 64, f"slice:{'0' * 64}:{'0' * 64}"
        base = signed_only()
        # receipt hashes sort before slice entries ("f" < "s"): string order, as for any entry
        self.assertEqual(code(sign(dict(base, inputs=[h, s]))), (True, "OK", "signed", None))
        self.assertEqual(code(sign(dict(base, inputs=[s, h])))[1], "E_CANON_SET")
        self.assertEqual(code(sign(dict(base, inputs=[s, s])))[1], "E_CANON_SET")
        s2 = f"slice:{'0' * 64}:{'1' * 64}"
        self.assertEqual(code(sign(dict(base, inputs=[s, s2])))[0], True)
        self.assertEqual(code(sign(dict(base, inputs=[s2, s])))[1], "E_CANON_SET")

    def test_one_entry_each_for_the_limit(self) -> None:
        base = signed_only()
        entries = sorted(f"slice:{i:064x}:{'0' * 64}" for i in range(4096))
        self.assertTrue(code(sign(dict(base, inputs=entries)))[0])
        more = sorted(entries + [f"slice:{4096:064x}:{'0' * 64}"])
        self.assertEqual(code(sign(dict(base, inputs=more)))[1], "E_CANON_LIMIT")

    def test_spec_0_3_0_receipts_unchanged(self) -> None:
        # A receipt with single-cell inputs is checked exactly as before: same hash, same result.
        v = vector("receipt/computed-with-lineage")
        res = verify(v["input"], env_keys(v["keys"]), recompute_of(v))
        self.assertEqual((res.ok, res.level, res.code, res.hash), (True, "recomputed", "OK", v["sha256"]))


# ---------------------------------------------------------------- descriptors


def fn(args: Dict[str, Any], order: Any = None, returns: Any = "string") -> Dict[str, Any]:
    sig: Dict[str, Any] = {"args": args, "returns": returns}
    if order is not None:
        sig["order"] = order
    return {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": sig}


def fcode(d: Any) -> Optional[str]:
    try:
        canonicalize(d, "function")
        return None
    except DatumeshError as e:
        return e.code


S = {"type": "string", "valid": False}
D = {"type": "date", "valid": True}
N = {"type": "number", "unit": "1", "valid": False}


class DescriptorOrderTest(unittest.TestCase):
    def test_accepted_and_hashed(self) -> None:
        a = fn({"a": S, "b": S}, ["b", "a"])
        b = fn({"a": S, "b": S}, ["a", "b"])
        c = fn({"a": S, "b": S})
        self.assertIsNone(fcode(a))
        self.assertEqual(len({datumesh.function_hash(x) for x in (a, b, c)}), 3)
        self.assertIsNone(fcode(fn({}, [])))

    def test_codes(self) -> None:
        self.assertEqual(fcode(fn({"a": S, "b": S}, ["a"])), "E_CANON_SET")  # misses an argument
        self.assertEqual(fcode(fn({"a": S, "b": S}, ["a", "b", "a"])), "E_CANON_SET")  # repeats one
        self.assertEqual(fcode(fn({"a": S, "b": S}, ["a", "c"])), "E_CANON_SET")  # names one not declared
        self.assertEqual(fcode(fn({"a": S}, ["A"])), "E_CANON_SET")
        self.assertEqual(fcode(fn({}, ["a"])), "E_CANON_SET")
        for bad in ("a", {"a": 1}, [1], ["a", None], True, 0):
            with self.subTest(bad):
                self.assertEqual(fcode(fn({"a": S}, bad)), "E_SCHEMA")

    def test_check_order(self) -> None:
        # Structure over the whole descriptor first: a bad order shape beats a canonical failure anywhere.
        d = fn({"a": {"type": "nope", "valid": False}}, "a")
        self.assertEqual(fcode(d), "E_SCHEMA")
        # Then: arguments, order, returns.
        self.assertEqual(fcode(fn({"a": {"type": "nope", "valid": False}}, ["b"])), "E_CANON_TYPE")
        self.assertEqual(fcode(fn({"a": S}, ["b"], returns="nope")), "E_CANON_SET")
        self.assertEqual(fcode(fn({"a": S}, ["a"], returns="nope")), "E_CANON_TYPE")
        self.assertEqual(fcode(dict(fn({"a": S}, ["b"]), inputs=["B"])), "E_CANON_NAME")


class DescriptorExtentTest(unittest.TestCase):
    def test_accepted(self) -> None:
        for decl in (dict(S, extent=["EUR", "USD"]), dict(S, extent=[]), dict(D, extent=["2026-01-01", "2026-01-02"]),
                     dict(N, extent=["-1", "0.5", "2", "10"]), dict(D, extent={"hi": "2026-01-01", "lo": "2026-01-01"}),
                     dict(N, extent={"hi": "10", "lo": "-3"}),
                     {"type": "instant", "valid": True,
                      "extent": ["2026-01-01T00:00:00.000000Z", "2026-01-01T00:00:00.000001Z"]}):
            with self.subTest(decl):
                self.assertIsNone(fcode(fn({"a": decl}, ["a"])))
                self.assertIsNone(fcode(fn({"a": decl})))  # extent without order
        self.assertNotEqual(datumesh.function_hash(fn({"a": dict(S, extent=["x"])})), datumesh.function_hash(fn({"a": S})))

    def test_codes(self) -> None:
        cases = [
            (dict(S, extent=["b", "a"]), "E_CANON_SET"),
            (dict(S, extent=["a", "a"]), "E_CANON_SET"),
            (dict(S, extent=["B", "a"]), None),  # code point order
            (dict(N, extent=["10", "9"]), "E_CANON_SET"),  # numerically
            (dict(N, extent=["9", "10"]), None),
            (dict(N, extent=["1.50"]), "E_CANON_NUMBER"),
            (dict(D, extent=["2026-02-30"]), "E_CANON_DATE"),
            (dict(S, extent=["\u0007"]), "E_CANON_STRING"),
            ({"type": "boolean", "valid": False, "extent": ["false", "true"]}, "E_CANON_TYPE"),
            ({"type": "blob", "valid": False, "extent": []}, "E_CANON_TYPE"),
            (dict(S, extent={"hi": "z", "lo": "a"}), "E_CANON_TYPE"),
            ({"type": "instant", "valid": True,
              "extent": {"hi": "2026-01-02T00:00:00.000000Z", "lo": "2026-01-01T00:00:00.000000Z"}}, "E_CANON_TYPE"),
            (dict(N, extent={"hi": "2.5", "lo": "1"}), "E_CANON_NUMBER"),
            (dict(N, extent={"hi": "2", "lo": "01"}), "E_CANON_NUMBER"),
            (dict(N, extent={"hi": "1", "lo": "2"}), "E_CANON_SET"),
            (dict(D, extent={"hi": "2026-01-01", "lo": "2026-12-31"}), "E_CANON_SET"),
            (dict(D, extent={"hi": "2026-13-01", "lo": "2026-01-01"}), "E_CANON_DATE"),
            (dict(S, extent={"hi": "z", "lo": "a", "step": "1"}), "E_SCHEMA"),
            (dict(D, extent={"hi": "2026-01-01"}), "E_SCHEMA"),
            (dict(S, extent="a"), "E_SCHEMA"),
            (dict(S, extent=[1]), "E_SCHEMA"),
            (dict(S, extent=None), "E_SCHEMA"),
            (dict(N, extent={"hi": 2, "lo": 1}), "E_SCHEMA"),
        ]
        for decl, want in cases:
            with self.subTest(decl):
                self.assertEqual(fcode(fn({"a": decl}, ["a"])), want)

    def test_order_within_a_declaration(self) -> None:
        # type, then unit, then valid, then extent: its values in order, then their order, then their count
        self.assertEqual(fcode(fn({"a": {"type": "number", "valid": False, "extent": ["x"]}})), "E_CANON_UNIT")
        self.assertEqual(fcode(fn({"a": {"type": "number", "unit": "1", "valid": True, "extent": ["x"]}})),
                         "E_CANON_TYPE")
        self.assertEqual(fcode(fn({"a": dict(N, extent=["2", "1", "x"])})), "E_CANON_NUMBER")
        many = [str(i) for i in range(4097)]
        self.assertEqual(fcode(fn({"a": dict(N, extent=many)})), "E_CANON_LIMIT")
        self.assertIsNone(fcode(fn({"a": dict(N, extent=many[:4096])})))
        self.assertEqual(fcode(fn({"a": dict(N, extent=list(reversed(many)))})), "E_CANON_SET")
        # arguments in JCS order of names: a's extent before b's type
        self.assertEqual(fcode(fn({"b": {"type": "nope", "valid": False}, "a": dict(S, extent=["b", "a"])})),
                         "E_CANON_SET")

    def test_recompute_with_order_and_extent(self) -> None:
        # Verification uses only args, valid and returns: order and extent change nothing there.
        r, rc = world()
        self.assertEqual(code(r, rc), (True, "OK", "recomputed", None))


# ---------------------------------------------------------------- slice objects and manifests


def scode(obj: Any, kind: str = "slice") -> Optional[str]:
    try:
        canonicalize(obj, kind)
        return None
    except DatumeshError as e:
        return e.code


CELL = {"args": {"date": {"type": "date", "value": "2026-03-01"}, "station": {"type": "string", "value": "kew"}},
        "fn": "temp", "fn_hash": STORED_HASH, "ns": NS}


def with_args(**args: Any) -> Dict[str, Any]:
    return dict(CELL, args=dict(CELL["args"], **args))


class SliceObjectTest(unittest.TestCase):
    def test_forms(self) -> None:
        unbounded = with_args(station="*")
        self.assertIsNone(scode(unbounded))
        # an unbounded slice's id is the cell id of 4.4
        self.assertEqual(datumesh.slice_id(unbounded), datumesh.cell_hash(unbounded))
        rng = with_args(date={"hi": "2026-03-05", "lo": "2026-03-01", "type": "date"})
        self.assertIsNone(scode(rng))
        self.assertEqual(datumesh.slice_id(rng), sha(datumesh.jcs(rng)))
        self.assertIsNone(scode(with_args(date={"hi": "2026-03-01", "lo": "2026-03-05", "type": "date"})))  # empty
        version = {"cell": CELL, "from": T1, "to": T2}
        self.assertIsNone(scode(version))
        self.assertIsNone(scode({"cell": CELL, "from": T2, "to": T1}))
        self.assertEqual(datumesh.slice_id(json.dumps(version)), sha(datumesh.jcs(version)))

    def test_codes(self) -> None:
        cases = [
            (CELL, "E_SLICE"),  # no open or ranged argument
            (with_args(station={"hi": "z", "lo": "a", "type": "boolean"}), "E_CANON_TYPE"),
            (with_args(station={"hi": "z", "lo": "a", "type": "blob"}), "E_CANON_TYPE"),
            (with_args(station={"hi": "z", "lo": "a", "type": "text"}), "E_CANON_TYPE"),
            (with_args(date={"hi": "2026-02-30", "lo": "2026-02-01", "type": "date"}), "E_CANON_DATE"),
            (with_args(date={"hi": "1.50", "lo": "1", "type": "number"}), "E_CANON_NUMBER"),
            (with_args(date={"hi": "2026-03-01", "lo": "2026-03-01", "type": "instant"}), "E_CANON_INSTANT"),
            (with_args(station={"hi": "\u0000", "lo": "a", "type": "string"}), "E_CANON_STRING"),
            (with_args(date={"hi": "2026-03-05", "lo": "2026-03-01", "type": "date", "step": "1"}), "E_SCHEMA"),
            (with_args(date={"hi": "2026-03-05", "type": "date"}), "E_SCHEMA"),
            (with_args(date={"hi": 5, "lo": "1", "type": "number"}), "E_SCHEMA"),
            (with_args(station="**"), "E_SCHEMA"),
            ({"cell": with_args(station="*"), "from": T1, "to": T2}, "E_SLICE"),
            ({"cell": with_args(station={"hi": "z", "lo": "a", "type": "string"}), "from": T1, "to": T2}, "E_SCHEMA"),
            ({"cell": CELL, "from": "2026-03-01", "to": T2}, "E_CANON_INSTANT"),
            ({"cell": CELL, "from": T1}, "E_SCHEMA"),
            ({"cell": CELL, "from": T1, "to": T2, "x": 1}, "E_SCHEMA"),
            (dict(with_args(station="*"), fn="Temp"), "E_CANON_NAME"),
            (dict(with_args(station="*"), asof=T1), "E_SCHEMA"),
            ([], "E_SCHEMA"),
        ]
        for obj, want in cases:
            with self.subTest(obj):
                self.assertEqual(scode(obj), want)

    def test_jcs_order(self) -> None:
        # Checked in JCS order like a cell: args (by name) before fn before fn_hash before ns; E_SLICE after all.
        obj = dict(with_args(date={"hi": "x", "lo": "x", "type": "date"}), fn="Temp")
        self.assertEqual(scode(obj), "E_CANON_DATE")
        self.assertEqual(scode(dict(CELL, ns="Bad")), "E_CANON_NAME")
        # A version slice's cell is "a cell without markers" (4.4), checked whole in its place: its canonical
        # form, then E_SLICE, both before from and to (the reference tool agrees; DEFECTS.md DEF-42).
        star = with_args(station="*")
        self.assertEqual(scode({"cell": star, "from": "bad", "to": "bad"}), "E_SLICE")
        self.assertEqual(scode({"cell": dict(star, ns="Bad"), "from": "bad", "to": "bad"}), "E_CANON_NAME")
        self.assertEqual(scode({"members": [], "slice": {"cell": star, "from": "bad", "to": T1}}, "manifest"), "E_SLICE")
        # A membership slice without an open or ranged argument: E_SLICE after its whole canonical form.
        self.assertEqual(scode(dict(CELL, fn_hash="x")), "E_CANON_HEX")


class ManifestTest(unittest.TestCase):
    def test_manifest(self) -> None:
        members = sorted(sha(bytes([i])) for i in range(3))
        sl = with_args(station="*")
        m = {"members": members, "slice": sl}
        self.assertIsNone(scode(m, "manifest"))
        self.assertEqual(datumesh.members_hash(members), sha(json.dumps(members, separators=(",", ":")).encode()))
        self.assertEqual(datumesh.members_hash([]), sha(b"[]"))
        self.assertEqual(datumesh.slice_entry(m), f"slice:{datumesh.slice_id(sl)}:{datumesh.members_hash(members)}")
        self.assertEqual(datumesh.slice_entry(json.dumps(m).encode()), datumesh.slice_entry(m))

    def test_codes(self) -> None:
        members = sorted(sha(bytes([i])) for i in range(3))
        sl = with_args(station="*")
        cases = [
            ({"members": members}, "E_SCHEMA"),
            ({"members": members, "slice": sl, "x": 1}, "E_SCHEMA"),
            ({"members": "a", "slice": sl}, "E_SCHEMA"),
            ({"members": [1], "slice": sl}, "E_SCHEMA"),
            ({"members": members, "slice": dict(sl, fn=1)}, "E_SCHEMA"),
            ({"members": list(reversed(members)), "slice": sl}, "E_CANON_SET"),
            ({"members": members + members[-1:], "slice": sl}, "E_CANON_SET"),
            ({"members": [m.upper() for m in members], "slice": sl}, "E_CANON_HEX"),
            ({"members": members, "slice": CELL}, "E_SLICE"),
            # JCS order: members before slice
            ({"members": list(reversed(members)), "slice": CELL}, "E_CANON_SET"),
        ]
        for obj, want in cases:
            with self.subTest(obj):
                self.assertEqual(scode(obj, "manifest"), want)
        with self.assertRaises(DatumeshError) as cm:
            datumesh.members_hash(["b" * 64, "a" * 64])
        self.assertEqual(cm.exception.code, "E_CANON_SET")

    def test_members_limit(self) -> None:
        self.assertEqual(datumesh._lexical.LIMIT_MEMBERS, 1048576)
        self.assertEqual(datumesh._lexical.LIMIT_EXTENT, 4096)
        members = sorted(sha(bytes([i])) for i in range(4))
        with mock.patch.object(datumesh._lexical, "LIMIT_MEMBERS", 3):
            self.assertEqual(scode({"members": members, "slice": with_args(station="*")}, "manifest"),
                             "E_CANON_LIMIT")
        self.assertIsNone(scode({"members": members, "slice": with_args(station="*")}, "manifest"))


# ---------------------------------------------------------------- step 7.5: slice entries


class SliceRecomputeTest(unittest.TestCase):
    def test_recomputed(self) -> None:
        r, rc = world()
        self.assertEqual(code(r, rc), (True, "OK", "recomputed", None))
        # manifests as text, bytes or parsed values; member receipts as text, bytes or parsed values
        rc2 = dict(rc, manifests={k: json.loads(t) for k, t in rc["manifests"].items()},
                   inputs={k: t.encode() for k, t in rc["inputs"].items()})
        self.assertEqual(code(r, rc2), (True, "OK", "recomputed", None))
        # without value: E_EVAL_UNAVAILABLE after the slice checks
        rc3 = {k: x for k, x in rc.items() if k != "value"}
        self.assertEqual(code(r, rc3), (True, "E_EVAL_UNAVAILABLE", "signed", "$.value"))

    def test_manifest_obtained(self) -> None:
        r, rc = world()
        e = r["inputs"][0]
        self.assertEqual(code(r, dict(rc, manifests={})), (False, "E_INPUT_UNAVAILABLE", None, "$.inputs[0]"))
        self.assertEqual(code(r, {k: x for k, x in rc.items() if k != "manifests"})[1], "E_INPUT_UNAVAILABLE")
        # parsed strictly, with the parse codes
        self.assertEqual(code(r, dict(rc, manifests={e: "{"}))[1], "E_PARSE_JSON")
        dup = rc["manifests"][e][:-1] + ', "members": []}'
        self.assertEqual(code(r, dict(rc, manifests={e: dup}))[1], "E_PARSE_DUPLICATE_KEY")
        # then its structure and canonical form, before the hashes
        m = json.loads(rc["manifests"][e])
        self.assertEqual(code(r, dict(rc, manifests={e: dict(m, extra=1)}))[1], "E_SCHEMA")
        self.assertEqual(code(r, dict(rc, manifests={e: dict(m, members=m["members"][::-1])}))[1], "E_CANON_SET")
        self.assertEqual(code(r, dict(rc, manifests={e: dict(m, slice=CELL)}))[1], "E_SLICE")
        # a canonical manifest for another entry: E_INPUT_UNAVAILABLE, as a receipt with another hash
        self.assertEqual(code(r, dict(rc, manifests={e: dict(m, members=m["members"][:1])}))[1],
                         "E_INPUT_UNAVAILABLE")
        self.assertEqual(code(r, dict(rc, manifests={e: dict(m, slice=with_args(date="*"))}))[1],
                         "E_INPUT_UNAVAILABLE")

    def test_declared_function(self) -> None:
        r, rc = world()
        other = dict(MEAN, inputs=[f"{NS}/rain"])
        r2 = sign(dict(r, cell=dict(r["cell"], fn_hash=datumesh.function_hash(other))))
        self.assertEqual(code(r2, dict(rc, descriptor=other)), (False, "E_INPUT_UNDECLARED", None, "$.inputs[0]"))

    def test_members(self) -> None:
        kew = stored("2026-03-01", "kew", "10", T1)
        soho = stored("2026-03-01", "soho", "12", T2)
        r, rc = world([kew, soho])
        # a member that cannot be obtained, that is not signature-valid, or that has another hash
        rc2 = copy.deepcopy(rc)
        del rc2["inputs"][rhash(kew)]
        self.assertEqual(code(r, rc2)[1], "E_INPUT_UNAVAILABLE")
        rc2 = copy.deepcopy(rc)
        rc2["inputs"][rhash(kew)] = json.dumps(dict(kew, sig="0" * 128))
        self.assertEqual(code(r, rc2)[1], "E_INPUT_INVALID")
        rc2 = copy.deepcopy(rc)
        rc2["inputs"][rhash(kew)] = json.dumps(soho)
        self.assertEqual(code(r, rc2)[1], "E_INPUT_UNAVAILABLE")

    def test_membership(self) -> None:
        def members_code(members: List[Dict[str, Any]], slice_obj: Optional[Dict[str, Any]] = None) -> str:
            r, rc = world(members, manifest(members, slice_obj))
            return code(r, rc)[1]

        kew = stored("2026-03-01", "kew", "10", T1)
        self.assertEqual(members_code([kew]), "OK")
        # bound argument differs
        self.assertEqual(members_code([kew, stored("2026-03-02", "soho", "12", T2)]), "E_SLICE_MEMBER")
        # another function hash, function or namespace
        other_hash = datumesh.function_hash(dict(STORED, code={"body": "x", "lang": "stored"}))
        self.assertEqual(members_code([kew, stored("2026-03-01", "soho", "12", T2, fn_hash=other_hash)]),
                         "E_SLICE_MEMBER")
        self.assertEqual(members_code([kew, stored("2026-03-01", "soho", "12", T2, fn="temp_max")]), "E_SLICE_MEMBER")
        # other argument names
        sl = {"args": {"date": {"type": "date", "value": "2026-03-01"}, "station": "*", "x": "*"},
              "fn": "temp", "fn_hash": STORED_HASH, "ns": NS}
        self.assertEqual(members_code([kew], sl), "E_SLICE_MEMBER")
        sl = {"args": {"station": "*"}, "fn": "temp", "fn_hash": STORED_HASH, "ns": NS}
        self.assertEqual(members_code([kew], sl), "E_SLICE_MEMBER")
        # ranges: of the range's type, within it, both ends inclusive
        def rng(lo: str, hi: str, t: str = "date") -> Dict[str, Any]:
            return {"args": {"date": {"hi": hi, "lo": lo, "type": t}, "station": "*"},
                    "fn": "temp", "fn_hash": STORED_HASH, "ns": NS}
        self.assertEqual(members_code([kew], rng("2026-03-01", "2026-03-01")), "OK")
        self.assertEqual(members_code([kew], rng("2026-02-01", "2026-03-01")), "OK")
        self.assertEqual(members_code([kew], rng("2026-03-02", "2026-03-31")), "E_SLICE_MEMBER")
        self.assertEqual(members_code([kew], rng("2026-01-01", "2026-02-28")), "E_SLICE_MEMBER")
        self.assertEqual(members_code([kew], rng("2026-03-05", "2026-03-01")), "E_SLICE_MEMBER")  # empty range
        self.assertEqual(members_code([], rng("2026-03-05", "2026-03-01")), "OK")
        self.assertEqual(members_code([kew], rng("2026-03-01T00:00:00.000000Z", "2026-03-02T00:00:00.000000Z",
                                                 "instant")), "E_SLICE_MEMBER")
        self.assertEqual(members_code([kew], rng("2026-03-01", "2026-03-01", "string")), "E_SLICE_MEMBER")
        # string ranges by code point
        def srange(lo: str, hi: str) -> Dict[str, Any]:
            return {"args": {"date": {"type": "date", "value": "2026-03-01"},
                             "station": {"hi": hi, "lo": lo, "type": "string"}},
                    "fn": "temp", "fn_hash": STORED_HASH, "ns": NS}
        self.assertEqual(members_code([kew], srange("a", "z")), "OK")
        self.assertEqual(members_code([kew], srange("A", "Z")), "E_SLICE_MEMBER")
        self.assertEqual(members_code([kew], srange("kew", "kew")), "OK")
        self.assertEqual(members_code([kew], srange("kewa", "z")), "E_SLICE_MEMBER")
        # two members of a membership slice are one cell: two versions of kew
        kew2 = stored("2026-03-01", "kew", "11", T2)
        self.assertEqual(members_code([kew, kew2]), "E_SLICE_MEMBER")

    def test_number_ranges_compare_numerically(self) -> None:
        desc = {"code": {"body": "", "lang": "stored"}, "inputs": [],
                "signature": {"args": {"size": {"type": "number", "unit": "mm", "valid": False}},
                              "returns": {"type": "number", "unit": "1"}}}
        h = datumesh.function_hash(desc)

        def member(size: str) -> Dict[str, Any]:
            return sign({"asof": T1, "cell": {"args": {"size": {"type": "number", "value": size}}, "fn": "sized",
                                              "fn_hash": h, "ns": NS},
                         "computed_by": f"{NS}#{KID}", "inputs": [], "issued": T1, "licence": "CC0-1.0",
                         "proto": "datumesh/1", "publisher": NS, "summary": "s", "tx": T1, "type": "number",
                         "valid": {}, "value": "1"})

        def run(size: str, lo: str, hi: str) -> str:
            m = member(size)
            mf = manifest([m], {"args": {"size": {"hi": hi, "lo": lo, "type": "number"}}, "fn": "sized",
                                "fn_hash": h, "ns": NS})
            desc_c = dict(MEAN, inputs=[f"{NS}/sized"])
            e = entry_of(mf)
            r = sign(dict(computed([e], "1", T1, T3), cell=dict(computed([e], "1", T1, T3)["cell"],
                                                                     fn_hash=datumesh.function_hash(desc_c))))
            rc = {"descriptor": desc_c, "inputs": {rhash(m): json.dumps(m)}, "manifests": {e: mf},
                  "value": {"type": "number", "value": "1"}}
            return code(r, rc)[1]

        self.assertEqual(run("9", "2", "10"), "OK")  # "9" > "10" as strings
        self.assertEqual(run("10", "9", "10"), "OK")
        self.assertEqual(run("10.5", "9", "10"), "E_SLICE_MEMBER")
        self.assertEqual(run("-1", "-2", "-0.5"), "OK")
        self.assertEqual(run("-0.1", "-2", "-0.5"), "E_SLICE_MEMBER")

    def test_version_slice(self) -> None:
        v1 = stored("2026-03-01", "kew", "10", T1)
        v2 = stored("2026-03-01", "kew", "11", T2)
        vs = {"cell": v1["cell"], "from": T1, "to": T2}
        r, rc = world([v1, v2], manifest([v1, v2], vs))
        self.assertEqual(code(r, rc), (True, "OK", "recomputed", None))  # versions of one cell are fine here
        self.assertEqual(code(*world([v1, v2], manifest([v1, v2], dict(vs, to=T1))))[1], "E_SLICE_MEMBER")
        self.assertEqual(code(*world([v1, v2], manifest([v1, v2], dict(vs, **{"from": T2}))))[1], "E_SLICE_MEMBER")
        other = stored("2026-03-01", "soho", "11", T2)
        self.assertEqual(code(*world([v1, other], manifest([v1, other], vs)))[1], "E_SLICE_MEMBER")

    def test_member_asof_and_tx(self) -> None:
        kew = stored("2026-03-01", "kew", "10", T1)
        late = stored("2026-03-01", "soho", "12", T1, asof="2026-03-01T21:00:00.000000Z")
        self.assertEqual(code(*world([kew, late]))[1], "E_TIME_ORDER")
        # tx is the latest tx of every input receipt, members included
        r, rc = world(tx=T1)
        self.assertEqual(code(r, rc), (False, "E_TIME_ORDER", None, "$.tx"))
        # with a plain input too: the latest across both
        plain = stored("2026-03-01", "rain", "0", T3)
        members = [kew]
        m = manifest(members)
        e = entry_of(m)
        desc = dict(MEAN, inputs=[f"{NS}/temp"])
        r = computed([e, rhash(plain)], "11", T3, T3)
        rc = {"descriptor": desc, "inputs": {rhash(x): json.dumps(x) for x in (kew, plain)},
              "manifests": {e: m}, "value": {"type": "number", "value": "11"}}
        self.assertEqual(code(r, rc), (True, "OK", "recomputed", None))
        r = computed([e, rhash(plain)], "11", T1, T3)
        self.assertEqual(code(r, rc)[1], "E_TIME_ORDER")

    def test_only_empty_slices_no_tx_constraint(self) -> None:
        for tx in ("0001-01-01T00:00:00.000000Z", T1, T3):
            with self.subTest(tx):
                self.assertEqual(code(*world([], tx=tx)), (True, "OK", "recomputed", None))
        v = vector("receipt/slice-empty")
        res = verify(v["input"], env_keys(v["keys"]), recompute_of(v))
        self.assertEqual((res.ok, res.level), (True, "recomputed"))

    def test_entries_in_order(self) -> None:
        # Each entry in its place in inputs: the first failing entry is reported.
        kew = stored("2026-03-01", "kew", "10", T1)
        m1 = manifest([kew])
        sl2 = {"args": {"date": {"type": "date", "value": "2026-03-01"}, "station": "*"}, "fn": "temp",
               "fn_hash": STORED_HASH, "ns": "rain.example.org"}
        m2 = {"members": [], "slice": sl2}
        e1, e2 = entry_of(m1), entry_of(m2)
        r = computed([e1, e2], "10", T1, T3)
        first = sorted([e1, e2]).index(e2)
        rc = {"descriptor": MEAN, "inputs": {rhash(kew): json.dumps(kew)}, "manifests": {e1: m1, e2: m2},
              "value": {"type": "number", "value": "10"}}
        self.assertEqual(code(r, rc), (False, "E_INPUT_UNDECLARED", None, f"$.inputs[{first}]"))

    def test_recompute_argument_types(self) -> None:
        r, rc = world()
        # lineage must be a list or tuple; its items are not validated (10.1 step 7.6, 18be70f)
        for bad in (dict(rc, manifests=[1]), dict(rc, lineage="x"), dict(rc, lineage={"a": 1})):
            with self.subTest(bad), self.assertRaises(TypeError):
                verify(json.dumps(r), KEYS, bad)


# ---------------------------------------------------------------- step 7.6: E_INPUT_SUPERSEDED


class SupersededTest(unittest.TestCase):
    def test_vectors(self) -> None:
        for vid in ("receipt/slice-superseded", "receipt/slice-superseded-member"):
            v = vector(vid)
            with self.subTest(vid):
                res = verify(v["input"], env_keys(v["keys"]), recompute_of(v))
                self.assertEqual((res.ok, res.code, res.level, res.path, res.hash),
                                 (True, "E_INPUT_SUPERSEDED", "signed", "$.inputs", v["sha256"]))
                # without a lineage: E_VALUE_MISMATCH, as before
                rc = {k: x for k, x in recompute_of(v).items() if k != "lineage"}
                res = verify(v["input"], env_keys(v["keys"]), rc)
                self.assertEqual((res.ok, res.code), (False, "E_VALUE_MISMATCH"))
                # a lineage that replaces nothing: E_VALUE_MISMATCH
                rc = dict(recompute_of(v), lineage=json.loads(v["input"])["inputs"])
                self.assertEqual(verify(v["input"], env_keys(v["keys"]), rc).code, "E_VALUE_MISMATCH")
                # the value matches: the lineage is not consulted
                rc = dict(recompute_of(v), value={"type": "number", "value": json.loads(v["input"])["value"]})
                res = verify(v["input"], env_keys(v["keys"]), rc)
                self.assertEqual((res.ok, res.code, res.level), (True, "OK", "recomputed"))
                # evaluation unavailable: the lineage is not consulted
                rc = {k: x for k, x in recompute_of(v).items() if k != "value"}
                self.assertEqual(verify(v["input"], env_keys(v["keys"]), rc).code, "E_EVAL_UNAVAILABLE")

    def _plain_world(self) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        old = stored("2026-03-01", "kew", "10", T1)
        new = stored("2026-03-01", "kew", "13", T2)
        r = computed([rhash(old)], "10", T1, T3)
        rc = {"descriptor": MEAN, "inputs": {rhash(old): json.dumps(old), rhash(new): json.dumps(new)},
              "value": {"type": "number", "value": "13"}, "lineage": [rhash(new)]}
        return r, rc, old, new

    def test_replaced_receipt(self) -> None:
        r, rc, old, new = self._plain_world()
        self.assertEqual(code(r, rc), (True, "E_INPUT_SUPERSEDED", "signed", "$.inputs"))
        # the replacement must be obtainable, signature-valid, have its hash, be the same cell, with a later tx
        rc2 = copy.deepcopy(rc)
        del rc2["inputs"][rhash(new)]
        self.assertEqual(code(r, rc2)[1], "E_VALUE_MISMATCH")
        rc2 = copy.deepcopy(rc)
        rc2["inputs"][rhash(new)] = json.dumps(dict(new, sig="0" * 128))
        self.assertEqual(code(r, rc2)[1], "E_VALUE_MISMATCH")
        rc2 = copy.deepcopy(rc)
        rc2["inputs"][rhash(new)] = json.dumps(old)
        self.assertEqual(code(r, rc2)[1], "E_VALUE_MISMATCH")
        other = stored("2026-03-01", "soho", "13", T2)
        rc2 = dict(rc, lineage=[rhash(other)], inputs=dict(rc["inputs"], **{rhash(other): json.dumps(other)}))
        self.assertEqual(code(r, rc2)[1], "E_VALUE_MISMATCH")
        earlier = stored("2026-03-01", "kew", "13", "2026-03-01T17:00:00.000000Z")
        rc2 = dict(rc, lineage=[rhash(earlier)], inputs=dict(rc["inputs"], **{rhash(earlier): json.dumps(earlier)}))
        self.assertEqual(code(r, rc2)[1], "E_VALUE_MISMATCH")
        same_tx = stored("2026-03-01", "kew", "13", T1, asof=T2)
        rc2 = dict(rc, lineage=[rhash(same_tx)], inputs=dict(rc["inputs"], **{rhash(same_tx): json.dumps(same_tx)}))
        self.assertEqual(code(r, rc2)[1], "E_VALUE_MISMATCH")
        # an empty lineage replaces nothing
        self.assertEqual(code(r, dict(rc, lineage=[]))[1], "E_VALUE_MISMATCH")

    def test_replaced_slice(self) -> None:
        kew = stored("2026-03-01", "kew", "10", T1)
        soho = stored("2026-03-01", "soho", "12", T1)
        r, rc = world([kew], value="10", tx=T1)
        m2 = manifest([kew, soho])
        self.assertEqual(code(r, dict(rc, value={"type": "number", "value": "11"}, lineage=[entry_of(m2)])),
                         (True, "E_INPUT_SUPERSEDED", "signed", "$.inputs"))
        # another slice id with the same members hash is not a replacement
        m3 = manifest([kew], with_args(date="*"))
        self.assertEqual(code(r, dict(rc, value={"type": "number", "value": "11"}, lineage=[entry_of(m3)]))[1],
                         "E_VALUE_MISMATCH")

    def test_lineage_rules_of_18be70f(self) -> None:
        """10.1 step 7.6 as settled at 18be70f: e is replaced only when the lineage does not list e; a slice
        replacement is any string beginning slice:<e's slice id>:; a non-string item replaces nothing; the
        lineage is a set."""
        r, rc, old, new = self._plain_world()
        # the lineage lists e itself as well as a later version of its cell: not replaced
        self.assertEqual(code(r, dict(rc, lineage=[r["inputs"][0], rhash(new)]))[1], "E_VALUE_MISMATCH")
        self.assertEqual(code(r, dict(rc, lineage=[rhash(new), r["inputs"][0]]))[1], "E_VALUE_MISMATCH")
        # non-string items replace nothing, and do not stop the check
        self.assertEqual(code(r, dict(rc, lineage=[1, None, {"x": 1}, rhash(new)])),
                         (True, "E_INPUT_SUPERSEDED", "signed", "$.inputs"))
        self.assertEqual(code(r, dict(rc, lineage=[1, None]))[1], "E_VALUE_MISMATCH")
        kew = stored("2026-03-01", "kew", "10", T1)
        r2, rc2 = world([kew], value="10", tx=T1)
        e = r2["inputs"][0]
        sid = e.split(":")[1]
        v11 = {"type": "number", "value": "11"}
        for n, want in ((f"slice:{sid}:", "E_INPUT_SUPERSEDED"), (f"slice:{sid}:x:y", "E_INPUT_SUPERSEDED"),
                        (f"slice:{sid}:{'0' * 64}", "E_INPUT_SUPERSEDED"), (f"slice:{sid}", "E_VALUE_MISMATCH"),
                        (f"Slice:{sid}:{'0' * 64}", "E_VALUE_MISMATCH")):
            with self.subTest(n):
                self.assertEqual(code(r2, dict(rc2, value=v11, lineage=[n]))[1], want)
        # e listed too: not replaced
        self.assertEqual(code(r2, dict(rc2, value=v11, lineage=[e, f"slice:{sid}:{'0' * 64}"]))[1],
                         "E_VALUE_MISMATCH")

    def test_blob_after_superseded(self) -> None:
        r, rc, _, _ = self._plain_world()
        res = verify(json.dumps(r), KEYS, rc, b"x")
        self.assertEqual((res.ok, res.code), (False, "E_SCHEMA"))


# ---------------------------------------------------------------- envelopes, units, codes, runner


class EnvelopeFaultTest(unittest.TestCase):
    REQ = {"cell_id": "a" * 64}

    def test_fault(self) -> None:
        for fault in datumesh.FAULT_CODES:
            res = check_envelope(404, json.dumps({"outcome": "not_covered", "fault": fault}), [], self.REQ)
            self.assertEqual((res.ok, res.outcome, res.fault), (True, "not_covered", fault))
        res = check_envelope(404, '{"outcome": "not_covered"}', [], self.REQ)
        self.assertEqual((res.ok, res.fault), (True, None))
        self.assertEqual(datumesh.FAULT_CODES, ("E_FORMULA_DIV_ZERO", "E_FORMULA_DOMAIN", "E_FORMULA_RANGE",
                                                "E_FORMULA_EMPTY", "E_FORMULA_ABSENT", "E_FORMULA_FUTURE"))

    def test_bad_fault(self) -> None:
        for body in ({"outcome": "not_covered", "fault": "E_FORMULA_BUDGET"},
                     {"outcome": "not_covered", "fault": "E_FORMULA_CYCLE"},
                     {"outcome": "not_covered", "fault": "E_VALUE_MISMATCH"},
                     {"outcome": "not_covered", "fault": "e_formula_div_zero"},
                     {"outcome": "not_covered", "fault": None},
                     {"outcome": "not_covered", "fault": ["E_FORMULA_DIV_ZERO"]},
                     {"outcome": "unlicensed", "fault": "E_FORMULA_DIV_ZERO"},
                     {"outcome": "error", "error": "E_EVAL_UNAVAILABLE", "fault": "E_FORMULA_DIV_ZERO"}):
            status = {"not_covered": 404, "unlicensed": 403, "error": 500}[body["outcome"]]
            with self.subTest(body):
                res = check_envelope(status, json.dumps(body), [], self.REQ)
                self.assertEqual((res.ok, res.code, res.fault), (False, "E_ENVELOPE", None))
        # the fault does not change the status rule
        self.assertEqual(check_envelope(500, '{"outcome":"not_covered","fault":"E_FORMULA_DOMAIN"}', [], self.REQ).code,
                         "E_ENVELOPE")

    def test_error_carries_new_codes(self) -> None:
        for c in ("E_SLICE_MEMBER", "E_INPUT_SUPERSEDED"):
            res = check_envelope(500, json.dumps({"outcome": "error", "error": c}), [], self.REQ)
            self.assertEqual((res.ok, res.outcome), (True, "error"))
        res = check_envelope(500, json.dumps({"outcome": "error", "error": "E_FORMULA_DIV_ZERO"}), [], self.REQ)
        self.assertEqual(res.code, "E_ENVELOPE")


class UnitsTest(unittest.TestCase):
    def test_new_units(self) -> None:
        for u in ("min", "h", "d", "km", "deg"):
            with self.subTest(u):
                self.assertIn(u, datumesh.UNITS)
                self.assertIsNone(fcode(fn({"a": dict(N, unit=u)}, returns={"type": "number", "unit": u})))
        for u in ("Min", "H", "D", "KM", "Deg", "degree", "hr", "day"):
            with self.subTest(u):
                self.assertEqual(fcode(fn({"a": dict(N, unit=u)})), "E_CANON_UNIT")


class CodesTest(unittest.TestCase):
    def test_new_codes(self) -> None:
        codes = datumesh.ERROR_CODES
        self.assertEqual(codes[codes.index("E_INPUT_UNDECLARED") + 1], "E_SLICE_MEMBER")
        self.assertEqual(codes[codes.index("E_EVAL_UNAVAILABLE") + 1], "E_INPUT_SUPERSEDED")
        self.assertEqual(codes[codes.index("E_INPUT_SUPERSEDED") + 1], "E_BLOB_MISMATCH")
        self.assertEqual(datumesh.SUCCESS_CODES, ("E_EVAL_UNAVAILABLE", "E_INPUT_SUPERSEDED"))
        for c in datumesh.FAULT_CODES:
            self.assertNotIn(c, codes)

    def test_versions(self) -> None:
        self.assertEqual(datumesh.SPEC_VERSION, "spec-0.4.0")
        self.assertEqual(datumesh.__version__, "0.4.0")
        self.assertIn("slice", datumesh.KINDS)
        self.assertIn("manifest", datumesh.KINDS)
        for name in ("slice_id", "members_hash", "slice_entry", "FAULT_CODES", "SUCCESS_CODES"):
            self.assertIn(name, datumesh.__all__)

    def test_kind_inference_unchanged(self) -> None:
        # A slice object or manifest is never inferred: kind="slice" or "manifest" is explicit.
        with self.assertRaises(DatumeshError) as cm:
            canonicalize({"cell": CELL, "from": T1, "to": T2})
        self.assertEqual(cm.exception.code, "E_SCHEMA")  # inferred as a receipt, as in spec-0.3.0
        self.assertEqual(canonicalize(with_args(station="*")), canonicalize(with_args(station="*"), "slice"))


class RunnerTest(unittest.TestCase):
    def test_formula_kinds_skipped(self) -> None:
        run = runner().run_vector
        for kind in ("formula", "formula-eval", "excel", "decimal"):
            self.assertEqual(run({"id": "x/y", "kind": kind, "valid": True}),
                             {"id": "x/y", "error": None, "skipped": kind})

    def test_slice_kind(self) -> None:
        run = runner().run_vector
        v = vector("slice/manifest")
        self.assertEqual(run(v), {"id": v["id"], "error": None, "canonical": v["canonical"], "sha256": v["sha256"],
                                  "slice_id": v["slice_id"], "members_hash": v["members_hash"], "entry": v["entry"]})
        v = vector("slice/range")
        self.assertEqual(run(v), {"id": v["id"], "error": None, "canonical": v["canonical"], "sha256": v["sha256"],
                                  "slice_id": v["slice_id"]})
        self.assertEqual(run({"id": "x/y", "kind": "slice", "valid": False, "input": "[]"}),
                         {"id": "x/y", "error": "E_SCHEMA"})


if __name__ == "__main__":
    unittest.main()
