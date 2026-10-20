"""Units (SPEC 7.1, units.md): the embedded list, descriptor checks and unit resolution."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
import unittest

from util import ROOT, SPEC, vectors_of

import datumesh
from datumesh import DatumeshError, function_hash, resolved_unit
from datumesh import _units


def units_md_blocks() -> dict:
    """The fenced blocks tagged units-... in spec/units.md, read independently of the generator."""
    text = (SPEC / "units.md").read_text(encoding="utf-8")
    out: dict = {}
    for tag, body in re.findall(r"^```(units-[a-z]+)\n(.*?)^```$", text, re.M | re.S):
        out.setdefault(tag, []).extend(body.split())
    return out


def descriptor(returns, args=None) -> dict:
    return {"code": {"body": "", "lang": "stored"}, "inputs": [],
            "signature": {"args": args or {}, "returns": returns}}


def number(unit) -> dict:
    return {"type": "number", "unit": unit}


def code_of(desc) -> object:
    try:
        function_hash(desc)
        return None
    except DatumeshError as e:
        return e.code


S = {"type": "string", "valid": False}


class EmbeddedListTest(unittest.TestCase):
    def test_embedded_copy_equals_units_md(self) -> None:
        blocks = units_md_blocks()
        self.assertEqual(sorted(blocks), ["units-currency", "units-physical", "units-ratio"])
        self.assertEqual(_units.CURRENCIES, frozenset(blocks["units-currency"]))
        self.assertEqual(_units.LITERALS, frozenset(sum(blocks.values(), [])))
        self.assertEqual(len(blocks["units-currency"]), len(set(blocks["units-currency"])))
        self.assertEqual(datumesh.CURRENCIES, _units.CURRENCIES)
        self.assertEqual(set(datumesh.UNITS), set(_units.LITERALS))
        self.assertEqual(len(_units.CURRENCIES), 191)
        self.assertNotIn("XXX", _units.CURRENCIES)
        self.assertEqual(_units.SOURCE_SHA256, hashlib.sha256((SPEC / "units.md").read_bytes()).hexdigest())

    def test_generator_is_reproducible(self) -> None:
        proc = subprocess.run([sys.executable, str(ROOT / "tools" / "gen_units.py"), "--check"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_schema_lists_agree(self) -> None:
        # defs.schema.json repeats the list; it must agree with units.md (a spec self-consistency check).
        defs = json.loads((SPEC / "schemas" / "defs.schema.json").read_text(encoding="utf-8"))["$defs"]
        self.assertEqual(set(defs["currency"]["enum"]), set(_units.CURRENCIES))
        self.assertEqual(set(defs["unitLiteral"]["anyOf"][0]["enum"]), set(_units.LITERALS))


class DescriptorUnitTest(unittest.TestCase):
    """Contract test 3: every listed unit is accepted, near-misses are E_CANON_UNIT."""

    def test_every_literal_is_accepted(self) -> None:
        n = 0
        for unit in sorted(_units.LITERALS):
            with self.subTest(unit):
                self.assertIsNone(code_of(descriptor(number(unit))))
                self.assertIsNone(code_of(descriptor("boolean", {"x": {"type": "number", "unit": unit, "valid": False}})))
                n += 2
        for cur in sorted(_units.CURRENCIES):
            with self.subTest(cur):
                self.assertIsNone(code_of(descriptor(number({"of": cur, "per": "EUR"}))))
                self.assertIsNone(code_of(descriptor(number({"of": {"arg": "q"}, "per": cur}), {"q": S})))
                n += 2
        print(f"\nunits accepted in descriptors: {n} checks over {len(_units.LITERALS)} literals", file=sys.stderr)

    def test_index_units(self) -> None:
        cases = {
            "index:2015=100": None, "index:1984-01-03=1000": None, "index:2015-01=100": None,
            "index:2024-02-29=1": None, "index:9999-12-31=1": None, "index:2015=0.5": None,
            "index:2015-01-01=0.001": None, "index:2015=" + "1" * 53: None,  # 64 characters
            "index:2015=" + "1" * 54: "E_CANON_UNIT",  # 65: not E_CANON_LIMIT (reference agrees)
            "index:2015=0": "E_CANON_UNIT", "index:2015=-1": "E_CANON_UNIT", "index:2015=100.0": "E_CANON_UNIT",
            "index:2015=01": "E_CANON_UNIT", "index:2015=": "E_CANON_UNIT", "index:2015-13=100": "E_CANON_UNIT",
            "index:2015-00=1": "E_CANON_UNIT", "index:2015-1=100": "E_CANON_UNIT", "index:2023-02-29=1": "E_CANON_UNIT",
            "index:2015-02-30=1": "E_CANON_UNIT", "index:0000=100": "E_CANON_UNIT", "index:20150=1": "E_CANON_UNIT",
            "index:2015=100 ": "E_CANON_UNIT", "index:2015=1e2": "E_CANON_UNIT", "Index:2015=100": "E_CANON_UNIT",
            "index:2015=1" + "0" * 127: "E_CANON_UNIT", "index:2015": "E_CANON_UNIT",
        }
        for unit, code in cases.items():
            with self.subTest(unit[:40]):
                self.assertEqual(code_of(descriptor(number(unit))), code)

    NEAR_MISSES = [
        # case changes
        "eur", "Eur", "usd", "DEGC", "degc", "KWH", "kwh", "Kwh", "PERCENT", "Percent", "COUNT", "BP", "Bp", "M", "KG",
        "S", "a", "k", "MOL", "CD", "w", "M/S",
        # added whitespace
        " EUR", "EUR ", "E UR", "\tEUR", "EUR\n", " 1", "1 ", "deg C", "m / s", " EUR",
        # other spellings and non-units
        "°C", "℃", "C", "degF", "USD/EUR", "EUR/USD", "m/s2", "km/h", "1.0", "01", "%", "per cent", "",
        "XXX", "ABC", "dollars", "index", "index:", "kWh ", "k‍Wh",
    ]

    def test_near_misses(self) -> None:
        for unit in self.NEAR_MISSES:
            with self.subTest(ascii(unit)):
                self.assertEqual(code_of(descriptor(number(unit))), "E_CANON_UNIT")
                self.assertEqual(code_of(descriptor("boolean", {"x": {"type": "number", "unit": unit, "valid": False}})),
                                 "E_CANON_UNIT")

    def test_shapes_and_placement(self) -> None:
        # Codes confirmed against the reference tool.
        cases = [
            (descriptor({"type": "decimal", "unit": "1"}), "E_CANON_TYPE"),
            (descriptor({"type": "decimal"}), "E_CANON_TYPE"),
            (descriptor({"type": "number", "unit": "1", "valid": False}), "E_SCHEMA"),
            (descriptor({"unit": "1"}), "E_SCHEMA"),
            (descriptor({"type": 5, "unit": "1"}), "E_SCHEMA"),
            (descriptor({"type": "blob", "unit": "1"}), "E_CANON_UNIT"),
            (descriptor({"type": "boolean"}), "E_CANON_UNIT"),
            (descriptor({"type": "string", "unit": "1"}), "E_CANON_UNIT"),
            (descriptor({"type": "boolean", "unit": 5}), "E_SCHEMA"),
            (descriptor({"type": "number"}), "E_CANON_UNIT"),
            (descriptor("number"), "E_CANON_UNIT"),
            (descriptor("decimal"), "E_CANON_TYPE"),
            (descriptor(5), "E_SCHEMA"),
            (descriptor(None), "E_SCHEMA"),
            (descriptor([]), "E_SCHEMA"),
            (descriptor(number(None)), "E_SCHEMA"),
            (descriptor(number(1)), "E_SCHEMA"),
            (descriptor(number(True)), "E_SCHEMA"),
            (descriptor(number(["USD"])), "E_SCHEMA"),
            (descriptor(number({})), "E_SCHEMA"),
            (descriptor(number({"arg": 5}), {"c": S}), "E_SCHEMA"),
            (descriptor(number({"arg": "c", "x": 1}), {"c": S}), "E_SCHEMA"),
            (descriptor(number({"arg": "Bad"}), {"c": S}), "E_CANON_UNIT"),
            (descriptor(number({"arg": "asof"}), {"c": S}), "E_CANON_UNIT"),
            (descriptor(number({"arg": "zz"}), {"c": S}), "E_CANON_UNIT"),
            (descriptor(number({"arg": "c"}), {"c": {"type": "date", "valid": False}}), "E_CANON_UNIT"),
            (descriptor(number({"arg": "c"}), {"c": {"type": "number", "unit": "1", "valid": False}}), "E_CANON_UNIT"),
            (descriptor(number({"arg": "c"}), {"c": {"type": "string", "valid": True}}), None),
            (descriptor(number({"of": {"of": "USD", "per": "EUR"}, "per": "EUR"})), "E_SCHEMA"),
            (descriptor(number({"of": 1, "per": "EUR"})), "E_SCHEMA"),
            (descriptor(number({"of": "USD"})), "E_SCHEMA"),
            (descriptor(number({"of": "USD", "per": "EUR", "scale": "1"})), "E_SCHEMA"),
            (descriptor(number({"of": "index:2015=100", "per": "EUR"})), "E_CANON_UNIT"),
            (descriptor(number({"of": "1", "per": "EUR"})), "E_CANON_UNIT"),
            (descriptor(number({"of": "USD", "per": "kg"})), "E_CANON_UNIT"),
            (descriptor(number({"of": {"arg": "zz"}, "per": "EUR"})), "E_CANON_UNIT"),
            (descriptor(number({"of": "EUR", "per": "EUR"})), None),
            # arguments: type, then unit, then valid
            (descriptor("boolean", {"a": {"type": "number", "valid": True}}), "E_CANON_UNIT"),
            (descriptor("boolean", {"a": {"type": "number", "unit": "zz", "valid": True}}), "E_CANON_UNIT"),
            (descriptor("boolean", {"a": {"type": "blob", "unit": "1", "valid": True}}), "E_CANON_UNIT"),
            (descriptor("boolean", {"a": {"type": "number", "unit": "1", "valid": True}}), "E_CANON_TYPE"),
            (descriptor("boolean", {"a": {"type": "decimal", "unit": "1", "valid": False}}), "E_CANON_TYPE"),
            (descriptor("boolean", {"a": {"type": "number", "unit": None, "valid": False}}), "E_SCHEMA"),
            (descriptor("boolean", {"a": {"type": "string", "unit": None, "valid": False}}), "E_SCHEMA"),
            (descriptor("boolean", {"a": {"type": "number", "unit": "1"}}), "E_SCHEMA"),
            (descriptor("boolean", {"a": {"type": "number", "unit": {"arg": "a"}, "valid": False}}), "E_CANON_UNIT"),
            # members in JCS order: arguments before returns; structure (E_SCHEMA) before canonical form
            (descriptor("decimal", {"a": {"type": "number", "valid": False}}), "E_CANON_UNIT"),
            (descriptor("boolean", {"a": {"type": "number", "valid": False}, "b": {"type": "decimal", "valid": False}}),
             "E_CANON_UNIT"),
            (dict(descriptor(number(5)), code={"body": "", "lang": "Bad"}), "E_SCHEMA"),
            (dict(descriptor(number("zz")), code={"body": "", "lang": "Bad"}), "E_CANON_NAME"),
            (dict(descriptor(number(5)), inputs=["Bad"]), "E_SCHEMA"),
            (descriptor("boolean", {"A": S, "b": {"type": "number", "unit": 5, "valid": False}}), "E_SCHEMA"),
        ]
        for desc, code in cases:
            with self.subTest(json.dumps(desc["signature"])[:90]):
                self.assertEqual(code_of(desc), code)

    def test_function_vectors_unchanged_without_numbers(self) -> None:
        # SPEC 14: descriptors without a number keep their spec-0.1.1 hashes.
        holiday = descriptor("boolean", {"calendar": S, "date": {"type": "date", "valid": True}})
        self.assertEqual(function_hash(holiday), "ed1f0ecb7166dd6d70ae263456e3af94147d4781f43035e534b9368e9561f84a")


def fh(d: dict) -> str:
    return hashlib.sha256(datumesh.jcs(d)).hexdigest()


def sv(x: str) -> dict:
    return {"type": "string", "value": x}


FX = descriptor(number({"of": {"arg": "quote"}, "per": {"arg": "base"}}),
                {"base": S, "quote": S, "date": {"type": "date", "valid": True}})
REF = descriptor(number({"arg": "c"}), {"c": S})
BOOL = descriptor("boolean", {"c": S})
DATE = {"type": "date", "value": "2024-03-15"}


def cell(desc: dict, args: dict, **kw) -> dict:
    return dict({"args": args, "fn": "f", "fn_hash": fh(desc), "ns": "rates.example.org"}, **kw)


def unit_code(desc, c):
    try:
        return resolved_unit(desc, c)
    except DatumeshError as e:
        return e.code


class ResolutionTest(unittest.TestCase):
    def test_unit_vectors(self) -> None:
        n = 0
        for v in vectors_of("unit"):
            obj = json.loads(v["input"])
            with self.subTest(v["id"]):
                got = unit_code(obj["descriptor"], obj["cell"])
                self.assertEqual(got, v["unit"] if v["valid"] else v["error"])
                n += 1
        self.assertEqual(n, 10)

    def test_resolution_cases(self) -> None:
        # Codes and results confirmed against the reference tool (see DEFECTS.md for the unstated rules).
        cases = [
            (REF, {"c": sv("USD")}, "USD"),
            (REF, {"c": sv("index:2015=100")}, "index:2015=100"),
            (REF, {"c": sv("m/s")}, "m/s"),
            (REF, {"c": sv("1")}, "1"),
            (REF, {"c": sv("USD/EUR")}, "E_CANON_UNIT"),
            (REF, {"c": sv("")}, "E_CANON_UNIT"),
            (REF, {"c": sv("index:2015=0")}, "E_CANON_UNIT"),
            (REF, {"c": sv("usd")}, "E_CANON_UNIT"),
            (REF, {"c": "*"}, "E_SLICE"),
            (REF, {}, "E_ARG_MISSING"),
            (REF, {"c": {"type": "number", "value": "1"}}, "E_ARG_TYPE"),
            (FX, {"base": sv("EUR"), "quote": sv("USD"), "date": DATE}, "USD/EUR"),
            (FX, {"base": sv("EUR"), "quote": sv("kg"), "date": DATE}, "E_CANON_UNIT"),
            (FX, {"base": "*", "quote": sv("kg"), "date": DATE}, "E_CANON_UNIT"),  # of before per
            (FX, {"base": sv("kg"), "quote": "*", "date": DATE}, "E_SLICE"),
            (FX, {"base": sv("EUR"), "quote": sv("USD"), "date": "*"}, "USD/EUR"),
            (FX, {"base": sv("EUR"), "quote": sv("USD")}, "USD/EUR"),  # unreferenced arguments are not looked at
            (FX, {"base": sv("EUR"), "quote": sv("USD"), "date": DATE, "zz": sv("x")}, "USD/EUR"),
            (FX, {"base": sv("EUR"), "quote": sv("USD"), "date": sv("x")}, "USD/EUR"),
            (FX, {"base": sv("EUR"), "date": DATE}, "E_ARG_MISSING"),
            (FX, {"base": sv("EUR"), "quote": DATE, "date": DATE}, "E_ARG_TYPE"),
            (BOOL, {"c": "*"}, None),
            (BOOL, {}, None),
            (descriptor(number("EUR"), {"c": S}), {"c": "*"}, "EUR"),
            (descriptor(number({"of": "USD", "per": "EUR"})), {}, "USD/EUR"),
            (descriptor("blob"), {}, None),
        ]
        for desc, args, want in cases:
            with self.subTest(json.dumps(args)[:80], returns=json.dumps(desc["signature"]["returns"])):
                self.assertEqual(unit_code(desc, cell(desc, args)), want)

    def test_check_order(self) -> None:
        # Structure of both, then the cell's canonical form, then fn_hash, then the descriptor's canonical form.
        good = cell(REF, {"c": sv("USD")})
        bad_unit = descriptor(number("zz"), {"c": S})
        bad_schema = descriptor(number(5), {"c": S})
        bad_lang = dict(REF, code={"body": "", "lang": "Bad"})
        cases = [
            (BOOL, dict(good, fn_hash="0" * 64), "E_FN_HASH_MISMATCH"),
            (REF, dict(good, fn_hash="0" * 64, args={"c": sv("zz")}), "E_FN_HASH_MISMATCH"),
            (REF, dict(good, fn_hash="A" * 64), "E_CANON_HEX"),
            (bad_unit, cell(bad_unit, {"c": sv("x")}), "E_CANON_UNIT"),
            (bad_unit, dict(good, fn_hash="0" * 64), "E_FN_HASH_MISMATCH"),
            (bad_schema, dict(good, fn_hash="0" * 64), "E_SCHEMA"),
            (bad_schema, dict(good, ns="Bad"), "E_SCHEMA"),
            (bad_unit, dict(cell(bad_unit, {"c": sv("x")}), ns="Bad"), "E_CANON_NAME"),
            (REF, dict(good, ns="Bad"), "E_CANON_NAME"),
            (REF, dict(good, fn_hash="0" * 64, args={"c": {"type": "number", "value": "1.50"}}), "E_CANON_NUMBER"),
            (bad_lang, good, "E_FN_HASH_MISMATCH"),
            (bad_lang, cell(bad_lang, {"c": sv("USD")}), "E_CANON_NAME"),
            ("x", good, "E_SCHEMA"),
            ("\"x\"", dict(good, ns="Bad"), "E_SCHEMA"),
            (REF, {"args": {}, "fn": "f", "ns": "a.example"}, "E_SCHEMA"),
            (REF, dict(good, ns=5), "E_SCHEMA"),
            ('{"a": 1, "a": 2}', good, "E_PARSE_DUPLICATE_KEY"),
            (REF, '{"args": {}, "args": {}}', "E_PARSE_DUPLICATE_KEY"),
        ]
        for desc, c, want in cases:
            with self.subTest(str(desc)[:60], cell=str(c)[:60]):
                self.assertEqual(unit_code(desc, c), want)

    def test_inputs_not_modified(self) -> None:
        c = cell(FX, {"base": sv("EUR"), "quote": sv("USD"), "date": DATE})
        before = (copy.deepcopy(FX), copy.deepcopy(c))
        resolved_unit(FX, c)
        self.assertEqual((FX, c), before)

    def test_non_objects_are_schema_errors(self) -> None:
        for bad in (5, None, 1.5, [], True):
            with self.subTest(bad=bad):
                self.assertEqual(unit_code(bad, cell(REF, {"c": sv("USD")})), "E_SCHEMA")
                self.assertEqual(unit_code(REF, bad), "E_SCHEMA")


if __name__ == "__main__":
    unittest.main()
