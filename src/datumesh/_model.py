"""Validation of Datumesh JSON forms: typed scalars, cells, references, descriptors, receipts.

Every validator runs SPEC.md 10.1 step 2 (structure, E_SCHEMA) over the whole
object first, then step 3 (canonical form) with members visited in JCS order,
depth first; for receipts, step 4 (consistency) follows.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import _lexical as lx
from . import _units
from ._errors import fail
from ._json import sort_key

SLICE = "*"
PROTO = "datumesh/1"

RECEIPT_MEMBERS = ("asof", "cell", "computed_by", "inputs", "issued", "licence", "proto", "publisher",
                   "sig", "summary", "tx", "type", "valid", "value")


def _sorted(names: Iterable[str]) -> List[str]:
    return sorted(names, key=sort_key)


def _child(path: str, name: str) -> str:
    return f"{path}.{name}"


# ---------------------------------------------------------------- step 2: structure


def require_object(v: Any, path: str, required: Tuple[str, ...], optional: Tuple[str, ...] = ()) -> Dict[str, Any]:
    if not isinstance(v, dict):
        fail("E_SCHEMA", "expected an object", path)
    for name in _sorted(required):
        if name not in v:
            fail("E_SCHEMA", f"missing member {name!r}", path)
    allowed = set(required) | set(optional)
    for name in _sorted(v):
        if name not in allowed:
            fail("E_SCHEMA", f"unexpected member {name!r}", path)
    out: Dict[str, Any] = v
    return out


def require_string(v: Any, path: str, what: str) -> str:
    if not isinstance(v, str):
        fail("E_SCHEMA", f"{what} must be a string", path)
    out: str = v
    return out


def _scalar_structure(v: Any, path: str) -> None:
    require_object(v, path, ("type", "value"))
    require_string(v["type"], _child(path, "type"), "type")
    if not isinstance(v["value"], (str, bool)):
        fail("E_SCHEMA", "value must be a string or a boolean", _child(path, "value"))


def _args_structure(v: Any, path: str) -> None:
    """An argument map (SPEC 4.2): typed scalars or the slice marker."""
    if not isinstance(v, dict):
        fail("E_SCHEMA", "expected an object", path)
    for name in _sorted(v):
        item = v[name]
        if item == SLICE:
            continue
        _scalar_structure(item, _child(path, name))


def _string_array_structure(v: Any, path: str) -> None:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        fail("E_SCHEMA", "expected an array of strings", path)


def _extent_structure(v: Any, path: str) -> None:
    """An argument's ``extent`` (SPEC 7, spec-0.4.0): an array of strings, or a range ``{"hi", "lo"}`` of
    strings. Any other shape is E_SCHEMA; what the values may be is step 3."""
    if isinstance(v, dict):
        require_object(v, path, ("hi", "lo"))
        for end in ("hi", "lo"):
            require_string(v[end], _child(path, end), end)
    else:
        _string_array_structure(v, path)


def _signature_structure(v: Any, path: str) -> None:
    """A signature's JSON shape (SPEC 7): argument declarations are ``{"type", "valid"}`` with an optional
    ``unit`` and, since spec-0.4.0, an optional ``extent``; ``returns`` is a type name or ``{"type"}`` with an
    optional ``unit``; units have the shapes of units.md 1; the optional ``order`` (spec-0.4.0) is an array
    of strings. Whether a unit belongs there, and whether it is listed, is step 3 (E_CANON_UNIT)."""
    require_object(v, path, ("args", "returns"), ("order",))
    args = v["args"]
    if not isinstance(args, dict):
        fail("E_SCHEMA", "expected an object", _child(path, "args"))
    for name in _sorted(args):
        p = _child(_child(path, "args"), name)
        require_object(args[name], p, ("type", "valid"), ("extent", "unit"))
        require_string(args[name]["type"], _child(p, "type"), "type")
        if "unit" in args[name]:
            _units.check_unit_shape(args[name]["unit"], _child(p, "unit"))
        if not isinstance(args[name]["valid"], bool):
            fail("E_SCHEMA", "valid must be a boolean", _child(p, "valid"))
        if "extent" in args[name]:
            _extent_structure(args[name]["extent"], _child(p, "extent"))
    if "order" in v:
        _string_array_structure(v["order"], _child(path, "order"))
    returns = v["returns"]
    rp = _child(path, "returns")
    if isinstance(returns, dict):
        require_object(returns, rp, ("type",), ("unit",))
        require_string(returns["type"], _child(rp, "type"), "type")
        if "unit" in returns:
            _units.check_unit_shape(returns["unit"], _child(rp, "unit"))
    else:
        require_string(returns, rp, "returns")


# ---------------------------------------------------------------- step 3: canonical form


def _args_canonical(v: Dict[str, Any], path: str) -> None:
    if len(v) > lx.LIMIT_ARGS:
        fail("E_CANON_LIMIT", f"more than {lx.LIMIT_ARGS} arguments", path)
    for name in _sorted(v):
        p = _child(path, name)
        lx.check_arg_name(name, p)
        item = v[name]
        if item == SLICE:
            continue
        lx.check_typed_value(item["type"], item["value"], _child(p, "type"), _child(p, "value"))


def _inputs_canonical(v: List[str], path: str) -> None:
    """A receipt's ``inputs`` (SPEC 10.1 step 3): each entry a receipt hash or a slice entry (E_CANON_HEX),
    strictly ascending in string order (E_CANON_SET), at most 4096 entries, a slice entry counting as one."""
    for i, h in enumerate(v):
        lx.check_input_entry(h, f"{path}[{i}]")
    _set_order(v, path)
    if len(v) > lx.LIMIT_INPUTS:
        fail("E_CANON_LIMIT", f"more than {lx.LIMIT_INPUTS} inputs", path)


def members_canonical(v: List[str], path: str) -> None:
    """A manifest's ``members`` (SPEC 10.1 step 7.5, 15.13): receipt hashes (E_CANON_HEX), strictly
    ascending (E_CANON_SET), at most 1,048,576 (E_CANON_LIMIT)."""
    for i, h in enumerate(v):
        lx.check_hex(h, 64, f"{path}[{i}]")
    _set_order(v, path)
    if len(v) > lx.LIMIT_MEMBERS:
        fail("E_CANON_LIMIT", f"more than {lx.LIMIT_MEMBERS} members", path)


def _set_order(v: List[str], path: str) -> None:
    for i in range(1, len(v)):
        if not v[i - 1] < v[i]:
            fail("E_CANON_SET", "entries must be strictly ascending (sorted, no duplicates)", path)


def _signature_canonical(v: Dict[str, Any], path: str) -> None:
    args = v["args"]
    ap = _child(path, "args")
    if len(args) > lx.LIMIT_ARGS:
        fail("E_CANON_LIMIT", f"more than {lx.LIMIT_ARGS} arguments", ap)
    for name in _sorted(args):
        # Within a declaration: type (E_CANON_TYPE), then unit (E_CANON_UNIT), then valid (SPEC 7).
        p = _child(ap, name)
        lx.check_arg_name(name, p)
        decl = args[name]
        t = decl["type"]
        if t not in lx.TYPES:
            fail("E_CANON_TYPE", f"unknown type {t!r}", _child(p, "type"))
        if t == "number":
            if "unit" not in decl:
                fail("E_CANON_UNIT", "a number argument declares its unit", p)
            _units.check_unit(decl["unit"], args, _child(p, "unit"))
        elif "unit" in decl:
            fail("E_CANON_UNIT", "only number arguments have a unit", _child(p, "unit"))
        if decl["valid"] and t not in lx.VALID_TIME_TYPES:
            fail("E_CANON_TYPE", "a valid-time argument must be a date, instant or string", p)
        if "extent" in decl:
            _extent_canonical(t, decl["extent"], _child(p, "extent"))
    if "order" in v:
        # every argument name exactly once (SPEC 7, spec-0.4.0)
        order = v["order"]
        if len(set(order)) != len(order) or set(order) != set(args):
            fail("E_CANON_SET", "order lists every argument name exactly once, and nothing else",
                 _child(path, "order"))
    returns = v["returns"]
    rp = _child(path, "returns")
    if isinstance(returns, str):
        if returns not in lx.TYPES:
            fail("E_CANON_TYPE", f"unknown type {returns!r}", rp)
        if returns == "number":
            fail("E_CANON_UNIT", 'a number return is written {"type": "number", "unit": ...}', rp)
    else:
        t = returns["type"]
        if t not in lx.TYPES:
            fail("E_CANON_TYPE", f"unknown type {t!r}", _child(rp, "type"))
        if t != "number":
            fail("E_CANON_UNIT", f"a {t} return is written as the bare type name, without a unit", rp)
        if "unit" not in returns:
            fail("E_CANON_UNIT", "a number return declares its unit", rp)
        _units.check_unit(returns["unit"], args, _child(rp, "unit"))


def _extent_canonical(t: str, ext: Any, path: str) -> None:
    """Step 3 for an argument's ``extent`` of type ``t`` (SPEC 7, spec-0.4.0). Values: each in the type's
    lexical form (that type's code), then strictly ascending in the type's order (E_CANON_SET), then at most
    4096 (E_CANON_LIMIT). A range ``{"hi", "lo"}``: date and number arguments only (E_CANON_TYPE), ends in
    the type's form, integers for numbers (E_CANON_NUMBER), ``lo <= hi`` (E_CANON_SET). Booleans and blobs
    have no extent (E_CANON_TYPE)."""
    if t in ("boolean", "blob"):
        fail("E_CANON_TYPE", f"a {t} argument has no extent", path)
    if isinstance(ext, dict):
        if t not in ("date", "number"):
            fail("E_CANON_TYPE", f"an extent range is for date and number arguments, not {t}", path)
        for end in ("hi", "lo"):  # JCS order
            ep = _child(path, end)
            lx.check_typed_value(t, ext[end], None, ep)
            if t == "number" and "." in ext[end]:
                fail("E_CANON_NUMBER", "a number extent range has integer ends", ep)
        if lx.order_key(t, ext["lo"]) > lx.order_key(t, ext["hi"]):
            fail("E_CANON_SET", "an extent range has lo <= hi", path)
        return
    for i, x in enumerate(ext):
        lx.check_typed_value(t, x, None, f"{path}[{i}]")
    keys = [lx.order_key(t, x) for x in ext]
    for i in range(1, len(keys)):
        if not keys[i - 1] < keys[i]:
            fail("E_CANON_SET", f"extent values are strictly ascending in the {t} order", path)
    if len(ext) > lx.LIMIT_EXTENT:
        fail("E_CANON_LIMIT", f"more than {lx.LIMIT_EXTENT} extent values", path)


def return_type(signature: Dict[str, Any]) -> str:
    """The declared return type of a canonical signature: ``returns``, or its ``type`` member (SPEC 7)."""
    r = signature["returns"]
    out: str = r if isinstance(r, str) else r["type"]
    return out


# ---------------------------------------------------------------- kinds


def validate_scalar(v: Any, path: str = "$") -> None:
    _scalar_structure(v, path)
    lx.check_typed_value(v["type"], v["value"], _child(path, "type"), _child(path, "value"))


def _cell_like_structure(v: Any, path: str, with_hash: bool) -> None:
    if with_hash:
        require_object(v, path, ("args", "fn", "fn_hash", "ns"))
    else:
        require_object(v, path, ("args", "fn", "ns"), ("asof",))
    _args_structure(v["args"], _child(path, "args"))
    if not with_hash and "asof" in v:
        require_string(v["asof"], _child(path, "asof"), "asof")
    require_string(v["fn"], _child(path, "fn"), "fn")
    if with_hash:
        require_string(v["fn_hash"], _child(path, "fn_hash"), "fn_hash")
    require_string(v["ns"], _child(path, "ns"), "ns")


def _cell_like_canonical(v: Dict[str, Any], path: str, with_hash: bool) -> None:
    _args_canonical(v["args"], _child(path, "args"))
    if not with_hash and "asof" in v:
        lx.check_instant(v["asof"], _child(path, "asof"))
    lx.check_name(v["fn"], _child(path, "fn"))
    if with_hash:
        lx.check_hex(v["fn_hash"], 64, _child(path, "fn_hash"))
    lx.check_namespace(v["ns"], _child(path, "ns"))
    lx.check_function_name_length(v["ns"], v["fn"], path)


def cell_structure(v: Any, path: str = "$") -> None:
    _cell_like_structure(v, path, True)


def cell_canonical(v: Dict[str, Any], path: str = "$") -> None:
    _cell_like_canonical(v, path, True)


def validate_cell(v: Any, path: str = "$") -> None:
    _cell_like_structure(v, path, True)
    _cell_like_canonical(v, path, True)


def validate_ref(v: Any, path: str = "$") -> None:
    _cell_like_structure(v, path, False)
    _cell_like_canonical(v, path, False)


def validate_signature(v: Any, path: str = "$") -> None:
    _signature_structure(v, path)
    _signature_canonical(v, path)


def validate_function(v: Any, path: str = "$") -> None:
    function_structure(v, path)
    function_canonical(v, path)


def function_structure(v: Any, path: str = "$") -> None:
    """Step 2 for a descriptor (SPEC 7)."""
    require_object(v, path, ("code", "inputs", "signature"))
    cp = _child(path, "code")
    require_object(v["code"], cp, ("body", "lang"))
    require_string(v["code"]["body"], _child(cp, "body"), "body")
    require_string(v["code"]["lang"], _child(cp, "lang"), "lang")
    _string_array_structure(v["inputs"], _child(path, "inputs"))
    _signature_structure(v["signature"], _child(path, "signature"))


def function_canonical(v: Dict[str, Any], path: str = "$") -> None:
    """Step 3 for a descriptor whose structure is checked (SPEC 6-7, units included)."""
    cp = _child(path, "code")
    lx.check_text(v["code"]["body"], _child(cp, "body"), lx.LIMIT_BODY, allow_tab_lf=True)
    lx.check_name(v["code"]["lang"], _child(cp, "lang"))
    ip = _child(path, "inputs")
    for i, name in enumerate(v["inputs"]):
        lx.check_function_name(name, f"{ip}[{i}]")
    _set_order(v["inputs"], ip)
    if len(v["inputs"]) > lx.LIMIT_INPUTS:
        fail("E_CANON_LIMIT", f"more than {lx.LIMIT_INPUTS} inputs", ip)
    _signature_canonical(v["signature"], _child(path, "signature"))


def receipt_structure(v: Any, path: str = "$") -> None:
    """SPEC 10.1 step 2."""
    require_object(v, path, RECEIPT_MEMBERS)
    for name in RECEIPT_MEMBERS:  # already in JCS order
        p = _child(path, name)
        item = v[name]
        if name == "cell":
            _cell_like_structure(item, p, True)
        elif name == "valid":
            _args_structure(item, p)
        elif name == "inputs":
            _string_array_structure(item, p)
        elif name == "value":
            if not isinstance(item, (str, bool)):
                fail("E_SCHEMA", "value must be a string or a boolean", p)
        else:
            require_string(item, p, name)
            if name == "proto" and item != PROTO:
                fail("E_SCHEMA", f"proto must be {PROTO!r}", p)


def receipt_canonical(v: Dict[str, Any], path: str = "$") -> None:
    """SPEC 10.1 step 3 (structure already checked)."""
    c = _child
    lx.check_instant(v["asof"], c(path, "asof"))
    _cell_like_canonical(v["cell"], c(path, "cell"), True)
    lx.check_key_ref(v["computed_by"], c(path, "computed_by"))
    _inputs_canonical(v["inputs"], c(path, "inputs"))
    lx.check_instant(v["issued"], c(path, "issued"))
    lx.check_licence(v["licence"], c(path, "licence"))
    lx.check_namespace(v["publisher"], c(path, "publisher"))
    lx.check_hex(v["sig"], 128, c(path, "sig"))
    lx.check_text(v["summary"], c(path, "summary"), lx.LIMIT_SUMMARY)
    if v["summary"] == "":
        fail("E_CANON_STRING", "summary must not be empty", c(path, "summary"))
    lx.check_instant(v["tx"], c(path, "tx"))
    if v["type"] not in lx.TYPES:
        fail("E_CANON_TYPE", f"unknown type {v['type']!r}", c(path, "type"))
    _args_canonical(v["valid"], c(path, "valid"))
    lx.check_typed_value(v["type"], v["value"], c(path, "type"), c(path, "value"))


def receipt_consistency(v: Dict[str, Any], path: str = "$") -> None:
    """SPEC 10.1 step 4."""
    args = v["cell"]["args"]
    for name in _sorted(args):
        if args[name] == SLICE:
            fail("E_SLICE", "a receipt answers one cell, not a slice", f"{path}.cell.args.{name}")
    valid = v["valid"]
    for name in _sorted(valid):
        if valid[name] == SLICE:
            fail("E_SLICE", "a receipt answers one cell, not a slice", f"{path}.valid.{name}")
    if v["publisher"] != v["cell"]["ns"]:
        fail("E_PUBLISHER_MISMATCH", "publisher must equal cell.ns", f"{path}.publisher")
    for name in _sorted(valid):
        p = f"{path}.valid.{name}"
        if name not in args or not same_scalar(valid[name], args[name]):
            fail("E_VALID_MISMATCH", f"valid.{name} does not echo cell.args.{name}", p)
        if valid[name]["type"] not in lx.VALID_TIME_TYPES:
            fail("E_VALID_MISMATCH", "valid-time arguments are dates, instants or strings", p)
    if not (v["tx"] <= v["asof"] <= v["issued"]):
        fail("E_TIME_ORDER", "requires tx <= asof <= issued", path)


# ---------------------------------------------------------------- slice objects and manifests (spec-0.4.0)

RANGE_TYPES = ("date", "instant", "number", "string")


def is_version_slice(v: Dict[str, Any]) -> bool:
    return "cell" in v


def slice_structure(v: Any, path: str = "$") -> None:
    """Step 2 for a slice object (SPEC 4.4): a cell object whose arguments are typed scalars, the slice
    marker or range objects ``{"hi", "lo", "type"}``; or a version slice ``{"cell", "from", "to"}``."""
    if isinstance(v, dict) and "cell" in v:
        require_object(v, path, ("cell", "from", "to"))
        _cell_like_structure(v["cell"], _child(path, "cell"), True)
        require_string(v["from"], _child(path, "from"), "from")
        require_string(v["to"], _child(path, "to"), "to")
        return
    require_object(v, path, ("args", "fn", "fn_hash", "ns"))
    args = v["args"]
    ap = _child(path, "args")
    if not isinstance(args, dict):
        fail("E_SCHEMA", "expected an object", ap)
    for name in _sorted(args):
        item, p = args[name], _child(ap, name)
        if item == SLICE:
            continue
        if isinstance(item, dict) and "value" not in item:
            require_object(item, p, ("hi", "lo", "type"))
            for m in ("hi", "lo", "type"):
                require_string(item[m], _child(p, m), m)
        else:
            _scalar_structure(item, p)
    for m in ("fn", "fn_hash", "ns"):
        require_string(v[m], _child(path, m), m)


def slice_canonical(v: Dict[str, Any], path: str = "$") -> None:
    """Step 3 for a slice object, in JCS order like a cell. A range's ``type`` is checked before its ends,
    whose lexical rules it selects; booleans and blobs have no ranges (E_CANON_TYPE)."""
    if is_version_slice(v):
        # "cell": a cell without markers (4.4), checked whole in its place in JCS order: its canonical form,
        # then no slice marker (E_SLICE), before "from" and "to"
        cp = _child(path, "cell")
        cell_canonical(v["cell"], cp)
        args = v["cell"]["args"]
        for name in _sorted(args):
            if args[name] == SLICE:
                fail("E_SLICE", "a version slice is of one cell, without slice markers", f"{cp}.args.{name}")
        lx.check_instant(v["from"], _child(path, "from"))
        lx.check_instant(v["to"], _child(path, "to"))
        return
    args = v["args"]
    ap = _child(path, "args")
    if len(args) > lx.LIMIT_ARGS:
        fail("E_CANON_LIMIT", f"more than {lx.LIMIT_ARGS} arguments", ap)
    for name in _sorted(args):
        p = _child(ap, name)
        lx.check_arg_name(name, p)
        item = args[name]
        if item == SLICE:
            continue
        if "value" in item:
            lx.check_typed_value(item["type"], item["value"], _child(p, "type"), _child(p, "value"))
            continue
        t = item["type"]
        if t not in RANGE_TYPES:
            fail("E_CANON_TYPE", f"a range is of a date, instant, number or string, not {t!r}", _child(p, "type"))
        lx.check_typed_value(t, item["hi"], None, _child(p, "hi"))
        lx.check_typed_value(t, item["lo"], None, _child(p, "lo"))
    lx.check_name(v["fn"], _child(path, "fn"))
    lx.check_hex(v["fn_hash"], 64, _child(path, "fn_hash"))
    lx.check_namespace(v["ns"], _child(path, "ns"))
    lx.check_function_name_length(v["ns"], v["fn"], path)


def slice_consistency(v: Dict[str, Any], path: str = "$") -> None:
    """E_SLICE: a membership slice has an open or ranged argument, checked after its canonical form. (A
    version slice's cell is checked for markers with the cell, in :func:`slice_canonical`.)"""
    if is_version_slice(v):
        return
    if all(isinstance(a, dict) and "value" in a for a in v["args"].values()):
        fail("E_SLICE", "a slice object has at least one open or ranged argument", _child(path, "args"))


def validate_slice(v: Any, path: str = "$") -> None:
    slice_structure(v, path)
    slice_canonical(v, path)
    slice_consistency(v, path)


def validate_members(v: Any, path: str = "$") -> None:
    _string_array_structure(v, path)
    members_canonical(v, path)


def validate_manifest(v: Any, path: str = "$") -> None:
    """A slice manifest ``{"members", "slice"}`` (SPEC 15.13, 10.1 step 7.5): structure over the whole
    manifest (E_SCHEMA), then members, then the slice object, in JCS order."""
    require_object(v, path, ("members", "slice"))
    _string_array_structure(v["members"], _child(path, "members"))
    slice_structure(v["slice"], _child(path, "slice"))
    members_canonical(v["members"], _child(path, "members"))
    slice_canonical(v["slice"], _child(path, "slice"))
    slice_consistency(v["slice"], _child(path, "slice"))


def slice_function(v: Dict[str, Any]) -> str:
    """The fully qualified name of a valid slice object's function."""
    c = v["cell"] if is_version_slice(v) else v
    return f"{c['ns']}/{c['fn']}"


def member_of(slice_obj: Dict[str, Any], receipt: Dict[str, Any]) -> Optional[str]:
    """Whether a signature-valid receipt belongs to a valid slice object (SPEC 10.1 step 7.5). Returns None
    when it does, else why not. A membership slice: the same ``ns``, ``fn`` and ``fn_hash``, the same argument
    names, bound arguments equal, ranged arguments of the range's type and within it (inclusive, in the
    type's order), any value for an open argument. A version slice: the same cell, with ``tx`` in
    ``[from, to]``."""
    cell = receipt["cell"]
    if is_version_slice(slice_obj):
        sc = slice_obj["cell"]
        if (cell["ns"], cell["fn"], cell["fn_hash"]) != (sc["ns"], sc["fn"], sc["fn_hash"]) \
                or set(cell["args"]) != set(sc["args"]) \
                or not all(same_scalar(cell["args"][n], sc["args"][n]) for n in sc["args"]):
            return "the member is not the version slice's cell"
        if not slice_obj["from"] <= receipt["tx"] <= slice_obj["to"]:
            return f"the member's tx {receipt['tx']} is outside [{slice_obj['from']}, {slice_obj['to']}]"
        return None
    for m in ("ns", "fn", "fn_hash"):
        if cell[m] != slice_obj[m]:
            return f"the member's {m} differs from the slice's"
    sargs, cargs = slice_obj["args"], cell["args"]
    if set(sargs) != set(cargs):
        return "the member's argument names differ from the slice's"
    for name in _sorted(sargs):
        s, c = sargs[name], cargs[name]
        if s == SLICE:
            continue
        if "value" in s:
            if not same_scalar(s, c):
                return f"the member's argument {name!r} differs from the slice's"
            continue
        t = s["type"]
        if c["type"] != t:
            return f"the member's argument {name!r} is a {c['type']}, the range a {t}"
        k = lx.order_key(t, c["value"])
        if not lx.order_key(t, s["lo"]) <= k <= lx.order_key(t, s["hi"]):
            return f"the member's argument {name!r} is outside [{s['lo']}, {s['hi']}]"
    return None


def same_scalar(a: Any, b: Any) -> bool:
    """Lexical equality of two typed scalars (booleans are not strings)."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    return (a.get("type") == b.get("type") and type(a.get("value")) is type(b.get("value"))
            and a.get("value") == b.get("value"))


def validate_receipt(v: Any, path: str = "$") -> None:
    receipt_structure(v, path)
    receipt_canonical(v, path)
    receipt_consistency(v, path)


VALIDATORS = {
    "scalar": validate_scalar,
    "cell": validate_cell,
    "ref": validate_ref,
    "function": validate_function,
    "receipt": validate_receipt,
    "slice": validate_slice,
    "manifest": validate_manifest,
}


def infer_kind(v: Any) -> Optional[str]:
    if not isinstance(v, dict):
        return None
    if any(k in v for k in ("proto", "sig", "computed_by", "cell")):
        return "receipt"
    if "code" in v or "signature" in v:
        return "function"
    if "fn_hash" in v:
        return "cell"
    if any(k in v for k in ("fn", "ns", "args")):
        return "ref"
    if "type" in v or "value" in v:
        return "scalar"
    return None
