"""Validation of Datumesh JSON forms: typed scalars, cells, references, descriptors, receipts.

Every validator runs SPEC.md 10.1 step 2 (structure, E_SCHEMA) over the whole
object first, then step 3 (canonical form) with members visited in JCS order,
depth first; for receipts, step 4 (consistency) follows.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import _lexical as lx
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


def _signature_structure(v: Any, path: str) -> None:
    require_object(v, path, ("args", "returns"))
    args = v["args"]
    if not isinstance(args, dict):
        fail("E_SCHEMA", "expected an object", _child(path, "args"))
    for name in _sorted(args):
        p = _child(_child(path, "args"), name)
        require_object(args[name], p, ("type", "valid"))
        require_string(args[name]["type"], _child(p, "type"), "type")
        if not isinstance(args[name]["valid"], bool):
            fail("E_SCHEMA", "valid must be a boolean", _child(p, "valid"))
    require_string(v["returns"], _child(path, "returns"), "returns")


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


def _hash_set_canonical(v: List[str], path: str) -> None:
    for i, h in enumerate(v):
        lx.check_hex(h, 64, f"{path}[{i}]")
    _set_order(v, path)
    if len(v) > lx.LIMIT_INPUTS:
        fail("E_CANON_LIMIT", f"more than {lx.LIMIT_INPUTS} inputs", path)


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
        p = _child(ap, name)
        lx.check_arg_name(name, p)
        t = args[name]["type"]
        if t not in lx.TYPES:
            fail("E_CANON_TYPE", f"unknown type {t!r}", _child(p, "type"))
        if args[name]["valid"] and t not in lx.VALID_TIME_TYPES:
            fail("E_CANON_TYPE", "a valid-time argument must be a date, instant or string", p)
    if v["returns"] not in lx.TYPES:
        fail("E_CANON_TYPE", f"unknown type {v['returns']!r}", _child(path, "returns"))


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
    require_object(v, path, ("code", "inputs", "signature"))
    cp = _child(path, "code")
    require_object(v["code"], cp, ("body", "lang"))
    require_string(v["code"]["body"], _child(cp, "body"), "body")
    require_string(v["code"]["lang"], _child(cp, "lang"), "lang")
    _string_array_structure(v["inputs"], _child(path, "inputs"))
    _signature_structure(v["signature"], _child(path, "signature"))
    # step 3
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
    _hash_set_canonical(v["inputs"], c(path, "inputs"))
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
