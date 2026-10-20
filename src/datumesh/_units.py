"""Units (SPEC.md 7.1, units.md): checking units in a signature and resolving the unit of a cell's value.

A unit is never parsed: literals are compared byte for byte with the list of
units.md (embedded in _unitlist.py by tools/gen_units.py). The only pattern is
the index unit of units.md 2.4.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from . import _lexical as lx
from . import _unitlist
from ._errors import fail

SOURCE_SHA256 = _unitlist.SOURCE_SHA256
#: Currency codes (units.md 2.1).
CURRENCIES = frozenset(_unitlist.CURRENCY)
#: Every listed literal unit (units.md 2.1-2.3). Index units are a pattern, see :func:`is_literal_unit`.
LITERALS = frozenset(_unitlist.CURRENCY + _unitlist.PHYSICAL + _unitlist.RATIO)

LIMIT_INDEX_UNIT = 64
_INDEX = re.compile(r"index:([0-9]{4})(?:-([0-9]{2})(?:-([0-9]{2}))?)?=(.*)", re.S)


def is_index_unit(s: str) -> bool:
    """``index:<period>=<value>`` (units.md 2.4): at most 64 characters, a real year, month or day
    (years 0001-9999, as SPEC 3.2), and a canonical number (SPEC 3.1) greater than zero."""
    if len(s) > LIMIT_INDEX_UNIT:
        return False
    m = _INDEX.fullmatch(s)
    if not m:
        return False
    year = int(m.group(1))
    month = int(m.group(2)) if m.group(2) else 1
    day = int(m.group(3)) if m.group(3) else 1
    if not lx.real_day(year, month, day):
        return False
    value = m.group(4)
    return lx.is_number(value) and not value.startswith("-") and value != "0"


def is_literal_unit(s: str) -> bool:
    """A literal unit: listed in units.md, or an index unit."""
    return s in LITERALS or is_index_unit(s)


# ---------------------------------------------------------------- step 2: JSON shape


def _is_arg_ref(u: Any) -> bool:
    return isinstance(u, dict) and set(u) == {"arg"} and isinstance(u["arg"], str)


def check_unit_shape(u: Any, path: str) -> None:
    """A unit is a string, ``{"arg": <string>}`` or ``{"of": side, "per": side}`` where a side is a
    string or an argument reference (units.md 1). Any other JSON shape is E_SCHEMA."""
    if isinstance(u, str) or _is_arg_ref(u):
        return
    if isinstance(u, dict) and set(u) == {"of", "per"}:
        for side in ("of", "per"):
            if not (isinstance(u[side], str) or _is_arg_ref(u[side])):
                fail("E_SCHEMA", "a side of a rate is a currency code or {\"arg\": <name>}", f"{path}.{side}")
        return
    fail("E_SCHEMA", "a unit is a string, {\"arg\": <name>} or {\"of\": ..., \"per\": ...}", path)


# ---------------------------------------------------------------- step 3: units in a signature


def _check_arg_ref(name: str, args: Dict[str, Any], path: str) -> None:
    decl = args.get(name)
    if decl is None or decl["type"] != "string":
        fail("E_CANON_UNIT", f"a unit reference names a string argument of the signature, not {name!r}", path)


def check_unit(u: Any, args: Dict[str, Any], path: str) -> None:
    """SPEC 7.1: a listed literal, a reference to a string argument, or a rate of currencies or references.
    ``args`` is the signature's (structurally valid) argument map."""
    if isinstance(u, str):
        if not is_literal_unit(u):
            fail("E_CANON_UNIT", f"{u!r} is not a unit listed in units.md", path)
    elif "arg" in u:
        _check_arg_ref(u["arg"], args, f"{path}.arg")
    else:
        for side in ("of", "per"):
            s = u[side]
            if isinstance(s, str):
                if s not in CURRENCIES:
                    fail("E_CANON_UNIT", f"a side of a rate is a currency code, not {s!r}", f"{path}.{side}")
            else:
                _check_arg_ref(s["arg"], args, f"{path}.{side}.arg")


# ---------------------------------------------------------------- resolution (units.md 3)


def _substitute(name: str, cell_args: Dict[str, Any], path: str) -> str:
    p = f"{path}.args.{name}"
    if name not in cell_args:
        fail("E_ARG_MISSING", f"the unit refers to argument {name!r}, which the cell does not bind", f"{path}.args")
    v = cell_args[name]
    if v == "*":
        fail("E_SLICE", f"argument {name!r} is a slice marker: the unit cannot be resolved", p)
    if v["type"] != "string":
        fail("E_ARG_TYPE", f"argument {name!r} is declared a string", f"{p}.type")
    out: str = v["value"]
    return out


def resolve(returns: Any, cell_args: Dict[str, Any], cell_path: str) -> Optional[str]:
    """The unit of a cell's value from the canonical ``returns`` of its descriptor (units.md 3)."""
    if not isinstance(returns, dict):
        return None  # only a number return is an object
    u = returns["unit"]
    if isinstance(u, str):
        return u
    if "arg" in u:
        value = _substitute(u["arg"], cell_args, cell_path)
        if not is_literal_unit(value):
            fail("E_CANON_UNIT", f"argument {u['arg']!r} is {value!r}, which is not a unit",
                 f"{cell_path}.args.{u['arg']}.value")
        return value
    sides = []
    for side in ("of", "per"):
        s = u[side]
        if isinstance(s, str):
            sides.append(s)
            continue
        value = _substitute(s["arg"], cell_args, cell_path)
        if value not in CURRENCIES:
            fail("E_CANON_UNIT", f"argument {s['arg']!r} is {value!r}, which is not a currency code",
                 f"{cell_path}.args.{s['arg']}.value")
        sides.append(value)
    return f"{sides[0]}/{sides[1]}"
