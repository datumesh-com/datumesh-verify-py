"""Strict JSON parsing (SPEC.md 6.1, I-JSON) and RFC 8785 canonical serialisation (SPEC.md 6.2)."""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Tuple, Union

from ._errors import DatumeshError, fail

JSONText = Union[str, bytes, bytearray, memoryview]


class _Duplicate(Exception):
    def __init__(self, key: str) -> None:
        self.key = key


def _pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise _Duplicate(k)
        out[k] = v
    return out


def _number(literal: str) -> float:
    value = float(literal)
    if math.isinf(value):
        raise ValueError(f"number out of IEEE 754 double range: {literal}")
    return value


def _constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _has_surrogate(s: str) -> bool:
    for ch in s:
        if "\ud800" <= ch <= "\udfff":
            return True
    return False


def parse_json(data: JSONText, path: str = "$") -> Any:
    """Parse JSON text strictly per SPEC.md 6.1.

    ``data`` is bytes (must be UTF-8 without a byte order mark) or str (must not
    start with U+FEFF). Duplicate member names raise E_PARSE_DUPLICATE_KEY; every
    other failure (syntax, lone surrogates, NaN/Infinity, numbers outside the
    double range, invalid UTF-8) raises E_PARSE_JSON. Numbers become floats.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
        if raw.startswith(b"\xef\xbb\xbf"):
            fail("E_PARSE_JSON", "byte order mark", path)
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as e:
            fail("E_PARSE_JSON", f"invalid UTF-8: {e.reason}", path)
    elif isinstance(data, str):
        text = data
        if text.startswith("﻿"):
            fail("E_PARSE_JSON", "byte order mark", path)
    else:
        raise TypeError(f"JSON text must be str or bytes, not {type(data).__name__}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_number,
            parse_int=_number,
            parse_constant=_constant,
        )
    except _Duplicate as e:
        fail("E_PARSE_DUPLICATE_KEY", f"duplicate member {e.key!r}", path)
    except RecursionError:
        fail("E_PARSE_JSON", "nesting too deep", path)
    except ValueError as e:  # json.JSONDecodeError is a ValueError
        fail("E_PARSE_JSON", str(e), path)
    check_json_value(value, path)
    return value


class NumberText(str):
    """The source text of a JSON number, as :func:`number_texts` reports it."""


def number_texts(data: JSONText) -> Dict[str, str]:
    """The source text of each top-level member of a JSON object whose value is a number.

    For text that :func:`parse_json` has already accepted. SPEC 5.5 constrains how
    the envelope's integer members are written, which the parsed double cannot show.
    """
    text = bytes(data).decode("utf-8") if isinstance(data, (bytes, bytearray, memoryview)) else data
    value = json.loads(text, parse_float=NumberText, parse_int=NumberText, parse_constant=_constant)
    if not isinstance(value, dict):
        return {}
    return {k: str(v) for k, v in value.items() if isinstance(v, NumberText)}


def check_json_value(value: Any, path: str = "$") -> None:
    """Check that an already-parsed value is I-JSON: dict/list/str/float/int/bool/None only,
    string keys, no lone surrogates, finite numbers within the double range."""
    stack: List[Tuple[Any, str]] = [(value, path)]
    while stack:
        v, p = stack.pop()
        if v is None or isinstance(v, bool):
            continue
        if isinstance(v, str):
            if _has_surrogate(v):
                fail("E_PARSE_JSON", "lone surrogate", p)
        elif isinstance(v, float):
            if not math.isfinite(v):
                fail("E_PARSE_JSON", "NaN and infinities are not JSON", p)
        elif isinstance(v, int):
            try:
                float(v)
            except OverflowError:
                fail("E_PARSE_JSON", "number out of IEEE 754 double range", p)
        elif isinstance(v, dict):
            for k, item in v.items():
                if not isinstance(k, str):
                    fail("E_PARSE_JSON", f"member name {k!r} is not a string", p)
                if _has_surrogate(k):
                    fail("E_PARSE_JSON", "lone surrogate in member name", p)
                stack.append((item, f"{p}.{k}"))
        elif isinstance(v, list):
            for i, item in enumerate(v):
                stack.append((item, f"{p}[{i}]"))
        else:
            fail("E_PARSE_JSON", f"{type(v).__name__} is not a JSON value", p)


# ---------------------------------------------------------------- RFC 8785


def _escape(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append({"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}.get(ch, "\\u%04x" % o))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def format_number(value: float) -> str:
    """ECMAScript Number.prototype.toString for a finite double (RFC 8785 3.2.2.3)."""
    if not math.isfinite(value):
        raise DatumeshError("E_PARSE_JSON", "NaN and infinities have no JSON form")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr() gives the shortest digit string that round-trips, choosing the closest
    # when several exist: the same digits ECMAScript's algorithm selects.
    mantissa, _, exp = repr(abs(value)).partition("e")
    int_part, _, frac_part = mantissa.partition(".")
    all_digits = int_part + frac_part
    # value = 0.<all_digits> * 10**point
    point = len(int_part) + (int(exp) if exp else 0)
    leading = len(all_digits) - len(all_digits.lstrip("0"))
    digits = all_digits[leading:].rstrip("0")
    n = point - leading  # ECMAScript's n: value = 0.<digits> * 10**n
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + s


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", errors="surrogatepass")


def _serialise(value: Any, out: List[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_escape(value))
    elif isinstance(value, float):
        out.append(format_number(value))
    elif isinstance(value, int):
        out.append(format_number(float(value)))
    elif isinstance(value, dict):
        out.append("{")
        first = True
        for k in sorted(value, key=_utf16_key):
            if not first:
                out.append(",")
            first = False
            out.append(_escape(k))
            out.append(":")
            _serialise(value[k], out)
        out.append("}")
    elif isinstance(value, list):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialise(item, out)
        out.append("]")
    else:
        raise DatumeshError("E_PARSE_JSON", f"{type(value).__name__} is not a JSON value")


def jcs_bytes(value: Any) -> bytes:
    """RFC 8785 serialisation of an I-JSON value (checked first), as UTF-8 bytes."""
    check_json_value(value)
    out: List[str] = []
    try:
        _serialise(value, out)
    except RecursionError:
        fail("E_PARSE_JSON", "nesting too deep")
    return "".join(out).encode("utf-8")


def sort_key(name: str) -> bytes:
    """The JCS member order (UTF-16 code units)."""
    return _utf16_key(name)
