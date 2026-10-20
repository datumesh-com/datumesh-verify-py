"""Lexical rules of SPEC.md sections 2-4 and 8 (names, scalars, blobs, hex, licences, key references).

Each check raises DatumeshError with the code the specification assigns. Where
one value breaks several rules, the order of checks is: grammar first, then
the length limit, then reservation (names); grammar, then length (numbers,
licences); characters, NFC, then length (strings, SPEC 3.5).
"""

from __future__ import annotations

import re
from typing import Any, Optional

from ._errors import fail
from ._unicode import is_assigned, is_nfc

TYPES = ("blob", "boolean", "date", "instant", "number", "string")
VALID_TIME_TYPES = ("date", "instant", "string")

LIMIT_NAME = 64
LIMIT_FUNCTION_NAME = 512
LIMIT_ARGS = 32
LIMIT_NUMBER = 128
LIMIT_STRING = 1024
LIMIT_SUMMARY = 1024
LIMIT_BODY = 1048576
LIMIT_INPUTS = 4096
LIMIT_LICENCE_SPDX = 64
LIMIT_LICENCE_URL = 512
LIMIT_KEYS = 64
LIMIT_DNS = 253
LIMIT_BLOB_LENGTH = 2 ** 53 - 1
LIMIT_MEDIA_TYPE = 128

_NAME = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_DIGITS = re.compile(r"[0-9]+")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?")
_DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
_INSTANT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{6}Z")
_HEX16 = re.compile(r"[0-9a-f]{16}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_SPDX = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
_URL_REST = re.compile(r"[!-~]+")
_RESTRICTED_NAME = r"[a-z0-9][a-z0-9!#$&^_.+-]*"
_BLOB = re.compile(r"[0-9a-f]{64}:(0|[1-9][0-9]*):(" + _RESTRICTED_NAME + "/" + _RESTRICTED_NAME + ")")


def check_name(s: str, path: Optional[str], code: str = "E_CANON_NAME") -> None:
    """A snake_case name (SPEC 2.2): grammar (``code``), then at most 64 characters (E_CANON_LIMIT)."""
    if not _NAME.fullmatch(s):
        fail(code, f"not a lowercase snake_case name: {s!r}", path)
    if len(s) > LIMIT_NAME:
        fail("E_CANON_LIMIT", f"name longer than {LIMIT_NAME} characters", path)


def check_arg_name(s: str, path: Optional[str]) -> None:
    """An argument name (SPEC 2.4): a name that is not ``asof`` and does not start with ``dm_``."""
    check_name(s, path, "E_CANON_ARG_NAME")
    if s == "asof" or s.startswith("dm_"):
        fail("E_CANON_ARG_NAME", f"reserved argument name {s!r}", path)


def check_dns_name(s: str, path: Optional[str]) -> None:
    """A DNS name (SPEC 2.1). Every failure is E_CANON_NAME."""
    labels = s.split(".")
    if len(labels) < 2:
        fail("E_CANON_NAME", f"DNS name needs at least two labels: {s!r}", path)
    for label in labels:
        if not _LABEL.fullmatch(label):
            fail("E_CANON_NAME", f"bad DNS label {label!r}", path)
    if _DIGITS.fullmatch(labels[-1]):
        fail("E_CANON_NAME", "the last DNS label is all digits", path)
    if len(s) > LIMIT_DNS:
        fail("E_CANON_NAME", f"DNS name longer than {LIMIT_DNS} characters", path)


def check_namespace(s: str, path: Optional[str]) -> None:
    """A namespace (SPEC 2.3): a DNS name followed by zero or more ``/name`` segments."""
    parts = s.split("/")
    check_dns_name(parts[0], path)
    for seg in parts[1:]:
        check_name(seg, path)


def check_function_name_length(namespace: str, fn: str, path: Optional[str]) -> None:
    if len(namespace) + 1 + len(fn) > LIMIT_FUNCTION_NAME:
        fail("E_CANON_LIMIT", f"function name longer than {LIMIT_FUNCTION_NAME} characters", path)


def check_function_name(s: str, path: Optional[str]) -> None:
    """A fully qualified function name ``<namespace>/<name>`` (SPEC 2.3)."""
    ns, sep, fn = s.rpartition("/")
    if not sep:
        fail("E_CANON_NAME", f"function name has no namespace: {s!r}", path)
    check_namespace(ns, path)
    check_name(fn, path)
    check_function_name_length(ns, fn, path)


def host_of(namespace: str) -> str:
    return namespace.split("/", 1)[0]


def is_number(s: str) -> bool:
    """The canonical decimal grammar of SPEC 3.1 (without the length limit)."""
    return bool(_NUMBER.fullmatch(s)) and s != "-0"


def check_number(s: str, path: Optional[str]) -> None:
    if not is_number(s):
        fail("E_CANON_NUMBER", f"not a canonical decimal: {s!r}", path)
    if len(s) > LIMIT_NUMBER:
        fail("E_CANON_LIMIT", f"number longer than {LIMIT_NUMBER} characters", path)


def _is_leap(y: int) -> bool:
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


_MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def real_day(y: int, m: int, d: int) -> bool:
    """A day of the proleptic Gregorian calendar, years 0001-9999 (SPEC 3.2)."""
    if y < 1 or not 1 <= m <= 12 or d < 1:
        return False
    days = 29 if m == 2 and _is_leap(y) else _MONTH_DAYS[m - 1]
    return d <= days


def check_date(s: str, path: Optional[str]) -> None:
    m = _DATE.fullmatch(s)
    if not m or not real_day(int(m.group(1)), int(m.group(2)), int(m.group(3))):
        fail("E_CANON_DATE", f"not a YYYY-MM-DD calendar date: {s!r}", path)


def check_instant(s: str, path: Optional[str]) -> None:
    m = _INSTANT.fullmatch(s)
    if (not m or not real_day(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            or int(m.group(4)) > 23 or int(m.group(5)) > 59 or int(m.group(6)) > 59):
        fail("E_CANON_INSTANT", f"not a UTC instant YYYY-MM-DDTHH:MM:SS.ffffffZ: {s!r}", path)


def check_blob(s: str, path: Optional[str]) -> None:
    """``<sha256>:<length>:<media type>`` (SPEC 3.7). Every failure is E_CANON_BLOB."""
    m = _BLOB.fullmatch(s)
    if (not m or len(m.group(1)) > 16 or int(m.group(1)) > LIMIT_BLOB_LENGTH
            or len(m.group(2)) > LIMIT_MEDIA_TYPE):
        fail("E_CANON_BLOB", "not <64 lowercase hex>:<length up to 2^53 - 1>:<lowercase type/subtype, "
             f"at most {LIMIT_MEDIA_TYPE} characters>", path)


def blob_parts(s: str) -> tuple:
    """(sha256 hex, length, media type) of a blob value already checked with :func:`check_blob`."""
    digest, length, media = s.split(":", 2)
    return digest, int(length), media


def check_text(s: str, path: Optional[str], limit: int, allow_tab_lf: bool = False) -> None:
    """The string rules of SPEC 3.5: characters, then NFC (E_CANON_STRING), then UTF-8 length (E_CANON_LIMIT)."""
    for ch in s:
        cp = ord(ch)
        if cp < 0x20 or 0x7F <= cp <= 0x9F:
            if allow_tab_lf and (cp == 0x09 or cp == 0x0A):
                continue
            fail("E_CANON_STRING", f"control character U+{cp:04X}", path)
        if 0xD800 <= cp <= 0xDFFF:
            fail("E_CANON_STRING", f"surrogate code point U+{cp:04X}", path)
        if cp >= 0x0378 and not is_assigned(cp):
            fail("E_CANON_STRING", f"U+{cp:04X} is not assigned in Unicode 15.1", path)
    if not is_nfc(s):
        fail("E_CANON_STRING", "not in Normalization Form C", path)
    if len(s) > limit // 4 and len(s.encode("utf-8")) > limit:
        fail("E_CANON_LIMIT", f"longer than {limit} UTF-8 bytes", path)


def check_string(s: str, path: Optional[str]) -> None:
    check_text(s, path, LIMIT_STRING)


def check_hex(s: str, digits: int, path: Optional[str]) -> None:
    pattern = {16: _HEX16, 64: _HEX64, 128: _HEX128}[digits]
    if not pattern.fullmatch(s):
        fail("E_CANON_HEX", f"expected {digits} lowercase hex digits", path)


def check_licence(s: str, path: Optional[str]) -> None:
    """An SPDX licence identifier or an ``https://`` URL (SPEC 8.1, 4.5)."""
    if s.startswith("https://"):
        if not _URL_REST.fullmatch(s[8:]):
            fail("E_CANON_LICENCE", "licence URL must be https:// followed by printable ASCII without spaces", path)
        if len(s) > LIMIT_LICENCE_URL:
            fail("E_CANON_LIMIT", f"licence URL longer than {LIMIT_LICENCE_URL} characters", path)
    else:
        if not _SPDX.fullmatch(s):
            fail("E_CANON_LICENCE", f"not an SPDX identifier or https URL: {s!r}", path)
        if len(s) > LIMIT_LICENCE_SPDX:
            fail("E_CANON_LIMIT", f"licence identifier longer than {LIMIT_LICENCE_SPDX} characters", path)


def check_key_ref(s: str, path: Optional[str]) -> None:
    """``<host>#<key id>`` (SPEC 9.1): the host is a DNS name (E_CANON_NAME), the id 16 lowercase hex (E_CANON_HEX)."""
    host, sep, kid = s.partition("#")
    if not sep:
        fail("E_CANON_NAME", f"not a key reference <host>#<key id>: {s!r}", path)
    check_dns_name(host, path)
    check_hex(kid, 16, path)


def check_typed_value(type_: str, value: Any, path_type: Optional[str], path_value: Optional[str]) -> None:
    """Step 3 for a typed scalar whose structure (string ``type``, string or boolean ``value``) is already checked."""
    if type_ not in TYPES:
        fail("E_CANON_TYPE", f"unknown type {type_!r}", path_type)
    if type_ == "boolean":
        if not isinstance(value, bool):
            fail("E_CANON_TYPE", "a boolean value is JSON true or false", path_value)
        return
    if not isinstance(value, str):
        fail("E_CANON_TYPE", f"a {type_} value is a JSON string", path_value)
    if type_ == "number":
        check_number(value, path_value)
    elif type_ == "date":
        check_date(value, path_value)
    elif type_ == "instant":
        check_instant(value, path_value)
    elif type_ == "blob":
        check_blob(value, path_value)
    else:
        check_string(value, path_value)
