"""datumesh: verify Datumesh receipts (signed answers for addressable data cells).

Implements the Datumesh protocol specification, revision ``spec-0.2.0``
(https://github.com/datumesh-com/datumesh-spec): RFC 8785 canonical JSON,
SHA-256 hashes, Ed25519 receipt signatures, blob content, units, cell URIs,
response envelopes and key documents. Only :func:`fetch_keys` touches the network.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from . import _model, _units
from ._envelope import EnvelopeResult, check_envelope
from ._errors import ERROR_CODES, DatumeshError, fail
from ._json import jcs_bytes
from ._keys import Key, KeysResult, fetch_keys, key_id, keys_from_response
from ._uri import format_uri, parse_uri, uri_to_https
from ._verify import VerifyResult, load, payload_bytes, verify

__version__ = "0.2.0"
#: The specification revision this package conforms to.
SPEC_VERSION = "spec-0.2.0"
#: Every literal unit listed in units.md (index units, ``index:<period>=<value>``, are a pattern and not listed).
UNITS = tuple(sorted(_units.LITERALS))
#: The currency codes of units.md 2.1.
CURRENCIES = _units.CURRENCIES

KINDS = ("scalar", "cell", "ref", "function", "receipt")

__all__ = [
    "SPEC_VERSION",
    "CURRENCIES",
    "ERROR_CODES",
    "KINDS",
    "DatumeshError",
    "EnvelopeResult",
    "Key",
    "KeysResult",
    "UNITS",
    "VerifyResult",
    "canonicalize",
    "cell_hash",
    "check_envelope",
    "fetch_keys",
    "format_uri",
    "function_hash",
    "jcs",
    "key_id",
    "keys_from_response",
    "parse_json",
    "parse_uri",
    "receipt_hash",
    "receipt_payload",
    "resolved_unit",
    "uri_to_https",
    "verify",
]


def _validated(obj: Any, kind: Optional[str]) -> Dict[str, Any]:
    value = load(obj)
    if kind is None:
        kind = _model.infer_kind(value)
        if kind is None:
            raise DatumeshError("E_SCHEMA", "cannot tell which kind of Datumesh object this is", "$")
    elif kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}, not {kind!r}")
    _model.VALIDATORS[kind](value)
    out: Dict[str, Any] = value
    return out


def canonicalize(obj: Any, kind: Optional[str] = None) -> bytes:
    """Validate ``obj`` as a Datumesh ``kind`` and return its RFC 8785 (JCS) bytes.

    ``kind`` is ``"scalar"``, ``"cell"``, ``"ref"`` (cell reference),
    ``"function"`` (descriptor) or ``"receipt"`` (the full receipt, ``sig``
    included; steps 2-4 of SPEC 10.1 are checked). When omitted it is inferred
    from the members present. ``obj`` is a parsed object or JSON text/bytes,
    which is parsed strictly (SPEC 6.1). Raises :class:`DatumeshError`.
    """
    return jcs_bytes(_validated(obj, kind))


def cell_hash(cell: Any) -> str:
    """The cell id: SHA-256 of the cell's canonical bytes (SPEC 4.4), in lowercase hex. Slices are allowed."""
    return hashlib.sha256(jcs_bytes(_validated(cell, "cell"))).hexdigest()


def function_hash(descriptor: Any) -> str:
    """The function hash: SHA-256 of the canonical descriptor (SPEC 7), in lowercase hex."""
    return hashlib.sha256(jcs_bytes(_validated(descriptor, "function"))).hexdigest()


def receipt_payload(receipt: Any) -> bytes:
    """The bytes a receipt's signature covers: JCS of the receipt without ``sig`` (SPEC 8.3)."""
    return payload_bytes(_validated(receipt, "receipt"))


def receipt_hash(receipt: Any) -> str:
    """The receipt hash: SHA-256 of the receipt without ``sig`` (SPEC 8.3), in lowercase hex.

    The receipt is validated (steps 1-4) first; the signature is not checked.
    """
    return hashlib.sha256(receipt_payload(receipt)).hexdigest()


def parse_json(text: Any) -> Any:
    """Parse JSON text (str or bytes) strictly, as SPEC 6.1 requires. Raises :class:`DatumeshError`
    (E_PARSE_JSON, E_PARSE_DUPLICATE_KEY)."""
    if not isinstance(text, (str, bytes, bytearray, memoryview)):
        raise TypeError(f"text must be str or bytes, not {type(text).__name__}")
    return load(text)


def jcs(value: Any) -> bytes:
    """RFC 8785 canonical bytes of any JSON value (parsed, or text parsed strictly). No Datumesh rules."""
    return jcs_bytes(load(value))


def resolved_unit(descriptor: Any, cell: Any) -> Optional[str]:
    """The unit of ``cell``'s value (SPEC 7.1, units.md 3), or None when the function does not return a number.

    ``descriptor`` is the function descriptor that ``cell.fn_hash`` pins and ``cell``
    a cell (4.4); each is a parsed object or JSON text/bytes (parsed strictly). The
    checks run in this order, first failure raised as :class:`DatumeshError`: the
    structure of the cell, then of the descriptor (E_SCHEMA); the cell's canonical
    form; the descriptor hashes to ``cell.fn_hash`` (E_FN_HASH_MISMATCH); the
    descriptor's canonical form (units included); then resolution: a referenced
    argument must be bound (E_ARG_MISSING), not a slice (E_SLICE), a string
    (E_ARG_TYPE), and its value a listed unit, or on a side of a rate a currency
    code (E_CANON_UNIT). Arguments the unit does not reference are not examined.
    """
    c = load(cell, "cell")
    d = load(descriptor, "descriptor")
    _model.cell_structure(c, "cell")
    _model.function_structure(d, "descriptor")
    _model.cell_canonical(c, "cell")
    if hashlib.sha256(jcs_bytes(d)).hexdigest() != c["fn_hash"]:
        fail("E_FN_HASH_MISMATCH", "the descriptor does not hash to cell.fn_hash", "cell.fn_hash")
    _model.function_canonical(d, "descriptor")
    return _units.resolve(d["signature"]["returns"], c["args"], "cell")
