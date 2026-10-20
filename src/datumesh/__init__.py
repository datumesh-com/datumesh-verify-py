"""datumesh: verify Datumesh receipts (signed answers for addressable data cells).

Implements the Datumesh protocol specification, revision ``spec-0.1.1``
(https://github.com/datumesh-com/datumesh-spec): RFC 8785 canonical JSON,
SHA-256 hashes, Ed25519 receipt signatures, cell URIs and key documents.
Only :func:`fetch_keys` touches the network.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from . import _model
from ._errors import ERROR_CODES, DatumeshError
from ._json import jcs_bytes
from ._keys import Key, KeysResult, fetch_keys, key_id, keys_from_response
from ._uri import format_uri, parse_uri, uri_to_https
from ._verify import VerifyResult, load, payload_bytes, verify

__version__ = "0.1.1"
#: The specification revision this package conforms to.
SPEC_VERSION = "spec-0.1.1"

KINDS = ("scalar", "cell", "ref", "function", "receipt")

__all__ = [
    "SPEC_VERSION",
    "ERROR_CODES",
    "KINDS",
    "DatumeshError",
    "Key",
    "KeysResult",
    "VerifyResult",
    "canonicalize",
    "cell_hash",
    "fetch_keys",
    "format_uri",
    "function_hash",
    "jcs",
    "key_id",
    "keys_from_response",
    "parse_uri",
    "receipt_hash",
    "receipt_payload",
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


def jcs(value: Any) -> bytes:
    """RFC 8785 canonical bytes of any JSON value (parsed, or text parsed strictly). No Datumesh rules."""
    return jcs_bytes(load(value))
