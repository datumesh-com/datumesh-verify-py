"""Receipt verification (SPEC.md section 10)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey

from . import _model
from ._errors import DatumeshError, fail
from ._json import check_json_value, jcs_bytes, parse_json
from ._keys import find_key, key_sources, _Source
from ._lexical import host_of

_TEXT = (str, bytes, bytearray, memoryview)


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of :func:`verify`.

    ``ok``: the receipt verified. ``code``: ``"OK"`` or the first failing
    error code. ``level``: ``"signed"`` (steps 1-6) or ``"recomputed"`` (step 7
    too) when ok, else None. ``hash``: the receipt hash once the receipt is in
    canonical form (steps 1-3 passed), else None. ``key``: the ``computed_by``
    value when ok. ``detail``: human-readable text. ``path``: where the
    failure is (a JSON path) or None.
    """

    ok: bool
    code: str
    level: Optional[str]
    hash: Optional[str]
    key: Optional[str]
    detail: str
    path: Optional[str]


def load(obj: Any, path: str = "$") -> Any:
    """Parse JSON text strictly, or check that a parsed value is JSON."""
    if isinstance(obj, _TEXT):
        return parse_json(obj, path)
    check_json_value(obj, path)
    return obj


def payload_bytes(receipt: Dict[str, Any]) -> bytes:
    """The signed and hashed bytes: JCS of the receipt without ``sig`` (SPEC 8.3)."""
    return jcs_bytes({k: v for k, v in receipt.items() if k != "sig"})


def _signed(receipt: Any, sources: Tuple[_Source, ...]) -> Tuple[Dict[str, Any], str]:
    """Steps 1-6. Returns (receipt, receipt hash); raises DatumeshError. The hash is
    attached to the error as ``receipt_hash`` once it is known."""
    r = load(receipt)
    _model.receipt_structure(r)
    _model.receipt_canonical(r)
    payload = payload_bytes(r)
    h = hashlib.sha256(payload).hexdigest()
    try:
        _model.receipt_consistency(r)
        host, _, kid = r["computed_by"].partition("#")
        key = find_key(sources, host, kid, r["issued"])
        try:
            VerifyKey(bytes.fromhex(key.public)).verify(payload, bytes.fromhex(r["sig"]))
        except (CryptoError, ValueError, TypeError) as e:
            fail("E_SIGNATURE", f"Ed25519 verification failed ({type(e).__name__})", "$.sig")
    except DatumeshError as e:
        e.receipt_hash = h  # type: ignore[attr-defined]
        raise
    return r, h


def _recompute(r: Dict[str, Any], recompute: Mapping[str, Any], sources: Tuple[_Source, ...]) -> None:
    """Step 7. Raises DatumeshError."""
    # 7.1 descriptor
    desc = recompute.get("descriptor")
    if desc is None:
        fail("E_FN_UNAVAILABLE", "no descriptor supplied for cell.fn_hash", "$.cell.fn_hash")
    desc = load(desc, "descriptor")
    if hashlib.sha256(jcs_bytes(desc)).hexdigest() != r["cell"]["fn_hash"]:
        fail("E_FN_HASH_MISMATCH", "the descriptor does not hash to cell.fn_hash", "$.cell.fn_hash")
    _model.validate_function(desc, "descriptor")
    sig_args = desc["signature"]["args"]
    args = r["cell"]["args"]
    # 7.2 arguments
    for name in _model._sorted(args):
        if name not in sig_args:
            fail("E_ARG_UNKNOWN", f"the function declares no argument {name!r}", f"$.cell.args.{name}")
    for name in _model._sorted(sig_args):
        if name not in args:
            fail("E_ARG_MISSING", f"declared argument {name!r} is not bound", "$.cell.args")
    for name in _model._sorted(args):
        if args[name]["type"] != sig_args[name]["type"]:
            fail("E_ARG_TYPE", f"argument {name!r} is declared {sig_args[name]['type']}", f"$.cell.args.{name}.type")
    # 7.3 valid-time arguments
    declared_valid = {n for n, a in sig_args.items() if a["valid"]}
    if set(r["valid"]) != declared_valid:
        fail("E_VALID_MISMATCH", "valid must echo exactly the declared valid-time arguments", "$.valid")
    # 7.4 return type
    if r["type"] != desc["signature"]["returns"]:
        fail("E_RETURN_TYPE", f"the function returns {desc['signature']['returns']}", "$.type")
    # 7.5 inputs
    supplied = recompute.get("inputs") or {}
    declared_inputs = set(desc["inputs"])
    latest_tx: Optional[str] = None
    for i, h in enumerate(r["inputs"]):
        p = f"$.inputs[{i}]"
        text = supplied.get(h)
        if text is None:
            fail("E_INPUT_UNAVAILABLE", f"input receipt {h} not supplied", p)
        try:
            sub, sub_hash = _signed(text, sources)
        except DatumeshError as e:
            fail("E_INPUT_INVALID", f"input {h}: {e.code}: {e.detail}", p)
        if sub_hash != h:
            fail("E_INPUT_UNAVAILABLE", f"the receipt supplied for {h} hashes to {sub_hash}", p)
        fqn = f"{sub['cell']['ns']}/{sub['cell']['fn']}"
        if fqn not in declared_inputs:
            fail("E_INPUT_UNDECLARED", f"input {h} is a cell of {fqn}, which the descriptor does not declare", p)
        if sub["asof"] != r["asof"]:
            fail("E_TIME_ORDER", f"input {h} has asof {sub['asof']}, not {r['asof']}", p)
        if latest_tx is None or sub["tx"] > latest_tx:
            latest_tx = sub["tx"]
    if latest_tx is not None and r["tx"] != latest_tx:
        fail("E_TIME_ORDER", f"a computed cell's tx is the latest input tx ({latest_tx})", "$.tx")
    # 7.6 value
    v = dict(recompute["value"])
    if not _model.same_scalar(v, {"type": r["type"], "value": r["value"]}):
        fail("E_VALUE_MISMATCH", "the recomputed value differs from the receipt's", "$.value")


def _check_recompute_arg(recompute: Any) -> None:
    if recompute is None:
        return
    if not isinstance(recompute, Mapping):
        raise TypeError("recompute must be a mapping with 'value' and optional 'descriptor' and 'inputs'")
    v = recompute.get("value")
    if not isinstance(v, Mapping) or "type" not in v or "value" not in v:
        raise TypeError("recompute['value'] must be {'type': ..., 'value': ...}: the evaluated result")
    inputs = recompute.get("inputs")
    if inputs is not None and not isinstance(inputs, Mapping):
        raise TypeError("recompute['inputs'] must be a mapping of receipt hash to receipt JSON text")


def verify(receipt: Any, keys: Any, recompute: Optional[Mapping[str, Any]] = None) -> VerifyResult:
    """Verify a receipt (SPEC.md 10.1) against keys supplied by the caller.

    ``receipt``: JSON text (str or bytes) or a parsed object (duplicate members
    can only be detected in text). ``keys``: a key document, a
    :class:`KeysResult`, a ``{key id: public key hex}`` mapping (any host, no
    validity windows), or a list of those; the first source that covers the
    ``computed_by`` host is used. ``recompute`` (optional) enables step 7:
    ``{"descriptor": ..., "inputs": {hash: receipt text}, "value": {"type", "value"}}``.

    Never raises for an invalid receipt or bad key material: the outcome is in
    the returned :class:`VerifyResult`. Raises TypeError only for arguments of
    the wrong Python type. Uses no network and no global state.
    """
    if not isinstance(receipt, _TEXT + (dict,)):
        raise TypeError(f"receipt must be JSON text, bytes or a dict, not {type(receipt).__name__}")
    sources = key_sources(keys)
    _check_recompute_arg(recompute)
    h: Optional[str] = None
    try:
        r, h = _signed(receipt, sources)
        if recompute is None:
            return VerifyResult(True, "OK", "signed", h, r["computed_by"], "signature-valid", None)
        _recompute(r, recompute, sources)
        return VerifyResult(True, "OK", "recomputed", h, r["computed_by"], "fully verified by recomputation", None)
    except DatumeshError as e:
        h = h or getattr(e, "receipt_hash", None)
        return VerifyResult(False, e.code, None, h, None, e.detail, e.path)
