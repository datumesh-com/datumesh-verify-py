"""Receipt verification (SPEC.md section 10)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey

from . import _lexical as lx
from . import _model
from ._errors import DatumeshError, fail
from ._json import check_json_value, jcs_bytes, parse_json
from ._keys import find_key, key_sources, _Source
from ._lexical import blob_parts

_TEXT = (str, bytes, bytearray, memoryview)


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of :func:`verify`.

    ``ok``: the receipt verified. ``code``: ``"OK"`` or the first failing
    error code; on success it is one of ``SUCCESS_CODES`` instead of ``"OK"``
    (SPEC 10.1 step 7.6, the level stays ``signed``): ``"E_EVAL_UNAVAILABLE"``
    when recomputation was asked for without an evaluated ``value`` (steps
    7.1-7.5 passed, nothing was compared), ``"E_INPUT_SUPERSEDED"`` when the
    value differs and the evaluation's lineage replaces an input (the receipt
    is historical, not wrong). ``level``: ``"signed"`` (steps 1-6) or
    ``"recomputed"`` (step 7 too) when ok, else None. ``hash``: the receipt hash
    once the receipt is in canonical form (steps 1-3 passed), else None.
    ``key``: the ``computed_by`` value when ok. ``detail``: human-readable text.
    ``path``: where the failure is (a JSON path), ``"$.value"`` with
    ``E_EVAL_UNAVAILABLE``, ``"$.inputs"`` with ``E_INPUT_SUPERSEDED``, or None.
    ``blob_checked``: True only when blob content was supplied and step 7.7 ran
    and passed (the level and the code are unchanged).
    """

    ok: bool
    code: str
    level: Optional[str]
    hash: Optional[str]
    key: Optional[str]
    detail: str
    path: Optional[str]
    blob_checked: bool = False


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


def _manifest(supplied: Mapping[str, Any], entry: str, path: str) -> Dict[str, Any]:
    """Step 7.5 for a slice entry: obtain its manifest (E_INPUT_UNAVAILABLE), parse it strictly, check its
    structure and canonical form (their own codes), then that it hashes to the entry (E_INPUT_UNAVAILABLE)."""
    if entry not in supplied:
        fail("E_INPUT_UNAVAILABLE", f"no manifest supplied for {entry}", path)
    m = load(supplied[entry], "manifest")
    _model.validate_manifest(m, "manifest")
    _, slice_id, members = entry.split(":")
    if hashlib.sha256(jcs_bytes(m["slice"])).hexdigest() != slice_id:
        fail("E_INPUT_UNAVAILABLE", f"the manifest supplied for {entry} is of another slice", path)
    if hashlib.sha256(jcs_bytes(m["members"])).hexdigest() != members:
        fail("E_INPUT_UNAVAILABLE", f"the manifest supplied for {entry} has other members", path)
    out: Dict[str, Any] = m
    return out


def _input_receipt(supplied: Mapping[str, Any], h: str, sources: Tuple[_Source, ...], path: str,
                   what: str = "input") -> Dict[str, Any]:
    """Obtain (E_INPUT_UNAVAILABLE), verify through step 6 (E_INPUT_INVALID), check the hash (E_INPUT_UNAVAILABLE)."""
    text = supplied.get(h)
    if text is None:
        fail("E_INPUT_UNAVAILABLE", f"{what} receipt {h} not supplied", path)
    try:
        sub, sub_hash = _signed(text, sources)
    except DatumeshError as e:
        fail("E_INPUT_INVALID", f"{what} {h}: {e.code}: {e.detail}", path)
    if sub_hash != h:
        fail("E_INPUT_UNAVAILABLE", f"the receipt supplied for {h} hashes to {sub_hash}", path)
    return sub


def _cell_id(r: Dict[str, Any]) -> str:
    return hashlib.sha256(jcs_bytes(r["cell"])).hexdigest()


def _superseded(r: Dict[str, Any], plain: Dict[str, Dict[str, Any]], lineage: Any,
                supplied: Mapping[str, Any], sources: Tuple[_Source, ...]) -> bool:
    """Step 7.6 (spec-0.4.0): whether an entry of the receipt's ``inputs`` was replaced in the evaluation's
    lineage: a receipt hash by a receipt of the same cell with a later ``tx``, obtained from ``supplied``,
    signature-valid through step 6 and hashing to its entry; a slice entry by an entry for the same slice
    id with another members hash."""
    entries = [e for e in lineage if e not in set(r["inputs"])]
    slice_entries = {e.split(":")[1] for e in entries if lx.is_slice_entry(e) and e.count(":") == 2}
    candidates: Optional[list] = None
    for e in r["inputs"]:
        if lx.is_slice_entry(e):
            if e.split(":")[1] in slice_entries:
                return True
            continue
        if candidates is None:  # the lineage's receipts, verified once
            candidates = []
            for h in entries:
                if lx.is_slice_entry(h) or h not in supplied:
                    continue
                try:
                    sub, sub_hash = _signed(supplied[h], sources)
                except DatumeshError:
                    continue
                if sub_hash == h:
                    candidates.append(sub)
        old = plain[e]
        cid = _cell_id(old)
        if any(sub["tx"] > old["tx"] and _cell_id(sub) == cid for sub in candidates):
            return True
    return False


def _recompute(r: Dict[str, Any], recompute: Mapping[str, Any], sources: Tuple[_Source, ...]) -> str:
    """Step 7.1-7.6. Raises DatumeshError. Returns ``"recomputed"`` when 7.6 passed, ``"unavailable"`` when
    7.1-7.5 passed and there is no evaluated value to compare (E_EVAL_UNAVAILABLE), and ``"superseded"`` when
    the value differs and the lineage replaces an input (E_INPUT_SUPERSEDED)."""
    # 7.1 descriptor: only an absent member is "none obtained". Whatever is obtained is a JSON
    # value (None is JSON null); text or bytes are parsed strictly first.
    if "descriptor" not in recompute:
        fail("E_FN_UNAVAILABLE", "no descriptor supplied for cell.fn_hash", "$.cell.fn_hash")
    desc = load(recompute["descriptor"], "descriptor")
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
    # 7.4 return type: returns, or its type member when it is an object
    declared = _model.return_type(desc["signature"])
    if r["type"] != declared:
        fail("E_RETURN_TYPE", f"the function returns {declared}", "$.type")
    # 7.5 inputs: receipt hashes and (spec-0.4.0) slice entries, each in its place
    supplied = recompute.get("inputs") or {}
    manifests = recompute.get("manifests") or {}
    declared_inputs = set(desc["inputs"])
    latest_tx: Optional[str] = None
    plain: Dict[str, Dict[str, Any]] = {}
    for i, h in enumerate(r["inputs"]):
        p = f"$.inputs[{i}]"
        if lx.is_slice_entry(h):
            m = _manifest(manifests, h, p)
            sl = m["slice"]
            fqn = _model.slice_function(sl)
            if fqn not in declared_inputs:
                fail("E_INPUT_UNDECLARED", f"input {h} is a slice of {fqn}, which the descriptor does not declare", p)
            seen = set()
            for mh in m["members"]:
                sub = _input_receipt(supplied, mh, sources, p, "member")
                why = _model.member_of(sl, sub)
                if why is not None:
                    fail("E_SLICE_MEMBER", f"member {mh} of {h}: {why}", p)
                if not _model.is_version_slice(sl):
                    cid = _cell_id(sub)
                    if cid in seen:
                        fail("E_SLICE_MEMBER", f"member {mh} of {h} is a cell another member already is", p)
                    seen.add(cid)
                if sub["asof"] > r["asof"]:
                    fail("E_TIME_ORDER", f"member {mh} has asof {sub['asof']}, after the receipt's {r['asof']}", p)
                if latest_tx is None or sub["tx"] > latest_tx:
                    latest_tx = sub["tx"]
            continue
        sub = _input_receipt(supplied, h, sources, p)
        fqn = f"{sub['cell']['ns']}/{sub['cell']['fn']}"
        if fqn not in declared_inputs:
            fail("E_INPUT_UNDECLARED", f"input {h} is a cell of {fqn}, which the descriptor does not declare", p)
        # at or before the receipt's asof (D17, spec-0.3.0); canonical instants compare as strings (3.3)
        if sub["asof"] > r["asof"]:
            fail("E_TIME_ORDER", f"input {h} has asof {sub['asof']}, after the receipt's {r['asof']}", p)
        if latest_tx is None or sub["tx"] > latest_tx:
            latest_tx = sub["tx"]
        plain[h] = sub
    # the latest tx of every input receipt, members included; none (only empty slices, or no inputs): no rule
    if latest_tx is not None and r["tx"] != latest_tx:
        fail("E_TIME_ORDER", f"a computed cell's tx is the latest input tx ({latest_tx})", "$.tx")
    # 7.6 value; without one, evaluation is unavailable (not a failure)
    if "value" not in recompute:
        return "unavailable"
    v = dict(recompute["value"])
    if _model.same_scalar(v, {"type": r["type"], "value": r["value"]}):
        return "recomputed"
    lineage = recompute.get("lineage")
    if lineage is not None and _superseded(r, plain, lineage, supplied, sources):
        return "superseded"
    fail("E_VALUE_MISMATCH", "the recomputed value differs from the receipt's", "$.value")


def check_blob_content(r: Dict[str, Any], content: bytes) -> None:
    """Step 7.7: the content has exactly the blob's length and its SHA-256 is the blob's hash."""
    digest, length, _ = blob_parts(r["value"])
    if len(content) != length:
        fail("E_BLOB_MISMATCH", f"the content has {len(content)} bytes, the blob states {length}", "$.value")
    if hashlib.sha256(content).hexdigest() != digest:
        fail("E_BLOB_MISMATCH", "the content's SHA-256 differs from the blob's hash", "$.value")


def _check_recompute_arg(recompute: Any) -> None:
    if recompute is None:
        return
    if not isinstance(recompute, Mapping):
        raise TypeError("recompute must be a mapping with optional 'descriptor', 'inputs', 'manifests', 'lineage' "
                        "and 'value'")
    if "value" in recompute:
        v = recompute["value"]
        if not isinstance(v, Mapping) or "type" not in v or "value" not in v:
            raise TypeError("recompute['value'] must be {'type': ..., 'value': ...}: the evaluated result "
                            "(leave it out when the function could not be evaluated)")
    inputs = recompute.get("inputs")
    if inputs is not None and not isinstance(inputs, Mapping):
        raise TypeError("recompute['inputs'] must be a mapping of receipt hash to receipt JSON text")
    manifests = recompute.get("manifests")
    if manifests is not None and not isinstance(manifests, Mapping):
        raise TypeError("recompute['manifests'] must be a mapping of slice entry to manifest JSON text")
    lineage = recompute.get("lineage")
    if lineage is not None and (not isinstance(lineage, (list, tuple)) or not all(isinstance(e, str) for e in lineage)):
        raise TypeError("recompute['lineage'] must be a list of inputs entries (strings): what the evaluation read")


def verify(receipt: Any, keys: Any, recompute: Optional[Mapping[str, Any]] = None,
           blob: Optional[Union[bytes, bytearray, memoryview]] = None) -> VerifyResult:
    """Verify a receipt (SPEC.md 10.1) against keys supplied by the caller.

    ``receipt``: JSON text (str or bytes) or a parsed object (duplicate members
    can only be detected in text). ``keys``: a key document, a
    :class:`KeysResult`, a ``{key id: public key hex}`` mapping (any host, no
    validity windows), or a list of those; the first source that covers the
    ``computed_by`` host is used. ``recompute`` (optional) enables step 7:
    ``{"descriptor": ..., "inputs": {hash: receipt text}, "manifests": {entry: manifest text},
    "lineage": [entry, ...], "value": {"type", "value"}}``. ``inputs`` holds the input
    receipts, slice members included; ``manifests`` (spec-0.4.0) the manifest
    ``{"members", "slice"}`` for each slice entry ``slice:<slice id>:<members hash>``
    of ``inputs`` (missing: E_INPUT_UNAVAILABLE). Receipts and manifests are JSON
    text or bytes (parsed strictly) or parsed values. ``lineage`` (optional,
    spec-0.4.0) is the list of ``inputs`` entries the evaluation read, with their
    receipts in ``inputs``; when the value differs it decides between
    E_INPUT_SUPERSEDED and E_VALUE_MISMATCH (SPEC 10.1 step 7.6).
    ``descriptor`` is the descriptor obtained for ``cell.fn_hash``: a parsed JSON
    value, or JSON text/bytes (parsed strictly); leave it out when none was
    obtained (E_FN_UNAVAILABLE). Any other value, ``None`` (JSON null)
    included, is a descriptor offered and must hash to ``cell.fn_hash``
    (E_FN_HASH_MISMATCH). ``value`` is what evaluating the function gave; leave
    it out when the function could not be evaluated: once steps 7.1-7.5 pass,
    the result is then ok at level ``signed`` with ``code`` ``"E_EVAL_UNAVAILABLE"``
    and ``path`` ``"$.value"`` (SPEC 10.1 step 7.6). When ``value`` differs from the
    receipt's and ``lineage`` shows an input replaced (a receipt of the same cell
    with a later ``tx``, signature-valid, or the same slice id with another members
    hash), the result is ok at level ``signed`` with ``code``
    ``"E_INPUT_SUPERSEDED"`` and ``path`` ``"$.inputs"``.
    ``blob`` (optional): the content bytes of a blob value. Step 7.7 then runs
    last (after step 7 if ``recompute`` is given, else directly after step 6):
    the receipt's ``type`` must be ``blob`` (E_SCHEMA otherwise) and the content
    must have the blob's length and SHA-256 (E_BLOB_MISMATCH). The level stays
    ``signed`` or ``recomputed``; ``blob_checked`` reports that 7.7 passed. 7.7
    also runs after E_EVAL_UNAVAILABLE and E_INPUT_SUPERSEDED: if it passes the code is kept, if it
    fails its failure is reported instead.

    Never raises for an invalid receipt or bad key material: the outcome is in
    the returned :class:`VerifyResult`. Raises TypeError only for arguments of
    the wrong Python type. Uses no network and no global state.
    """
    if not isinstance(receipt, _TEXT + (dict,)):
        raise TypeError(f"receipt must be JSON text, bytes or a dict, not {type(receipt).__name__}")
    sources = key_sources(keys)
    _check_recompute_arg(recompute)
    if blob is not None and not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError(f"blob must be the content bytes, not {type(blob).__name__}")
    h: Optional[str] = None
    try:
        r, h = _signed(receipt, sources)
        level, detail = "signed", "signature-valid"
        code, path = "OK", None
        if recompute is not None:
            outcome = _recompute(r, recompute, sources)
            if outcome == "recomputed":
                level, detail = "recomputed", "fully verified by recomputation"
            elif outcome == "superseded":
                code, path = "E_INPUT_SUPERSEDED", "$.inputs"
                detail = ("signature-valid and historical: the recomputed value differs, and the evaluation read a "
                          "later version of an input cell, or other members of an input slice")
            else:
                code, path = "E_EVAL_UNAVAILABLE", "$.value"
                detail = ("signature-valid; recomputation checks 7.1-7.5 passed, but the function was not "
                          "evaluated (no value supplied)")
        checked = False
        if blob is not None:
            if r["type"] != "blob":
                fail("E_SCHEMA", f"content was supplied for a {r['type']} value, not a blob", "$.type")
            check_blob_content(r, bytes(blob))
            detail += "; blob content matches"
            checked = True
        return VerifyResult(True, code, level, h, r["computed_by"], detail, path, checked)
    except DatumeshError as e:
        h = h or getattr(e, "receipt_hash", None)
        return VerifyResult(False, e.code, None, h, None, e.detail, e.path)
