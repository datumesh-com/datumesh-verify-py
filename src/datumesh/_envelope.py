"""Response envelopes (SPEC.md 5.5): the mesh's unsigned statement around a receipt."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from . import _lexical as lx
from . import _units
from ._errors import ERROR_CODES, DatumeshError, fail
from ._json import jcs_bytes, number_texts, parse_json
from ._keys import key_sources
from ._verify import _signed

#: outcome -> (HTTP statuses, required members, optional members), SPEC 5.5.
OUTCOMES: Dict[str, Tuple[range, Tuple[str, ...], Tuple[str, ...]]] = {
    "ok": (range(200, 201), ("receipt", "trust"), ("superseded_by", "reason")),
    "stale": (range(200, 201), ("receipt", "trust", "age_seconds"), ("superseded_by", "reason")),
    "not_covered": (range(404, 405), (), ()),
    "unlicensed": (range(403, 404), (), ()),
    "payment_required": (range(402, 403), ("quote",), ()),
    "rate_limited": (range(429, 430), ("retry_after_seconds",), ()),
    "bad_request": (range(400, 401), ("error",), ()),
    "error": (range(500, 600), ("error",), ()),
}
#: Codes a bad_request may carry: the codes parse can raise (SPEC 5.4, 5.5).
BAD_REQUEST_CODES = frozenset((
    "E_PARSE_URI", "E_CANON_NAME", "E_CANON_ARG_NAME", "E_CANON_ARG_DUPLICATE", "E_CANON_ARG_ORDER",
    "E_CANON_PERCENT", "E_CANON_TYPE", "E_CANON_NUMBER", "E_CANON_DATE", "E_CANON_INSTANT", "E_CANON_STRING",
    "E_CANON_BLOB", "E_CANON_LIMIT", "E_ARG_UNKNOWN", "E_ARG_MISSING"))
#: Codes an error may carry: every code of SPEC 10.2 but E_ENVELOPE, which is a client's.
ERROR_OUTCOME_CODES = frozenset(c for c in ERROR_CODES if c != "E_ENVELOPE")
_INTEGER = re.compile(r"0|[1-9][0-9]*")
TRUST = ("primary", "verified", "unverified")
MAX_SECONDS = 2 ** 53 - 1


@dataclass(frozen=True)
class EnvelopeResult:
    """The outcome of :func:`check_envelope`.

    ``ok``: the envelope is well formed, its status matches, and its receipt (if any)
    is signature-valid and labelled correctly. ``code``: ``"OK"`` or the first failing
    error code. When ok: ``outcome`` is the envelope's outcome, and ``trust`` and
    ``receipt_hash`` are the trust label and the receipt hash when the envelope carries
    a receipt (else None). When not ok, all three are None. ``detail``: human-readable
    text. ``path``: where the failure is (``status``, or a JSON path such as
    ``$.receipt.sig``), or None.
    """

    ok: bool
    code: str
    outcome: Optional[str]
    trust: Optional[str]
    receipt_hash: Optional[str]
    detail: str
    path: Optional[str]


def _bad(detail: str, path: str) -> None:
    fail("E_ENVELOPE", detail, path)


def _seconds(v: Any, text: Optional[str], path: str) -> None:
    """An integer member (SPEC 5.5): a JSON number written 0 or [1-9][0-9]*, at most 2^53 - 1.
    ``text`` is the number's source text (None when the value is not a JSON number)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or text is None:
        _bad("a whole number of seconds (a JSON number)", path)
    if not _INTEGER.fullmatch(text):
        _bad("an integer member is written 0 or [1-9][0-9]*: no sign, fraction or exponent", path)
    if len(text) > 16 or int(text) > MAX_SECONDS:
        _bad(f"at most {MAX_SECONDS} seconds", path)


def _quote(q: Any, path: str) -> None:
    if not isinstance(q, dict) or set(q) != {"amount", "authorise", "currency"}:
        _bad("quote has exactly amount, authorise and currency", path)
    amount, authorise, currency = q["amount"], q["authorise"], q["currency"]
    if not (isinstance(amount, str) and lx.is_number(amount) and len(amount) <= lx.LIMIT_NUMBER
            and not amount.startswith("-") and amount != "0"):
        _bad("amount is a canonical decimal (SPEC 3.1) greater than zero", f"{path}.amount")
    try:
        if not isinstance(authorise, str):
            raise DatumeshError("E_CANON_LICENCE", "not a string")
        if not authorise.startswith("https://"):
            raise DatumeshError("E_CANON_LICENCE", "not https://")
        lx.check_licence(authorise, None)
    except DatumeshError:
        _bad("authorise is an https:// URL in the form of a licence URL (SPEC 8.1)", f"{path}.authorise")
    if not isinstance(currency, str) or currency not in _units.CURRENCIES:
        _bad("currency is a currency code from units.md", f"{path}.currency")


def _members(env: Any, numbers: Dict[str, str]) -> Dict[str, Any]:
    """Step 2: the members against the table and rules of SPEC 5.5. ``numbers`` holds the source
    text of the top-level members that are JSON numbers."""
    if not isinstance(env, dict):
        _bad("an envelope is a JSON object", "$")
    if "outcome" not in env:
        _bad("missing member 'outcome'", "$")
    outcome = env["outcome"]
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        _bad(f"outcome is one of {', '.join(OUTCOMES)}", "$.outcome")
    _, required, optional = OUTCOMES[outcome]
    allowed = {"outcome", *required, *optional}
    for name in sorted(env):
        if name not in allowed:
            _bad(f"member {name!r} is not allowed with outcome {outcome!r}", f"$.{name}")
    for name in sorted(required):
        if name not in env:
            _bad(f"outcome {outcome!r} requires member {name!r}", "$")
    if "reason" in env and "superseded_by" not in env:
        _bad("reason is only present with superseded_by", "$.reason")
    for name in sorted(env):  # JCS order (all names are ASCII)
        v, p = env[name], f"$.{name}"
        if name in ("age_seconds", "retry_after_seconds"):
            _seconds(v, numbers.get(name), p)
        elif name == "error":
            allowed_codes = BAD_REQUEST_CODES if outcome == "bad_request" else ERROR_OUTCOME_CODES
            if not isinstance(v, str) or v not in allowed_codes:
                _bad("bad_request carries a code parse can raise (SPEC 5.4)" if outcome == "bad_request"
                     else "error is a code from SPEC 10.2 other than E_ENVELOPE", p)
        elif name == "quote":
            _quote(v, p)
        elif name == "reason":
            try:
                if not isinstance(v, str) or v == "":
                    raise DatumeshError("E_CANON_STRING", "not a non-empty string")
                lx.check_text(v, None, lx.LIMIT_SUMMARY)
            except DatumeshError as e:
                _bad(f"reason is a non-empty string under the rules of SPEC 3.5 ({e.code})", p)
        elif name == "receipt":
            if not isinstance(v, dict):
                _bad("receipt is a receipt object", p)
        elif name == "superseded_by":
            if not isinstance(v, str):
                _bad("superseded_by is a receipt hash", p)
            try:
                lx.check_hex(v, 64, p)
            except DatumeshError:
                _bad("superseded_by is a receipt hash: 64 lowercase hex digits", p)
        elif name == "trust":
            if not isinstance(v, str) or v not in TRUST:
                _bad(f"trust is one of {', '.join(TRUST)}", p)
    out: Dict[str, Any] = env
    return out


def _is_primary(r: Dict[str, Any]) -> bool:
    """SPEC 5.5: the host of computed_by is the host of cell.ns, and inputs is empty."""
    return r["computed_by"].partition("#")[0] == lx.host_of(r["cell"]["ns"]) and not r["inputs"]


def _check_request(request: Any) -> Tuple[str, Optional[str]]:
    if not isinstance(request, Mapping):
        raise TypeError('request must be {"cell_id": <hex>, "asof": <instant> (optional)}')
    if not set(request) <= {"cell_id", "asof"} or "cell_id" not in request:
        raise ValueError('request has cell_id and optionally asof, nothing else')
    cell_id, asof = request["cell_id"], request.get("asof")
    try:
        if not isinstance(cell_id, str) or ("asof" in request and not isinstance(asof, str)):
            raise TypeError("request cell_id and asof are strings")
        lx.check_hex(cell_id, 64, "request.cell_id")
        if asof is not None:
            lx.check_instant(asof, "request.asof")
    except DatumeshError as e:
        raise ValueError(f"invalid request: {e}") from None
    return cell_id, asof


def check_envelope(status: Any, body: Union[str, bytes, bytearray, memoryview], keys: Any,
                   request: Mapping[str, str]) -> EnvelopeResult:
    """Check a mesh's response (SPEC 5.5): the HTTP ``status`` and the ``body`` (JSON text or bytes)
    against the ``request`` it answers.

    ``request`` is ``{"cell_id": <hex>, "asof": <instant>}``: the cell id (SPEC 4.4) of
    the cell requested, that is the cell its URI denotes with the ``fn_hash`` you
    resolved, and the ``asof`` of the request, omitted when the request had none.

    Steps, first failure reported: strict JSON (6.1); members against the table
    of 5.5 (``E_ENVELOPE``); the status matches the outcome (``E_ENVELOPE``); an
    embedded receipt is verified through step 6 of 10.1 with ``keys`` (the forms
    :func:`verify` takes) and keeps that procedure's codes; the receipt answers
    the request: same cell id, and the same ``asof`` when one was requested
    (``E_ENVELOPE``); then ``trust`` is checked against the receipt (``primary``
    exactly when the signer's host is the namespace's host and there are no
    inputs) and ``superseded_by`` must not be the receipt's own hash (``E_ENVELOPE``).

    Never raises for an invalid envelope; raises TypeError for a body that is not
    text or bytes, keys of an unsupported type or a request that is not a mapping,
    and ValueError for a malformed request. Uses no network.
    """
    if not isinstance(body, (str, bytes, bytearray, memoryview)):
        raise TypeError(f"body must be JSON text or bytes, not {type(body).__name__}")
    sources = key_sources(keys)
    want_cell, want_asof = _check_request(request)
    try:
        parsed = parse_json(body)
        env = _members(parsed, number_texts(body) if isinstance(parsed, dict) else {})
        outcome = env["outcome"]
        if isinstance(status, bool) or not isinstance(status, int) or status not in OUTCOMES[outcome][0]:
            _bad(f"HTTP status {status!r} does not match outcome {outcome!r}", "status")
        trust: Optional[str] = None
        h: Optional[str] = None
        if "receipt" in env:
            try:
                r, h = _signed(env["receipt"], sources)
            except DatumeshError as e:
                path = e.path
                if path is not None and path.startswith("$"):
                    path = "$.receipt" + path[1:]
                raise DatumeshError(e.code, e.detail, path) from None
            if hashlib.sha256(jcs_bytes(r["cell"])).hexdigest() != want_cell:
                _bad("the receipt's cell is not the cell requested", "$.receipt.cell")
            if want_asof is not None and r["asof"] != want_asof:
                _bad(f"the receipt answers as of {r['asof']}, the request asked for {want_asof}", "$.receipt.asof")
            trust = env["trust"]
            if (trust == "primary") != _is_primary(r):
                _bad("trust is primary exactly when the signer's host is the namespace's host and there are no "
                     "inputs", "$.trust")
            if env.get("superseded_by") == h:
                _bad("superseded_by is the receipt's own hash", "$.superseded_by")
        return EnvelopeResult(True, "OK", outcome, trust, h, "well-formed envelope" + (
            "; receipt signature-valid" if h else ""), None)
    except DatumeshError as e:
        return EnvelopeResult(False, e.code, None, None, None, e.detail, e.path)
