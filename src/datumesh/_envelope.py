"""Response envelopes (SPEC.md 5.5): the mesh's unsigned statement around a receipt."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

from . import _lexical as lx
from . import _units
from ._errors import ERROR_CODES, DatumeshError, fail
from ._json import parse_json
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
    "error": (range(500, 600), ("error",), ()),
}
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


def _seconds(v: Any, path: str) -> None:
    """A JSON number with an integral value, 0 to 2^53 - 1 (SPEC 5.5). ``30.0`` and ``3e1`` are integral."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        _bad("a whole number of seconds (a JSON number)", path)
    if isinstance(v, float) and (not math.isfinite(v) or not v.is_integer()):
        _bad("a whole number of seconds", path)
    if not 0 <= v <= MAX_SECONDS:
        _bad(f"seconds are between 0 and {MAX_SECONDS}", path)


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


def _members(env: Any) -> Dict[str, Any]:
    """Step 2: the members against the table and rules of SPEC 5.5."""
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
            _seconds(v, p)
        elif name == "error":
            if not isinstance(v, str) or v not in ERROR_CODES:
                _bad("error is a code from SPEC 10.2", p)
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


def check_envelope(status: Any, body: Union[str, bytes, bytearray, memoryview], keys: Any) -> EnvelopeResult:
    """Check a mesh's response (SPEC 5.5): the HTTP ``status`` and the ``body`` (JSON text or bytes).

    Steps, first failure reported: strict JSON (6.1); members against the table
    of 5.5 (``E_ENVELOPE``); the status matches the outcome (``E_ENVELOPE``); an
    embedded receipt is verified through step 6 of 10.1 with ``keys`` (the forms
    :func:`verify` takes) and keeps that procedure's codes; then ``trust`` is
    checked against the receipt (``primary`` exactly when the signer's host is
    the namespace's host and there are no inputs) and ``superseded_by`` must not
    be the receipt's own hash (``E_ENVELOPE``).

    Never raises for an invalid envelope; raises TypeError only for a body that
    is not text or bytes, or keys of an unsupported type. Uses no network.
    """
    if not isinstance(body, (str, bytes, bytearray, memoryview)):
        raise TypeError(f"body must be JSON text or bytes, not {type(body).__name__}")
    sources = key_sources(keys)
    try:
        env = _members(parse_json(body))
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
