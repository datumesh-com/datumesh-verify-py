"""Response envelopes (SPEC.md 5.5): the mesh's unsigned statement around a receipt."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, NoReturn, Optional, Tuple, Union

from . import _lexical as lx
from . import _units
from ._errors import ERROR_CODES, FAULT_CODES, DatumeshError, fail
from ._json import jcs_bytes, number_texts, parse_json
from ._keys import key_sources
from ._verify import _signed

#: outcome -> (HTTP statuses, required members, optional members), SPEC 5.5.
OUTCOMES: Dict[str, Tuple[range, Tuple[str, ...], Tuple[str, ...]]] = {
    "ok": (range(200, 201), ("receipt", "trust"), ("superseded_by", "reason")),
    "stale": (range(200, 201), ("receipt", "trust", "age_seconds"), ("superseded_by", "reason")),
    "not_covered": (range(404, 405), (), ("fault",)),
    "unlicensed": (range(403, 404), (), ()),
    "payment_required": (range(402, 403), ("quote",), ()),
    "rate_limited": (range(429, 430), ("retry_after_seconds",), ()),
    "bad_request": (range(400, 401), ("error",), ()),
    "error": (range(500, 600), ("error",), ()),
    "pending": (range(202, 203), ("estimate_seconds", "job", "poll", "request"), ()),  # spec-0.4.1
}
#: Codes a bad_request may carry: the codes parse can raise (SPEC 5.4, 5.5).
BAD_REQUEST_CODES = frozenset((
    "E_PARSE_URI", "E_CANON_NAME", "E_CANON_ARG_NAME", "E_CANON_ARG_DUPLICATE", "E_CANON_ARG_ORDER",
    "E_CANON_PERCENT", "E_CANON_TYPE", "E_CANON_NUMBER", "E_CANON_DATE", "E_CANON_INSTANT", "E_CANON_STRING",
    "E_CANON_BLOB", "E_CANON_LIMIT", "E_ARG_UNKNOWN", "E_ARG_MISSING"))
#: Codes an error may carry: every code of SPEC 10.2 but E_ENVELOPE, which is a client's, and E_JOB_UNKNOWN
#: (spec-0.4.1), which is a bad_request's at a job URL.
ERROR_OUTCOME_CODES = frozenset(c for c in ERROR_CODES if c not in ("E_ENVELOPE", "E_JOB_UNKNOWN"))
_INTEGER = re.compile(r"0|[1-9][0-9]*")
JOB = re.compile(r"[0-9a-f]{32,64}")
_URL_REST = re.compile(r"[!-~]+")
LIMIT_POLL = 512
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
    ``$.receipt.sig``), or None. ``fault`` (spec-0.4.0): for a ``not_covered``
    envelope, the formula evaluation fault it carries (one of ``FAULT_CODES``): the
    cell is computed and its evaluation faulted, so it has no value, which is not
    missing data; else None. ``job``, ``estimate_seconds`` and ``poll`` (spec-0.4.1):
    for a ``pending`` envelope, the job id, the mesh's estimate in seconds and the URL
    to poll; else None.
    """

    ok: bool
    code: str
    outcome: Optional[str]
    trust: Optional[str]
    receipt_hash: Optional[str]
    detail: str
    path: Optional[str]
    fault: Optional[str] = None
    job: Optional[str] = None
    estimate_seconds: Optional[int] = None
    poll: Optional[str] = None


def _bad(detail: str, path: str) -> NoReturn:
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
        if name in ("age_seconds", "retry_after_seconds", "estimate_seconds"):
            _seconds(v, numbers.get(name), p)
        elif name == "error":
            # E_JOB_UNKNOWN in bad_request is bound to a job URL in step 5
            allowed_codes = BAD_REQUEST_CODES | {"E_JOB_UNKNOWN"} if outcome == "bad_request" else ERROR_OUTCOME_CODES
            if not isinstance(v, str) or v not in allowed_codes:
                _bad("bad_request carries a code parse can raise (SPEC 5.4), or E_JOB_UNKNOWN" if outcome == "bad_request"
                     else "error is a code from SPEC 10.2 other than E_ENVELOPE and E_JOB_UNKNOWN", p)
        elif name == "job":
            if not isinstance(v, str) or not JOB.fullmatch(v):
                _bad("job is 32 to 64 lowercase hex digits", p)
        elif name == "poll":
            if (not isinstance(v, str) or len(v) > LIMIT_POLL or not v.startswith("https://")
                    or not _URL_REST.fullmatch(v[8:])):
                _bad(f"poll is https:// followed by printable ASCII, at most {LIMIT_POLL} characters", p)
            if not v.endswith("/jobs/" + str(env.get("job"))):
                _bad("poll ends /jobs/<job> with this envelope's job", p)
        elif name == "request":
            _echoed_request(v, p)
        elif name == "fault":
            if not isinstance(v, str) or v not in FAULT_CODES:
                _bad(f"fault is a formula evaluation fault: one of {', '.join(FAULT_CODES)}", p)
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


def _echoed_request(v: Any, path: str) -> None:
    """A pending envelope's ``request`` (spec-0.4.1): exactly ``cell_id`` (64 lowercase hex) and an optional
    ``asof`` (an instant)."""
    if not isinstance(v, dict) or "cell_id" not in v or not set(v) <= {"cell_id", "asof"}:
        _bad("request has exactly cell_id and, when the request carried one, asof", path)
    try:
        if not isinstance(v["cell_id"], str):
            raise DatumeshError("E_CANON_HEX", "not a string")
        lx.check_hex(v["cell_id"], 64, None)
        if "asof" in v:
            if not isinstance(v["asof"], str):
                raise DatumeshError("E_CANON_INSTANT", "not a string")
            lx.check_instant(v["asof"], None)
    except DatumeshError as e:
        _bad(f"request.cell_id is 64 lowercase hex digits and request.asof an instant ({e.code})", path)


def _is_primary(r: Dict[str, Any]) -> bool:
    """SPEC 5.5: the host of computed_by is the host of cell.ns, and inputs is empty."""
    return r["computed_by"].partition("#")[0] == lx.host_of(r["cell"]["ns"]) and not r["inputs"]


def _check_request(request: Any) -> Tuple[str, Optional[str], Optional[str]]:
    if not isinstance(request, Mapping):
        raise TypeError('request must be {"cell_id": <hex>, "asof": <instant> (optional), "job": <id> (optional)}')
    if not set(request) <= {"cell_id", "asof", "job"} or "cell_id" not in request:
        raise ValueError('request has cell_id, and optionally asof and job, nothing else')
    cell_id, asof, job = request["cell_id"], request.get("asof"), request.get("job")
    if not isinstance(cell_id, str) or ("asof" in request and not isinstance(asof, str)) \
            or ("job" in request and not isinstance(job, str)):
        raise TypeError("request cell_id, asof and job are strings")
    try:
        lx.check_hex(cell_id, 64, "request.cell_id")
        if asof is not None:
            lx.check_instant(asof, "request.asof")
    except DatumeshError as e:
        raise ValueError(f"invalid request: {e}") from None
    if job is not None and not JOB.fullmatch(job):
        raise ValueError("invalid request: job is 32 to 64 lowercase hex digits")
    return cell_id, asof, job


def check_envelope(status: Any, body: Union[str, bytes, bytearray, memoryview], keys: Any,
                   request: Mapping[str, str]) -> EnvelopeResult:
    """Check a mesh's response (SPEC 5.5): the HTTP ``status`` and the ``body`` (JSON text or bytes)
    against the ``request`` it answers.

    ``request`` is ``{"cell_id": <hex>, "asof": <instant>, "job": <id>}``: the cell id (SPEC 4.4) of
    the cell requested, that is the cell its URI denotes with the ``fn_hash`` you
    resolved, and the ``asof`` of the request, omitted when the request had none.

    Steps, first failure reported: strict JSON (6.1); members against the table
    of 5.5 (``E_ENVELOPE``); the status matches the outcome (``E_ENVELOPE``); an
    embedded receipt is verified through step 6 of 10.1 with ``keys`` (the forms
    :func:`verify` takes) and keeps that procedure's codes; the receipt answers
    the request: same cell id, and when an ``asof`` was requested a receipt
    ``asof`` at or before it, for ``ok`` and ``stale`` alike (``E_ENVELOPE``); then ``trust`` is checked against the receipt (``primary``
    exactly when the signer's host is the namespace's host and there are no
    inputs) and ``superseded_by`` must not be the receipt's own hash (``E_ENVELOPE``).
    A ``not_covered`` envelope may carry ``fault``, a formula evaluation fault
    (spec-0.4.0), exposed as ``EnvelopeResult.fault``.

    Jobs (spec-0.4.1): a ``pending`` envelope (202) echoes the request; its
    ``request`` must equal ``request`` (the same ``cell_id``, ``asof`` present
    exactly when requested, and equal). When polling a job, pass the ORIGINAL
    request with ``"job": <the job polled>``: a ``pending`` answer must then carry
    that job, a ``bad_request`` may carry ``E_JOB_UNKNOWN`` (without ``job`` it is
    ``E_ENVELOPE``), and any other answer is bound to the original ``cell_id`` and
    ``asof`` as above, never to the job URL.

    Never raises for an invalid envelope; raises TypeError for a body that is not
    text or bytes, keys of an unsupported type or a request that is not a mapping,
    and ValueError for a malformed request. Uses no network.
    """
    if not isinstance(body, (str, bytes, bytearray, memoryview)):
        raise TypeError(f"body must be JSON text or bytes, not {type(body).__name__}")
    sources = key_sources(keys)
    want_cell, want_asof, want_job = _check_request(request)
    try:
        parsed = parse_json(body)
        numbers = number_texts(body) if isinstance(parsed, dict) else {}
        env = _members(parsed, numbers)
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
            # ok and stale alike: the receipt's asof at or before the requested one (D31, spec-0.3.0;
            # canonical instants compare as strings, SPEC 3.3). No requested asof: any.
            if want_asof is not None and r["asof"] > want_asof:
                _bad(f"the {outcome} receipt answers as of {r['asof']}, after the requested {want_asof}",
                     "$.receipt.asof")
            trust = env["trust"]
            if (trust == "primary") != _is_primary(r):
                _bad("trust is primary exactly when the signer's host is the namespace's host and there are no "
                     "inputs", "$.trust")
            if env.get("superseded_by") == h:
                _bad("superseded_by is the receipt's own hash", "$.superseded_by")
        if outcome == "pending":
            # step 5 for pending (spec-0.4.1): the echo is the request made, and the job is the one polled
            echo = env["request"]
            if echo["cell_id"] != want_cell:
                _bad("the pending envelope echoes another cell than the one requested", "$.request.cell_id")
            if echo.get("asof") != want_asof:
                _bad("the pending envelope's echoed asof is not the requested asof (present exactly when "
                     "requested, and equal)", "$.request")
            if want_job is not None and env["job"] != want_job:
                _bad("the pending envelope is for another job than the one polled", "$.job")
        if env.get("error") == "E_JOB_UNKNOWN" and want_job is None:
            _bad("E_JOB_UNKNOWN answers a job URL only, not a /cell request", "$.error")
        fault = env.get("fault")
        detail = "well-formed envelope" + ("; receipt signature-valid" if h else "") + (
            f"; evaluation fault {fault}" if fault else "") + (f"; job {env['job']}" if outcome == "pending" else "")
        if outcome == "pending":
            return EnvelopeResult(True, "OK", outcome, None, None, detail, None, None, env["job"],
                                  int(numbers["estimate_seconds"]), env["poll"])
        return EnvelopeResult(True, "OK", outcome, trust, h, detail, None, fault)
    except DatumeshError as e:
        return EnvelopeResult(False, e.code, None, None, None, e.detail, e.path)
