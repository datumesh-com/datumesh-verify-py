"""Response envelopes (SPEC.md 5.5), slice pages (5.6) and batches (5.7): the mesh's unsigned statements
around receipts."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, NoReturn, Optional, Sequence, Tuple, Union

from . import _lexical as lx
from . import _model
from . import _units
from ._errors import ERROR_CODES, FAULT_CODES, DatumeshError, fail
from ._json import jcs_bytes, number_tree, numbers_of, parse_json
from ._keys import _Source, key_sources
from ._verify import _signed

#: outcome -> (HTTP statuses, required members, optional members), SPEC 5.5.
OUTCOMES: Dict[str, Tuple[range, Tuple[str, ...], Tuple[str, ...]]] = {
    "ok": (range(200, 201), ("receipt", "trust"), ("superseded_by", "reason", "fn_hash")),
    "stale": (range(200, 201), ("receipt", "trust", "age_seconds"), ("superseded_by", "reason", "fn_hash")),
    "not_covered": (range(404, 405), (), ("fault", "error", "fn_hash")),
    "unlicensed": (range(403, 404), (), ("fn_hash",)),
    "payment_required": (range(402, 403), ("quote",), ("fn_hash",)),
    "rate_limited": (range(429, 430), ("retry_after_seconds",), ("fn_hash",)),
    "bad_request": (range(400, 401), ("error",), ("fn_hash",)),
    "error": (range(500, 600), ("error",), ("fn_hash",)),
    "pending": (range(202, 203), ("estimate_seconds", "job", "poll", "request"), ()),  # spec-0.4.1
}
#: A page of the slice endpoint (SPEC 5.6, spec-0.4.2): an ``ok`` with these members instead.
PAGE_MEMBERS: Tuple[Tuple[str, ...], Tuple[str, ...]] = (("members", "slice"), ("next", "fn_hash"))
#: Codes a bad_request may carry: the codes parse can raise (SPEC 5.4, 5.5), E_CANON_HEX (a pin) and
#: E_SLICE_AT_CELL since spec-0.4.2. E_JOB_UNKNOWN too, bound to a job URL in step 5.
BAD_REQUEST_CODES = frozenset((
    "E_PARSE_URI", "E_CANON_NAME", "E_CANON_ARG_NAME", "E_CANON_ARG_DUPLICATE", "E_CANON_ARG_ORDER",
    "E_CANON_PERCENT", "E_CANON_TYPE", "E_CANON_NUMBER", "E_CANON_DATE", "E_CANON_INSTANT", "E_CANON_STRING",
    "E_CANON_BLOB", "E_CANON_LIMIT", "E_ARG_UNKNOWN", "E_ARG_MISSING", "E_CANON_HEX", "E_SLICE_AT_CELL"))
#: Codes an error may carry: every code of SPEC 10.2 but E_ENVELOPE, which is a client's, and the request
#: codes E_JOB_UNKNOWN (spec-0.4.1), E_SLICE_AT_CELL and E_NAME_UNBOUND (spec-0.4.2).
ERROR_OUTCOME_CODES = frozenset(c for c in ERROR_CODES
                                if c not in ("E_ENVELOPE", "E_JOB_UNKNOWN", "E_SLICE_AT_CELL", "E_NAME_UNBOUND"))
#: The outcomes that refuse a whole batch (SPEC 5.7).
REFUSALS = ("unlicensed", "payment_required", "rate_limited", "bad_request", "error")
_INTEGER = re.compile(r"0|[1-9][0-9]*")
JOB = re.compile(r"[0-9a-f]{32,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_URL_REST = re.compile(r"[!-~]+")
LIMIT_POLL = 512
LIMIT_NEXT = 512
#: The trust values (SPEC 5.5); ``computed`` since spec-0.4.2.
TRUST = ("primary", "verified", "unverified", "computed")
MAX_SECONDS = 2 ** 53 - 1


@dataclass(frozen=True)
class MemberResult:
    """One member of a slice page (SPEC 5.6, spec-0.4.2): its outcome (``ok`` or ``stale``), trust label and
    receipt hash."""

    outcome: str
    trust: str
    receipt_hash: str


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
    to poll; else None. Since spec-0.4.2: ``fn_hash``, the function hash the envelope
    echoes (or None); ``error``, the code an ``error``, ``bad_request`` or ``not_covered``
    envelope carries (``E_NAME_UNBOUND`` for the last); and for a page of the slice
    endpoint, ``members`` (a :class:`MemberResult` per member, in order) and ``next``.
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
    fn_hash: Optional[str] = None
    error: Optional[str] = None
    members: Tuple[MemberResult, ...] = ()
    next: Optional[str] = None


@dataclass(frozen=True)
class BatchResult:
    """The outcome of :func:`check_batch` (SPEC 5.7, spec-0.4.2).

    ``ok``: the response passed as a whole. ``code``: ``"OK"`` or the whole response's first failure.
    For a 200 response, ``items`` has one :class:`EnvelopeResult` per request, in order; each is ok or
    reports its own failure, which does not fail the others; ``outcome`` is None. For a refusal of the
    whole batch, ``outcome`` is its outcome and ``items`` is empty. ``detail`` and ``path`` as for an
    envelope.
    """

    ok: bool
    code: str
    outcome: Optional[str]
    items: Tuple[EnvelopeResult, ...]
    detail: str
    path: Optional[str]


@dataclass(frozen=True)
class _Request:
    kind: str  # "cell", "slice", or "none" (a refusal of a whole batch: nothing to bind)
    target: Optional[str] = None  # cell_id or slice_id
    asof: Optional[str] = None
    job: Optional[str] = None
    fn_hash: Optional[str] = None
    mesh: Optional[str] = None
    after: Optional[Dict[str, Any]] = None
    extra: Dict[str, Any] = field(default_factory=dict)


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


def _url_host(v: Any, limit: int, name: str, path: str) -> str:
    """``https://``, a DNS name, then a path (``/`` and printable ASCII), at most ``limit`` characters.
    Returns the host."""
    if not isinstance(v, str) or len(v) > limit or not v.startswith("https://") or not _URL_REST.fullmatch(v[8:]):
        _bad(f"{name} is https:// followed by printable ASCII, at most {limit} characters", path)
    host, slash, _ = v[8:].partition("/")
    try:
        lx.check_dns_name(host, path)
    except DatumeshError:
        _bad(f"{name}'s host (between https:// and the next /) is a DNS name (SPEC 2.1): no port, userinfo, "
             "IP address or query", path)
    if not slash:
        _bad(f"{name} has a path after its host", path)
    return host


def _members(env: Any, numbers: Dict[str, str], path: str, at_slice: bool, member: bool = False) -> Dict[str, Any]:
    """Step 2: the members against the table and rules of SPEC 5.5 (and 5.6 at the slice endpoint, where
    ``ok`` is a page; ``member``: a page's member, an ``ok`` or ``stale`` envelope). ``numbers`` holds the
    source text of the top-level members that are JSON numbers."""
    if not isinstance(env, dict):
        _bad("an envelope is a JSON object", path)
    if "outcome" not in env:
        _bad("missing member 'outcome'", path)
    outcome = env["outcome"]
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        _bad(f"outcome is one of {', '.join(OUTCOMES)}", f"{path}.outcome")
    if member and outcome not in ("ok", "stale"):
        _bad("a slice member is an ok or stale envelope", path)
    if at_slice and not member and outcome in ("stale", "pending"):
        _bad(f"{outcome} is not an answer of the slice endpoint", f"{path}.outcome")
    if at_slice and not member and outcome == "ok":
        required, optional = PAGE_MEMBERS
    else:
        _, required, optional = OUTCOMES[outcome]
    allowed = {"outcome", *required, *optional}
    for name in sorted(env):
        if name not in allowed:
            _bad(f"member {name!r} is not allowed with outcome {outcome!r}", f"{path}.{name}")
    for name in sorted(required):
        if name not in env:
            _bad(f"outcome {outcome!r} requires member {name!r}", path)
    if "reason" in env and "superseded_by" not in env:
        _bad("reason is only present with superseded_by", f"{path}.reason")
    if "fault" in env and "error" in env:
        _bad("not_covered carries fault or error, not both", f"{path}.error")
    for name in sorted(env):  # JCS order (all names are ASCII)
        v, p = env[name], f"{path}.{name}"
        if name in ("age_seconds", "retry_after_seconds", "estimate_seconds"):
            _seconds(v, numbers.get(name), p)
        elif name == "error":
            if outcome == "bad_request":
                allowed_codes = BAD_REQUEST_CODES | {"E_JOB_UNKNOWN"}
            elif outcome == "not_covered":
                allowed_codes = frozenset(("E_NAME_UNBOUND",))
            else:
                allowed_codes = ERROR_OUTCOME_CODES
            if not isinstance(v, str) or v not in allowed_codes:
                _bad(f"{outcome} does not carry error {v!r} (SPEC 5.5)", p)
        elif name == "fn_hash":
            if not isinstance(v, str) or not _HEX64.fullmatch(v):
                _bad("fn_hash is 64 lowercase hex digits", p)
        elif name == "job":
            if not isinstance(v, str) or not JOB.fullmatch(v):
                _bad("job is 32 to 64 lowercase hex digits", p)
        elif name == "poll":
            _url_host(v, LIMIT_POLL, "poll", p)
            if not v.endswith("/jobs/" + str(env.get("job"))):
                _bad("poll ends /jobs/<job> with this envelope's job", p)
        elif name == "next":
            _url_host(v, LIMIT_NEXT, "next", p)
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
        elif name == "slice":
            if not isinstance(v, dict):
                _bad("slice is a slice object", p)
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


def _page_members(env: Dict[str, Any], tree: Any, path: str) -> None:
    """Step 1 of SPEC 5.6 for a page's members: an array of ok or stale envelopes."""
    members = env["members"]
    if not isinstance(members, list):
        _bad("members is an array of envelopes", f"{path}.members")
    trees = tree.get("members") if isinstance(tree, dict) else None
    for i, m in enumerate(members):
        mt = trees[i] if isinstance(trees, list) and i < len(trees) else None
        _members(m, numbers_of(mt), f"{path}.members[{i}]", True, member=True)


def _echoed_request(v: Any, path: str) -> None:
    """A pending envelope's ``request``: exactly ``cell_id`` (64 lowercase hex), an optional ``asof`` (an
    instant) and since spec-0.4.2 an optional ``fn_hash`` (the pin)."""
    if not isinstance(v, dict) or "cell_id" not in v or not set(v) <= {"cell_id", "asof", "fn_hash"}:
        _bad("request has exactly cell_id and, when the request carried them, asof and fn_hash", path)
    for k in sorted(v):
        if not isinstance(v[k], str):
            _bad(f"request.{k} is a string", path)
    try:
        lx.check_hex(v["cell_id"], 64, None)
        if "asof" in v:
            lx.check_instant(v["asof"], None)
        if "fn_hash" in v:
            lx.check_hex(v["fn_hash"], 64, None)
    except DatumeshError as e:
        _bad(f"request.cell_id and request.fn_hash are 64 lowercase hex digits and request.asof an instant "
             f"({e.code})", path)


def _is_primary(r: Dict[str, Any]) -> bool:
    """SPEC 5.5: the host of computed_by is the host of cell.ns, and inputs is empty."""
    return r["computed_by"].partition("#")[0] == lx.host_of(r["cell"]["ns"]) and not r["inputs"]


def _check_trust(trust: str, r: Dict[str, Any], mesh: Optional[str], path: str) -> None:
    """Step 6 (SPEC 5.5): primary exactly when the receipt is primary; computed, verified and unverified only
    for a receipt that is not; with the mesh asked known, computed exactly when that mesh signed it."""
    primary = _is_primary(r)
    if (trust == "primary") != primary:
        _bad("trust is primary exactly when the signer's host is the namespace's host and there are no "
             "inputs", path)
    if not primary and mesh is not None:
        signer = r["computed_by"].partition("#")[0]
        if (trust == "computed") != (signer == mesh):
            _bad("with the mesh asked known, trust is computed exactly when that mesh signed a receipt that is not "
                 "primary; verified and unverified are another signer's", path)


def _verify_receipt(v: Dict[str, Any], sources: Tuple[_Source, ...], path: str) -> Tuple[Dict[str, Any], str]:
    try:
        return _signed(v, sources)
    except DatumeshError as e:
        p = e.path
        if p is not None and p.startswith("$"):
            p = path + p[1:]
        raise DatumeshError(e.code, e.detail, p) from None


_REQUEST_HELP = ('request is {"cell_id", "asof"?, "job"?, "fn_hash"?, "mesh"?}, or for the slice endpoint '
                 '{"slice_id", "asof"?, "fn_hash"?, "mesh"?, "after"?}')


def _check_request(request: Any) -> _Request:
    """A request description (SPEC 5.5, 5.6). A malformed one is the caller's error: TypeError or ValueError."""
    if not isinstance(request, Mapping):
        raise TypeError(_REQUEST_HELP)
    if "slice_id" in request:
        kind, target_name, allowed = "slice", "slice_id", {"slice_id", "asof", "fn_hash", "mesh", "after"}
    else:
        kind, target_name, allowed = "cell", "cell_id", {"cell_id", "asof", "job", "fn_hash", "mesh"}
    if target_name not in request or not set(request) <= allowed:
        raise ValueError(_REQUEST_HELP)
    for k in sorted(set(request) - {"after"}):
        if not isinstance(request[k], str):
            raise TypeError(f"request {k} is a string")
    target, asof, job = request[target_name], request.get("asof"), request.get("job")
    fn_hash, mesh, after = request.get("fn_hash"), request.get("mesh"), request.get("after")
    try:
        lx.check_hex(target, 64, f"request.{target_name}")
        if asof is not None:
            lx.check_instant(asof, "request.asof")
        if fn_hash is not None:
            lx.check_hex(fn_hash, 64, "request.fn_hash")
        if mesh is not None:
            lx.check_dns_name(mesh, "request.mesh")
        if "after" in request:
            if not isinstance(after, dict) or not after:
                raise ValueError("request after is an object from open argument names to typed scalars")
            for name in sorted(after):
                lx.check_arg_name(name, f"request.after.{name}")
                _model.validate_scalar(after[name], f"request.after.{name}")
    except DatumeshError as e:
        raise ValueError(f"invalid request: {e}") from None
    if job is not None and not JOB.fullmatch(job):
        raise ValueError("invalid request: job is 32 to 64 lowercase hex digits")
    return _Request(kind, target, asof, job, fn_hash, mesh, after)


def _key(slice_obj: Dict[str, Any], args: Dict[str, Any]) -> Optional[Tuple[Any, ...]]:
    """A member's key (SPEC 15.13): its open (or ranged) arguments in ascending name order, each in its
    type's order (booleans false before true). None when ``args`` lacks one of them or has another type."""
    out: List[Any] = []
    sargs = slice_obj["args"] if "args" in slice_obj else {}
    for name in _model._sorted(sargs):
        s = sargs[name]
        if s != _model.SLICE and "value" in s:
            continue
        a = args.get(name)
        if not isinstance(a, dict) or "type" not in a or "value" not in a:
            return None
        t = a["type"]
        if s != _model.SLICE and t != s.get("type"):
            return None
        out.append((t, a["value"] if t == "boolean" else lx.order_key(t, a["value"])))
    return tuple(out)


def _check_parsed(status: Any, env_v: Any, tree: Any, sources: Tuple[_Source, ...], req: _Request,
                  path: str = "$", outcomes: Optional[Tuple[str, ...]] = None) -> EnvelopeResult:
    """Steps 2-6 of SPEC 5.5 (and 5.6 at the slice endpoint) on a parsed envelope. Raises DatumeshError."""
    at_slice = req.kind == "slice"
    env = _members(env_v, numbers_of(tree), path, at_slice)
    outcome = env["outcome"]
    page = at_slice and outcome == "ok"
    if page:
        _page_members(env, tree, path)
    if outcomes is not None and outcome not in outcomes:
        _bad("a batch is refused whole only by a refusal outcome", f"{path}.outcome")
    if isinstance(status, bool) or not isinstance(status, int) or status not in OUTCOMES[outcome][0]:
        _bad(f"HTTP status {status!r} does not match outcome {outcome!r}", "status" if path == "$" else path)
    # the fn_hash echo against the pin (spec-0.4.2), before the receipt, as the reference tool orders it
    if req.fn_hash is not None and req.kind != "none":
        if "fn_hash" in env and env["fn_hash"] != req.fn_hash:
            _bad("fn_hash echoes another function than the one pinned", f"{path}.fn_hash")
        if "fn_hash" not in env and outcome not in ("rate_limited", "bad_request", "pending"):
            _bad("an envelope answering a pinned request echoes its fn_hash", f"{path}.fn_hash")
    trust: Optional[str] = None
    h: Optional[str] = None
    r: Optional[Dict[str, Any]] = None
    if "receipt" in env:  # step 4
        r, h = _verify_receipt(env["receipt"], sources, f"{path}.receipt")
    # step 5: the answer answers the request
    if req.kind == "cell" and r is not None:
        if hashlib.sha256(jcs_bytes(r["cell"])).hexdigest() != req.target:
            _bad("the receipt's cell is not the cell requested", f"{path}.receipt.cell")
        # ok and stale alike: the receipt's asof at or before the requested one (D31); none requested: any
        if req.asof is not None and r["asof"] > req.asof:
            _bad(f"the {outcome} receipt answers as of {r['asof']}, after the requested {req.asof}",
                 f"{path}.receipt.asof")
    if outcome == "pending" and req.kind == "cell":
        echo = env["request"]
        if echo["cell_id"] != req.target or echo.get("asof") != req.asof or echo.get("fn_hash") != req.fn_hash:
            _bad("the pending envelope echoes another request (cell_id; asof and fn_hash present exactly when "
                 "requested, and equal)", f"{path}.request")
        if req.job is not None and env["job"] != req.job:
            _bad("the pending envelope is for another job than the one polled", f"{path}.job")
    if env.get("error") == "E_JOB_UNKNOWN" and req.job is None:
        _bad("E_JOB_UNKNOWN answers a job URL only, not a /cell request", f"{path}.error")
    # the fn_hash echo against the receipt (spec-0.4.2)
    if r is not None and "fn_hash" in env and env["fn_hash"] != r["cell"]["fn_hash"]:
        _bad("fn_hash echoes another function than the receipt's", f"{path}.fn_hash")
    # step 6
    if r is not None:
        trust = env["trust"]
        _check_trust(trust, r, req.mesh, f"{path}.trust")
        if env.get("superseded_by") == h:
            _bad("superseded_by is the receipt's own hash", f"{path}.superseded_by")
    if outcome == "pending" and req.mesh is not None and _url_host(env["poll"], LIMIT_POLL, "poll", "") != req.mesh:
        _bad("poll is on another host than the mesh asked", f"{path}.poll")
    members: Tuple[MemberResult, ...] = ()
    if page:
        members = _check_page(env, sources, req, path)
    fault, error = env.get("fault"), env.get("error")
    detail = "well-formed envelope" + ("; receipt signature-valid" if h else "") + (
        f"; evaluation fault {fault}" if fault else "") + (f"; job {env['job']}" if outcome == "pending" else "") + (
        f"; a page of {len(members)} members" if page else "")
    if outcome == "pending":
        return EnvelopeResult(True, "OK", outcome, None, None, detail, None, None, env["job"],
                              int(numbers_of(tree)["estimate_seconds"]), env["poll"])
    return EnvelopeResult(True, "OK", outcome, trust, h, detail, None, fault, None, None, None, env.get("fn_hash"),
                          error, members, env.get("next"))


def _check_page(env: Dict[str, Any], sources: Tuple[_Source, ...], req: _Request, path: str) -> Tuple[MemberResult, ...]:
    """Steps 2-3 of SPEC 5.6 for a page whose members' shapes are checked."""
    sl = env["slice"]
    if hashlib.sha256(jcs_bytes(sl)).hexdigest() != req.target:
        _bad("the page is of another slice than the one requested", f"{path}.slice")
    try:
        _model.validate_slice(sl, f"{path}.slice")
    except DatumeshError as e:
        _bad(f"slice is a slice object ({e.code})", f"{path}.slice")
    if "next" in env and req.mesh is not None and _url_host(env["next"], LIMIT_NEXT, "next", "") != req.mesh:
        _bad("next is on another host than the mesh asked", f"{path}.next")
    slice_hash = sl["cell"]["fn_hash"] if _model.is_version_slice(sl) else sl["fn_hash"]
    if "fn_hash" in env and env["fn_hash"] != slice_hash:
        _bad("fn_hash echoes another function than the slice's", f"{path}.fn_hash")
    previous: Optional[Tuple[Any, ...]] = None
    if req.after is not None:
        previous = _key(sl, req.after)
        if previous is None:
            _bad("after does not name the slice's open arguments with their types", "request.after")
    out: List[MemberResult] = []
    for i, m in enumerate(env["members"]):
        mp = f"{path}.members[{i}]"
        r, h = _verify_receipt(m["receipt"], sources, f"{mp}.receipt")
        why = _model.member_of(sl, r)
        if why is not None:
            _bad(f"the member is not a cell of the slice: {why}", f"{mp}.receipt.cell")
        if req.asof is not None and r["asof"] > req.asof:
            _bad(f"the member answers as of {r['asof']}, after the requested {req.asof}", f"{mp}.receipt.asof")
        if "fn_hash" in m and m["fn_hash"] != r["cell"]["fn_hash"]:
            _bad("fn_hash echoes another function than the receipt's", f"{mp}.fn_hash")
        _check_trust(m["trust"], r, req.mesh, f"{mp}.trust")
        if m.get("superseded_by") == h:
            _bad("superseded_by is the receipt's own hash", f"{mp}.superseded_by")
        key = _key(sl, r["cell"]["args"])
        if key is None or (previous is not None and [t for t, _ in key] != [t for t, _ in previous]):
            _bad("a member's key and the cursor or the previous member's key have other types", mp)
        if previous is not None and not key > previous:
            _bad("members are in strictly ascending key order, after the cursor", mp)
        previous = key
        out.append(MemberResult(m["outcome"], m["trust"], h))
    return tuple(out)


def check_envelope(status: Any, body: Union[str, bytes, bytearray, memoryview], keys: Any,
                   request: Mapping[str, Any]) -> EnvelopeResult:
    """Check a mesh's response (SPEC 5.5): the HTTP ``status`` and the ``body`` (JSON text or bytes)
    against the ``request`` it answers.

    ``request`` is ``{"cell_id": <hex>, "asof": <instant>, "job": <id>, "fn_hash": <hex>, "mesh": <host>}``:
    the cell id (SPEC 4.4) of the cell requested, that is the cell its URI denotes with
    the ``fn_hash`` you resolved (or pinned); the ``asof`` of the request, omitted when
    the request had none; ``job`` when polling (below); ``fn_hash`` (spec-0.4.2) when the
    request was pinned; and ``mesh`` (spec-0.4.2), optionally, the host you sent the
    request to. For the slice endpoint (SPEC 5.6) it is ``{"slice_id", "asof"?,
    "fn_hash"?, "mesh"?, "after"?}``, ``after`` the key of the last member already
    received (open argument name to typed scalar).

    Steps, first failure reported: strict JSON (6.1); members against the table
    of 5.5 (``E_ENVELOPE``); the status matches the outcome (``E_ENVELOPE``); an
    embedded receipt is verified through step 6 of 10.1 with ``keys`` (the forms
    :func:`verify` takes) and keeps that procedure's codes; the receipt answers
    the request: same cell id, and when an ``asof`` was requested a receipt
    ``asof`` at or before it, for ``ok`` and ``stale`` alike (``E_ENVELOPE``); the
    ``fn_hash`` echo (a pinned request's answers carry the pin, except
    ``rate_limited``, ``bad_request`` and ``pending``; with a receipt it is the
    receipt's); then ``trust`` against the receipt (``primary`` exactly when the
    signer's host is the namespace's host and there are no inputs; with ``mesh``,
    ``computed`` exactly when that host signed it), ``superseded_by`` not the
    receipt's own hash, and with ``mesh`` a ``poll`` on it (``E_ENVELOPE``).
    Without ``mesh``, comparing ``computed`` and ``poll`` with the host asked is
    your own check, to make before relying on them.

    Jobs (spec-0.4.1): a ``pending`` envelope (202) echoes the request; its
    ``request`` must equal ``request`` (the same ``cell_id``, ``asof`` and ``fn_hash``
    present exactly when requested, and equal). When polling a job, pass the ORIGINAL
    request with ``"job": <the job polled>``: a ``pending`` answer must then carry
    that job, a ``bad_request`` may carry ``E_JOB_UNKNOWN`` (without ``job`` it is
    ``E_ENVELOPE``), and any other answer is bound to the original ``cell_id`` and
    ``asof`` as above, never to the job URL.

    Slice pages (SPEC 5.6): an ``ok`` answer is a page (``slice``, ``members``,
    ``next``); every member is an ``ok`` or ``stale`` envelope whose receipt verifies
    (10.1's codes), is a cell of the slice, answers as of the requested ``asof`` or
    before, is labelled by the trust rules, and has a key after the previous member's
    and after ``after``. ``stale`` and ``pending`` are not answers there.

    Never raises for an invalid envelope; raises TypeError for a body that is not
    text or bytes, keys of an unsupported type or a request that is not a mapping,
    and ValueError for a malformed request. Uses no network.
    """
    if not isinstance(body, (str, bytes, bytearray, memoryview)):
        raise TypeError(f"body must be JSON text or bytes, not {type(body).__name__}")
    sources = key_sources(keys)
    req = _check_request(request)
    try:
        parsed = parse_json(body)
        return _check_parsed(status, parsed, number_tree(body), sources, req)
    except DatumeshError as e:
        return EnvelopeResult(False, e.code, None, None, None, e.detail, e.path)


def check_batch(status: Any, body: Union[str, bytes, bytearray, memoryview], keys: Any,
                requests: Sequence[Mapping[str, Any]]) -> BatchResult:
    """Check a mesh's answer to a batch (SPEC 5.7, spec-0.4.2): ``POST <cells>`` with one request per item.

    ``requests`` is the list of request descriptions, as :func:`check_envelope` takes them, one per request
    sent, in order. A 200 answer is an array with exactly one item per request, each exactly ``{"envelope",
    "status"}`` with ``status`` an integer 100-599 (else the whole answer fails, ``E_ENVELOPE``); each item is
    then checked as an envelope, with its own status, against its own request, and reported in its place in
    ``items``: a failing item does not fail the others. Any other status is a refusal of the whole batch:
    one envelope of outcome ``unlicensed``, ``payment_required``, ``rate_limited``, ``bad_request`` or
    ``error``, with nothing to bind. Never raises for an invalid answer; TypeError or ValueError for
    malformed arguments, as for :func:`check_envelope`. Uses no network.
    """
    if not isinstance(body, (str, bytes, bytearray, memoryview)):
        raise TypeError(f"body must be JSON text or bytes, not {type(body).__name__}")
    if not isinstance(requests, (list, tuple)):
        raise TypeError("requests is a list of request descriptions, one per request in the batch")
    reqs = [_check_request(r) for r in requests]
    sources = key_sources(keys)
    try:
        parsed = parse_json(body)
        tree = number_tree(body)
        if not (isinstance(status, int) and not isinstance(status, bool) and status == 200):
            res = _check_parsed(status, parsed, tree, sources, _Request("none"), outcomes=REFUSALS)
            return BatchResult(True, "OK", res.outcome, (), f"the batch refused whole: {res.outcome}", None)
        if not isinstance(parsed, list) or len(parsed) != len(reqs):
            _bad("a batch response is an array with one item per request", "$")
        for i, item in enumerate(parsed):
            p = f"$[{i}]"
            if not isinstance(item, dict) or set(item) != {"envelope", "status"}:
                _bad("an item is exactly {envelope, status}", p)
            text = numbers_of(tree[i]).get("status")
            st = item["status"]
            if (isinstance(st, bool) or not isinstance(st, (int, float)) or text is None
                    or not _INTEGER.fullmatch(text) or not 100 <= int(text) <= 599):
                _bad("an item's status is an HTTP status code, an integer 100-599", f"{p}.status")
        items: List[EnvelopeResult] = []
        for i, (item, req) in enumerate(zip(parsed, reqs)):
            try:
                env_tree = tree[i]["envelope"]
                st = int(numbers_of(tree[i])["status"])
                items.append(_check_parsed(st, item["envelope"], env_tree, sources, req, f"$[{i}].envelope"))
            except DatumeshError as e:
                items.append(EnvelopeResult(False, e.code, None, None, None, e.detail, e.path))
        failed = sum(1 for x in items if not x.ok)
        return BatchResult(True, "OK", None, tuple(items), f"{len(items)} items, {failed} failing", None)
    except DatumeshError as e:
        return BatchResult(False, e.code, None, (), e.detail, e.path)
