"""Licence inheritance (SPEC.md 8.5), the entitlement check (10.3) and unrooted namespaces (2.5), since
spec-0.4.3. Pure functions: no network, no verification codes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from . import _lexical as lx
from . import _model
from ._errors import DatumeshError, fail
from ._keys import Declaration, KeysResult, declaration_entries, key_sources, validate_key_document
from ._verify import _input_receipt, _manifest, load, payload_bytes

#: The open licences of SPEC 8.5 by tier, each tier in the order listed there (least to most demanding).
#: Every other licence, compared byte for byte, is restricted (tier 4).
PUBLIC_DOMAIN: Tuple[str, ...] = ("CC0-1.0", "PDDL-1.0")
ATTRIBUTION: Tuple[str, ...] = ("MIT", "Apache-2.0", "CC-BY-4.0", "OGL-UK-3.0")
SHARE_ALIKE: Tuple[str, ...] = ("CC-BY-SA-4.0", "ODbL-1.0")
_OPEN: Dict[str, Tuple[int, int]] = {lic: (tier, i) for tier, names in enumerate((PUBLIC_DOMAIN, ATTRIBUTION,
                                                                                  SHARE_ALIKE), 1)
                                     for i, lic in enumerate(names)}
RESTRICTED_TIER = 4

#: The reasons of SPEC 8.5 and 10.3: the first three entitle (and are the rule's outcomes that give a
#: licence), the next four are the rule's refusals, ``licence_mismatch`` is the entitlement check's own.
REASONS: Tuple[str, ...] = ("no_inputs", "open", "declared", "share_alike_conflict", "restricted_conflict",
                            "not_declared", "declaration_not_open", "licence_mismatch")
ENTITLED_REASONS: Tuple[str, ...] = REASONS[:3]


def licence_tier(licence: str) -> int:
    """The tier of a licence (SPEC 8.5): 1 public domain, 2 attribution, 3 share-alike, 4 restricted (any other
    licence: an ``https://`` URL, or an SPDX identifier not listed, compared byte for byte)."""
    if not isinstance(licence, str):
        raise TypeError(f"licence must be a str, not {type(licence).__name__}")
    return _OPEN.get(licence, (RESTRICTED_TIER, 0))[0]


@dataclass(frozen=True)
class LicenceResult:
    """The outcome of :func:`inherit_licence`: ``licence`` the result's licence, or None when the mesh may not
    compute the cell (it answers ``unlicensed``); ``reason`` the rule's step (SPEC 8.5): ``no_inputs``,
    ``open`` or ``declared`` with a licence, ``share_alike_conflict``, ``restricted_conflict``, ``not_declared``
    or ``declaration_not_open`` for a refusal."""

    licence: Optional[str]
    reason: str

    @property
    def refused(self) -> bool:
        return self.licence is None


@dataclass(frozen=True)
class EntitlementResult:
    """The outcome of :func:`check_entitlement` (SPEC 10.3): ``entitled``, ``reason`` (one of ``REASONS``), and
    ``licence``, the licence the inheritance rule gives (None when it refuses). Not a verification result."""

    entitled: bool
    reason: str
    licence: Optional[str]


def _licences(licences: Any) -> List[str]:
    if isinstance(licences, (str, bytes)) or not isinstance(licences, Iterable):
        raise TypeError("licences must be an iterable of licence strings (an empty one for no inputs)")
    out = []
    for i, lic in enumerate(licences):
        if not isinstance(lic, str):
            raise TypeError(f"licences[{i}] must be a str, not {type(lic).__name__}")
        lx.check_licence(lic, f"licences[{i}]")
        out.append(lic)
    return out


def _entries_for(declarations: Any, fn: str) -> Tuple[Declaration, ...]:
    """The entries declared for ``fn``. ``declarations``: None, a :class:`KeysResult` (its declarations), or a
    mapping of full function name to entries, each a :class:`Declaration` or an object as in a key document."""
    if declarations is None:
        return ()
    if isinstance(declarations, KeysResult):
        if not declarations.ok:
            raise ValueError(f"the key document was not accepted ({declarations.code}): it declares nothing usable")
        declarations = declarations.declarations or {}
    if not isinstance(declarations, Mapping):
        raise TypeError("declarations must be None, a KeysResult, or a mapping of function name to entries")
    entries = declarations.get(fn)
    if entries is None:
        return ()
    if isinstance(entries, (list, tuple)) and all(isinstance(e, Declaration) for e in entries):
        return tuple(entries)
    if isinstance(entries, tuple):
        entries = list(entries)
    return declaration_entries(entries, f"declarations[{fn!r}]")


def inherit_licence(licences: Iterable[str], declarations: Any, fn: str, issued: str,
                    mesh_licence: str) -> LicenceResult:
    """The licence of a computed receipt by the inheritance rule of SPEC 8.5, a pure function.

    ``licences``: the licences of the input receipts, slice members included (repeats allowed; empty for no
    inputs). ``declarations``: the declarations of the function's publisher, read from the key document of the
    host of ``cell.ns`` (None for none; a :class:`KeysResult`; or a mapping of full function name to entries).
    ``fn``: the function's full name, ``cell.ns + "/" + cell.fn``. ``issued``: the receipt's ``issued``.
    ``mesh_licence``: the mesh's own licence, the result when there are no inputs.

    The five steps run in the order of 8.5: no inputs; a share-alike licence with a different share-alike one or
    with any restricted one (``share_alike_conflict``, before every restricted outcome); two different restricted
    licences; one restricted licence, declared for ``fn`` and open at ``issued`` or not; open inputs only.
    Malformed arguments raise :class:`DatumeshError` (a bad licence, name or instant) or TypeError.
    """
    lics = _licences(licences)
    if not isinstance(fn, str):
        raise TypeError("fn must be a str: the function's full name")
    lx.check_function_name(fn, "fn")
    if not isinstance(issued, str):
        raise TypeError("issued must be a str: an instant")
    lx.check_instant(issued, "issued")
    if not isinstance(mesh_licence, str):
        raise TypeError("mesh_licence must be a str")
    lx.check_licence(mesh_licence, "mesh_licence")
    entries = _entries_for(declarations, fn)
    # 1. no inputs
    if not lics:
        return LicenceResult(mesh_licence, "no_inputs")
    distinct = set(lics)
    share_alike = {x for x in distinct if licence_tier(x) == 3}
    restricted = {x for x in distinct if licence_tier(x) == RESTRICTED_TIER}
    # 2. share-alike with a different share-alike licence or with any restricted one
    if share_alike and (len(share_alike) > 1 or restricted):
        return LicenceResult(None, "share_alike_conflict")
    # 3. two different restricted licences
    if len(restricted) > 1:
        return LicenceResult(None, "restricted_conflict")
    # 4. one restricted licence: declared for fn, open at issued
    if restricted:
        (r,) = restricted
        named = [e for e in entries if e.licence == r]
        if not named:
            return LicenceResult(None, "not_declared")
        if not any(e.open_at(issued) for e in named):
            return LicenceResult(None, "declaration_not_open")
        return LicenceResult(r, "declared")
    # 5. open inputs only: the highest tier, and in it the identifier listed last
    return LicenceResult(max(distinct, key=lambda x: _OPEN[x]), "open")


def _publisher_keys(keys: Any, host: str) -> KeysResult:
    """K of SPEC 10.3: an accepted key document of ``host``. Anything else is the caller's error."""
    if isinstance(keys, KeysResult):
        k = keys
    elif isinstance(keys, Mapping) and any(m in keys for m in ("host", "keys", "proto")):
        k = validate_key_document(dict(keys), None)
    else:
        raise TypeError("keys must be the publisher's key document (a parsed dict) or a KeysResult")
    if not k.ok:
        raise ValueError(f"the publisher's key document was not accepted ({k.code}): {k.detail}")
    if k.host != host:
        raise ValueError(f"the key document is of {k.host!r}, not of the publisher's host {host!r} (the host of "
                         "cell.ns, SPEC 10.3)")
    return k


def check_entitlement(receipt: Any, licences: Iterable[str], keys: Any) -> EntitlementResult:
    """The licence entitlement check of SPEC 10.3, a pure function of R, L and K.

    ``receipt`` (R): a receipt (JSON text, bytes or parsed) that has passed verification; its structure and
    canonical form are checked (:class:`DatumeshError`), its signature is not. ``licences`` (L): the licences
    of its input receipts, slice members included, one per receipt (:func:`input_licences` follows them).
    ``keys`` (K): the key document of the publisher's host, the host of ``cell.ns`` even when ``computed_by``
    names another, as a :class:`KeysResult` or a parsed key document. A K of another host, or one that was
    not accepted, is the caller's error (ValueError), never a reason.

    Entitled (``no_inputs``, ``open``, ``declared``) exactly when the receipt's licence is the one 8.5 gives;
    otherwise not entitled, with the rule's refusal reason or ``licence_mismatch``. Never a verification failure.
    """
    r = _receipt(receipt)
    k = _publisher_keys(keys, lx.host_of(r["cell"]["ns"]))
    fn = f"{r['cell']['ns']}/{r['cell']['fn']}"
    res = inherit_licence(licences, k, fn, r["issued"], r["licence"])
    if res.licence is None:
        return EntitlementResult(False, res.reason, None)
    if res.licence != r["licence"]:
        return EntitlementResult(False, "licence_mismatch", res.licence)
    return EntitlementResult(True, res.reason, res.licence)


def _receipt(receipt: Any) -> Dict[str, Any]:
    r = load(receipt)
    _model.receipt_structure(r)
    _model.receipt_canonical(r)
    out: Dict[str, Any] = r
    return out


def _obtained(supplied: Mapping[str, Any], h: str, path: str, what: str) -> Dict[str, Any]:
    """An input receipt without keys: obtained (E_INPUT_UNAVAILABLE), its form checked (E_INPUT_INVALID), and
    of the hash cited (E_INPUT_UNAVAILABLE)."""
    text = supplied.get(h)
    if text is None:
        fail("E_INPUT_UNAVAILABLE", f"{what} receipt {h} not supplied", path)
    try:
        sub = _receipt(text)
    except DatumeshError as e:
        fail("E_INPUT_INVALID", f"{what} {h}: {e.code}: {e.detail}", path)
    sub_hash = hashlib.sha256(payload_bytes(sub)).hexdigest()
    if sub_hash != h:
        fail("E_INPUT_UNAVAILABLE", f"the receipt supplied for {h} hashes to {sub_hash}", path)
    return sub


def input_licences(receipt: Any, receipts: Mapping[str, Any], manifests: Optional[Mapping[str, Any]] = None,
                   keys: Any = None) -> List[str]:
    """L for :func:`check_entitlement` (SPEC 10.3): the licence of every input receipt of ``receipt``, one per
    receipt, in the order of its ``inputs``, a slice entry's members in manifest order.

    ``receipts``: receipt hash to receipt (JSON text or parsed), slice members included; ``manifests``: slice
    entry to manifest. Each input is obtained as 10.1 step 7.5 obtains it: a missing receipt or manifest, or
    one of another hash, slice or members, is E_INPUT_UNAVAILABLE. With ``keys`` (as :func:`verify` takes
    them), each input receipt is also verified through step 6 (E_INPUT_INVALID); without, only its form is
    checked. Slice membership and time order are verification's (10.1), not checked here. Raises
    :class:`DatumeshError`.
    """
    if not isinstance(receipts, Mapping):
        raise TypeError("receipts must be a mapping of receipt hash to receipt")
    if manifests is not None and not isinstance(manifests, Mapping):
        raise TypeError("manifests must be a mapping of slice entry to manifest")
    sources = key_sources(keys) if keys is not None else None
    r = _receipt(receipt)

    def get(h: str, path: str, what: str) -> Dict[str, Any]:
        if sources is None:
            return _obtained(receipts, h, path, what)
        return _input_receipt(receipts, h, sources, path, what)

    out: List[str] = []
    for i, entry in enumerate(r["inputs"]):
        p = f"$.inputs[{i}]"
        if lx.is_slice_entry(entry):
            m = _manifest(manifests or {}, entry, p)
            out.extend(get(mh, p, "member")["licence"] for mh in m["members"])
        else:
            out.append(get(entry, p, "input")["licence"])
    return out


def is_unrooted(name: str) -> bool:
    """SPEC 2.5: whether a namespace (or a host) is unrooted, its host's last label being ``invalid``
    (``local.invalid``, ``agent-7.local.invalid``, ``local.invalid/notes``). The name is checked as a namespace
    (2.3) first: :class:`DatumeshError` (E_CANON_NAME) when it is not one."""
    if not isinstance(name, str):
        raise TypeError(f"name must be a str, not {type(name).__name__}")
    lx.check_namespace(name, "name")
    return lx.host_of(name).rsplit(".", 1)[-1] == "invalid"

