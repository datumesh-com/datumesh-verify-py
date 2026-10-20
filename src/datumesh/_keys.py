"""Keys (SPEC.md section 9): key ids, key documents, and their retrieval over HTTPS."""

from __future__ import annotations

import hashlib
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, Union

from . import _lexical as lx
from ._errors import DatumeshError, fail
from ._json import parse_json
from ._model import PROTO, require_object

WELL_KNOWN_PATH = "/.well-known/datumesh.json"
MAX_DOCUMENT_BYTES = 1 << 20


def key_id(public: str) -> str:
    """The key id of an Ed25519 public key given as 64 lowercase hex digits (SPEC 9.1)."""
    if not isinstance(public, str):
        raise TypeError("public must be a str of 64 lowercase hex digits")
    lx.check_hex(public, 64, "public")
    return hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16]


@dataclass(frozen=True)
class Key:
    """One published key. ``valid_from``/``valid_to`` are instants, or None for keys
    supplied as a bare ``{key id: public key}`` mapping (no validity window)."""

    id: str
    public: str
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None

    def usable_at(self, issued: str) -> bool:
        """SPEC 9.5: ``valid_from <= issued`` and, if present, ``issued < valid_to``."""
        if self.valid_from is not None and not self.valid_from <= issued:
            return False
        return self.valid_to is None or issued < self.valid_to


@dataclass(frozen=True)
class KeysResult:
    """The outcome of resolving a host's keys (SPEC 9.3).

    ``ok`` is True and ``code`` is ``"OK"`` when ``keys`` holds the host's
    validated keys; otherwise ``code`` is ``E_KEY_UNAVAILABLE`` or ``E_KEY_DOC``
    and ``keys`` is empty. ``host`` is the host the keys belong to.
    """

    ok: bool
    code: str
    host: Optional[str]
    detail: str = ""
    keys: Tuple[Key, ...] = field(default_factory=tuple)

    @property
    def key_ids(self) -> Tuple[str, ...]:
        return tuple(k.id for k in self.keys)


def _doc_error(host: Optional[str], detail: str) -> KeysResult:
    return KeysResult(False, "E_KEY_DOC", host, detail)


def validate_key_document(doc: Any, host: Optional[str]) -> KeysResult:
    """Check a parsed key document against SPEC 9.2. ``host`` is the host it was
    fetched from (None: take the document's own ``host`` member)."""
    try:
        require_object(doc, "$", ("host", "keys", "proto"))
        if doc["proto"] != PROTO:
            fail("E_SCHEMA", f"proto must be {PROTO!r}", "$.proto")
        doc_host = doc["host"]
        if not isinstance(doc_host, str):
            fail("E_SCHEMA", "host must be a string", "$.host")
        lx.check_dns_name(doc_host, "$.host")
        if host is not None and doc_host != host:
            fail("E_SCHEMA", f"document is for host {doc_host!r}, fetched from {host!r}", "$.host")
        keys = doc["keys"]
        if not isinstance(keys, list) or not 1 <= len(keys) <= lx.LIMIT_KEYS:
            fail("E_SCHEMA", f"keys must be an array of 1 to {lx.LIMIT_KEYS} keys", "$.keys")
        out = []
        seen_ids: set[str] = set()
        seen_public: set[str] = set()
        for i, entry in enumerate(keys):
            p = f"$.keys[{i}]"
            require_object(entry, p, ("alg", "id", "public", "valid_from"), ("valid_to",))
            for name in ("alg", "id", "public", "valid_from", "valid_to"):
                if name in entry and not isinstance(entry[name], str):
                    fail("E_SCHEMA", f"{name} must be a string", f"{p}.{name}")
            if entry["alg"] != "ed25519":
                fail("E_SCHEMA", "alg must be 'ed25519'", f"{p}.alg")
            lx.check_hex(entry["id"], 16, f"{p}.id")
            lx.check_hex(entry["public"], 64, f"{p}.public")
            if key_id(entry["public"]) != entry["id"]:
                fail("E_SCHEMA", "id is not the key id of public", f"{p}.id")
            lx.check_instant(entry["valid_from"], f"{p}.valid_from")
            valid_to = entry.get("valid_to")
            if valid_to is not None:
                lx.check_instant(valid_to, f"{p}.valid_to")
                if not valid_to > entry["valid_from"]:
                    fail("E_SCHEMA", "valid_to must be later than valid_from", f"{p}.valid_to")
            if entry["id"] in seen_ids or entry["public"] in seen_public:
                fail("E_SCHEMA", "the same key appears twice", p)
            seen_ids.add(entry["id"])
            seen_public.add(entry["public"])
            out.append(Key(entry["id"], entry["public"], entry["valid_from"], valid_to))
        return KeysResult(True, "OK", doc_host, "", tuple(out))
    except DatumeshError as e:
        where = f" at {e.path}" if e.path else ""
        return _doc_error(host if host is not None else (doc.get("host") if isinstance(doc, dict) and isinstance(doc.get("host"), str) else None),
                          f"{e.code}{where}: {e.detail}")


def keys_from_response(host: str, status: Optional[int], body: Union[str, bytes, None]) -> KeysResult:
    """Interpret the response to ``GET https://<host>/.well-known/datumesh.json`` (SPEC 9.3).

    ``status`` is the HTTP status, or None for a network, DNS, TLS or timeout
    failure. Any status other than 200 (redirects and 404 included) is
    E_KEY_UNAVAILABLE; a 200 whose body is not a valid key document for
    ``host``, or any 200 for a host that is not a DNS name, is E_KEY_DOC.
    Never raises.
    """
    if not isinstance(host, str):
        return KeysResult(False, "E_KEY_UNAVAILABLE", None, f"host must be a str, not {type(host).__name__}")
    if status is None:
        return KeysResult(False, "E_KEY_UNAVAILABLE", host, "network, DNS, TLS or timeout failure")
    if isinstance(status, bool) or not isinstance(status, int) or status != 200:
        return KeysResult(False, "E_KEY_UNAVAILABLE", host, f"HTTP status {status!r}")
    try:
        lx.check_dns_name(host, "host")
    except DatumeshError as e:
        # SPEC 9.3: a response offered for a host that is not a DNS name cannot satisfy 9.2.
        return _doc_error(host, f"a document for a host that is not a DNS name cannot satisfy 9.2: {e.detail}")
    if body is None:
        return _doc_error(host, "200 response without a body")
    if not isinstance(body, (str, bytes, bytearray, memoryview)):
        return _doc_error(host, f"body must be str or bytes, not {type(body).__name__}")
    try:
        doc = parse_json(body)
    except DatumeshError as e:
        return _doc_error(host, f"{e.code}: {e.detail}")
    return validate_key_document(doc, host)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None  # urllib then raises HTTPError with the 3xx status


def _fetch_url(url: str, timeout: float, context: Optional[ssl.SSLContext] = None) -> Tuple[Optional[int], Optional[bytes]]:
    """One GET without following redirects. Returns (status, body); status None on any failure."""
    ctx = context if context is not None else ssl.create_default_context()
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, method="GET", headers={
        "Accept": "application/json",
        "User-Agent": "datumesh-py",
    })
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(MAX_DOCUMENT_BYTES + 1)
            return resp.status, body
    except urllib.error.HTTPError as e:
        try:
            e.close()
        except Exception:  # pragma: no cover
            pass
        return e.code, None
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, TimeoutError, ConnectionError, OSError, ValueError):
        return None, None


def fetch_keys(host: str, timeout: float = 10.0) -> KeysResult:
    """Fetch and validate ``https://<host>/.well-known/datumesh.json`` (SPEC 9.3, 9.4).

    One GET; the TLS certificate is verified against the system trust store;
    redirects are not followed (a 3xx is E_KEY_UNAVAILABLE); ``timeout`` is in
    seconds. This is the only function in the package that uses the network,
    and nothing else calls it.
    """
    if not isinstance(host, str):
        raise TypeError(f"host must be a str, not {type(host).__name__}")
    try:
        lx.check_dns_name(host, "host")
    except DatumeshError as e:
        return KeysResult(False, "E_KEY_UNAVAILABLE", host, f"cannot retrieve keys for an invalid host: {e.detail}")
    status, body = _fetch_url(f"https://{host}{WELL_KNOWN_PATH}", timeout)
    if status == 200 and body is not None and len(body) > MAX_DOCUMENT_BYTES:
        return _doc_error(host, f"key document larger than {MAX_DOCUMENT_BYTES} bytes")
    return keys_from_response(host, status, body)


# ---------------------------------------------------------------- key sources for verify


@dataclass(frozen=True)
class _Source:
    host: Optional[str]  # None: covers every host
    result: KeysResult
    by_id: Dict[str, Key]


def _source_from_result(r: KeysResult) -> _Source:
    return _Source(r.host, r, {k.id: k for k in r.keys})


def _source_from_mapping(m: Dict[Any, Any]) -> _Source:
    keys = []
    for kid in sorted(m, key=str):
        pub = m[kid]
        if not isinstance(kid, str) or not isinstance(pub, str):
            return _source_from_result(_doc_error(None, "a key mapping maps key id strings to public key strings"))
        try:
            lx.check_hex(kid, 16, kid)
            if key_id(pub) != kid:
                fail("E_SCHEMA", f"{kid} is not the key id of {pub}", kid)
        except DatumeshError as e:
            return _source_from_result(_doc_error(None, f"bad key mapping entry {kid!r}: {e.detail}"))
        keys.append(Key(kid, pub))
    r = KeysResult(True, "OK", None, "key id mapping (no validity windows, any host)", tuple(keys))
    return _source_from_result(r)


def key_sources(keys: Any) -> Tuple[_Source, ...]:
    """Normalise the ``keys`` argument of verify. Raises TypeError only for argument types it cannot accept."""
    out = []

    def add(item: Any, depth: int) -> None:
        if isinstance(item, KeysResult):
            out.append(_source_from_result(item))
        elif isinstance(item, dict):
            if any(k in item for k in ("host", "keys", "proto")):
                out.append(_source_from_result(validate_key_document(item, None)))
            else:
                out.append(_source_from_mapping(item))
        elif isinstance(item, (list, tuple)) and depth == 0:
            for x in item:
                add(x, 1)
        else:
            raise TypeError("keys must be a key document (dict), a KeysResult, a {key id: public key} dict, "
                            f"or a list of those; got {type(item).__name__}")

    add(keys, 0)
    return tuple(out)


def find_key(sources: Tuple[_Source, ...], host: str, kid: str, issued: str) -> Key:
    """SPEC 10.1 step 5. Raises DatumeshError with a key code."""
    for s in sources:
        if s.host is None or s.host == host:
            if not s.result.ok:
                fail(s.result.code, f"keys for {host}: {s.result.detail}", "$.computed_by")
            key = s.by_id.get(kid)
            if key is None:
                fail("E_KEY_UNKNOWN", f"{host} publishes no key {kid}", "$.computed_by")
            if not key.usable_at(issued):
                fail("E_KEY_NOT_VALID", "issued is outside the key's validity window", "$.issued")
            return key
    fail("E_KEY_UNAVAILABLE", f"no keys supplied for host {host}", "$.computed_by")
