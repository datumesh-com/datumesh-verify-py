"""Mesh documents and cross-mesh resolution (SPEC.md 9.6, spec-0.4.1). Separate from verification: a verifier
never needs a mesh document."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from ._errors import DatumeshError
from ._json import parse_json
from ._keys import KeysResult, validate_key_document
from ._model import PROTO

#: The path of the mesh document on its host.
MESH_WELL_KNOWN_PATH = "/.well-known/datumesh-mesh.json"

#: The endpoints of SPEC 9.6: name -> (placeholders, required).
MESH_ENDPOINTS: Dict[str, Tuple[Tuple[str, ...], bool]] = {
    "blob": (("sha256",), False),
    "cell": (("cell",), True),
    "cells": ((), False),
    "descriptor": (("hash",), True),
    "explain": (("cell",), False),
    "find": ((), False),
    "jobs": (("job",), True),
    "manifest": (("slice_id", "members_hash"), True),
    "receipt": (("hash",), True),
    "slice": (("cell",), False),
    "verify": ((), False),
}

LIMIT_URL = 512
_URL_REST = re.compile(r"[!-~]+")


@dataclass(frozen=True)
class MeshResult:
    """The outcome of :func:`resolve_mesh`.

    ``ok``: both documents passed. ``code``: ``"OK"``, or the first failure: ``E_KEY_UNAVAILABLE``,
    ``E_KEY_DOC`` or ``E_MESH_DOC``. ``host``: the host resolved. ``detail``: human-readable text. When ok,
    ``bindings`` is the bindings URL, ``endpoints`` the known endpoint templates (unknown members dropped) and
    ``keys`` the host's validated key document as a :class:`KeysResult`; otherwise None, ``{}`` and None. A host
    that fails is not to be used for anything.
    """

    ok: bool
    code: str
    host: Optional[str]
    detail: str
    bindings: Optional[str] = None
    endpoints: Dict[str, str] = field(default_factory=dict)
    keys: Optional[KeysResult] = None


class _Fail(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _response(r: Any, what: str) -> Tuple[Any, Any]:
    if r is None:
        return None, None
    if not isinstance(r, (tuple, list)) or len(r) != 2:
        raise TypeError(f"{what} must be a (status, body) pair, or None for a failed retrieval")
    return r[0], r[1]


def _is_200(status: Any) -> bool:
    return isinstance(status, int) and not isinstance(status, bool) and status == 200


def _parse(body: Any, code: str, what: str) -> Any:
    if not isinstance(body, (str, bytes, bytearray, memoryview)):
        raise _Fail(code, f"the {what} body must be text or bytes")
    try:
        return parse_json(body)
    except DatumeshError as e:
        raise _Fail(code, f"the {what} is not strict JSON ({e.code})") from None


def _url_on_host(v: Any, host: str, name: str) -> str:
    """The licence URL rule (``https://`` and printable ASCII, at most 512 characters) on this host: the
    authority is exactly ``host``, followed by a path."""
    if not isinstance(v, str) or len(v) > LIMIT_URL or not v.startswith("https://") \
            or not _URL_REST.fullmatch(v[8:]):
        raise _Fail("E_MESH_DOC", f"{name} is https:// followed by printable ASCII, at most {LIMIT_URL} characters")
    if not v.startswith(f"https://{host}/"):
        raise _Fail("E_MESH_DOC", f"{name} is a URL on this host ({host}), with a path")
    return v


def _endpoint(v: Any, host: str, name: str) -> str:
    url = _url_on_host(v, host, f"endpoints.{name}")
    placeholders = MESH_ENDPOINTS[name][0]
    if url.count("{") != len(placeholders) or any(url.count("{" + p + "}") != 1 for p in placeholders):
        listed = ", ".join("{" + p + "}" for p in placeholders) or "none"
        raise _Fail("E_MESH_DOC", f"endpoints.{name} has exactly the placeholders {listed}, each once, and no other {{")
    return url


def resolve_mesh(host: Any, keys: Any, mesh: Any) -> MeshResult:
    """Resolve a host for cross-mesh use (SPEC 9.6): its key document and its mesh document must both pass.

    ``keys`` is the response to ``GET https://<host>/.well-known/datumesh.json`` and ``mesh`` the response to
    ``GET https://<host>/.well-known/datumesh-mesh.json``, each a ``(status, body)`` pair: ``status`` the HTTP
    status (an int), or None for a network, DNS, TLS or timeout failure, and ``body`` the text or bytes, or None.
    ``None`` for a whole pair is a failed retrieval. The steps, first failure reported:

    1. the key document is retrieved: an int 200 (``E_KEY_UNAVAILABLE`` otherwise), with a body (``E_KEY_DOC``);
    2. the mesh document is retrieved: an int 200 with a body (``E_MESH_DOC``, 404 included);
    3. both parse strictly: the key document (``E_KEY_DOC``), then the mesh document, an object (``E_MESH_DOC``);
    4. they describe the same mesh (``E_MESH_DOC``): the mesh document's ``host`` is ``host``; the key document's,
       where it is a string, too; and, when the key document is an object, the two ``proto``\\ s are equal and
       ``"datumesh/1"``;
    5. the key document by 9.2 (``E_KEY_DOC``);
    6. the mesh document's members (``E_MESH_DOC``): ``bindings``, then ``endpoints`` (an object with every
       required endpoint), then each known endpoint in ascending name order.

    Unknown members are not checked and are dropped from the result. Never raises for invalid input (TypeError
    only for a ``keys`` or ``mesh`` that is not a pair or None); uses no network. A verifier never needs this.
    """
    if not isinstance(host, str):
        return MeshResult(False, "E_KEY_UNAVAILABLE", None, f"host must be a str, not {type(host).__name__}")
    k_status, k_body = _response(keys, "keys")
    m_status, m_body = _response(mesh, "mesh")
    try:
        # 1-2: retrieval
        if not _is_200(k_status):
            raise _Fail("E_KEY_UNAVAILABLE", f"key document: HTTP status {k_status!r}" if k_status is not None
                        else "key document: network, DNS, TLS or timeout failure")
        if k_body is None:
            raise _Fail("E_KEY_DOC", "key document: a 200 response without a document")
        if not _is_200(m_status) or m_body is None:
            raise _Fail("E_MESH_DOC", f"mesh document not retrieved (HTTP status {m_status!r})")
        # 3: parse
        kd = _parse(k_body, "E_KEY_DOC", "key document")
        md = _parse(m_body, "E_MESH_DOC", "mesh document")
        if not isinstance(md, dict):
            raise _Fail("E_MESH_DOC", "the mesh document is a JSON object")
        # 4: the same mesh
        if md.get("host") != host or not isinstance(md.get("host"), str):
            raise _Fail("E_MESH_DOC", f"the mesh document names another host than {host!r}")
        if isinstance(kd, dict):
            if isinstance(kd.get("host"), str) and kd["host"] != host:
                raise _Fail("E_MESH_DOC", f"the key document names another host than {host!r}")
            if "proto" not in md or "proto" not in kd or md["proto"] != kd["proto"] or md["proto"] != PROTO:
                raise _Fail("E_MESH_DOC", f"the mesh document and the key document disagree on proto, or it is "
                            f"not {PROTO!r}")
        # 5: the key document
        kr = validate_key_document(kd, host)
        if not kr.ok:
            raise _Fail("E_KEY_DOC", kr.detail)
        # 6: the mesh document's members
        bindings = _url_on_host(md.get("bindings"), host, "bindings")
        eps = md.get("endpoints")
        if not isinstance(eps, dict):
            raise _Fail("E_MESH_DOC", "endpoints is an object")
        for name, (_, required) in sorted(MESH_ENDPOINTS.items()):
            if required and name not in eps:
                raise _Fail("E_MESH_DOC", f"endpoints has the required endpoint {name!r}")
        out = {name: _endpoint(eps[name], host, name) for name in sorted(MESH_ENDPOINTS) if name in eps}
        return MeshResult(True, "OK", host, "key document and mesh document agree", bindings, out, kr)
    except _Fail as f:
        return MeshResult(False, f.code, host, f.detail)
