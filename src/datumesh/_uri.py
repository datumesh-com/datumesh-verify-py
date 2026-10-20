"""Cell URIs (SPEC.md section 5): parse a URI to a cell reference and format a reference as its URI."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import _lexical as lx
from ._errors import fail
from ._json import sort_key
from ._model import SLICE, validate_ref

SCHEME = "cell://"
_LITERAL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:")
_UPHEX = frozenset("0123456789ABCDEF")


def _decode(value: str, path: str) -> str:
    """Check canonical percent-encoding (SPEC 5.2) and return the decoded UTF-8 text."""
    out = bytearray()
    i, n = 0, len(value)
    while i < n:
        ch = value[i]
        if ch == "%":
            h = value[i + 1:i + 3]
            if len(h) != 2 or not (h[0] in _UPHEX and h[1] in _UPHEX):
                fail("E_CANON_PERCENT", "percent-encoding must be % and two uppercase hex digits", path)
            b = int(h, 16)
            if chr(b) in _LITERAL:
                fail("E_CANON_PERCENT", f"{chr(b)!r} must not be percent-encoded", path)
            out.append(b)
            i += 3
        elif ch in _LITERAL:
            out.append(ord(ch))
            i += 1
        else:
            fail("E_CANON_PERCENT", f"{ch!r} must be percent-encoded", path)
    try:
        return out.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail("E_CANON_PERCENT", "percent-encoded bytes are not UTF-8", path)


def _encode(text: str) -> str:
    parts: List[str] = []
    for b in text.encode("utf-8"):
        c = chr(b)
        parts.append(c if c in _LITERAL else "%%%02X" % b)
    return "".join(parts)


def _declared_types(signature: Any) -> Dict[str, str]:
    """SPEC 5.4 step 5: read the argument types; an unreadable signature is E_SCHEMA."""
    if not isinstance(signature, dict):
        fail("E_SCHEMA", "the signature is an object", "signature")
    args = signature.get("args")
    if not isinstance(args, dict):
        fail("E_SCHEMA", "the signature has an args object", "signature" if "args" not in signature
             else "signature.args")
    for name in sorted(args, key=sort_key):
        a = args[name]
        if not isinstance(a, dict) or not isinstance(a.get("type"), str):
            fail("E_SCHEMA", "an argument declaration is an object with a string type", f"signature.args.{name}")
    return {name: a["type"] for name, a in args.items()}


def parse_uri(uri: str, signature: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a cell URI into a cell reference (SPEC 4.3, 5.4).

    ``signature`` is the ``signature`` member of the function's descriptor; it
    supplies each argument's type. As SPEC 5.4 says, it is taken as given (it comes
    from a descriptor already checked under section 7): only its argument types are
    read, in step 5, and a signature from which they cannot be read is E_SCHEMA.
    Checks run in the order of SPEC 5.4 and the first failure is raised as DatumeshError.
    """
    if not isinstance(uri, str):
        raise TypeError(f"uri must be a str, not {type(uri).__name__}")

    # 1. Outer grammar.
    if not uri.startswith(SCHEME) or "#" in uri:
        fail("E_PARSE_URI", "not cell://<namespace>/<function>[?<query>] without a fragment", "uri")
    path, qmark, query = uri[len(SCHEME):].partition("?")
    authority = path.split("/", 1)[0]
    if "@" in authority:
        fail("E_PARSE_URI", "a cell URI has no userinfo", "uri")
    if ":" in authority:
        fail("E_PARSE_URI", "a cell URI has no port", "uri")
    params: List[Tuple[str, str]] = []
    if qmark:
        if query == "":
            fail("E_PARSE_URI", "empty query", "uri")
        for part in query.split("&"):
            name, eq, value = part.partition("=")
            if not eq:
                fail("E_PARSE_URI", f"parameter without '=': {part!r}", "uri")
            params.append((name, value))

    # 2. Namespace and function name.
    ns, slash, fn = path.rpartition("/")
    if not slash:
        fail("E_CANON_NAME", "missing namespace", "uri.path")
    lx.check_namespace(ns, "uri.path")
    lx.check_name(fn, "uri.path")
    lx.check_function_name_length(ns, fn, "uri.path")

    # 3. Parameter names, left to right: grammar, reserved names, duplicates, order.
    asof: Optional[str] = None
    if params and params[-1][0] == "asof":
        asof = params.pop()[1]
    previous: Optional[str] = None
    for name, _ in params:
        p = f"uri.query.{name}"
        lx.check_name(name, p, "E_CANON_ARG_NAME")
        if name == "asof":
            if asof is not None:
                fail("E_CANON_ARG_DUPLICATE", "asof appears more than once", p)
            fail("E_CANON_ARG_ORDER", "asof must be the last parameter", p)
        if name.startswith("dm_"):
            fail("E_CANON_ARG_NAME", f"reserved argument name {name!r}", p)
        if previous is not None:
            if name == previous:
                fail("E_CANON_ARG_DUPLICATE", f"argument {name!r} repeated", p)
            if name < previous:
                fail("E_CANON_ARG_ORDER", "arguments must be in ascending order of name", p)
        previous = name

    # 4. Argument count.
    if len(params) > lx.LIMIT_ARGS:
        fail("E_CANON_LIMIT", f"more than {lx.LIMIT_ARGS} arguments", "uri.query")

    # 5. The signature (read, not checked: SPEC 5.4), then the arguments against it: unknown, then missing.
    declared = _declared_types(signature)
    present = {name for name, _ in params}
    for name, _ in params:
        if name not in declared:
            fail("E_ARG_UNKNOWN", f"the function declares no argument {name!r}", f"uri.query.{name}")
    for name in sorted(declared):
        if name not in present:
            fail("E_ARG_MISSING", f"argument {name!r} absent (a slice is written {name}=*)", "uri.query")

    # 6. Values, left to right.
    args: Dict[str, Any] = {}
    for name, raw in params:
        p = f"uri.query.{name}"
        if raw == SLICE:
            args[name] = SLICE
            continue
        text = _decode(raw, p)
        t = declared[name]
        if t == "boolean":
            if text not in ("true", "false"):
                fail("E_CANON_TYPE", "a boolean is true or false", p)
            args[name] = {"type": t, "value": text == "true"}
        else:
            lx.check_typed_value(t, text, p, p)
            args[name] = {"type": t, "value": text}

    ref: Dict[str, Any] = {"args": args, "fn": fn, "ns": ns}
    # 7. asof.
    if asof is not None:
        text = _decode(asof, "uri.query.asof")
        lx.check_instant(text, "uri.query.asof")
        ref["asof"] = text
    return ref


def format_uri(ref: Dict[str, Any]) -> str:
    """Write the unique cell URI of a cell reference (SPEC 5.2). The reference is validated first."""
    validate_ref(ref)
    parts: List[str] = []
    for name in sorted(ref["args"]):
        v = ref["args"][name]
        if v == SLICE:
            parts.append(f"{name}=*")
        elif v["type"] == "boolean":
            parts.append(f"{name}={'true' if v['value'] else 'false'}")
        else:
            parts.append(f"{name}={_encode(v['value'])}")
    if "asof" in ref:
        parts.append(f"asof={ref['asof']}")
    uri = f"{SCHEME}{ref['ns']}/{ref['fn']}"
    return uri + ("?" + "&".join(parts) if parts else "")


def uri_to_https(uri: str, mesh: str) -> str:
    """The HTTPS URL of a cell URI on mesh host ``mesh`` (SPEC 5.3): ``https://<mesh>/cell/<rest>``."""
    if not uri.startswith(SCHEME):
        fail("E_PARSE_URI", "not a cell URI", "uri")
    lx.check_dns_name(mesh, "mesh")
    return f"https://{mesh}/cell/{uri[len(SCHEME):]}"
