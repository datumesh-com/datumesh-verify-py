#!/usr/bin/env python3
"""Datumesh conformance runner.

Reads JSON lines on stdin, each a test vector in the format of SPEC.md section
11, and writes one JSON line per input to stdout (ASCII only: non-ASCII is \\u-escaped, so
no output line contains U+2028 or other line separators):

    {"id": ..., "error": <code or null>, ...outputs}

where the outputs (only when error is null) are exactly the section 11 output
fields for the vector's kind: canonical, sha256, object, https (on mesh
"mesh.example"), key_id, key_ids, sig, level, unit (may be null), outcome, and
for an envelope with a receipt trust and receipt_hash. Key environments (``env``
of a keys vector, each host of a receipt or envelope vector's ``keys``) are
converted with ``keys_from_response``; a status of "error" means a failed
retrieval. A receipt vector's ``blob_hex`` is passed to ``verify`` as the blob
content (step 7.7), and the output then has ``blob_checked``; an envelope
vector's ``request`` is passed to ``check_envelope``.

    jq -c . spec/vectors/*/*.json | python tools/run_vectors.py
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from typing import Any, Dict, List

try:
    import datumesh
except ImportError:  # running from a source checkout
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))
    import datumesh

MESH = "mesh.example"


def _env_keys(host: str, env: Dict[str, Any]) -> datumesh.KeysResult:
    https = env.get("https") or {}
    status = https.get("status", "error")
    return datumesh.keys_from_response(host, None if status == "error" else status, https.get("body"))


def _input(v: Dict[str, Any]) -> Any:
    if "input_hex" in v:
        return bytes.fromhex(v["input_hex"])
    return v["input"]


def run_vector(v: Dict[str, Any]) -> Dict[str, Any]:
    """Run one vector; return the output object (id, error, and outputs when valid)."""
    kind = v.get("kind")
    out: Dict[str, Any] = {"id": v.get("id"), "error": None}
    try:
        if kind == "jcs":
            b = datumesh.jcs(_input(v))
            out.update(canonical=b.decode("utf-8"), sha256=hashlib.sha256(b).hexdigest())
        elif kind in ("scalar", "cell", "ref", "function"):
            b = datumesh.canonicalize(_input(v), kind)
            out.update(canonical=b.decode("utf-8"), sha256=hashlib.sha256(b).hexdigest())
        elif kind == "uri":
            ref = datumesh.parse_uri(v["input"], v["signature"])
            b = datumesh.canonicalize(ref, "ref")
            out.update(object=ref, canonical=b.decode("utf-8"), sha256=hashlib.sha256(b).hexdigest(),
                       https=datumesh.uri_to_https(v["input"], MESH))
        elif kind == "keyid":
            out.update(key_id=datumesh.key_id(v["input"]))
        elif kind == "keys":
            r = _env_keys(v["host"], v.get("env") or {})
            if not r.ok:
                out["error"] = r.code
            else:
                out.update(key_ids=list(r.key_ids))
        elif kind == "receipt":
            keys: List[datumesh.KeysResult] = [_env_keys(h, e) for h, e in (v.get("keys") or {}).items()]
            blob = bytes.fromhex(v["blob_hex"]) if "blob_hex" in v else None
            res = datumesh.verify(_input(v), keys, v.get("recompute"), blob)
            if not res.ok:
                out["error"] = res.code
            else:
                payload = datumesh.receipt_payload(_input(v))
                parsed = json.loads(_input(v))
                out.update(canonical=payload.decode("utf-8"), sha256=res.hash, sig=parsed["sig"], level=res.level)
                if blob is not None:
                    out["blob_checked"] = res.blob_checked
        elif kind == "unit":
            # input: JSON text of {"cell", "descriptor"}, parsed strictly
            obj = datumesh.parse_json(_input(v))
            if not isinstance(obj, dict) or set(obj) != {"cell", "descriptor"}:
                raise datumesh.DatumeshError("E_SCHEMA", "a unit vector input has exactly cell and descriptor", "$")
            # Members are parsed JSON values: pass them as JSON text, so that a JSON string member is a
            # string value (resolved_unit would otherwise parse a str as JSON text).
            out["unit"] = datumesh.resolved_unit(json.dumps(obj["descriptor"]), json.dumps(obj["cell"]))
        elif kind == "envelope":
            keys = [_env_keys(h, e) for h, e in (v.get("keys") or {}).items()]
            env = datumesh.check_envelope(v["status"], _input(v), keys, v["request"])
            if not env.ok:
                out["error"] = env.code
            else:
                out["outcome"] = env.outcome
                if env.receipt_hash is not None:
                    out.update(trust=env.trust, receipt_hash=env.receipt_hash)
        else:
            out["error"] = f"UNSUPPORTED_KIND:{kind}"
    except datumesh.DatumeshError as e:
        out = {"id": v.get("id"), "error": e.code}
    return out


def main() -> int:
    for raw in sys.stdin.buffer:
        line = raw.strip()
        if not line:
            continue
        v: Any = None
        try:
            v = json.loads(line)
            result = run_vector(v)
        except Exception as e:  # keep the stream aligned: one output line per input line
            vid = v.get("id") if isinstance(v, dict) else None
            result = {"id": vid, "error": f"INTERNAL:{type(e).__name__}: {e}"}
        sys.stdout.buffer.write(json.dumps(result, ensure_ascii=True).encode("ascii") + b"\n")
        sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
