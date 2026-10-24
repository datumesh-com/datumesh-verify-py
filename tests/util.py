"""Shared helpers for the test suite."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
from typing import Any, Dict, List

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = ROOT / "spec"
VECTORS = SPEC / "vectors"
FIXTURES = ROOT / "tests" / "fixtures"

try:
    import datumesh  # noqa: F401
except ImportError:  # source checkout without installation
    sys.path.insert(0, str(ROOT / "src"))
    import datumesh  # noqa: F401


def load_vectors() -> List[Dict[str, Any]]:
    files = sorted(VECTORS.glob("*/*.json"))
    if not files:
        raise RuntimeError("no vectors found: check out the spec submodule (git submodule update --init)")
    return [json.loads(f.read_text(encoding="utf-8")) for f in files]


#: Vector kinds for formula evaluators, not for verifier libraries (CONTRACT-0.4.0-libs item 9, SPEC 11 and
#: 15): the runner skips them.
FORMULA_KINDS = ("formula", "formula-eval", "excel", "decimal")


def verifier_vectors() -> List[Dict[str, Any]]:
    """Every vector a verifier library runs: all but the formula evaluator kinds."""
    return [v for v in load_vectors() if v["kind"] not in FORMULA_KINDS]


def vectors_of(kind: str, valid: Any = None) -> List[Dict[str, Any]]:
    return [v for v in load_vectors() if v["kind"] == kind and (valid is None or v["valid"] == valid)]


def runner():
    """The conformance runner module, tools/run_vectors.py."""
    spec = importlib.util.spec_from_file_location("run_vectors", ROOT / "tools" / "run_vectors.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def env_keys(keys: Dict[str, Any]) -> list:
    """A receipt vector's ``keys`` (an env per host) as KeysResults."""
    out = []
    for host, env in keys.items():
        https = env.get("https") or {}
        status = https.get("status")
        out.append(datumesh.keys_from_response(host, None if status == "error" else status, https.get("body")))
    return out


#: Output fields per vector kind (SPEC.md section 11).
OUTPUTS = {
    "jcs": ["canonical", "sha256"],
    "scalar": ["canonical", "sha256"],
    "cell": ["canonical", "sha256"],
    "ref": ["canonical", "sha256"],
    "function": ["canonical", "sha256"],
    "uri": ["object", "canonical", "sha256", "https"],
    "keyid": ["key_id"],
    "keys": ["key_ids"],
    "receipt": ["canonical", "sha256", "sig", "level"],
    "unit": ["unit"],
    # envelope: outcome, and trust and receipt_hash only when the envelope carries a receipt
    "envelope": ["outcome", "trust", "receipt_hash"],
    # slice (spec-0.4.0): members_hash and entry only for a manifest
    "slice": ["canonical", "sha256", "slice_id", "members_hash", "entry"],
}


def expected_output(v: Dict[str, Any]) -> Dict[str, Any]:
    exp: Dict[str, Any] = {"id": v["id"], "error": v.get("error")}
    if v["valid"]:
        for k in OUTPUTS[v["kind"]]:
            if v["kind"] == "envelope" and k != "outcome" and k not in v:
                continue
            if v["kind"] == "slice" and k in ("members_hash", "entry") and k not in v:
                continue
            exp[k] = v[k]
        if v["kind"] == "receipt" and "blob_hex" in v:
            # SPEC 11: "blob_checked (true) when blob_hex is given". The vector files carry it since
            # spec commit 1400247 (DEFECTS.md DEF-35); the rule is the fallback.
            exp["blob_checked"] = v.get("blob_checked", True)
        if v["kind"] == "receipt" and "code" in v:
            # SPEC 11: a code reported with success, E_EVAL_UNAVAILABLE (spec-0.3.0) or
            # E_INPUT_SUPERSEDED (spec-0.4.0).
            exp["code"] = v["code"]
    return exp


def runner_output(v: Dict[str, Any]) -> Dict[str, Any]:
    """What the runner writes for a vector: the expected output, or for a formula evaluator kind the
    skip line (the kind is not for verifier libraries)."""
    if v["kind"] in FORMULA_KINDS:
        return {"id": v["id"], "error": None, "skipped": v["kind"]}
    return expected_output(v)


def recompute_of(v: Dict[str, Any]) -> Any:
    """A receipt vector's ``recompute`` as ``verify`` takes it, or None.

    In a vector, ``descriptor`` is always a JSON value (SPEC 11, spec-0.3.0): a JSON string is a
    string value, never text to parse. ``verify`` parses a str as JSON text, so a string value is
    passed as its JSON text. Every other value (``null`` included) is passed as it is; an absent
    member stays absent (the descriptor is unavailable), and so does an absent ``value``
    (evaluation is unavailable).
    """
    rc = v.get("recompute")
    if rc is None:
        return None
    rc = dict(rc)
    if isinstance(rc.get("descriptor"), str):
        rc["descriptor"] = json.dumps(rc["descriptor"])
    return rc


def blob_of(v: Dict[str, Any]) -> Any:
    """A receipt vector's blob content (``blob_hex``) as bytes, or None."""
    return bytes.fromhex(v["blob_hex"]) if "blob_hex" in v else None
