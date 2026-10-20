#!/usr/bin/env python3
"""Differential fuzzing against the reference tool, used as a black box.

Generates mutated copies of the spec's vectors (receipts are re-signed with the
vector's keypair seed so later verification steps are reached), runs them
through ``spec/tools/canon.py check`` in a scratch copy of the spec, and
compares the error code it reports with ours. Only canon.py's command-line
output is used; its source is not read.

Needs Docker and the ``datumesh-test`` image (Python 3.13 + PyNaCl):

    python3 tools/oracle_fuzz.py --n 3000 --seed 1

Prints every disagreement. A disagreement is a bug here, a deliberate
divergence (listed in DEFECTS.md), or an ambiguity in SPEC.md.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

GEN = r'''
import copy, glob, json, os, random, sys
sys.path.insert(0, "/repo/src")
import datumesh
from nacl.signing import SigningKey

rnd = random.Random(int(sys.argv[1]))
N = int(sys.argv[2])
OUT = "/work/vectors/probe"
os.makedirs(OUT, exist_ok=True)
vectors = [json.load(open(f)) for f in sorted(glob.glob("/repo/spec/vectors/*/*.json"))]

POOL = ["", "*", "X", "a" * 65, "a" * 64, "1.50", "-0", "0", "1", "true", "2024-02-30", "2024-03-15",
        "2024-03-15T16:00:00.000000Z", "2024-03-16T09:00:00.000000Z", "2099-01-01T00:00:00.000000Z",
        "ü", "͸", "\u0007", "a\nb", "\U0001E08F", "Rates.example.org", "rates.example.org",
        "calc.example.net", "calc.example.net#f7ec60a92abf4774", "rates.example.org#d712b32a2cc5cb7c",
        "rates.example.org#d9a2df65559c4444", "rates.example.org/fx_rate", "ecb/fx_rate", "datumesh/1",
        "number", "string", "date", "instant", "boolean", "decimal", "ed25519", "https://x.example/l",
        "CC-BY-4.0", "f" * 64, "0" * 64, "A" * 64, "0" * 128, "dm_x", "asof", "fx_rate", "stored", "expr",
        "x.example/" + "/".join(["a" * 60] * 9)]
# Strings whose validity differs between Unicode 13 (Python 3.10) and the pinned 15.1, or 15.1 and 16.0.
POOL += [chr(0x870), chr(0x1E030), chr(0x2EBF0), chr(0x31350), chr(0x1C89), chr(0x897),
         "a" + chr(0x1E08F) + chr(0x316), "a" + chr(0x316) + chr(0x1E08F)]
ALPHA = "aAzZ09-_./#:%*?&= ü̈€"
ALPHA += chr(0x1E08F) + chr(0x316) + chr(0x870) + chr(0x1C89)
NAMES = ["x", "asof", "dm_x", "A", "base", "date", "quote", "value", "type", "valid", "sig", "proto",
         "valid_to", "host", "keys", "alg", "id", "public", "valid_from", "rounding", "zone"]

def edit(s):
    s = list(s)
    op = rnd.randrange(3)
    i = rnd.randrange(len(s) + 1)
    if op == 0 or not s:
        s.insert(i, rnd.choice(ALPHA))
    elif op == 1:
        del s[min(i, len(s) - 1)]
    else:
        s[min(i, len(s) - 1)] = rnd.choice(ALPHA)
    return "".join(s)

def nodes(v, path=()):
    yield path, v
    if isinstance(v, dict):
        for k in v:
            yield from nodes(v[k], path + (k,))
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from nodes(x, path + (i,))

def get(v, path):
    for p in path:
        v = v[p]
    return v

def mutate(v):
    v = copy.deepcopy(v)
    all_nodes = list(nodes(v))
    path, node = rnd.choice(all_nodes)
    r = rnd.random()
    if not path:
        if isinstance(v, dict) and rnd.random() < 0.5:
            v[rnd.choice(NAMES)] = rnd.choice(POOL)
        return v
    parent = get(v, path[:-1])
    key = path[-1]
    if isinstance(node, str) and r < 0.45:
        parent[key] = edit(node) if rnd.random() < 0.5 else rnd.choice(POOL)
    elif r < 0.55:
        parent[key] = rnd.choice([True, False, None, 1.5, [], {}, "*"])
    elif r < 0.7 and isinstance(parent, dict):
        del parent[key]
    elif r < 0.8 and isinstance(parent, dict):
        parent[rnd.choice(NAMES)] = copy.deepcopy(rnd.choice([node, rnd.choice(POOL), {"type": "date", "value": "2024-03-15"}]))
    elif r < 0.9 and isinstance(parent, dict):
        nk = edit(key)
        parent[nk] = parent.pop(key)
    elif isinstance(parent, list):
        if rnd.random() < 0.5:
            parent.insert(rnd.randrange(len(parent) + 1), rnd.choice(POOL))
        elif parent:
            parent.reverse()
    else:
        parent[key] = rnd.choice(POOL)
    return v

def resign(r, seed):
    if not isinstance(r, dict) or "sig" not in r:
        return r
    payload = {k: x for k, x in r.items() if k != "sig"}
    try:
        b = datumesh.jcs(payload)
    except Exception:
        return r
    r["sig"] = SigningKey(bytes.fromhex(seed)).sign(b).signature.hex()
    return r

def emit(i, v):
    v = dict(v, id="probe/f%05d" % i, valid=False, error="E_PROBE", description="fuzz")
    for k in ("canonical", "sha256", "object", "https", "key_id", "key_ids", "sig", "level"):
        v.pop(k, None)
    json.dump(v, open(os.path.join(OUT, "f%05d.json" % i), "w"))

i = 0
while i < N:
    base = rnd.choice(vectors)
    kind = base["kind"]
    v = copy.deepcopy(base)
    if kind in ("jcs", "keyid"):
        continue
    try:
        if kind == "uri":
            # Only the URI is mutated: signatures are validated here but not by the
            # reference tool (a known divergence, see DEFECTS.md).
            s = v["input"]
            for _ in range(rnd.randint(1, 3)):
                s = edit(s)
            v["input"] = s
        elif kind == "keys":
            env = v["env"]["https"]
            if "body" in env and rnd.random() < 0.8:
                env["body"] = json.dumps(mutate(json.loads(env["body"])))
            else:
                env["status"] = rnd.choice([200, 301, 404, "error"])
                if env["status"] == 200 and "body" not in env:
                    continue
        elif kind == "receipt":
            r = json.loads(v["input"])
            target = rnd.random()
            if target < 0.6:
                for _ in range(rnd.randint(1, 2)):
                    r = mutate(r)
                if rnd.random() < 0.8:
                    r = resign(r, v["keypair"]["seed"])
                v["input"] = json.dumps(r)
            elif target < 0.8 and "recompute" in v:
                rc = v["recompute"]
                if rc.get("descriptor") is not None and rnd.random() < 0.5:
                    rc["descriptor"] = mutate(rc["descriptor"])
                elif rnd.random() < 0.5:
                    rc["value"] = {"type": rnd.choice(["number", "string"]), "value": rnd.choice(["1.0892", "108.92", "1", "x"])}
                else:
                    rc.pop("inputs", None)
                if "value" not in rc or not isinstance(rc.get("value"), dict):
                    continue
            else:
                h = rnd.choice(list(v["keys"]))
                env = v["keys"][h]["https"]
                if "body" in env and rnd.random() < 0.7:
                    env["body"] = json.dumps(mutate(json.loads(env["body"])))
                else:
                    env["status"] = rnd.choice([404, "error"])
                    env.pop("body", None)
        else:
            src = v.get("input")
            if src is None:
                continue
            v["input"] = json.dumps(mutate(json.loads(src)))
    except Exception:
        continue
    emit(i, v)
    i += 1
'''


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", action="store_true", help="keep the scratch directory")
    ap.add_argument("--ours-image", default="datumesh-test",
                    help="Docker image to run our side in, e.g. python:3.10-slim (PyNaCl is installed if missing)")
    args = ap.parse_args()
    work = pathlib.Path(tempfile.mkdtemp(prefix="dm-oracle-"))
    try:
        shutil.copytree(ROOT / "spec", work / "spec", ignore=shutil.ignore_patterns(".git"))
        (work / "gen.py").write_text(GEN)
        docker = ["docker", "run", "--rm", "-v", f"{ROOT}:/repo:ro", "-v", f"{work / 'spec'}:/work", "-v", f"{work}:/scratch"]
        subprocess.run(docker + ["datumesh-test", "python", "/scratch/gen.py", str(args.seed), str(args.n)], check=True)
        probe_dir = work / "spec" / "vectors" / "probe"
        files = sorted(probe_dir.glob("*.json"))
        crash_dir = work / "crashed"
        crash_dir.mkdir()
        # Reference codes: canon.py check prints "FAIL <file>" then "expected E_PROBE, got <CODE> ...".
        # When it crashes on an input, record "crash" for that file, set it aside and run again.
        ref = {}
        for _ in range(len(files) + 1):
            proc = subprocess.run(docker + ["-w", "/work", "datumesh-test", "python", "tools/canon.py", "check"],
                                  capture_output=True, text=True)
            lines = proc.stdout.splitlines()
            last = None
            for i, line in enumerate(lines):
                m = re.match(r"FAIL vectors/probe/(f\d+)\.json", line)
                if m and i + 1 < len(lines):
                    g = re.search(r"got (E_[A-Z_]+|success)", lines[i + 1])
                    ref[m.group(1)] = g.group(1) if g else "?" + lines[i + 1].strip()[:80]
                    last = m.group(1)
            if "Traceback" not in proc.stderr and "Traceback" not in proc.stdout:
                break
            remaining = sorted(p.stem for p in probe_dir.glob("*.json"))
            nxt = [n for n in remaining if last is None or n > last]
            if not nxt:
                break
            ref[nxt[0]] = "crash"
            shutil.move(str(probe_dir / f"{nxt[0]}.json"), str(crash_dir / f"{nxt[0]}.json"))
        # Our codes.
        feed = "\n".join(json.dumps(json.loads(f.read_text())) for f in files)
        ours_cmd = ["sh", "-c", "python -c 'import nacl' 2>/dev/null || pip install -q --root-user-action=ignore "
                    "pynacl >/dev/null 2>&1; python /repo/tools/run_vectors.py"]
        ours_raw = subprocess.run(docker + ["-i", args.ours_image] + ours_cmd,
                                  input=feed, capture_output=True, text=True, check=True).stdout
        ours = {}
        for line in ours_raw.splitlines():
            r = json.loads(line)
            ours[r["id"].split("/")[1]] = r["error"] or "success"
        diffs = 0
        for name in sorted(ours):
            if ref.get(name) != ours[name]:
                diffs += 1
                src = probe_dir / f"{name}.json"
                v = json.loads((src if src.exists() else crash_dir / f"{name}.json").read_text())
                print(f"DIFF {name} kind={v['kind']} reference={ref.get(name)} ours={ours[name]}")
        counts: dict = {}
        for code in ours.values():
            counts[code] = counts.get(code, 0) + 1
        print("our codes: " + ", ".join(f"{k} {counts[k]}" for k in sorted(counts)))
        crashes = sum(1 for x in ref.values() if x == "crash")
        print(f"compared {len(ours)} vectors ({crashes} crashed the reference tool), {diffs} disagreements")
        if args.keep:
            print(f"scratch kept at {work}")
        return 1 if diffs else 0
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
