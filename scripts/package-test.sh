#!/bin/sh
# Packaging test (no publishing):
#   1. build the sdist and the wheel in a clean python:3.13-slim container;
#   2. install the wheel, with only its declared dependencies, into a FRESH python:3.10-slim container;
#   3. run the README's Python example verbatim (extracted from README.md) in a checkout of the
#      spec at tag spec-0.1.1 (the spec/ submodule stands in for the README's `git clone`, and the
#      built wheel for `pip install datumesh`), and compare its output with the README's comment.
set -eu
cd "$(dirname "$0")/.."
[ -f spec/vectors/receipt/stored-number.json ] || { echo "spec submodule missing: git submodule update --init" >&2; exit 1; }
[ "$(git -C spec describe --tags --exact-match 2>/dev/null)" = "spec-0.1.1" ] || { echo "spec/ is not at tag spec-0.1.1" >&2; exit 1; }

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
mkdir -p "$out/dist"

echo "--- build"
docker run --rm -v "$PWD":/src:ro -v "$out/dist":/dist python:3.13-slim sh -c '
  set -e
  mkdir /b && cd /src && tar --exclude=./spec --exclude=./dist --exclude=./.git -cf - . | tar -C /b -xf -
  cd /b
  pip install -q --disable-pip-version-check --root-user-action=ignore build
  python -m build --outdir /dist >/dev/null
  ls -l /dist
  python -m zipfile -l /dist/datumesh-0.1.1-py3-none-any.whl
'

echo "--- extract the README example"
awk '/^```python$/{on=1; next} /^```$/{if(on){exit}} on' README.md > "$out/readme_example.py"
cat "$out/readme_example.py"
expected="$(sed -n 's/^print(.*)  # //p' "$out/readme_example.py")"
[ -n "$expected" ] || { echo "no expected output comment in the README example" >&2; exit 1; }

echo "--- install the wheel in a fresh python:3.10-slim and run the example"
got="$(docker run --rm -v "$out":/pkg:ro -v "$PWD/spec":/spec:ro python:3.10-slim sh -c '
  set -e
  pip install -q --disable-pip-version-check --root-user-action=ignore /pkg/dist/datumesh-0.1.1-py3-none-any.whl >&2
  pip list --format=freeze >&2
  python - >&2 <<PY
import importlib.metadata as md
m = md.metadata("datumesh")
print("metadata:", m["Name"], m["Version"], "| Requires-Dist:", md.requires("datumesh"),
      "| Keywords:", m["Keywords"], "| License-Expression:", m.get("License-Expression"))
for u in m.get_all("Project-URL"): print("  ", u)
import datumesh, pathlib
print("SPEC_VERSION:", datumesh.SPEC_VERSION, "| py.typed:", (pathlib.Path(datumesh.__file__).parent / "py.typed").exists())
PY
  cd /spec && python /pkg/readme_example.py
')"
echo "output:   $got"
echo "expected: $expected"
[ "$got" = "$expected" ] || { echo "PACKAGE TEST FAILED" >&2; exit 1; }
echo "PACKAGE TEST PASSED"
