#!/bin/sh
# Run the test suite in fresh python:3.10-slim and python:3.13-slim containers
# (the oldest and newest supported runtimes). Usage: scripts/test.sh [3.10|3.13 ...]
set -eu
cd "$(dirname "$0")/.."
[ -f spec/SPEC.md ] || { echo "spec submodule missing: git submodule update --init" >&2; exit 1; }
versions="${*:-3.10 3.13}"
for v in $versions; do
  echo "=== Python $v"
  docker run --rm -v "$PWD":/src:ro "python:$v-slim" sh -c '
    set -e
    cp -r /src /w && cd /w
    pip install -q --disable-pip-version-check --root-user-action=ignore "pynacl>=1.5.0"
    PYTHONPATH=src python -m unittest discover -s tests -v 2>&1 | tail -n 40
    exit ${PIPESTATUS:-0}
  '
done
