#!/bin/sh
# Run the test suite in fresh python:3.10-slim and python:3.13-slim containers
# (the oldest and newest supported runtimes). Usage: scripts/test.sh [3.10|3.13 ...]
# Exits non-zero if any run fails.
set -eu
cd "$(dirname "$0")/.."
[ -f spec/SPEC.md ] || { echo "spec submodule missing: git submodule update --init" >&2; exit 1; }
versions="${*:-3.10 3.13}"
status=0
for v in $versions; do
  echo "=== Python $v"
  docker run --rm -v "$PWD":/src:ro "python:$v-slim" sh -c '
    cp -r /src /w && cd /w || exit 1
    pip install -q --disable-pip-version-check --root-user-action=ignore "pynacl>=1.5.0" || exit 1
    PYTHONPATH=src python -m unittest discover -s tests -v > /tmp/test.log 2>&1
    rc=$?
    grep -E "^(conformance|bit flips|runtime Python)" /tmp/test.log
    tail -n 4 /tmp/test.log
    [ $rc -eq 0 ] || cat /tmp/test.log
    exit $rc
  ' || status=1
done
exit $status
