# datumesh

Verify [Datumesh](https://datumesh.com) receipts in Python. A receipt is a signed answer for one addressable data cell; this library checks its canonical form (RFC 8785 JSON) and its Ed25519 signature against the signer's published keys, and optionally the recomputation checks (function descriptor, input receipts and slice manifests, and a value you computed) and the content of a blob value, as the [Datumesh specification](https://github.com/datumesh-com/datumesh-spec/blob/spec-0.4.1/SPEC.md) (revision `spec-0.4.1`) defines. It also checks a mesh's response envelope (including `pending` jobs), resolves the unit of a cell's value, and checks a host's mesh document for cross-mesh use.

```sh
pip install datumesh
git clone --depth 1 --branch spec-0.4.1 https://github.com/datumesh-com/datumesh-spec && cd datumesh-spec
```

```python
import json
from datumesh import keys_from_response, verify

vector = json.load(open("vectors/receipt/stored-number.json"))
key_doc = vector["keys"]["rates.example.org"]["https"]["body"]  # served at https://rates.example.org/.well-known/datumesh.json
keys = keys_from_response("rates.example.org", 200, key_doc)
result = verify(vector["input"], keys)
print(result.ok, result.level, result.key)  # True signed rates.example.org#d712b32a2cc5cb7c
```

Website: https://datumesh.com · Specification: https://github.com/datumesh-com/datumesh-spec

## API

- `verify(receipt, keys, recompute=None, blob=None) -> VerifyResult`: runs the verification procedure of SPEC 10.1. Never raises for an invalid receipt or bad key material; the result has `ok`, `code` (`"OK"` or an error code), `level` (`"signed"` or `"recomputed"`), `hash`, `key`, `detail` and `path`. Two codes come with success, at level `signed` (SPEC 10.1 step 7.6): `"E_EVAL_UNAVAILABLE"` when you pass `recompute` without a `value` because you could not evaluate the function (the other recomputation checks still run first), and `"E_INPUT_SUPERSEDED"` when your value differs but the evaluation's `lineage` shows that an input was replaced by a later version (the receipt is historical, not wrong). It uses no network: keys are an argument (a key document, a `KeysResult`, a `{key id: public key}` mapping, or a list of these). `recompute` takes the descriptor (leave it out if you have none; `None` is a JSON null and fails the hash check), the input receipts (slice members included), the manifests of slice entries (`slice:<slice id>:<members hash>`), the value you computed and optionally the evaluation's lineage (the library does not evaluate functions, formulas included); `blob` takes the content bytes of a blob value, whose length and SHA-256 are then checked (step 7.7, reported as `blob_checked`).
- `check_envelope(status, body, keys, request) -> EnvelopeResult`: checks a mesh's response to `https://<mesh>/cell/...` (SPEC 5.5), verifies the receipt inside it, and checks that it answers your request (`request` is `{"cell_id": ..., "asof": ...}`, `asof` only if you asked for one; the receipt's `asof` must be at or before it, for `ok` and `stale` alike). A `not_covered` envelope may carry a formula evaluation `fault` (exposed as `fault`). The envelope itself is unsigned: `stale`, `superseded_by`, a `verified` label and the currency `ok` asserts remain the mesh's claims.
- Jobs (spec-0.4.1): a `pending` envelope (HTTP 202) carries `job`, `estimate_seconds` and `poll` (exposed on the result) and echoes your request, which must match. When you poll, pass the original request plus `"job": <the job id>`: the answer is checked against the original cell and `asof`, never the job URL, and only then may it be `bad_request` with `E_JOB_UNKNOWN` (ask again).
- `resolve_mesh(host, keys, mesh) -> MeshResult`: checks a host's key document and mesh document (`/.well-known/datumesh-mesh.json`, SPEC 9.6) together, given each response as a `(status, body)` pair; the result has `bindings` and the known `endpoints`, or `E_KEY_UNAVAILABLE`, `E_KEY_DOC` or `E_MESH_DOC`. It uses no network, and verification never needs it.
- `resolved_unit(descriptor, cell) -> str | None`: the unit of a cell's value, such as `USD/EUR` (SPEC 7.1, units.md).
- `keys_from_response(host, status, body) -> KeysResult`: interprets a response for `https://<host>/.well-known/datumesh.json` (SPEC 9.3).
- `fetch_keys(host, timeout=10.0) -> KeysResult`: the only function that uses the network. One GET, TLS verified, redirects not followed.
- `canonicalize(obj, kind=None) -> bytes`, `cell_hash`, `function_hash`, `receipt_hash`, `receipt_payload`, `jcs`: validation, RFC 8785 canonical bytes and SHA-256 hashes. Kinds `"slice"` and `"manifest"`, with `slice_id`, `members_hash` and `slice_entry`, cover slice objects and manifests (SPEC 4.4, 15.13).
- `parse_uri(uri, signature)`, `format_uri(ref)`, `uri_to_https(uri, mesh)`: cell URIs (SPEC 5).
- `DatumeshError` (with `.code` and `.path`), `ERROR_CODES`, `SUCCESS_CODES`, `FAULT_CODES`, `SPEC_VERSION`, `UNITS`, `CURRENCIES`.

Requires Python 3.10 or later and PyNaCl. String rules use Unicode 15.1 tables shipped with the package, so results do not depend on the Python version's own Unicode database; the unit list is copied from the specification's `units.md`. Choosing which publishers to trust is up to you: a valid signature only means the key holder made the statement.

Licence: Apache-2.0.
