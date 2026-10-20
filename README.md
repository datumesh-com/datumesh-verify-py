# datumesh

Verify [Datumesh](https://datumesh.com) receipts in Python. A receipt is a signed answer for one addressable data cell; this library checks its canonical form (RFC 8785 JSON) and its Ed25519 signature against the signer's published keys, and optionally the recomputation checks (function descriptor, input receipts, and a value you computed) and the content of a blob value, as the [Datumesh specification](https://github.com/datumesh-com/datumesh-spec/blob/spec-0.2.0/SPEC.md) (revision `spec-0.2.0`) defines. It also checks a mesh's response envelope and resolves the unit of a cell's value.

```sh
pip install datumesh
git clone --depth 1 --branch spec-0.2.0 https://github.com/datumesh-com/datumesh-spec && cd datumesh-spec
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

- `verify(receipt, keys, recompute=None, blob=None) -> VerifyResult`: runs the verification procedure of SPEC 10.1. Never raises for an invalid receipt or bad key material; the result has `ok`, `code` (`"OK"` or an error code), `level` (`"signed"` or `"recomputed"`), `hash`, `key`, `detail` and `path`. It uses no network: keys are an argument (a key document, a `KeysResult`, a `{key id: public key}` mapping, or a list of these). `recompute` takes the descriptor, the input receipts and the value you computed (the library does not evaluate functions); `blob` takes the content bytes of a blob value, whose length and SHA-256 are then checked (step 7.7).
- `check_envelope(status, body, keys) -> EnvelopeResult`: checks a mesh's response to `https://<mesh>/cell/...` (SPEC 5.5) and verifies the receipt inside it. The envelope itself is unsigned: `stale`, `superseded_by` and a `verified` label remain the mesh's claims, and whether the receipt answers the cell you asked for is yours to compare.
- `resolved_unit(descriptor, cell) -> str | None`: the unit of a cell's value, such as `USD/EUR` (SPEC 7.1, units.md).
- `keys_from_response(host, status, body) -> KeysResult`: interprets a response for `https://<host>/.well-known/datumesh.json` (SPEC 9.3).
- `fetch_keys(host, timeout=10.0) -> KeysResult`: the only function that uses the network. One GET, TLS verified, redirects not followed.
- `canonicalize(obj, kind=None) -> bytes`, `cell_hash`, `function_hash`, `receipt_hash`, `receipt_payload`, `jcs`: validation, RFC 8785 canonical bytes and SHA-256 hashes.
- `parse_uri(uri, signature)`, `format_uri(ref)`, `uri_to_https(uri, mesh)`: cell URIs (SPEC 5).
- `DatumeshError` (with `.code` and `.path`), `ERROR_CODES`, `SPEC_VERSION`, `UNITS`, `CURRENCIES`.

Requires Python 3.10 or later and PyNaCl. String rules use Unicode 15.1 tables shipped with the package, so results do not depend on the Python version's own Unicode database; the unit list is copied from the specification's `units.md`. Choosing which publishers to trust is up to you: a valid signature only means the key holder made the statement.

Licence: Apache-2.0.
