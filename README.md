# datumesh

Verify [Datumesh](https://datumesh.com) receipts in Python. A receipt is a signed answer for one addressable data cell; this library checks its canonical form (RFC 8785 JSON) and its Ed25519 signature against the signer's published keys, and optionally the recomputation checks (function descriptor, input receipts, and a value you computed), as the [Datumesh specification](https://github.com/datumesh-com/datumesh-spec/blob/spec-0.1.1/SPEC.md) (revision `spec-0.1.1`) defines.

```sh
pip install datumesh
git clone --depth 1 --branch spec-0.1.1 https://github.com/datumesh-com/datumesh-spec && cd datumesh-spec
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

- `verify(receipt, keys, recompute=None) -> VerifyResult`: runs the verification procedure of SPEC 10.1. Never raises for an invalid receipt or bad key material; the result has `ok`, `code` (`"OK"` or an error code), `level` (`"signed"` or `"recomputed"`), `hash`, `key`, `detail` and `path`. It uses no network: keys are an argument (a key document, a `KeysResult`, a `{key id: public key}` mapping, or a list of these).
- `keys_from_response(host, status, body) -> KeysResult`: interprets a response for `https://<host>/.well-known/datumesh.json` (SPEC 9.3).
- `fetch_keys(host, timeout=10.0) -> KeysResult`: the only function that uses the network. One GET, TLS verified, redirects not followed.
- `canonicalize(obj, kind=None) -> bytes`, `cell_hash`, `function_hash`, `receipt_hash`, `receipt_payload`, `jcs`: validation, RFC 8785 canonical bytes and SHA-256 hashes.
- `parse_uri(uri, signature)`, `format_uri(ref)`, `uri_to_https(uri, mesh)`: cell URIs (SPEC 5).
- `DatumeshError` (with `.code` and `.path`), `ERROR_CODES`, `SPEC_VERSION`.

Requires Python 3.10 or later and PyNaCl. String rules use Unicode 15.1 tables shipped with the package, so results do not depend on the Python version's own Unicode database. Choosing which publishers to trust is up to you: a valid signature only means the key holder made the statement.

Licence: Apache-2.0.
