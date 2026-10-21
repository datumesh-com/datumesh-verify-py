"""Test 4: key handling, through both keys_from_response and verify; fetch_keys over a local HTTPS server."""

from __future__ import annotations

import copy
import hashlib
import http.server
import json
import ssl
import threading
import time
import unittest
from typing import Any, Dict, List, Optional
from unittest import mock

from util import FIXTURES, env_keys, vectors_of

import datumesh
from datumesh import KeysResult, keys_from_response, verify
from datumesh import _keys

VECTOR = next(v for v in vectors_of("receipt", True) if v["id"] == "receipt/stored-number")
HOST = "rates.example.org"
DOC_TEXT = VECTOR["keys"][HOST]["https"]["body"]
DOC = json.loads(DOC_TEXT)
RECEIPT = json.loads(VECTOR["input"])
SEED = bytes.fromhex(VECTOR["keypair"]["seed"])


def signed(**changes: Any) -> Dict[str, Any]:
    """The stored-number receipt with members changed and re-signed with its key."""
    from nacl.signing import SigningKey
    r = dict(RECEIPT, **changes)
    r.pop("sig")
    payload = datumesh.jcs(r)
    r["sig"] = SigningKey(SEED).sign(payload).signature.hex()
    return r


class KeysFromResponseTest(unittest.TestCase):
    def test_valid_document(self) -> None:
        r = keys_from_response(HOST, 200, DOC_TEXT)
        self.assertTrue(r.ok)
        self.assertEqual(r.code, "OK")
        self.assertEqual(r.host, HOST)
        self.assertEqual(r.key_ids, ("d712b32a2cc5cb7c", "d9a2df65559c4444"))
        self.assertEqual(keys_from_response(HOST, 200, DOC_TEXT.encode()), r)

    def test_unavailable(self) -> None:
        for status in (None, 404, 301, 302, 500, 503, 204, "200", True):
            with self.subTest(status=status):
                r = keys_from_response(HOST, status, DOC_TEXT)  # type: ignore[arg-type]
                self.assertFalse(r.ok)
                self.assertEqual(r.code, "E_KEY_UNAVAILABLE")
                self.assertEqual(r.keys, ())

    def test_malformed_documents(self) -> None:
        def mutated(fn) -> str:
            d = copy.deepcopy(DOC)
            fn(d)
            return json.dumps(d)
        bodies = {
            "not json": "<html>Not here</html>",
            "bom": "﻿" + DOC_TEXT,
            "duplicate member": DOC_TEXT[:-1] + ', "proto": "datumesh/1"}',
            "host mismatch": mutated(lambda d: d.update(host="other.example.org")),
            "proto": mutated(lambda d: d.update(proto="datumesh/2")),
            "extra member": mutated(lambda d: d.update(x=1)),
            "empty keys": mutated(lambda d: d.update(keys=[])),
            "alg": mutated(lambda d: d["keys"][0].update(alg="EdDSA")),
            "wrong id": mutated(lambda d: d["keys"][0].update(id="0000000000000000")),
            "uppercase public": mutated(lambda d: d["keys"][0].update(public=d["keys"][0]["public"].upper())),
            "valid_to before valid_from": mutated(lambda d: d["keys"][0].update(valid_to="2019-01-01T00:00:00.000000Z")),
            "valid_to equals valid_from": mutated(lambda d: d["keys"][0].update(valid_to=d["keys"][0]["valid_from"])),
            "valid_to null": mutated(lambda d: d["keys"][0].update(valid_to=None)),
            "duplicate key": mutated(lambda d: d["keys"].append(dict(d["keys"][0]))),
            "bad instant": mutated(lambda d: d["keys"][0].update(valid_from="2020-01-01")),
            "array": "[]",
            "invalid utf-8": b"\xff",
        }
        for name, body in bodies.items():
            with self.subTest(name):
                r = keys_from_response(HOST, 200, body)
                self.assertFalse(r.ok)
                self.assertEqual(r.code, "E_KEY_DOC", r.detail)
        self.assertEqual(keys_from_response(HOST, 200, None).code, "E_KEY_DOC")

    def test_too_many_keys(self) -> None:
        from nacl.signing import SigningKey
        d = copy.deepcopy(DOC)
        pubs = [SigningKey(bytes([i]) * 32).verify_key.encode().hex() for i in range(65)]
        d["keys"] = [{"alg": "ed25519", "id": hashlib.sha256(bytes.fromhex(p)).hexdigest()[:16], "public": p,
                      "valid_from": "2020-01-01T00:00:00.000000Z"} for p in pubs]
        self.assertEqual(keys_from_response(HOST, 200, json.dumps(d)).code, "E_KEY_DOC")
        d["keys"] = d["keys"][:64]
        self.assertTrue(keys_from_response(HOST, 200, json.dumps(d)).ok)

    def test_never_raises(self) -> None:
        for args in [(5, 200, DOC_TEXT), (HOST, 200, 5), ("Bad Host", 200, DOC_TEXT), (HOST, 200.0, DOC_TEXT)]:
            r = keys_from_response(*args)  # type: ignore[arg-type]
            self.assertFalse(r.ok)

    def test_key_id(self) -> None:
        for v in vectors_of("keyid"):
            self.assertEqual(datumesh.key_id(v["input"]), v["key_id"])
        with self.assertRaises(datumesh.DatumeshError) as cm:
            datumesh.key_id("ABCD")
        self.assertEqual(cm.exception.code, "E_CANON_HEX")


class VerifyKeyHandlingTest(unittest.TestCase):
    def keys(self) -> KeysResult:
        return keys_from_response(HOST, 200, DOC_TEXT)

    def test_ok(self) -> None:
        self.assertTrue(verify(VECTOR["input"], self.keys()).ok)

    def test_expired_key(self) -> None:
        r = signed(asof="2024-07-01T00:00:00.000000Z", issued="2024-07-01T00:00:00.000000Z")
        self.assertEqual(verify(r, self.keys()).code, "E_KEY_NOT_VALID")
        r = signed(asof="2024-06-01T00:00:00.000000Z", issued="2024-06-01T00:00:00.000000Z")  # issued == valid_to
        self.assertEqual(verify(r, self.keys()).code, "E_KEY_NOT_VALID")
        r = signed(tx="2020-01-01T00:00:00.000000Z", asof="2020-01-01T00:00:00.000000Z",
                   issued="2020-01-01T00:00:00.000000Z")  # issued == valid_from
        self.assertTrue(verify(r, self.keys()).ok)

    def test_not_yet_valid_key(self) -> None:
        r = signed(computed_by=f"{HOST}#d9a2df65559c4444")
        self.assertEqual(verify(r, self.keys()).code, "E_KEY_NOT_VALID")

    def test_unknown_key_id(self) -> None:
        r = signed(computed_by=f"{HOST}#db6bd819ef4c64bc")
        res = verify(r, self.keys())
        self.assertEqual(res.code, "E_KEY_UNKNOWN")
        self.assertEqual(res.path, "$.computed_by")

    def test_malformed_document(self) -> None:
        self.assertEqual(verify(VECTOR["input"], keys_from_response(HOST, 200, "{}")).code, "E_KEY_DOC")
        bad = dict(DOC, proto="datumesh/2")
        self.assertEqual(verify(VECTOR["input"], bad).code, "E_KEY_DOC")

    def test_network_failure_and_404(self) -> None:
        for status in (None, 404, 301, 503):
            with self.subTest(status=status):
                self.assertEqual(verify(VECTOR["input"], keys_from_response(HOST, status, None)).code,
                                 "E_KEY_UNAVAILABLE")

    def test_host_not_covered(self) -> None:
        other = keys_from_response("calc.example.net", 200, VECTOR["keys"]["calc.example.net"]["https"]["body"])
        res = verify(VECTOR["input"], [other])
        self.assertEqual(res.code, "E_KEY_UNAVAILABLE")
        self.assertEqual(verify(VECTOR["input"], []).code, "E_KEY_UNAVAILABLE")
        # A broken document for another host does not matter.
        self.assertTrue(verify(VECTOR["input"], [keys_from_response("calc.example.net", 200, "x"), self.keys()]).ok)

    def test_key_sources(self) -> None:
        # parsed key document
        self.assertTrue(verify(VECTOR["input"], DOC).ok)
        # {key id: public key}: no windows, any host
        mapping = {k["id"]: k["public"] for k in DOC["keys"]}
        late = signed(asof="2030-01-01T00:00:00.000000Z", issued="2030-01-01T00:00:00.000000Z")
        self.assertTrue(verify(late, mapping).ok)
        self.assertEqual(verify(late, DOC).code, "E_KEY_NOT_VALID")
        self.assertEqual(verify(VECTOR["input"], {"d712b32a2cc5cb7c": "00" * 32}).code, "E_KEY_DOC")
        self.assertEqual(verify(VECTOR["input"], {"d712b32a2cc5cb7c": 5}).code, "E_KEY_DOC")
        self.assertEqual(verify(VECTOR["input"], {}).code, "E_KEY_UNKNOWN")
        # lists: the first source covering the host decides
        self.assertTrue(verify(VECTOR["input"], [DOC, keys_from_response(HOST, 404, None)]).ok)
        self.assertEqual(verify(VECTOR["input"], [keys_from_response(HOST, 404, None), DOC]).code, "E_KEY_UNAVAILABLE")
        # every vector's keys env
        for v in vectors_of("receipt", True):
            self.assertTrue(verify(v["input"], env_keys(v["keys"])).ok, v["id"])

    def test_wrong_argument_types(self) -> None:
        for keys in (5, "doc", b"doc", None, [[DOC]]):
            with self.subTest(keys=keys), self.assertRaises(TypeError):
                verify(VECTOR["input"], keys)
        with self.assertRaises(TypeError):
            verify(5, DOC)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify(VECTOR["input"], DOC, {"descriptor": None})


# ---------------------------------------------------------------- fetch_keys


class _Handler(http.server.BaseHTTPRequestHandler):
    routes: Dict[str, Any] = {}
    hits: List[str] = []

    def do_GET(self) -> None:  # noqa: N802
        _Handler.hits.append(self.path)
        status, headers, body, delay = _Handler.routes.get(self.path, (404, {}, b"", 0))
        if delay:
            time.sleep(delay)
        self.send_response(status)
        for k, val in headers.items():
            self.send_header(k, val)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:  # the client gave up (timeout test)
            pass

    def log_message(self, *args: Any) -> None:
        pass


class _QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # TLS handshakes refused by an untrusting client end here


class FetchKeysTest(unittest.TestCase):
    server: _QuietServer
    base: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _QuietServer(("127.0.0.1", 0), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(FIXTURES / "test-tls.crt"), str(FIXTURES / "test-tls.key"))
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.base = f"https://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        _Handler.routes = {
            "/.well-known/datumesh.json": (200, {"Content-Type": "application/json"}, DOC_TEXT.encode(), 0),
            "/redirect": (301, {"Location": "/.well-known/datumesh.json"}, b"", 0),
            "/slow": (200, {}, DOC_TEXT.encode(), 3),
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def trusting(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=str(FIXTURES / "test-tls.crt"))
        return ctx

    def test_tls_is_verified(self) -> None:
        status, body = _keys._fetch_url(self.base + "/.well-known/datumesh.json", 5)
        self.assertIsNone(status)  # self-signed certificate, default trust store
        self.assertEqual(keys_from_response(HOST, status, body).code, "E_KEY_UNAVAILABLE")

    def test_document_over_trusted_tls(self) -> None:
        status, body = _keys._fetch_url(self.base + "/.well-known/datumesh.json", 5, self.trusting())
        self.assertEqual(status, 200)
        self.assertTrue(keys_from_response(HOST, status, body).ok)

    def test_redirect_not_followed(self) -> None:
        _Handler.hits.clear()
        status, body = _keys._fetch_url(self.base + "/redirect", 5, self.trusting())
        self.assertEqual(status, 301)
        self.assertEqual(_Handler.hits, ["/redirect"])
        self.assertEqual(keys_from_response(HOST, status, body).code, "E_KEY_UNAVAILABLE")

    def test_404(self) -> None:
        status, body = _keys._fetch_url(self.base + "/missing", 5, self.trusting())
        self.assertEqual(status, 404)
        self.assertEqual(keys_from_response(HOST, status, body).code, "E_KEY_UNAVAILABLE")

    def test_timeout(self) -> None:
        t0 = time.monotonic()
        status, _ = _keys._fetch_url(self.base + "/slow", 0.5, self.trusting())
        self.assertIsNone(status)
        self.assertLess(time.monotonic() - t0, 2.5)

    def test_fetch_keys_uses_well_known_url(self) -> None:
        seen: List[Any] = []

        def fake(url: str, timeout: float, context: Optional[ssl.SSLContext] = None):
            seen.append((url, timeout, context))
            return 200, DOC_TEXT.encode()
        with mock.patch.object(_keys, "_fetch_url", fake):
            r = datumesh.fetch_keys(HOST, timeout=3)
        self.assertTrue(r.ok)
        self.assertEqual(seen, [(f"https://{HOST}/.well-known/datumesh.json", 3, None)])
        with mock.patch.object(_keys, "_fetch_url", lambda *a, **k: (200, b"x" * (_keys.MAX_DOCUMENT_BYTES + 1))):
            self.assertEqual(datumesh.fetch_keys(HOST).code, "E_KEY_DOC")
        with mock.patch.object(_keys, "_fetch_url", lambda *a, **k: (None, None)):
            self.assertEqual(datumesh.fetch_keys(HOST).code, "E_KEY_UNAVAILABLE")

    def test_response_for_a_host_that_is_not_a_dns_name(self) -> None:
        # SPEC 9.3 (spec-0.2.1): a response offered for a host that is not a DNS name
        # cannot satisfy 9.2, so a 200 is E_KEY_DOC whatever its body; any other status is still
        # E_KEY_UNAVAILABLE. Confirmed against the reference tool.
        for host in ("Rates.example.org", "localhost", "10.0.0.1", "rates.example.org:443", "Bad Host"):
            doc = DOC_TEXT.replace(HOST, host)
            for status, body, code in ((200, doc, "E_KEY_DOC"), (200, DOC_TEXT, "E_KEY_DOC"), (200, None, "E_KEY_DOC"),
                                       (200, "x", "E_KEY_DOC"), (404, None, "E_KEY_UNAVAILABLE"),
                                       (301, None, "E_KEY_UNAVAILABLE"), (None, None, "E_KEY_UNAVAILABLE")):
                with self.subTest(host=host, status=status, body=str(body)[:10]):
                    self.assertEqual(keys_from_response(host, status, body).code, code)

    def test_fetch_keys_invalid_host_without_network(self) -> None:
        with mock.patch.object(_keys, "_fetch_url", side_effect=AssertionError("network used")):
            for host in ("localhost", "Rates.example.org", "127.0.0.1", "a/b.example"):
                self.assertEqual(datumesh.fetch_keys(host).code, "E_KEY_UNAVAILABLE")

    def test_verify_never_uses_the_network(self) -> None:
        import socket
        with mock.patch.object(_keys, "_fetch_url", side_effect=AssertionError("network used")), \
                mock.patch.object(socket, "socket", side_effect=AssertionError("socket opened")), \
                mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket opened")):
            for v in vectors_of("receipt"):
                datumesh.verify(v["input"], env_keys(v["keys"]), v.get("recompute"))
            datumesh.verify(VECTOR["input"], [])


if __name__ == "__main__":
    unittest.main()
