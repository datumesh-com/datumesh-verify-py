"""Test 2: every single-bit flip of a valid receipt fails verification."""

from __future__ import annotations

import json
import sys
import unittest

from util import env_keys, vectors_of

import datumesh


class BitFlipTest(unittest.TestCase):
    def test_canonical_receipt_bit_flips(self) -> None:
        total = 0
        for v in vectors_of("receipt", True):
            keys = env_keys(v["keys"])
            canonical = datumesh.canonicalize(v["input"], "receipt")
            self.assertTrue(datumesh.verify(canonical, keys).ok, v["id"])
            codes = set()
            for i in range(len(canonical)):
                for bit in range(8):
                    flipped = bytearray(canonical)
                    flipped[i] ^= 1 << bit
                    res = datumesh.verify(bytes(flipped), keys)
                    total += 1
                    if res.ok:
                        self.fail(f"{v['id']}: flipping bit {bit} of byte {i} still verifies")
                    codes.add(res.code)
            self.assertIn("E_SIGNATURE", codes)
        print(f"\nbit flips of canonical receipts: {total} run, {total} rejected", file=sys.stderr)

    def test_signature_bit_flips(self) -> None:
        total = 0
        for v in vectors_of("receipt", True):
            keys = env_keys(v["keys"])
            receipt = json.loads(v["input"])
            sig = bytes.fromhex(receipt["sig"])
            self.assertEqual(len(sig), 64)
            for i in range(64):
                for bit in range(8):
                    flipped = bytearray(sig)
                    flipped[i] ^= 1 << bit
                    res = datumesh.verify(dict(receipt, sig=flipped.hex()), keys)
                    total += 1
                    self.assertEqual(res.code, "E_SIGNATURE", f"{v['id']} byte {i} bit {bit}")
                    self.assertEqual(res.hash, v["sha256"])
        print(f"\nbit flips of raw signatures: {total} run, {total} rejected with E_SIGNATURE", file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
