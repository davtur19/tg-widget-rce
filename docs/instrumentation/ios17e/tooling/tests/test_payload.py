import os
import tempfile
import unittest
import zlib

from i17e_runner.errors import PayloadError
from i17e_runner.payload import hash_matches, inspect_bytes, inspect_payload


class PayloadTests(unittest.TestCase):
    def test_inspect_bytes_sizes_and_hash(self):
        data = b"<html>" + b"A" * 100 + b"</html>"
        info = inspect_bytes(data)
        self.assertEqual(info.raw, len(data))
        self.assertEqual(info.zlib9, len(zlib.compress(data, 9)))
        self.assertTrue(info.ok)

    def test_inspect_payload_rejects_raw_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "big.html")
            with open(path, "wb") as handle:
                handle.write(b"A" * 64)
            with self.assertRaises(PayloadError):
                inspect_payload(path, raw_limit=32, zlib_limit=4096)

    def test_inspect_payload_rejects_zlib_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "compressible.html")
            with open(path, "wb") as handle:
                handle.write(b"A" * 4000)
            with self.assertRaises(PayloadError):
                inspect_payload(path, raw_limit=32768, zlib_limit=1)

    def test_missing_payload(self):
        with self.assertRaises(PayloadError):
            inspect_payload("/nonexistent/payload.html")

    def test_hash_matches_full_and_abbreviated(self):
        sha = "4906d6f990c443103f0ab398ce0aa1fe5b06700ae4deb4ca0dfda9a58fb1101a"
        self.assertTrue(hash_matches(sha, sha))
        self.assertTrue(hash_matches(sha, "4906d6f9…101a"))
        self.assertTrue(hash_matches(sha, "4906d6f9...101a"))
        self.assertFalse(hash_matches(sha, "4906d6f9…9999"))
        self.assertTrue(hash_matches(sha, ""))


if __name__ == "__main__":
    unittest.main()
