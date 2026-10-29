"""Unit test: deteksi versi, verdict, tabel build, webshell generator."""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import support_level, lookup_build
from lib.detect import _branch_of, _verdict_for, _lt
from lib.memprobe import compute_send_mb
from lib import webshell


class TestVersionLogic(unittest.TestCase):
    def test_branch(self):
        self.assertEqual(_branch_of("8.4.26"), "8.4")
        self.assertEqual(_branch_of("7.4.33"), "7.4")

    def test_lt_numeric(self):
        self.assertTrue(_lt("8.4.26", "8.4.27"))
        self.assertFalse(_lt("8.4.27", "8.4.27"))
        self.assertFalse(_lt("8.10.0", "8.9.0"))  # numerik, bukan leksikal

    def test_verdict_vulnerable(self):
        v, floor, _ = _verdict_for("8.4.26")
        self.assertEqual(v, "vulnerable")
        self.assertEqual(floor, "8.4.27")

    def test_verdict_patched(self):
        v, _, _ = _verdict_for("8.4.27")
        self.assertEqual(v, "patched")

    def test_verdict_eol(self):
        v, _, _ = _verdict_for("7.4.33")
        self.assertEqual(v, "eol")

    def test_verdict_unknown_when_empty(self):
        v, _, _ = _verdict_for("")
        self.assertEqual(v, "unknown")


class TestBuildSupport(unittest.TestCase):
    def test_rce_build(self):
        self.assertEqual(support_level("8.4.26", "amd64"), "rce")

    def test_leak_build(self):
        self.assertEqual(support_level("8.3.35", "aarch64"), "leak")

    def test_unknown_build(self):
        self.assertEqual(support_level("9.9.9", "amd64"), "?")

    def test_lookup(self):
        e = lookup_build("8.5.11", "amd64")
        self.assertIsNotNone(e)
        self.assertEqual(e.level, "rce")


class TestMemProbe(unittest.TestCase):
    def test_default_when_unreadable(self):
        mp = compute_send_mb(None)
        self.assertEqual(mp.source, "default")

    def test_too_high(self):
        mp = compute_send_mb(1024 * 1024 * 1024)  # 1 GiB
        self.assertEqual(mp.source, "too-high")

    def test_probe_sends_above_limit(self):
        mp = compute_send_mb(8 * 1024 * 1024)  # 8 MiB
        self.assertEqual(mp.source, "probe")
        # Field yang dikirim harus > limit (dalam MB).
        self.assertGreater(mp.send_mb, 8)


class TestWebshell(unittest.TestCase):
    def test_generate(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            g = webshell.generate(td, ttl_hours=1, commands=("id", "whoami"))
            self.assertTrue(g.path.is_file())
            self.assertTrue(g.cred_path.is_file())
            body = g.path.read_text()
            self.assertIn("password_verify", body)
            # Plaintext password TIDAK boleh ada di dalam shell.
            self.assertNotIn(g.password, body)
            # Ada mekanisme kedaluwarsa.
            self.assertIn(str(g.expires_epoch), body)

    def test_reject_non_identity_command(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                webshell.generate(td, commands=("rm",))

    def test_expiry_in_future(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            g = webshell.generate(td, ttl_hours=2)
            self.assertGreater(g.expires_epoch, time.time())


if __name__ == "__main__":
    unittest.main()
