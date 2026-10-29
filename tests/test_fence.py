"""Unit test: pagar perintah (command fence) — inti dari desain proof-of-access."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import validate_command, build_command_preview, MAX_CMD_BYTES


class TestCommandFence(unittest.TestCase):
    def test_default_identity_ok(self):
        for cmd in ("id", "whoami", "uname", "hostname", "pwd"):
            self.assertTrue(validate_command(cmd).ok, cmd)

    def test_too_long_rejected(self):
        # 15 byte > 14.
        v = validate_command("whoamiXXXXXXXXX")
        self.assertFalse(v.ok)
        self.assertEqual(v.reason_key, "fence.too_long")

    def test_shell_operator_rejected(self):
        for cmd in ("id>/tmp/x", "id;ls", "id|wc", "id & id", "id`x`"):
            v = validate_command(cmd)
            self.assertFalse(v.ok, cmd)

    def test_reverse_shell_blocked(self):
        for cmd in ("bash", "sh", "nc", "python", "perl", "ruby"):
            v = validate_command(cmd)
            self.assertFalse(v.ok, cmd)

    def test_non_whitelisted_rejected(self):
        v = validate_command("cat /etc/shadow")
        self.assertFalse(v.ok)

    def test_extra_allow(self):
        v = validate_command("df", extra_allow=("df",))
        self.assertTrue(v.ok)

    def test_empty_rejected(self):
        self.assertFalse(validate_command("").ok)

    def test_preview_with_proof_file(self):
        self.assertEqual(build_command_preview("id", "p1"), "id>/out/p1")
        with self.assertRaises(ValueError):
            build_command_preview("id", "bad name!")

    def test_max_bytes_constant(self):
        self.assertEqual(MAX_CMD_BYTES, 14)


if __name__ == "__main__":
    unittest.main()
