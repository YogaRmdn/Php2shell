"""Unit test: mesin bahasa i18n (ID/EN lengkap + fallback + interpolasi)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.i18n import I18n, available_langs, detect_lang


class TestI18n(unittest.TestCase):
    def test_available_langs(self):
        langs = available_langs()
        self.assertIn("en", langs)
        self.assertIn("id", langs)

    def test_id_strings(self):
        t = I18n("id")
        self.assertEqual(t.lang, "id")
        # Judul sama di semua bahasa (ASCII art).
        self.assertIn("P H P 2 S H E L L", t("app.title"))
        # Kata kunci khas Indonesia.
        self.assertIn("rentan", t("verdict.vulnerable"))
        self.assertIn("TIDAK", t("verdict.not_ready"))
        self.assertEqual(t("exploit.proof"), "BUKTI")

    def test_en_strings(self):
        t = I18n("en")
        self.assertEqual(t.lang, "en")
        self.assertEqual(t("verdict.vulnerable"), "vulnerable")
        self.assertEqual(t("exploit.proof"), "PROOF")
        self.assertEqual(t("verdict.ready"), "READY")

    def test_interpolation(self):
        t = I18n("en")
        s = t("exploit.memory_limit_read", mb=8, send=10)
        self.assertIn("8", s)
        self.assertIn("10", s)

    def test_interpolation_id(self):
        t = I18n("id")
        s = t("fence.too_long", n=20, max=14)
        self.assertIn("20", s)
        self.assertIn("14", s)

    def test_missing_key_returns_marker(self):
        t = I18n("en")
        self.assertEqual(t("no.such.key"), "[no.such.key]")

    def test_detect_lang_explicit(self):
        self.assertEqual(detect_lang("id"), "id")
        self.assertEqual(detect_lang("en"), "en")
        # Bentuk panjang.
        self.assertEqual(detect_lang("id_ID"), "id")

    def test_detect_lang_unknown_falls_back(self):
        # Bahasa tak dikenal -> default (en), tidak crash.
        self.assertIn(detect_lang("xx"), ("en", "id"))

    def test_all_keys_parity(self):
        """Semua kunci di EN harus tersedia di ID (dan sebaliknya)."""
        en = I18n("en")
        id_ = I18n("id")
        # Ambil kunci dari berkas langsung untuk perbandingan penuh.
        import json
        lang_dir = Path(__file__).resolve().parent.parent / "lang"
        en_keys = set(_flatten(json.loads((lang_dir / "en.json").read_text())))
        id_keys = set(_flatten(json.loads((lang_dir / "id.json").read_text())))
        self.assertEqual(en_keys, id_keys,
                         f"kunci hilang di id: {en_keys - id_keys}; "
                         f"ekstra di id: {id_keys - en_keys}")


def _flatten(node, prefix=""):
    out = set()
    for k, v in node.items():
        full = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out |= _flatten(v, full)
        else:
            out.add(full)
    return out


if __name__ == "__main__":
    unittest.main()
