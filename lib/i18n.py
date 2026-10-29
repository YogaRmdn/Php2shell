"""i18n.py — mesin bahasa untuk php2shell (full ID + full EN).

Kenapa modul ini ada: toolkit asli hanya berbahasa Indonesia campur Inggris,
dicetak sebagai literal string yang tersebar di puluhan file. Sulit dirawat,
sulit diterjemahkan, dan mustahil ditambah bahasa lain.

Modul ini menggantinya dengan:
  - berkas JSON per bahasa di folder `lang/`
  - interpolasi `{placeholder}` ala str.format
  - fallback berantai: id -> en (bahasa apa pun yang kurang kuncinya jatuh ke EN)
  - deteksi otomatis dari --lang, env P2S_LANG, LC_ALL/LC_MESSAGES/LANG, lalu default
  - mode "kunci hilang" untuk pengembangan: kunci yang tak ada dicetak sebagai
    `[.namespace.key]` supaya kelihatan, bukan silent blank

Cara pakai:
    from lib.i18n import I18n, detect_lang
    t = I18n("id")
    print(t("app.title"))
    print(t("exploit.memory_limit_read", mb=8, send=10))

Penambahan bahasa baru = menambah `lang/<kode>.json` yang memuat minimal
kunci-kunci di `lang/en.json`. Tidak perlu menyentuh kode.
"""

from __future__ import annotations

import json
import locale
import os
from pathlib import Path
from typing import Any

# Folder berkas bahasa. Ada di root repo, sejajar dengan php2shell.py.
LANG_DIR = Path(__file__).resolve().parent.parent / "lang"

DEFAULT_LANG = "en"
# Bahasa yang dipakai bila kunci tidak ditemukan di bahasa terpilih.
FALLBACK_LANG = "en"

# Cache berkas bahasa yang sudah dimuat: {kode: dict}.
_CACHE: dict[str, dict[str, Any]] = {}


def available_langs() -> list[str]:
    """Daftar kode bahasa yang tersedia, diurutkan, EN duluan sebagai patokan."""
    if not LANG_DIR.is_dir():
        return [DEFAULT_LANG]
    codes = {p.stem for p in LANG_DIR.glob("*.json")}
    codes.add(DEFAULT_LANG)
    return sorted(codes)


def _load(lang: str) -> dict[str, Any]:
    """Muat dan flatten berkas bahasa sekali saja, lalu cache."""
    if lang in _CACHE:
        return _CACHE[lang]
    path = LANG_DIR / f"{lang}.json"
    data: dict[str, Any] = {}
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            data = _flatten(raw)
        except (OSError, json.JSONDecodeError) as exc:
            # Rusak? Jangan crash — pakai dict kosong dan biarkan fallback bekerja.
            data = {"__load_error__": str(exc)}
    _CACHE[lang] = data
    return data


def _flatten(node: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Ubah dict bersarang menjadi kunci datar: {"a": {"b": "x"}} -> {"a.b": "x"}."""
    out: dict[str, Any] = {}
    for key, val in node.items():
        full = f"{prefix}.{key}" if prefix else key
        if isinstance(val, dict):
            out.update(_flatten(val, full))
        else:
            out[full] = val
    return out


def detect_lang(explicit: str | None = None) -> str:
    """Pilih bahasa: argumen eksplisit -> P2S_LANG -> locale sistem -> default.

    `explicit` menang atas segalanya, tapi hanya bila benar-benar ada isinya.
    """
    if explicit:
        cand = explicit.strip().lower()
        if cand in available_langs():
            return cand
        # Izinkan bentuk panjang seperti "id_ID" / "en-US".
        base = cand.replace("_", "-").split("-")[0]
        if base in available_langs():
            return base

    env = os.environ.get("P2S_LANG", "").strip().lower()
    if env:
        if env in available_langs():
            return env
        base = env.replace("_", "-").split("-")[0]
        if base in available_langs():
            return base

    # Coba locale sistem. locale.getlocale bisa None di lingkungan tanpa CATALOG.
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(var, "")
        if val:
            base = val.split(".")[0].replace("_", "-").split("-")[0].lower()
            if base in available_langs():
                return base
    try:
        loc = locale.getlocale()[0]
        if loc:
            base = loc.replace("_", "-").split("-")[0].lower()
            if base in available_langs():
                return base
    except (ValueError, AttributeError):
        pass

    return DEFAULT_LANG


class I18n:
    """Penerjemah terikat satu bahasa, dengan fallback berantai ke EN."""

    def __init__(self, lang: str | None = None) -> None:
        self.lang = detect_lang(lang)
        self._strings = _load(self.lang)
        # Fallback: muat EN sebagai cadangan bila kunci hilang di bahasa utama.
        self._fallback: dict[str, Any] = (
            _load(FALLBACK_LANG) if self.lang != FALLBACK_LANG else {}
        )

    def __call__(self, key: str, /, **kwargs: Any) -> str:
        return self.get(key, **kwargs)

    def get(self, key: str, default: str | None = None, **kwargs: Any) -> str:
        """Ambil string untuk `key`, interpolasi kwargs, fallback ke EN lalu kunci."""
        val = self._strings.get(key)
        if val is None and self._fallback:
            val = self._fallback.get(key)
        if val is None:
            # Kunci benar-benar tak dikenal di mana pun.
            if default is not None:
                return default
            return f"[{key}]"  # mode kunci-hilang: kelihatan, bukan kosong
        if not isinstance(val, str):
            val = str(val)
        if kwargs:
            try:
                return val.format(**kwargs)
            except (KeyError, IndexError):
                # Interpolasi gagal (kunci format tak cocok) — kembalikan pola asli.
                return val
        return val

    def has(self, key: str) -> bool:
        """Apakah kunci ada di bahasa ini ATAU di fallback?"""
        return key in self._strings or key in self._fallback


# --------------------------------------------------------------------------- #
# API modul-level sekali-pakai untuk kode yang tidak mau ribet instance.       #
# --------------------------------------------------------------------------- #

_GLOBAL: I18n | None = None


def init(lang: str | None = None) -> I18n:
    """Inisialisasi (sekali) dan kembalikan instance global."""
    global _GLOBAL
    _GLOBAL = I18n(lang)
    return _GLOBAL


def get_i18n() -> I18n:
    """Ambil instance global; kalau belum ada, buat dengan bahasa terdeteksi."""
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = I18n(None)
    return _GLOBAL


def t(key: str, /, **kwargs: Any) -> str:
    """Pintasan: terjemahkan memakai instance global."""
    return get_i18n().get(key, **kwargs)
