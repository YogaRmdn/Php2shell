"""banner.py — identitas toolkit: HUD-frame + wordmark "shadow block".

Gaya ini DISENGaja berbeda dari versi asli (figlet blok + tema tengkorak).
Dirancang sebagai heads-up-display terminal:
  - wordmark "PHP2SHELL" dengan font double-block (ANSI Shadow)
  - dibingkai kotak ╔═╗ / ║ / ╚═╝ dengan sudut tegas
  - satu baris status (versi · bahasa · stealth · CVE) di dalam bingkai
  - gradien warna per baris (magenta -> biru -> cyan)

Murni presentasi, tanpa logika jaringan. Warna mati bila NO_COLOR / TERM=dumb.
"""

from __future__ import annotations

import os
import sys

from .config import FIX_FLOOR, LAST_VULN, CVE_FAMILY, VERSION as CFG_VERSION
from .i18n import t as _t

_WIDTH_PAD = 2  # spasi di kiri-kanan konten di dalam bingkai

# Glyph "shadow block" 6 baris per huruf. Lebar bebas — frame mengpad otomatis.
_GLYPHS: dict[str, list[str]] = {
    "P": [
        "██████╗ ",
        "██╔══██╗",
        "██████╔╝",
        "██╔═══╝ ",
        "██║     ",
        "╚═╝     ",
    ],
    "H": [
        "██╗  ██╗",
        "██║  ██║",
        "███████║",
        "██╔══██║",
        "██║  ██║",
        "╚═╝  ╚═╝",
    ],
    "2": [
        "███████╗",
        "╚══███╔╝",
        "  ███╔╝ ",
        " ███╔╝  ",
        "██╔██╗  ",
        "╚═╝ ╚═╝ ",
    ],
    "S": [
        "███████╗",
        "██╔════╝",
        "╚██████╗",
        " ╚════██║",
        "███████║",
        "╚══════╝",
    ],
    "E": [
        "███████╗",
        "██╔════╝",
        "█████╗  ",
        "██╔══╝  ",
        "███████╗",
        "╚══════╝",
    ],
    "L": [
        "██╗     ",
        "██║     ",
        "██║     ",
        "██║     ",
        "███████╗",
        "╚══════╝",
    ],
}

_WORD = "PHP2SHELL"

# Gradien warna per baris wordmark (magenta -> biru -> cyan).
_ROW_PAINTS = ("magenta", "magenta", "blue", "blue", "cyan", "cyan")


def _use_color() -> bool:
    """Warna default aktif; mati bila NO_COLOR diset atau TERM=dumb."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return True


class C:
    """ANSI 256-color (kontras tinggi di terminal gelap)."""

    def __init__(self, on: bool):
        self.on = on

    def _w(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.on else s

    def red(self, s):     return self._w("38;5;203", s)
    def green(self, s):   return self._w("38;5;48", s)
    def yellow(self, s):  return self._w("38;5;220", s)
    def blue(self, s):    return self._w("38;5;39", s)
    def magenta(self, s): return self._w("38;5;207", s)
    def cyan(self, s):    return self._w("38;5;51", s)
    def grey(self, s):    return self._w("38;5;245", s)
    def white(self, s):   return self._w("38;5;255", s)
    def bold(self, s):    return self._w("1", s)
    def dim(self, s):     return self._w("2", s)

    def paint(self, name: str, s: str) -> str:
        fn = getattr(self, name, self.grey)
        return fn(s)


def _wordmark_raw() -> list[str]:
    """Susun wordmark mentah (tanpa warna) dari glyph per huruf."""
    rows = [""] * 6
    for i, ch in enumerate(_WORD):
        g = _GLYPHS.get(ch)
        if not g:
            continue
        for r in range(6):
            rows[r] += g[r] + (" " if i < len(_WORD) - 1 else "")
    return rows


def art(c: "C") -> str:
    """Wordmark shadow-block berwarna (kompatibel dengan API lama)."""
    raw = _wordmark_raw()
    return "\n".join(c.paint(_ROW_PAINTS[i], row) for i, row in enumerate(raw))


def _status_plain(version: str, lang: str | None, stealth: bool,
                  delay: float, profile: str) -> str:
    """Baris status polos (untuk lebar) sebelum diwarnai."""
    parts = [f"v{version or CFG_VERSION}"]
    if lang:
        parts.append(f"lang {lang.upper()}")
    parts.append(f"stealth {'JA3' if stealth else 'OFF'}")
    if delay:
        parts.append(f"delay {delay}s")
    if profile:
        parts.append(f"ja3:{profile}")
    return "  ·  ".join(parts)


def _frame_row(c: "C", content: str, width: int, paint=None) -> str:
    pad = content + " " * (width - len(content))
    side = c.grey("║")
    body = f"{_WIDTH_PAD * ' '}{pad}{_WIDTH_PAD * ' '}"
    if paint:
        body = paint(body)
    return f"  {side} {body} {side}" if False else f"  {side} {body} {side}"


def _edge(c: "C", width: int, left: str, mid: str, right: str) -> str:
    inner = width + _WIDTH_PAD * 2
    return f"  {c.grey(left + mid * inner + right)}"


def render(mode: str = "", profile: str = "", delay: float = 0.0,
           stealth: bool = True, version: str | None = None,
           lang: str | None = None) -> str:
    c = C(_use_color())
    if version is None:
        version = ""
        for name in ("php2shell", "__main__"):
            mod = sys.modules.get(name)
            v = getattr(mod, "VERSION", None) if mod else None
            if v:
                version = v
                break

    raw = _wordmark_raw()
    status = _status_plain(version, lang, stealth, delay, profile)
    width = max(max(len(r) for r in raw), len(status))

    out: list[str] = []
    out.append(_edge(c, width, "╔", "═", "╗"))
    for i, row in enumerate(raw):
        pad = row + " " * (width - len(row))
        body = f"{_WIDTH_PAD * ' '}{pad}{_WIDTH_PAD * ' '}"
        out.append(f"  {c.grey('║')} {c.paint(_ROW_PAINTS[i], body)} {c.grey('║')}")
    out.append(_edge(c, width, "╠", "═", "╣"))

    # Baris status, diberi warna per bagian.
    left = (c.bold(c.white(f"v{version or CFG_VERSION}")) +
            c.grey("  ·  ") +
            (c.magenta(f"lang {(lang or 'EN').upper()}") + c.grey("  ·  ") if lang else "") +
            (c.green("stealth JA3") if stealth else c.red("stealth OFF")) +
            (c.grey(f"  ·  delay {delay}s") if delay else "") +
            (c.grey(f"  ·  ja3:{profile}") if profile else ""))
    body = f"{_WIDTH_PAD * ' '}"
    out.append(f"  {c.grey('║')} {body}{left}{c.grey(' ' * max(0, width - len(status) + _WIDTH_PAD))} {c.grey('║')}")

    out.append(_edge(c, width, "╚", "═", "╝"))

    # Di bawah bingkai: tagline + fix-floor + last-vulnerable.
    floors = "/".join(FIX_FLOOR[b] for b in sorted(FIX_FLOOR))
    lasts = "/".join(LAST_VULN[b] for b in sorted(LAST_VULN))
    out.append("")
    out.append("  " + c.grey(_t("app.tagline")))
    out.append("  " + c.white(f"{_t('app.fix_floor')}: ") + c.green(floors) +
               c.white(f"   {_t('app.last_vulnerable')}: ") + c.red(lasts))
    out.append("  " + c.grey(f"{CVE_FAMILY[0]} ({_t('app.full_chain')}) · "
                             f"{CVE_FAMILY[1]} ({_t('app.diff_chain')})"))
    if mode:
        out.append("  " + c.white(f"[{_t('app.mode')}] ") + c.bold(c.cyan(mode)))
    return "\n".join(out)


def splash(version: str, lang: str | None = None) -> str:
    """Tampilan ringkas saat tanpa argumen (kini dipakai interactive)."""
    c = C(_use_color())
    out = [render(version=version, lang=lang)]
    out.append("")
    out.append(c.grey(f"  {_t('banner.lab_note')}"))
    return "\n".join(out)


def guards_text() -> str:
    """Teks pagar untuk --help. Ditegakkan di KODE, bukan teks."""
    c = C(_use_color())
    lines = [c.yellow(f"  {_t('guards_text.title')}")]
    for i in range(1, 6):
        lines.append(c.white(f"    {i}. ") + _t(f"guards_text.g{i}"))
    return "\n".join(lines)
