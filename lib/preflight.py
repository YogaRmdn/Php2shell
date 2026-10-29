"""preflight.py — skor kesiapan exploit (0–90) + blocker keras.

Filosofi: deteksi = informasi, bukan gerbang. Versi tersembunyi CDN tetap
dilanjutkan. Blocker keras cuma dua: server mati, atau versi TERBACA sudah patch.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

from .config import support_level
from .detect import DetectResult

# Bobot komponen skor.
W_VULNERABLE = 30
W_UPLOAD_PROGRESS = 30
W_DISPLAY_ERRORS = 15
W_VERSION_KNOWN = 15
MAX_SCORE = 90


@dataclass
class PreflightResult:
    score: int = 0
    ready: bool = False
    blockers: list[str] = None      # type: ignore[assignment]
    support: str = "?"              # rce | leak | no | ?
    components: dict = None         # type: ignore[assignment]

    def __post_init__(self):
        if self.blockers is None:
            self.blockers = []
        if self.components is None:
            self.components = {}

    def as_dict(self) -> dict:
        return asdict(self)


def preflight(d: DetectResult) -> PreflightResult:
    p = PreflightResult()
    p.support = support_level(d.php_version, d.arch or "any")

    # --- blocker keras ---
    if not d.reachable:
        p.blockers.append("preflight.server_down")
        p.ready = False
        return p
    if d.verdict == "patched" and d.php_version:
        p.blockers.append("preflight.already_patched")
        p.ready = False
        return p

    # --- komponen skor ---
    score = 0
    if d.verdict == "vulnerable":
        score += W_VULNERABLE
        p.components["vulnerable"] = W_VULNERABLE
    if d.upload_progress == "on":
        score += W_UPLOAD_PROGRESS
        p.components["upload_progress"] = W_UPLOAD_PROGRESS
    if d.display_errors == "on":
        score += W_DISPLAY_ERRORS
        p.components["display_errors"] = W_DISPLAY_ERRORS
    if d.php_version:
        score += W_VERSION_KNOWN
        p.components["version_known"] = W_VERSION_KNOWN

    p.score = min(score, MAX_SCORE)
    # Siap = tanpa blocker keras. Skor rendah BUKAN penghalang (detection ≠ gate).
    p.ready = not p.blockers
    return p
