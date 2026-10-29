"""detect.py — sidik jari pasif + (opsional) probe OOM aktif. Non-destruktif.

Membaca: versi PHP (header / error page), branch & verdict terhadap fix-floor,
status session.upload_progress, display_errors, memory_limit, arsitektur.
Semua lewat GET/POST biasa — tidak ada yang menyerang.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

from . import oomprobe
from .config import FIX_FLOOR, EOL_MAX_BRANCH
from .transport import Transport

# Ekstraksi versi PHP dari berbagai sumber.
VER_RE = re.compile(r"PHP[/ ](\d+\.\d+\.\d+)", re.I)
X_POWERED_RE = re.compile(r"PHP/?(\d+\.\d+(?:\.\d+)?)", re.I)

# Pola error page yang memuat versi.
ERR_PAGE_RES = (
    re.compile(r"PHP Version\s*<b>(\d+\.\d+\.\d+)</b>", re.I),
    re.compile(r"PHP/(\d+\.\d+\.\d+)", re.I),
)


@dataclass
class DetectResult:
    url: str = ""
    reachable: bool = False
    status: int = 0
    server: str = ""
    php_version: str = ""
    branch: str = ""
    arch: str = ""
    sapi: str = ""
    verdict: str = "unknown"          # vulnerable | patched | eol | unknown
    fix_floor: str = ""
    upload_progress: str = "unknown"  # on | off | unknown
    display_errors: str = "unknown"   # on | off | unknown
    memory_limit: str = ""
    oom_signal: str = ""
    oom_detail: str = ""
    patched_but_bypassable: bool = False
    reason: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _branch_of(version: str) -> str:
    """Kembalikan branch mayor-minor, mis. "8.4" dari "8.4.26"."""
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return version


def _verdict_for(version: str) -> tuple[str, str, str]:
    """Kembalikan (verdict, fix_floor, reason_key)."""
    if not version:
        return "unknown", "", "detect.reading_version"
    branch = _branch_of(version)
    floor = FIX_FLOOR.get(branch)
    if floor is None:
        # Di bawah 8.2 atau branch tak dikenal: EOL / tidak dipatch.
        if branch <= EOL_MAX_BRANCH or branch.startswith(("5.", "7.")):
            return "eol", "", "advisory"
        return "unknown", "", ""
    if _lt(version, floor):
        return "vulnerable", floor, ""
    return "patched", floor, ""


def _lt(a: str, b: str) -> bool:
    """Bandingkan versi numerik per segmen (bukan string compare)."""
    def segs(v: str) -> list[int]:
        out = []
        for p in v.split("."):
            try:
                out.append(int(re.sub(r"\D", "", p) or 0))
            except ValueError:
                out.append(0)
        return out
    sa, sb = segs(a), segs(b)
    n = max(len(sa), len(sb))
    sa += [0] * (n - len(sa))
    sb += [0] * (n - len(sb))
    return sa < sb


def _extract_version(text: str, headers) -> str:
    """Coba semua sumber versi dalam urutan kepercayaan."""
    # 1. Header X-Powered-By.
    xp = headers.header("X-Powered-By") if headers else ""
    m = X_POWERED_RE.search(xp or "")
    if m:
        v = m.group(1)
        if v.count(".") == 1:
            v += ".0"
        return v
    # 2. Header Server.
    srv = headers.header("Server") if headers else ""
    m = VER_RE.search(srv or "")
    if m:
        return m.group(1)
    # 3. Badan body (error page / info page).
    for rx in ERR_PAGE_RES:
        m = rx.search(text or "")
        if m:
            return m.group(1)
    m = VER_RE.search(text or "")
    if m:
        return m.group(1)
    return ""


def _probe_flags(url: str, t: Transport) -> tuple[str, str]:
    """Probe ringan untuk status upload_progress & display_errors."""
    up, de = "unknown", "unknown"
    # display_errors: kirim payload yang memicu notice kecil, lihat apakah bocor.
    try:
        r = t.get(url, headers={"Cookie": "p2sde=" + "A" * 1024})
        if re.search(r"(Warning|Notice|Fatal error|Parse error)\s*:", r.body or ""):
            de = "on"
        elif r.body and r.status == 200:
            de = "off" if "display_errors" not in (r.body or "").lower() else "on"
    except Exception:
        pass
    # upload_progress: tidak ada cara pasif andal; lapor unknown bila tidak terbaca.
    return up, de


def detect(url: str, t: Transport, *,
           check_upload_progress: bool = True,
           check_display_errors: bool = True,
           check_oom: bool | None = None,
           sapi: str = "auto") -> DetectResult:
    """Deteksi satu URL. `check_oom=None` berarti 'otomatis' (bila unknown/eol)."""
    d = DetectResult(url=url)
    try:
        r = t.get(url)
    except Exception as exc:
        d.error = str(exc)
        return d

    d.status = r.status
    d.reachable = r.status > 0
    d.server = r.header("Server")
    if not d.reachable:
        d.reason = "preflight.server_down"
        return d

    d.php_version = _extract_version(r.body or "", r)
    d.branch = _branch_of(d.php_version) if d.php_version else ""
    d.sapi = sapi if sapi != "auto" else ("mod_php" if "Apache" in d.server else "unknown")

    d.verdict, d.fix_floor, _ = _verdict_for(d.php_version)
    d.patched_but_bypassable = (d.verdict == "patched" and not d.php_version)

    if check_display_errors:
        _, de = _probe_flags(url, t)
        d.display_errors = de
    if check_upload_progress:
        up, _ = _probe_flags(url, t)
        d.upload_progress = up

    # OOM aktif: hanya bila verdict unknown/eol (atau dipaksa), dan versi
    # terbaca >= fix-floor tidak pernah diprobe (hemat & minim jejak).
    want_oom = check_oom
    if want_oom is None:
        want_oom = d.verdict in ("unknown", "eol")
    if d.verdict == "patched" and d.php_version:
        want_oom = False
    if want_oom:
        res = oomprobe.probe(url, t)
        d.oom_signal = res.signal
        d.oom_detail = res.detail
        if res.triggered:
            # Sinyal OOM kuat -> angkat verdict ke vulnerable.
            d.verdict = "vulnerable"
            d.reason = f"detect.oom_{res.signal}"

    if d.verdict == "unknown" and not d.reason:
        d.reason = "detect.reading_version"
    return d
