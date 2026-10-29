"""memprobe.py — baca memory_limit target lewat 1 request.

Stage 1 butuh field multipart yang LEBIH BESAR dari memory_limit target.
Nilai ini dibaca dulu supaya tool tidak menebak (dulu dipaku 12MB dan gagal
diam-diam di target berlimit 128M/512M).

Cara baca: kirim payload yang memicu pesan fatal "Allowed memory size of N
bytes exhausted" (bila display_errors=On). Bila display_errors=Off, angka
tidak terbaca dan tool memakai default dengan pesan jujur — TIDAK dinaikkan
sampai berhasil.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .transport import Transport

# Pesan fatal PHP: "Allowed memory size of 8388608 bytes exhausted ..."
MEM_RE = re.compile(r"Allowed memory size of\s+(\d+)\s+bytes", re.I)

DEFAULT_LIMIT_BYTES = 12 * 1024 * 1024  # fallback 12 MB
# Di atas angka ini rantai memang tidak akan jalan — berhenti dan lapor.
TOO_HIGH_BYTES = 512 * 1024 * 1024
# Margin pengiriman: sedikit di atas limit supaya OOM pasti terjadi.
SEND_MARGIN = 1.2


@dataclass
class MemProbe:
    limit_bytes: int | None      # None bila tidak terbaca
    send_mb: int                 # ukuran field yang akan dikirim
    source: str                  # "probe" | "default" | "too-high"


def probe_memory_limit(url: str, t: Transport) -> int | None:
    """Kirim 1 request kecil yang memicu pesan fatal OOM, ekstrak angkanya."""
    # Payload array bersarang memicu alokasi besar saat parsing.
    try:
        r = t.get(url, headers={"Cookie": "x=" + "A" * 2048})
    except Exception:
        return None
    m = MEM_RE.search(r.body or "")
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def compute_send_mb(limit_bytes: int | None) -> MemProbe:
    """Tentukan ukuran field stage-1 dari limit yang terbaca."""
    if limit_bytes is None:
        return MemProbe(None, DEFAULT_LIMIT_BYTES // (1024 * 1024), "default")
    if limit_bytes > TOO_HIGH_BYTES:
        return MemProbe(limit_bytes, limit_bytes // (1024 * 1024), "too-high")
    send = int(limit_bytes * SEND_MARGIN)
    # Bulatkan ke MB, tambah 2MB agar pasti melewati limit.
    send_mb = send // (1024 * 1024) + 2
    return MemProbe(limit_bytes, send_mb, "probe")
