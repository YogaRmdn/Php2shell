"""scanner.py — pemindai multi-target: detect -> preflight -> (opsional) exploit.

Membaca daftar URL dari file, dedupe, lalu proses paralel (thread pool).
Menghasilkan daftar record seragam untuk reporter (JSON/CSV/tabel).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable

from .detect import detect
from .preflight import preflight
from .transport import Transport, load_targets


@dataclass
class ScanRecord:
    url: str
    detect: dict
    preflight: dict
    exploit: dict | None = None

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "detect": self.detect,
            "preflight": self.preflight,
            "exploit": self.exploit or {},
        }


def scan(
    targets: list[str] | str,
    t_factory: Callable[[], Transport],
    *,
    threads: int = 5,
    do_exploit: bool = False,
    exploit_kwargs: dict | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> list[ScanRecord]:
    """Pindai banyak target. `t_factory` membuat Transport baru per utas."""
    from pathlib import Path

    if isinstance(targets, (str, Path)):
        urls = load_targets(targets)
    else:
        urls = list(targets)
    if not urls:
        return []

    records: list[ScanRecord] = []
    total = len(urls)
    done = 0

    def work(url: str) -> ScanRecord:
        t = t_factory()
        d = detect(url, t)
        p = preflight(d)
        rec = ScanRecord(url=url, detect=d.as_dict(), preflight=p.as_dict())
        if do_exploit and p.ready and not p.blockers:
            from . import runner
            kwargs = dict(exploit_kwargs or {})
            out = runner.run(url, t, **kwargs)
            rec.exploit = {
                "success": out.success, "proof": out.proof,
                "blind": out.blind, "error": out.error,
            }
        return rec

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futs = {pool.submit(work, u): u for u in urls}
        for fut in as_completed(futs):
            url = futs[fut]
            try:
                rec = fut.result()
            except Exception as exc:
                rec = ScanRecord(
                    url=url,
                    detect={"url": url, "reachable": False, "error": str(exc)},
                    preflight={"score": 0, "ready": False, "blockers": ["preflight.server_down"]},
                )
            records.append(rec)
            done += 1
            if progress:
                progress(done, total, url)

    # Pertahankan urutan input.
    order = {u: i for i, u in enumerate(urls)}
    records.sort(key=lambda r: order.get(r.url, 1 << 30))
    return records
