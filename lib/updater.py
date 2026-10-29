"""updater.py — cek versi lokal vs rilis publik GitHub. Gagal-aman, tanpa telemetry.

Urutan sumber (berurutan, gagal-aman):
  1. releases/latest  -> tag rilis GitHub
  2. /tags           -> tag tertinggi, urut numerik (bukan leksikal)
  3. VERSION di main -> fallback selama repo belum punya tag

Perilaku:
  - offline / DNS mati / rate-limit / 404 -> status "unknown" + alasan, TIDAK crash
  - semver numerik: 1.10 > 1.2
  - cache 1 jam di out/version-check.json
  - exit code 0 = terbaru/tidak bisa dicek, 10 = ada update (bisa jadi gate CI)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .transport import Transport

REPO = "https://github.com/aarsaputra/php2shell"
CACHE_PATH = Path("out/version-check.json")
CACHE_TTL = 3600  # 1 jam


def _parse_tag(tag: str) -> tuple[int, ...]:
    """Ekstrak angka semver dari tag seperti 'v1.10.2' -> (1, 10, 2)."""
    s = tag.lstrip("vV")
    out = []
    for part in s.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out) or (0,)


def _read_cache() -> dict | None:
    try:
        if CACHE_PATH.is_file():
            data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            if time.time() - data.get("ts", 0) < CACHE_TTL:
                return data
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _write_cache(data: dict) -> None:
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(
            json.dumps({**data, "ts": time.time()}, indent=2), encoding="utf-8")
    except OSError:
        pass


def check(local_version: str, t: Transport, use_cache: bool = True) -> dict:
    """Kembalikan {local, remote, status, message, source, error}."""
    if use_cache:
        cached = _read_cache()
        if cached and cached.get("remote"):
            return cached

    result = {
        "local": local_version, "remote": "", "status": "unknown",
        "message": "", "source": "", "error": "", "repo": REPO,
    }

    remote, source = "", ""

    # 1) releases/latest
    try:
        r = t.get(f"{REPO}/releases/latest")
        if r.status == 200 and "/tag/" in (r.body or ""):
            import re
            m = re.search(r"/tag/([^\"']+)", r.body)
            if m:
                remote, source = m.group(1), "releases/latest"
    except Exception:
        pass

    # 2) /tags
    if not remote:
        try:
            r = t.get(f"{REPO}/tags")
            if r.status == 200:
                import re
                tags = re.findall(r"/tag/([^\"']+)", r.body or "")
                if tags:
                    remote = max(tags, key=_parse_tag)
                    source = "tags"
        except Exception:
            pass

    # 3) VERSION di main
    if not remote:
        try:
            r = t.get(f"{REPO}/raw/main/VERSION")
            if r.status == 200 and (r.body or "").strip():
                remote, source = (r.body or "").strip(), "branch"
        except Exception:
            pass

    if not remote:
        result["error"] = "offline / rate-limited / repo 404"
        result["message"] = "updater.unknown"
        return result

    result["remote"] = remote.lstrip("vV")
    result["source"] = source

    if _parse_tag(result["remote"]) > _parse_tag(local_version):
        result["status"] = "update"
        result["message"] = "updater.update_available"
    elif _parse_tag(result["remote"]) == _parse_tag(local_version):
        result["status"] = "current"
        result["message"] = "updater.current"
    else:
        # Lokal lebih baru dari remote (dev build).
        result["status"] = "ahead"
        result["message"] = "updater.current"

    _write_cache(result)
    return result
