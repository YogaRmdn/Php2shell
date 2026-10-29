"""transport.py — HTTP dengan sidik jari browser (JA3), rate limit, audit JSONL.

Kenapa modul ini ada: exploit mentah memakai TLS Python default tanpa
User-Agent — di balik Cloudflare/Akamai itu langsung tertandai sebagai bot.
Modul ini dipakai SEMUA tahap (detect, preflight, probe) supaya satu target
hanya melihat satu identitas yang konsisten.

`curl_cffi` opsional: kalau tidak terpasang, turun ke urllib dengan header
lengkap (lebih mudah terdeteksi, tapi tidak crash).
"""

from __future__ import annotations

import gzip
import json
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Profil = (impersonate, User-Agent, Accept-Language). Dipilih bergiliran.
PROFILES: dict[str, dict[str, str]] = {
    "chrome": {
        "impersonate": "chrome124",
        "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
        "lang": "en-US,en;q=0.9",
    },
    "safari": {
        "impersonate": "safari17_0",
        "ua": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
               "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"),
        "lang": "en-GB,en;q=0.9",
    },
    "firefox": {
        "impersonate": "firefox133",
        "ua": ("Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 "
               "Firefox/133.0"),
        "lang": "en-US,en;q=0.5",
    },
    "android": {
        "impersonate": "chrome99_android",
        "ua": ("Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/99.0.4844.88 Mobile Safari/537.36"),
        "lang": "en-US,en;q=0.9",
    },
    "edge": {
        "impersonate": "edge101",
        "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 "
               "Edg/101.0.1210.53"),
        "lang": "en-US,en;q=0.9",
    },
}

DEFAULT_PROFILE = "chrome"
DEFAULT_DELAY = 1.0
DEFAULT_TIMEOUT = 15


def _have_curl_cffi() -> bool:
    try:
        import curl_cffi  # noqa: F401
        return True
    except Exception:
        return False


HAVE_CURL_CFFI = _have_curl_cffi()


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400 and not self.error

    def header(self, name: str) -> str:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return ""


class Transport:
    """Klien HTTP tunggal untuk semua tahap, dengan rate limit + audit JSONL."""

    def __init__(
        self,
        profile: str = DEFAULT_PROFILE,
        delay: float = DEFAULT_DELAY,
        timeout: int = DEFAULT_TIMEOUT,
        proxy: str | None = None,
        audit_log: str | Path | None = None,
        retries: int = 2,
        verbose: bool = False,
        rotate_identity: bool = False,
    ) -> None:
        if profile not in PROFILES:
            raise ValueError(
                f"unknown profile: {profile} (choices: {', '.join(PROFILES)})")
        self.profile_name = profile
        self.profile = PROFILES[profile]
        self.delay = max(0.0, float(delay))
        self.timeout = timeout
        self.proxy = proxy
        self.retries = max(0, retries)
        self.audit_path = Path(audit_log) if audit_log else None
        self.verbose = bool(verbose)
        self.rotate_identity = bool(rotate_identity)
        self._last = 0.0
        self._session = None

    # ------------------------------------------------------------------ #
    # internal                                                            #
    # ------------------------------------------------------------------ #

    def _throttle(self) -> None:
        """Jeda antar request + jitter acak 0.75–1.35× (pola manusiawi)."""
        if self.delay <= 0:
            return
        gap = time.monotonic() - self._last
        jitter = self.delay * random.uniform(0.75, 1.35)
        if gap < jitter:
            time.sleep(jitter - gap)
        self._last = time.monotonic()

    def _audit(self, rec: dict[str, Any]) -> None:
        if not self.audit_path:
            return
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **rec}
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        h = {
            "User-Agent": self.profile["ua"],
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8"),
            "Accept-Language": self.profile["lang"],
            "Accept-Encoding": "gzip, deflate",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Connection": "keep-alive",
        }
        if extra:
            h.update(extra)
        return h

    def _maybe_rotate(self) -> None:
        """Ganti identitas bergiliran bila rotate_identity aktif."""
        if not self.rotate_identity or not PROFILES:
            return
        names = list(PROFILES)
        idx = (names.index(self.profile_name) + 1) % len(names)
        self.profile_name = names[idx]
        self.profile = PROFILES[self.profile_name]

    # ------------------------------------------------------------------ #
    # backend: curl_cffi bila ada, else urllib                            #
    # ------------------------------------------------------------------ #

    def _do_curl(self, method, url, data, headers, timeout) -> Response:
        from curl_cffi import requests as creq  # type: ignore
        if self._session is None:
            self._session = creq.Session()
        kw: dict[str, Any] = {
            "impersonate": self.profile["impersonate"],
            "timeout": timeout,
            "headers": headers,
        }
        if self.proxy:
            kw["proxies"] = {"http": self.proxy, "https": self.proxy}
        if data is not None:
            kw["data"] = data
        r = self._session.request(method, url, **kw)
        return Response(
            url=url, status=int(r.status_code),
            headers=dict(r.headers), body=r.text or "", error="",
            elapsed_ms=int(r.elapsed.total_seconds() * 1000) if r.elapsed else 0,
        )

    def _do_urllib(self, method, url, data, headers, timeout) -> Response:
        handlers: list[urllib.request.BaseHandler] = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": self.proxy, "https": self.proxy}))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                hdrs = dict(resp.headers.items())
                if hdrs.get("Content-Encoding", "").lower() == "gzip":
                    try:
                        raw = gzip.decompress(raw)
                    except OSError:
                        pass
                return Response(url=url, status=int(resp.status),
                                headers=hdrs, body=raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            raw = exc.read() if hasattr(exc, "read") else b""
            return Response(url=url, status=int(exc.code),
                            headers=dict(exc.headers.items() if exc.headers else {}),
                            body=raw.decode("utf-8", "replace"),
                            error=f"HTTP {exc.code}")
        except Exception as exc:  # URLError, timeout, ssl, dll.
            return Response(url=url, status=0, error=str(exc))

    def _do(self, method, url, data, headers, timeout) -> Response:
        if HAVE_CURL_CFFI:
            try:
                return self._do_curl(method, url, data, headers, timeout)
            except Exception:
                # curl_cffi gagal di tengah jalan? Jatuh ke urllib, jangan crash.
                pass
        return self._do_urllib(method, url, data, headers, timeout)

    # ------------------------------------------------------------------ #
    # publik                                                              #
    # ------------------------------------------------------------------ #

    def get(self, url, headers=None) -> Response:
        return self.request("GET", url, headers=headers)

    def head(self, url, headers=None) -> Response:
        return self.request("HEAD", url, headers=headers)

    def post(self, url, data=None, headers=None) -> Response:
        return self.request("POST", url, data=data, headers=headers)

    def request(self, method, url, data=None, headers=None) -> Response:
        attempt = 0
        last: Response | None = None
        while attempt <= self.retries:
            self._throttle()
            self._maybe_rotate()
            start = time.monotonic()
            hdrs = self._headers(headers)
            resp = self._do(method, url, data, hdrs, self.timeout)
            resp.elapsed_ms = int((time.monotonic() - start) * 1000)
            self._audit({
                "method": method, "url": url, "status": resp.status,
                "elapsed_ms": resp.elapsed_ms, "body_len": len(resp.body),
                "profile": self.profile_name, "attempt": attempt,
                "error": resp.error,
            })
            if self.verbose:
                print(f"    [{method}] {url} -> {resp.status} "
                      f"({resp.elapsed_ms}ms, {len(resp.body)}B) {resp.error}")
            if resp.status == 0 or resp.status >= 500:
                last = resp
                # Backoff eksponensial sopan, bukan nge-brut.
                time.sleep(min(2 ** attempt, 8))
                attempt += 1
                continue
            return resp
        return last or Response(url=url, status=0, error="all retries failed")


# --------------------------------------------------------------------------- #
# Pemuat daftar target                                                         #
# --------------------------------------------------------------------------- #

def load_targets(path: str | Path) -> list[str]:
    """Baca daftar URL: satu/baris, `#` komentar, dedupe, auto-https."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(str(p))
    seen: set[str] = set()
    out: list[str] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "://" not in s:
            s = "https://" + s
        # Dedupe: anggap sama bila beda huruf besar/kecil atau trailing slash.
        key = s.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s.rstrip("/"))
    return out
