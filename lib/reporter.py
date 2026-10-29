"""reporter.py — hasil ke JSON + CSV + tabel terminal. Warna dari banner.C."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .banner import C, _use_color
from .i18n import t

CSV_COLUMNS = [
    "url", "reachable", "status", "server", "php_version", "branch",
    "verdict", "fix_floor", "upload_progress", "display_errors",
    "patched_but_bypassable", "score", "ready", "exploited", "proof",
    "reason", "error",
]


def _row(rec: dict) -> dict:
    d = rec.get("detect", {}) or {}
    p = rec.get("preflight", {}) or {}
    e = rec.get("exploit", {}) or {}
    return {
        "url": d.get("url") or rec.get("url", ""),
        "reachable": d.get("reachable", False),
        "status": d.get("status", 0),
        "server": d.get("server", ""),
        "php_version": d.get("php_version") or "",
        "branch": d.get("branch") or "",
        "verdict": d.get("verdict", "unknown"),
        "fix_floor": d.get("fix_floor") or "",
        "upload_progress": d.get("upload_progress", "unknown"),
        "display_errors": d.get("display_errors", "unknown"),
        "patched_but_bypassable": d.get("patched_but_bypassable", False),
        "score": p.get("score", 0),
        "ready": p.get("ready", False),
        "exploited": e.get("success", False),
        "proof": e.get("proof", ""),
        "reason": d.get("reason", ""),
        "error": d.get("error", "") or e.get("error", ""),
    }


def write_json(path: str | Path, records: list[dict], meta: dict | None = None) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"meta": meta or {}, "count": len(records), "results": records}
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def write_csv(path: str | Path, records: list[dict]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for rec in records:
            w.writerow(_row(rec))
    return p


def _verdict_color(c: C, v: str) -> str:
    return {
        "vulnerable": c.red, "patched": c.green, "eol": c.yellow,
    }.get(v, c.grey)(v)


def table(records: list[dict]) -> str:
    if not records:
        return f"  {t('report.no_results')}"
    c = C(_use_color())
    hdr = (f"{'#':>3}  {t('verdict.vulnerable')[:0]}{'verdict':<11}  {'php':<9}  "
           f"{'up':<7}  {'disp':<7}  {'score':>5}  {'rdy':<4}  {'exp':<4}  url")
    lines = [c.bold(hdr), c.grey("-" * len(hdr))]
    for i, rec in enumerate(records, 1):
        r = _row(rec)
        vcol = _verdict_color(c, r["verdict"])
        rdy = c.green("YES") if r["ready"] else c.grey("no")
        exp = c.green("YES") if r["exploited"] else c.grey("no")
        lines.append(
            f"{i:>3}  {vcol:<11}  {(r['php_version'] or r['branch'] or '?'):<9}  "
            f"{r['upload_progress']:<7}  {r['display_errors']:<7}  "
            f"{r['score']:>2}/90  {rdy:<9}  {exp:<9}  {r['url']}"
        )
    return "\n".join(lines)


def summary(records: list[dict]) -> str:
    n = len(records)
    vuln = sum(1 for r in records if _row(r)["verdict"] == "vulnerable")
    eol = sum(1 for r in records if _row(r)["verdict"] == "eol")
    patched = sum(1 for r in records if _row(r)["verdict"] == "patched")
    unknown = sum(1 for r in records if _row(r)["verdict"] == "unknown")
    ready = sum(1 for r in records if _row(r)["ready"])
    exploited = sum(1 for r in records if _row(r)["exploited"])
    c = C(_use_color())
    return (c.white(f"  {t('report.total')}={n}  ") +
            c.red(f"vulnerable={vuln}  ") + c.yellow(f"eol={eol}  ") +
            c.green(f"patched={patched}  ") + c.grey(f"unknown={unknown}  ") +
            c.cyan(f"{t('report.ready')}={ready}  ") +
            c.magenta(f"{t('report.exploited')}={exploited}"))
