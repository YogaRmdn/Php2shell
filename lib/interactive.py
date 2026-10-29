"""interactive.py — alur utama berbasis INPUT (menu & prompt), bukan flag.

Dipanggil saat tool dijalankan TANPA argumen. Pengguna:
  1. memilih bahasa lewat menu input ( Indonesia / English )
  2. melihat banner baru (HUD-frame)
  3. memilih mode lewat menu input
  4. mengisi parameter lewat prompt, lalu hasil dijalankan
  5. kembali ke menu sampai memilih "Keluar"

Semua teks mengikuti bahasa terpilih (i18n). Tanpa flag sama sekali.
"""

from __future__ import annotations

from . import advisory, config, detect, preflight, reporter, updater, webshell
from . import runner, scanner
from .banner import C, _use_color, render
from .i18n import I18n, available_langs
from .transport import DEFAULT_DELAY, DEFAULT_TIMEOUT, PROFILES, Transport


# --------------------------------------------------------------------------- #
# helper input                                                                 #
# --------------------------------------------------------------------------- #

def _inp(prompt: str) -> str:
    """input() yang aman terhadap EOF (Ctrl-D) / Ctrl-C."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _pause(t: I18n) -> None:
    _inp(f"  {c_grey()}{t('ui.press_enter')}…{c_reset()} ")


def c_grey() -> str:
    return "\033[38;5;245m" if _use_color() else ""


def c_reset() -> str:
    return "\033[0m" if _use_color() else ""


def _choose(prompt_title: str, options: list[tuple[str, str]], t: I18n) -> str:
    """Tampilkan menu bernomor, kembalikan kunci terpilih (str). Loop sampai valid."""
    c = C(_use_color())
    keys = [k for k, _ in options]
    W = 56  # lebar konten di dalam bingkai (konsisten utk semua baris)
    print()

    def row(content: str, paint=None) -> str:
        pad = content + " " * max(0, W - len(content))
        body = f" {pad} "
        if paint:
            body = paint(body)
        return "  " + c.bold(c.cyan("│")) + body + c.bold(c.cyan("│"))

    print("  " + c.bold(c.cyan("┌" + "─" * (W + 2) + "┐")))
    print(row(prompt_title, c.bold))
    print("  " + c.bold(c.cyan("├" + "─" * (W + 2) + "┤")))
    for i, (k, label) in enumerate(options, 1):
        num = c.yellow(f"[{i}]")
        # Hitung lebar TANPA kode warna: pad berdasar panjang teks polos.
        plain = f"[{i}]  {label}"
        pad = " " * max(0, W - len(plain))
        print("  " + c.bold(c.cyan("│")) + f" {num}  {label}{pad} " + c.bold(c.cyan("│")))
    print("  " + c.bold(c.cyan("└" + "─" * (W + 2) + "┘")))
    print("  " + c.grey(t("ui.section_hint")))

    while True:
        raw = _inp("  " + c.bold(c.green(f"{t('ui.choose')}: ")))
        if raw == "":
            continue
        if raw.isdigit() and 1 <= int(raw) <= len(keys):
            return keys[int(raw) - 1]
        # Izinkan juga ketik huruf kode langsung (mis. "id"/"en" atau nama mode).
        low = raw.lower()
        for k in keys:
            if low == k.lower():
                return k
        print("  " + c.red(t("ui.invalid")))


def _ask(t: I18n, label: str, default: str = "") -> str:
    """Prompt satu nilai dengan default antara kurung siku."""
    suffix = f" [{default}]" if default else ""
    val = _inp(f"  {c_grey()}{label}{suffix}: {c_reset()}")
    return val or default


# --------------------------------------------------------------------------- #
# pemilih bahasa                                                               #
# --------------------------------------------------------------------------- #

def choose_language(seed: str | None = None) -> str:
    """Menu pemilihan bahasa lewat input. `seed` melewati menu (dari --lang)."""
    if seed:
        return seed
    langs = available_langs()
    # Tampilkan kedua opsi utama dulu (id, en), lalu sisanya bila ada.
    ordered = [x for x in ("id", "en") if x in langs] + \
              [x for x in langs if x not in ("id", "en")]
    # Label per kode: pakai nama asli dari berkas (meta.name) bila ada.
    labels = {"id": "Bahasa Indonesia", "en": "English"}
    options: list[tuple[str, str]] = []
    for code in ordered:
        name = _lang_name(code)
        labels.setdefault(code, name)
        options.append((code, labels.get(code, code)))
    c = C(_use_color())
    print()
    logo = [
        ("  .-----. ", "php2shell v" + config.VERSION),
        (" /  .-.  \\", "unauthorized-RCE research toolkit"),
        ("|  | |  |", ""),
        (" \\  '---' /", ""),
        ("  '-----' ", ""),
    ]
    for art_txt, note in logo:
        line = "  " + c.bold(c.magenta(art_txt))
        if note:
            line += c.grey("   " + note)
        print(line)
    key = _choose("Select language  ·  Pilih bahasa", options, I18n("en"))
    return key


def _lang_name(code: str) -> str:
    import json
    from .i18n import LANG_DIR
    p = LANG_DIR / f"{code}.json"
    try:
        meta = json.loads(p.read_text(encoding="utf-8")).get("meta", {})
        return meta.get("name", code)
    except Exception:
        return code


def _t_short() -> str:
    return "unauthorized-RCE research toolkit"


# --------------------------------------------------------------------------- #
# menu mode + dispatch                                                         #
# --------------------------------------------------------------------------- #

def _mode_options(t: I18n) -> list[tuple[str, str]]:
    return [
        ("detect", t("ui.m_detect")),
        ("preflight", t("ui.m_preflight")),
        ("exploit", t("ui.m_exploit")),
        ("scan", t("ui.m_scan")),
        ("shell", t("ui.m_shell")),
        ("builds", t("ui.m_builds")),
        ("advisories", t("ui.m_advisories")),
        ("version", t("ui.m_version")),
        ("exit", t("ui.m_exit")),
    ]


def _make_transport(profile: str = "chrome") -> Transport:
    return Transport(profile=profile, delay=DEFAULT_DELAY, timeout=DEFAULT_TIMEOUT)


def _print_detect(t: I18n, url: str, d, p) -> None:
    c = C(_use_color())
    vcol = {"vulnerable": c.red, "patched": c.green, "eol": c.yellow}.get(d.verdict, c.grey)
    print()
    print("  " + c.bold(url))
    print(f"    {t('detect.php_version'):<16}: {d.php_version or '?'}  [{vcol(d.verdict)}]")
    print(f"    {t('detect.server'):<16}: {d.server or '?'}")
    print(f"    {t('detect.upload_progress'):<16}: {d.upload_progress}")
    print(f"    {t('detect.display_errors'):<16}: {d.display_errors}")
    if d.oom_signal:
        print(f"    {t('detect.oom_verdict'):<16}: {d.oom_signal}  {d.oom_detail}")
    rdy = c.green(t("verdict.ready")) if p.ready else c.red(t("verdict.not_ready"))
    print(f"    {t('preflight.score'):<16}: {p.score}/90  {rdy}  "
          f"[{t('preflight.support_level')}: {p.support}]")
    for b in p.blockers:
        print("    " + c.red(t("preflight.blockers")) + f": {t(b)}")


def _require_scheme(t: I18n, url: str) -> str | None:
    if not url.lower().startswith(("http://", "https://")):
        print("  " + C(_use_color()).red(t("errors.url_scheme", url=url)))
        return None
    return url


def _mode_detect(t: I18n) -> None:
    url = _ask(t, t("ui.ask_url"))
    if not url:
        return
    url = _require_scheme(t, url)
    if not url:
        return
    tr = _make_transport()
    d = detect.detect(url, tr)
    p = preflight.preflight(d)
    _print_detect(t, url, d, p)


def _mode_preflight(t: I18n) -> None:
    _mode_detect(t)  # preflight = detect + skor (sudah dicetak bareng)


def _mode_exploit(t: I18n) -> None:
    c = C(_use_color())
    url = _ask(t, t("ui.ask_url"))
    if not url:
        return
    url = _require_scheme(t, url)
    if not url:
        return
    cmd = _ask(t, t("ui.ask_cmd"), default="id")
    tr = _make_transport()
    d = detect.detect(url, tr)
    p = preflight.preflight(d)
    _print_detect(t, url, d, p)
    if not p.ready:
        print("  " + c.red(t("exploit.not_ready_abort")))
        return
    loopback = any(h in url for h in ("127.0.0.1", "localhost", "0.0.0.0", "[::1]"))
    if not loopback:
        ans = _inp("  " + c.yellow(t("ui.ask_yes") + " "))
        if ans.lower() not in ("y", "yes"):
            return
    out = runner.run(url, tr, cmd=cmd, assume_yes=True, profile=config.DEFAULT_EXPLOIT_PROFILE)
    for line in out.log:
        print("    " + c.grey(line))
    if out.success:
        tag = c.green(t("exploit.proof")) if not out.blind else c.yellow(t("exploit.blind"))
        print(f"  {tag} ({out.result.elapsed:.1f}s): {out.proof or t('exploit.blind_note')}")
    else:
        print(f"  {c.red(t('exploit.failed'))}: {out.error}")


def _mode_scan(t: I18n) -> None:
    lst = _ask(t, t("ui.ask_list"))
    if not lst:
        return
    threads = _ask(t, t("ui.ask_threads"), default="5")
    try:
        threads = max(1, int(threads))
    except ValueError:
        threads = 5
    from pathlib import Path
    if not Path(lst).is_file():
        print("  " + C(_use_color()).red(t("errors.list_not_found", path=lst)))
        return

    def progress(done, total, url):
        print(f"  [{t('scanner.scanning')}] {done}/{total}  {url}")

    records = scanner.scan(lst, _make_transport, threads=threads, progress=progress)
    dicts = [r.as_dict() for r in records]
    print()
    print(reporter.table(dicts))
    print(reporter.summary(dicts))


def _mode_shell(t: I18n) -> None:
    c = C(_use_color())
    out_dir = _ask(t, t("ui.ask_out"), default="shell/")
    ttl = _ask(t, t("ui.ask_ttl"), default="72")
    cmds = _ask(t, t("ui.ask_commands"), default="id,whoami")
    try:
        ttl_h = max(1, int(ttl))
    except ValueError:
        ttl_h = 72
    try:
        g = webshell.generate(out_dir, ttl_hours=ttl_h,
                              commands=tuple(x.strip() for x in cmds.split(",") if x.strip()))
    except ValueError as exc:
        print("  " + c.red(str(exc)))
        return
    print("  " + c.green(t("shell_gen.written")) + f": {g.path}")
    print(f"  {t('shell_gen.credentials')}: {g.cred_path}")
    print(f"  {t('shell_gen.ttl')}: {ttl_h}h  ·  {t('shell_gen.commands_whitelist')}: {', '.join(g.commands)}")
    print("  " + c.grey(t("shell_gen.bcrypt_note")))
    print("  " + c.grey(t("shell_gen.local_test_hint")))
    print("  " + c.yellow(t("shell_gen.upload_notice")))


def _mode_builds(t: I18n) -> None:
    c = C(_use_color())
    print()
    print("  " + c.bold(t("builds.table_head")))
    head = f"{'PHP':<9} {t('builds.arch'):<9} {t('builds.support'):<8} {t('builds.note')}"
    print("  " + c.grey(head))
    counts = {"rce": 0, "leak": 0, "no": 0}
    lvl_key = {"rce": "builds.level_rce", "leak": "builds.level_leak", "no": "builds.level_no"}
    for e in config.BUILD_SUPPORT:
        counts[e.level] = counts.get(e.level, 0) + 1
        col = {"rce": c.red, "leak": c.yellow, "no": c.grey}[e.level]
        print(f"  {e.php:<9} {e.arch:<9} {col(t(lvl_key[e.level])):<8} {c.grey(e.note)}")
    print()
    print("  " + t("builds.total_line", n=len(config.BUILD_SUPPORT),
                   rce=counts["rce"], leak=counts["leak"], no=counts["no"]))


def _mode_advisories(t: I18n) -> None:
    c = C(_use_color())
    print()
    print("  " + c.bold(t("advisory.title")))
    for a in advisory.ADVISORIES:
        print("  " + c.cyan(a["cve"]))
        print(f"    {t('advisory.class'):<10}: {a['class']}")
        print(f"    {t('advisory.trigger'):<10}: {a['trigger'][:68]}...")
        st = t("advisory.implemented") if a["status"] == "implemented" else t("advisory.detect_only")
        print(f"    {t('advisory.status'):<10}: {st}")
    print()
    for n in advisory.NOTES:
        print("  " + c.yellow("!") + " " + t(n))


def _mode_version(t: I18n) -> None:
    c = C(_use_color())
    res = updater.check(config.VERSION, _make_transport(), use_cache=True)
    print()
    print(f"  {t('updater.local'):<8}: {res['local']}")
    print(f"  {t('updater.remote'):<8}: {res['remote'] or '?'}  ({t('updater.source')}: {res['source'] or '?'})")
    print(f"  {t('updater.status'):<8}: {res['status']}")
    msg = t(res["message"]) if res.get("message") else res.get("error", "")
    print(f"  {t('updater.message'):<8}: {msg}")
    print(f"  {t('updater.repo'):<8}: {res['repo']}")


_DISPATCH = {
    "detect": _mode_detect,
    "preflight": _mode_preflight,
    "exploit": _mode_exploit,
    "scan": _mode_scan,
    "shell": _mode_shell,
    "builds": _mode_builds,
    "advisories": _mode_advisories,
    "version": _mode_version,
}


# --------------------------------------------------------------------------- #
# loop utama                                                                   #
# --------------------------------------------------------------------------- #

def run(seed_lang: str | None = None) -> int:
    """Alur interaktif utama. Mengembalikan exit code."""
    lang = choose_language(seed_lang)
    t = I18n(lang)
    # Sinkronkan global i18n supaya banner/reporter memakai bahasa terpilih.
    from .i18n import init as i18n_init
    i18n_init(lang)
    c = C(_use_color())

    print()
    print(render(lang=lang, stealth=True, version=config.VERSION))

    while True:
        key = _choose(t("ui.mode_title"), _mode_options(t), t)
        if key == "exit":
            print()
            print("  " + c.grey(t("ui.goodbye")))
            return 0
        try:
            _DISPATCH[key](t)
        except KeyboardInterrupt:
            print()
        except Exception as exc:  # fail-aman: kembali ke menu, jangan crash.
            print("  " + c.red(t("errors.unexpected")) + f": {exc}")
        _pause(t)
