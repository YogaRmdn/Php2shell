#!/usr/bin/env bash
# install.sh — pemasang sekali-jalan: venv + dependensi + smoke test.
set -euo pipefail

cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
VENV=".venv"

echo "[*] python: $($PY --version)"

if [ ! -d "$VENV" ]; then
  echo "[*] membuat venv: $VENV"
  "$PY" -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "[*] meng-upgrade pip & memasang dependensi"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo "[*] smoke test"
"$VENV/bin/python" -m unittest discover -s tests -t . -q

echo
echo "[OK] php2shell terpasang."
echo "    jalankan: $VENV/bin/python php2shell.py --lang id"
echo "    atau    : $VENV/bin/python php2shell.py --lang en"
echo "    bantuan  : $VENV/bin/python php2shell.py --help"
