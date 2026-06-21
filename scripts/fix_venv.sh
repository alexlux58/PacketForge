#!/usr/bin/env bash
# Repair a local .venv on macOS (iCloud hidden flags) and install a robust launcher.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3.12}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON=python3
fi

if [[ ! -d .venv ]]; then
  "$PYTHON" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install -U pip
python -m pip install -e ".[dev]"

if [[ "$(uname -s)" == "Darwin" ]]; then
  chflags -R nohidden .venv 2>/dev/null || true
fi

install -m 755 packaging/packetforge_launcher.py .venv/bin/packetforge
install -m 755 packaging/packetforge_launcher.py .venv/bin/packetforge-gui

python -c "import packetforge; print('packetforge import OK:', packetforge.__file__)"
echo "Done. Run: source .venv/bin/activate && packetforge"
