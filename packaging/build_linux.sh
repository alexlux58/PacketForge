#!/usr/bin/env bash
# Build a standalone PacketForge binary on Linux using PyInstaller.
#
# Usage:
#   ./packaging/build_linux.sh
#
# Prereqs (in an activated venv):
#   pip install -e ".[package]"
#   # system libs for PySide6 (Debian/Ubuntu example):
#   sudo apt-get install -y libxcb-cursor0 libgl1 libegl1
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "pyinstaller not found. Install with: pip install -e \".[package]\"" >&2
  exit 1
fi

echo "Cleaning previous build output..."
rm -rf build dist

echo "Building PacketForge ..."
pyinstaller --clean --noconfirm packaging/packetforge.spec

echo
echo "Done. Binary written to: dist/PacketForge/PacketForge"
echo "Grant raw-socket capability without running as root with:"
echo "  sudo setcap cap_net_raw,cap_net_admin+eip dist/PacketForge/PacketForge"
