#!/usr/bin/env bash
# Build a standalone PacketForge.app on macOS using PyInstaller.
#
# Usage:
#   ./packaging/build_macos.sh
#
# Prereqs (in an activated venv):
#   pip install -e ".[package]"
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "pyinstaller not found. Install with: pip install -e \".[package]\"" >&2
  exit 1
fi

echo "Cleaning previous build output..."
rm -rf build dist

echo "Building PacketForge.app ..."
pyinstaller --clean --noconfirm packaging/packetforge.spec

echo
echo "Done. Bundle written to: dist/PacketForge.app"
echo "Note: raw-socket features still require elevated privileges at runtime;"
echo "see the macOS privilege notes in README.md."
