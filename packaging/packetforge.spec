# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for building a standalone PacketForge desktop bundle.

Build from the project root with the `package` extra installed:

    pip install -e ".[package]"
    pyinstaller packaging/packetforge.spec

Outputs land in `dist/`:
  * macOS  -> dist/PacketForge.app (and dist/PacketForge/)
  * Linux  -> dist/PacketForge/PacketForge

This spec bundles Scapy's submodules (collected dynamically) and the app icon
asset. Replace the placeholder icon and provide a platform icon (.icns/.ico)
via the `icon=` arguments below for a polished build.
"""

import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# SPECPATH is injected by PyInstaller and points at this file's directory.
PROJECT_ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))  # noqa: F821

hidden_imports = collect_submodules("scapy")

datas = [
    (os.path.join(PROJECT_ROOT, "packetforge", "assets", "icon.svg"), "packetforge/assets"),
]
datas += collect_data_files("scapy")

block_cipher = None

a = Analysis(
    [os.path.join(PROJECT_ROOT, "packetforge", "main.py")],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PacketForge",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon="packaging/icon.icns",  # provide a real .icns for macOS
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="PacketForge",
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="PacketForge.app",
        # icon="packaging/icon.icns",
        bundle_identifier="org.packetforge.app",
        info_plist={
            "NSHighResolutionCapable": True,
            "CFBundleDisplayName": "PacketForge",
        },
    )
