# -*- mode: python ; coding: utf-8 -*-
"""
phantom.spec
PyInstaller build spec for Phantom — Network Packet Sniffer

Build commands:
  macOS / Linux : pyinstaller phantom.spec
  Windows       : pyinstaller phantom.spec
"""

import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# ── Collect all scapy data files and submodules ───────────────────────────────
scapy_datas   = collect_data_files('scapy')
scapy_hiddens = collect_submodules('scapy')

# ── Source files in project root ──────────────────────────────────────────────
project_datas = [
    # Include GeoLite2 database if present
    ('GeoLite2-City.mmdb', '.'),
]

# Only include the mmdb if it actually exists
import os as _os
if not _os.path.exists('GeoLite2-City.mmdb'):
    project_datas = []

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=scapy_datas + project_datas,
    hiddenimports=scapy_hiddens + [
        'scapy.layers.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.layers.l2',
        'scapy.layers.dns',
        'scapy.layers.http',
        'scapy.contrib',
        'matplotlib',
        'matplotlib.backends.backend_tkagg',
        'matplotlib.pyplot',
        'geoip2',
        'geoip2.database',
        'geoip2.models',
        'maxminddb',
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'pkg_resources.py2_warn',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'test', 'tests', 'unittest',
        'IPython', 'jupyter', 'notebook',
        'scipy', 'pandas', 'numpy.testing',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Phantom',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,           # No terminal window — GUI only
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Windows icon (optional — create a phantom.ico file)
    # icon='phantom.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Phantom',
)

# ── macOS .app bundle ─────────────────────────────────────────────────────────
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='Phantom.app',
        # icon='phantom.icns',     # add a .icns file for a custom icon
        bundle_identifier='com.phantom.netsniffer',
        info_plist={
            'NSPrincipalClass':              'NSApplication',
            'NSAppleScriptEnabled':          False,
            'CFBundleName':                  'Phantom',
            'CFBundleDisplayName':           'Phantom',
            'CFBundleShortVersionString':    '1.0.0',
            'CFBundleVersion':               '1.0.0',
            'NSHighResolutionCapable':       True,
            # Required for packet capture on macOS
            'NSLocalNetworkUsageDescription': 'Phantom needs network access to capture packets.',
        },
    )
