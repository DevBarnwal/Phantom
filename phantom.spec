# -*- mode: python ; coding: utf-8 -*-
"""
phantom.spec
PyInstaller build spec for Phantom — Network Intelligence & Threat Monitor
"""

import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# ── Collect scapy data + submodules ──────────────────────────────────────────
scapy_datas   = collect_data_files('scapy')
scapy_hiddens = collect_submodules('scapy')

# ── Include GeoLite2 database if present ─────────────────────────────────────
project_datas = []
if os.path.exists('GeoLite2-City.mmdb'):
    project_datas = [('GeoLite2-City.mmdb', '.')]

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=scapy_datas + project_datas,
    hiddenimports=scapy_hiddens + [
        # Scapy layers
        'scapy.layers.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.layers.l2',
        'scapy.layers.dns',
        'scapy.layers.http',
        'scapy.contrib',
        # Matplotlib
        'matplotlib',
        'matplotlib.backends.backend_tkagg',
        'matplotlib.pyplot',
        'matplotlib.gridspec',
        # GeoIP
        'geoip2',
        'geoip2.database',
        'geoip2.models',
        'maxminddb',
        'maxminddb.reader',
        # Tkinter
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        # Standard library modules PyInstaller sometimes misses
        'unittest',
        'unittest.mock',
        'unittest.util',
        'collections',
        'collections.abc',
        'ipaddress',
        'json',
        'csv',
        'logging',
        'logging.handlers',
        'threading',
        'queue',
        'time',
        'platform',
        'subprocess',
        'webbrowser',
        'pathlib',
        'datetime',
        # Project modules
        'gui',
        'packet_sniffer',
        'packet_analyzer',
        'threat_detector',
        'geo_lookup',
        'exporter',
        'report_generator',
        'config',
        # Misc
        'pkg_resources',
        'pkg_resources.py2_warn',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
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
        bundle_identifier='com.phantom.netsniffer',
        info_plist={
            'NSPrincipalClass':               'NSApplication',
            'NSAppleScriptEnabled':           False,
            'CFBundleName':                   'Phantom',
            'CFBundleDisplayName':            'Phantom',
            'CFBundleShortVersionString':     '1.0.0',
            'CFBundleVersion':                '1.0.0',
            'NSHighResolutionCapable':        True,
            'NSLocalNetworkUsageDescription': 'Phantom needs network access to capture packets.',
        },
    )
