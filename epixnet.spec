# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for EpixNet
This file configures how PyInstaller bundles the EpixNet application
"""

import sys
import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# Determine platform-specific icon
if sys.platform == 'darwin':
    # macOS requires .icns format
    icon_file = 'plugins/Trayicon/trayicon.icns'
elif sys.platform == 'win32':
    # Windows uses .ico format
    icon_file = 'plugins/Trayicon/trayicon.ico'
else:
    # Linux uses .ico format
    icon_file = 'plugins/Trayicon/trayicon.ico'

# Collect all data files and submodules for dependencies
datas = []
binaries = []
hiddenimports = []

# Collect data files from packages
datas += collect_data_files('gevent')
datas += collect_data_files('maxminddb')

# Add EpixNet plugins and data
datas += [('plugins', 'plugins')]
datas += [('src', 'src')]

# Add tools directory (OpenSSL, Tor, etc.) if it exists
if os.path.isdir('tools'):
    datas += [('tools', 'tools')]

# Hidden imports for gevent and other packages
hiddenimports += collect_submodules('gevent')
hiddenimports += collect_submodules('asyncio_gevent')
hiddenimports += [
    'gevent',
    'gevent.monkey',
    'gevent.pywsgi',
    'gevent.queue',
    'gevent.event',
    'gevent.lock',
    'gevent.pool',
    'gevent.subprocess',
    'gevent.socket',
    'gevent.ssl',
    'gevent.threading',
    'gevent.time',
    'gevent.os',
    'gevent.signal',
    'gevent.select',
    'gevent.fileobject',
    'gevent.hub',
    'gevent.greenlet',
    'gevent.local',
    'gevent.resolver',
    'gevent.resolver.dnspython',
    'gevent.resolver.ares',
    'gevent.resolver.thread',
    'gevent.resolver.blocking',
    'gevent_ws',
    'websocket_client',
    'msgpack',
    'base58',
    'pymerkletools',
    'rsa',
    'PySocks',
    'pyasn1',
    'coincurve',
    'maxminddb',
    'rich',
    'defusedxml',
    'pyaes',
    'requests',
    'GitPython',
    'bech32',
    'Cryptodome',
    'Cryptodome.Cipher',
    'Cryptodome.PublicKey',
    'Cryptodome.Random',
    'Cryptodome.Util',
    'Cryptodome.Hash',
    'Cryptodome.Signature',
    'asyncio_gevent',
    'sockshandler',
    'aiobtdht',
    'aioudp',
    'merkletools',
]

a = Analysis(
    ['epixnet.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
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
    name='EpixNet',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_file,
)

# Create a directory with all files (onedir mode)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='EpixNet',
)

# macOS app bundle (only on macOS)
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='EpixNet.app',
        icon=icon_file,
        bundle_identifier='com.epixnet.app',
        info_plist={
            'NSPrincipalClass': 'NSApplication',
            'NSHighResolutionCapable': 'True',
        },
    )

