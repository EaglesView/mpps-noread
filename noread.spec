# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the noread GUI.
#   Build: pyinstaller noread.spec
# Produces a single windowed executable in dist/ (and a .app bundle on macOS).
# PyInstaller cannot cross-compile — build each OS binary on that OS.
import sys

block_cipher = None

a = Analysis(
    ['noread_gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='noread-gui',
    debug=False,
    strip=False,
    upx=False,
    console=False,          # windowed app
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='noread-gui.app',
        icon=None,
        bundle_identifier='com.tuneman.noread',
    )
