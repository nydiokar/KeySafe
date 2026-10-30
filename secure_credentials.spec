# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# Collect all pykeepass submodules and data files
pykeepass_hidden_imports = collect_submodules('pykeepass')
pykeepass_datas = collect_data_files('pykeepass')

# Collect ttkbootstrap submodules and data files
ttkbootstrap_hidden_imports = collect_submodules('ttkbootstrap')
ttkbootstrap_datas = collect_data_files('ttkbootstrap')

a = Analysis(
    ['secure_credentials/run_app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('secure_credentials/assets', 'secure_credentials/assets'),
    ] + pykeepass_datas + ttkbootstrap_datas,
    hiddenimports=[
        'win32timezone',
        'win32cred',
        'pywintypes',
        'construct',
        'argon2',
        'argon2.low_level',
        'lxml',
        'lxml.etree',
        'lxml._elementpath',
        'ttkbootstrap',
        'ttkbootstrap.themes',
        'ttkbootstrap.constants',
        'ttkbootstrap.scrolled',
        'pyperclip',
        'pystray',
        'PIL',
        'PIL.Image',
        'PIL.ImageDraw',
        'win32security',
        'win32con',
        'win32api',
        'win32gui',
        'cryptography',
        'tkinter',
        'tkinter.messagebox',
        'tkinter.simpledialog',
        'tkinter.filedialog',
        'tkinter.ttk',
        'secure_credentials.src.pass_manager',
        'secure_credentials.src.keepass_backend',
        'secure_credentials.src.security',
        'secure_credentials.src.ui.gui',
        'secure_credentials.src.hash_utility',
    ] + pykeepass_hidden_imports + ttkbootstrap_hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'scipy',
        'pandas',
        'jupyter',
        'IPython',
        'tornado',
        'zmq',
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
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SecureCredentialManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set back to False for windowed mode
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='secure_credentials/assets/icon.ico'
) 