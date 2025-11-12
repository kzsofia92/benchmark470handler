# BMarkTMC.spec  (fixed: no __file__ use)
import os, glob
# from PyInstaller.utils.hooks import collect_submodules  # uncomment if you need hiddenimports

# Use CWD as project root (PyInstaller runs the spec from its folder)
project_root = os.path.abspath(os.getcwd())

datas = [
    ('README.md', '.'),
    ('config.json', '.'),
    ('users.json', '.'),
    ('.vault', '.vault'),           # include entire .vault dir
]

# include _logs directory if present
if os.path.isdir('_logs'):
    datas.append(('_logs', '_logs'))

# include root CSVs like logs.csv / logs-*.csv
for f in glob.glob('logs*.csv'):
    datas.append((os.path.abspath(f), '.'))

hiddenimports = [
    # e.g.: *only if PyInstaller misses something*
    # *collect_submodules('serial'),
    # *collect_submodules('tksheet'),
]

block_cipher = None

a = Analysis(
    ['app.py'],
    pathex=[project_root],          # search path
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='BMarkTMC',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,                  # set True if you want a console window
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=True, upx_exclude=[],
    name='BMarkTMC'
)
