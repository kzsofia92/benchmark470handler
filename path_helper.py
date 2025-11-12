# path_helpers.py
import os, sys
from pathlib import Path

def resource_path(rel: str) -> str:
    base = getattr(sys, '_MEIPASS', os.path.dirname(__file__))
    return os.path.join(base, rel)

def user_config_dir(app="BMarkTMC") -> Path:
    try:
        from platformdirs import user_config_dir as ucfg
        return Path(ucfg(app))
    except Exception:
        return Path(os.getenv('APPDATA', Path.home())) / app

def user_log_dir(app="BMarkTMC") -> Path:
    try:
        from platformdirs import user_log_dir as ulog
        return Path(ulog(app))
    except Exception:
        return Path(os.getenv('LOCALAPPDATA', Path.home())) / app / "logs"
