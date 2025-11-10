from __future__ import annotations
# config_store.py
import json, os
from typing import Dict, Any
import secure_store as sstore

CFG_FILE = "config.json"

DEFAULTS = {
    "serial": {
        "port": "",
        "baud": 9600,
        "parity": "N",   # N, E, O
        "stopbits": 1, # 1, 0
    },
    "last_csv": "",
    "pattern": "",
}

def load_config() -> Dict[str, Any]:
    try:
        cfg = sstore.load_config()
        if not isinstance(cfg, dict):
            cfg = {}
    except Exception:
        cfg = {}

    def _merge(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
        for k, v in src.items():
            if k not in dst:
                dst[k] = v
            elif isinstance(v, dict) and isinstance(dst[k], dict):
                _merge(dst[k], v)

    _merge(cfg, DEFAULTS)
    return cfg

def save_config(cfg: Dict[str, Any]) -> None:
    sstore.save_config(cfg)