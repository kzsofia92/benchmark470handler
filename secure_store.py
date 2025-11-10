# secure_store.py
# Encrypted storage for users/config with AES-GCM.
# Also mirrors to plaintext JSON as a resilience fallback.
from __future__ import annotations
import os, json
from pathlib import Path
from typing import Dict, Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_OK = True
except Exception:
    _CRYPTO_OK = False

BASE_DIR = Path(__file__).resolve().parent
VAULT_DIR = BASE_DIR / ".vault"
KEY_FILE  = VAULT_DIR / "master.key"
USERS_FILE_ENC  = VAULT_DIR / "users.bin"
CONFIG_FILE_ENC = VAULT_DIR / "config.bin"

# plaintext mirrors (resilience)
USERS_JSON_MIRROR  = BASE_DIR / "users.json"
CONFIG_JSON_MIRROR = BASE_DIR / "config.json"

_MAGIC = b"B470"   # identify file type
_VER   = b"\x01"
_NONCE_LEN = 12

def _ensure_dir_secure(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        if os.name != "nt":
            os.chmod(path, 0o700)
    except Exception:
        pass

def _get_key() -> bytes:
    _ensure_dir_secure(VAULT_DIR)
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    k = os.urandom(32)
    KEY_FILE.write_bytes(k)
    try:
        if os.name != "nt":
            os.chmod(KEY_FILE, 0o600)
    except Exception:
        pass
    return k

def _encrypt_json(data: Dict[str, Any]) -> bytes:
    if not _CRYPTO_OK:
        # not expected, but caller will still mirror plaintext
        return b""
    key = _get_key()
    aes = AESGCM(key)
    ad = _MAGIC + _VER
    nonce = os.urandom(_NONCE_LEN)
    pt = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ct = aes.encrypt(nonce, pt, ad)
    return _MAGIC + _VER + nonce + ct

def _decrypt_json(blob: bytes) -> Dict[str, Any]:
    if not _CRYPTO_OK or not blob:
        return {}
    if len(blob) < len(_MAGIC) + 1 + _NONCE_LEN + 16:
        return {}
    if not blob.startswith(_MAGIC) or blob[len(_MAGIC):len(_MAGIC)+1] != _VER:
        return {}
    off = len(_MAGIC) + 1
    nonce = blob[off:off+_NONCE_LEN]
    ct    = blob[off+_NONCE_LEN:]
    key = _get_key()
    ad  = _MAGIC + _VER
    try:
        pt = AESGCM(key).decrypt(nonce, ct, ad)
        obj = json.loads(pt.decode("utf-8"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}

def save_json_secure(path: Path, data: Dict[str, Any], mirror: Path | None = None) -> None:
    _ensure_dir_secure(VAULT_DIR)
    blob = _encrypt_json(data)
    if blob:
        path.write_bytes(blob)
    # always mirror as resilience (plain JSON)
    if mirror:
        with open(mirror, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def load_json_secure(path: Path, mirror: Path | None = None) -> Dict[str, Any]:
    # try encrypted first
    if path.exists():
        obj = _decrypt_json(path.read_bytes())
        if isinstance(obj, dict) and obj:
            return obj
    # fallback to mirror if exists
    if mirror and mirror.exists():
        try:
            with open(mirror, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
    return {}

def save_users(db: Dict[str, Any]) -> None:
    save_json_secure(USERS_FILE_ENC, db, mirror=USERS_JSON_MIRROR)

def load_users() -> Dict[str, Any]:
    return load_json_secure(USERS_FILE_ENC, mirror=USERS_JSON_MIRROR)

def save_config(cfg: Dict[str, Any]) -> None:
    save_json_secure(CONFIG_FILE_ENC, cfg, mirror=CONFIG_JSON_MIRROR)

def load_config() -> Dict[str, Any]:
    return load_json_secure(CONFIG_FILE_ENC, mirror=CONFIG_JSON_MIRROR)
