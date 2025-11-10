# auth.py
from __future__ import annotations
import secrets, base64, hashlib, hmac, json
from dataclasses import dataclass
from typing import Optional, Literal, Dict, Any
from pathlib import Path

import secure_store as sstore

Role = Literal["admin", "operator"]
BASE_DIR = Path(__file__).resolve().parent
LEGACY_JSON = BASE_DIR / "users.json"   # mirror path already used by secure_store

@dataclass
class User:
    username: str
    role: Role
    pwd_salt_b64: str
    pwd_hash_b64: str
    iterations: int

def _canon(u: str) -> str:
    return (u or "").strip().lower()

def _pbkdf2(password: str, salt: bytes, iterations: int = 120_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)

def _new_user(username: str, password: str, role: Role) -> User:
    u = _canon(username)
    if not u: raise ValueError("Username required")
    salt = secrets.token_bytes(16)
    it = 120_000
    h  = _pbkdf2(password, salt, it)
    return User(
        username=u, role=role,
        pwd_salt_b64=base64.b64encode(salt).decode(),
        pwd_hash_b64=base64.b64encode(h).decode(),
        iterations=it,
    )

def _verify(password: str, user: User) -> bool:
    salt = base64.b64decode(user.pwd_salt_b64)
    h    = base64.b64decode(user.pwd_hash_b64)
    calc = _pbkdf2(password, salt, user.iterations)
    return hmac.compare_digest(calc, h)

def _repair(db: Dict[str, Any]) -> Dict[str, Any]:
    users = db.get("users", {}) or {}
    fixed: Dict[str, Any] = {}
    for k, rec in users.items():
        name = _canon(k if isinstance(k, str) else rec.get("username", ""))
        if not name or name in fixed: continue
        rec["username"] = name
        fixed[name] = rec
    db["users"] = fixed
    return db

def _load_all() -> Dict[str, Any]:
    db = sstore.load_users()
    if isinstance(db, dict) and db.get("users"):
        return db
    # legacy/mirror fallback
    if LEGACY_JSON.exists():
        try:
            with open(LEGACY_JSON, "r", encoding="utf-8") as f:
                j = json.load(f)
            if isinstance(j, dict) and j.get("users"):
                return j
        except Exception:
            pass
    return {}

def _save_all(db: Dict[str, Any]) -> None:
    sstore.save_users(db)

def _admin_count(db: Dict[str, Any]) -> int:
    return sum(1 for u in db.get("users", {}).values() if u.get("role") == "admin")

def init_seed_admin(force: bool = False) -> bool:
    """
    Ensure admin/admin exists. If force or empty, reseed.
    After saving, verify by reading back; if still empty, write mirror as hard fallback.
    """
    db = _repair(_load_all())
    users = db.get("users", {}) or {}
    needs = force or not users or not any(v.get("role") == "admin" for v in users.values())
    if needs:
        u = _new_user("admin", "admin", "admin")
        db = {"users": {u.username: u.__dict__}}
        _save_all(db)

        # verify we can read back
        back = _repair(_load_all())
        if not back.get("users"):
            # last resort: write mirror directly (sstore will read it next time)
            with open(LEGACY_JSON, "w", encoding="utf-8") as f:
                json.dump(db, f, indent=2, ensure_ascii=False)
        return True
    return False

def list_users() -> Dict[str, Dict[str, Any]]:
    db = _repair(_load_all())
    _save_all(db)  # persist repairs
    return db.get("users", {})

def get_user(username: str) -> Optional[User]:
    db = _repair(_load_all())
    rec = db.get("users", {}).get(_canon(username))
    return User(**rec) if rec else None

def authenticate(username: str, password: str) -> Optional[User]:
    u = get_user(username)
    return u if (u and _verify(password, u)) else None

def create_user(username: str, password: str, role: Role,) -> None:
    db = _repair(_load_all())
    users = db.setdefault("users", {})
    name = _canon(username)
    if not name: raise ValueError("Username required")
    if name in users: raise ValueError("User already exists")
    u = _new_user(name, password, role)
    users[name] = u.__dict__
    _save_all(db)

def change_password(username: str, new_password: str) -> None:
    db = _repair(_load_all())
    name = _canon(username)
    users = db.get("users", {})
    if name not in users: raise ValueError("User not found")
    role = users[name]["role"]
    u = _new_user(name, new_password, role)
    users[name] = u.__dict__
    _save_all(db)

def set_role(username: str, role: Role) -> None:
    db = _repair(_load_all())
    users = db.get("users", {})
    name = _canon(username)
    if name not in users: raise ValueError("User not found")
    if users[name]["role"] == "admin" and role != "admin" and _admin_count(db) <= 1:
        raise ValueError("Cannot demote the last admin")
    users[name]["role"] = role
    _save_all(db)

def delete_user(username: str) -> None:
    db = _repair(_load_all())
    users = db.get("users", {})
    name = _canon(username)
    if name not in users: return
    if users[name]["role"] == "admin" and _admin_count(db) <= 1:
        raise ValueError("Cannot delete the last admin")
    del users[name]
    _save_all(db)
