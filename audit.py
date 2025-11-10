# audit.py
from __future__ import annotations
import csv, json, datetime
from pathlib import Path
from typing import Any, Dict, Optional
import contextvars

# global "current actor"
_current_actor: contextvars.ContextVar[str] = contextvars.ContextVar("actor", default="system")

LOG_DIR  = Path(".logs")
LOG_FILE = LOG_DIR / "events.csv"

def set_actor(username: str | None) -> None:
    _current_actor.set((username or "system").strip() or "system")

def _ensure():
    LOG_DIR.mkdir(exist_ok=True)
    if not LOG_FILE.exists():
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ts","level","actor","action","details_json"])

def log(action: str, details: Optional[Dict[str, Any] | str] = None, level: str = "INFO") -> None:
    _ensure()
    actor = _current_actor.get()
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    if isinstance(details, str):
        details_json = json.dumps({"msg": details}, ensure_ascii=False)
    else:
        details_json = json.dumps(details or {}, ensure_ascii=False)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([ts, level, actor, action, details_json])
