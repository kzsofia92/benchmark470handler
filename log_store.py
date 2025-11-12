# log_store.py
from __future__ import annotations
import csv, os, datetime, shutil
from typing import List, Dict, Optional

_LOG_PATH = os.path.join(os.path.dirname(__file__), "logs.csv")
_HEADER = ["timestamp", "user", "state", "row", "line_content", "error"]

def _ensure_file():
    if not os.path.exists(_LOG_PATH):
        with open(_LOG_PATH, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(_HEADER)

def path() -> str:
    _ensure_file()
    return _LOG_PATH

def append_event(user: str, state: str, row_index: int, line_content: str, error: Optional[str]=None) -> None:
    """
    row_index: 0-based in code; we store 1-based in the log.
    """
    _ensure_file()
    ts = datetime.datetime.now().strftime("%Y.%m.%d %H:%M:%S")
    with open(_LOG_PATH, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow([ts, user or "", state, str(row_index + 1), line_content, (error or "")])

def read_all() -> List[Dict[str, str]]:
    _ensure_file()
    out: List[Dict[str, str]] = []
    with open(_LOG_PATH, "r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f, delimiter=";")
        for row in r:
            out.append({k: row.get(k, "") for k in _HEADER})
    return out

def clear() -> None:
    # keep the file, just truncate to header
    with open(_LOG_PATH, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(_HEADER)

def _write_header():
    with open(_LOG_PATH, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(_HEADER)

def backup_filename() -> str:
    _ensure_file()
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base, _ = os.path.splitext(_LOG_PATH)
    return f"{base}-{ts}.csv"

def clear_with_backup() -> str:
    """
    Copies logs.csv to a timestamped CSV, then truncates the main log to the header.
    Returns the backup path.
    """
    _ensure_file()
    bpath = backup_filename()
    try:
        shutil.copy2(_LOG_PATH, bpath)
    except Exception:
        # if copy fails, still proceed to clear — but return empty path
        bpath = ""
    _write_header()
    return bpath

def export_xlsx(xlsx_path: str) -> str:
    """
    Export the whole log to XLSX. Requires openpyxl.
    """
    try:
        from openpyxl import Workbook
    except Exception as e:
        raise RuntimeError("openpyxl is required to export XLSX (pip install openpyxl)") from e

    rows = read_all()
    wb = Workbook()
    ws = wb.active
    ws.title = "logs"
    ws.append(_HEADER)
    for r in rows:
        ws.append([r.get(h, "") for h in _HEADER])
    # basic autosize-ish
    for col_idx, h in enumerate(_HEADER, start=1):
        maxlen = max([len(h)] + [len(str(r.get(h, ""))) for r in rows])
        ws.column_dimensions[ws.cell(row=1, column=col_idx).column_letter].width = min(80, max(12, maxlen + 2))
    wb.save(xlsx_path)
    return xlsx_path