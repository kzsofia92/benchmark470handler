# app.py
import csv
import threading, queue
import time
from typing import List, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tksheet import Sheet

from tmc470 import TMC470, SERIAL_DEFAULTS
import auth
import config_store as cs
import os
import log_store as logs
# import audit
# in App.__init__ after imports/config load
import secure_store as sstore  # already imported elsewhere
# touching the master key + vault applies ACLs:
# _ = sstore._get_master_key() # loads/creates and ACLs .vault/master.key
import re 
import datetime

# app.py (add this near the top)
from pathlib import Path
import shutil, glob
from path_helper import resource_path, user_config_dir, user_log_dir

APP = "BMarkTMC"
_cfg = user_config_dir(APP); _cfg.mkdir(parents=True, exist_ok=True)
_logs = user_log_dir(APP);   _logs.mkdir(parents=True, exist_ok=True)

# copy defaults if missing
for name in ("config.json", "users.json"):
    dst = _cfg / name
    if not dst.exists():
        shutil.copyfile(resource_path(name), dst)

# bring shipped logs once (don’t overwrite)
for f in ["logs.csv", *glob.glob(resource_path("logs-*.csv"))]:
    p = Path(f)
    if p.exists():
        dst = _logs / p.name
        if not dst.exists():
            shutil.copyfile(p, dst)


PARITY_MAP = {"N": "N", "E": "E", "O": "O"}
STOPBITS_CHOICES = [1, 2]
DATABITS_CHOICES = [7, 8]

# Row timeouts (seconds)
READY_TIMEOUT_S = 10.0
DONE_TIMEOUT_S  = 10.0

# Highlight color for a timed-out / stopped row
TIMEOUT_ROW_BG = "#ffe2cc"   # light orange


def center(win):
    """Center any Toplevel or root using manual screen geometry."""
    # Layout kiszámítása
    win.update_idletasks()
    # Képernyő méret
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    # Ablak méret (ha még nem realizált, kérjük le újra)
    ww, wh = win.winfo_width(), win.winfo_height()
    if ww <= 1 or wh <= 1:
        try:
            win.update_idletasks()
            ww, wh = win.winfo_width(), win.winfo_height()
        except Exception:
            pass
    # Középpont kiszámítása, bal/felső minimum 0
    try:
        x = max((sw - ww) // 2, 0)
        y = max((sh - wh) // 2, 0)
        win.geometry(f"+{x}+{y}")
    except Exception:
        # ha valamiért nem megy, hagyjuk ahol van
        pass


def center_on_parent(win, parent=None):
    """Center Toplevel on parent (or screen) reliably."""
    win.update_idletasks()
    # Try Tk's built-in if available
    try:
        if parent is not None:
            # Tk doesn't have a direct "center on parent", so fall back to manual for parent-relative
            raise RuntimeError
        win.tk.call('tk::PlaceWindow', str(win), 'center')
        return
    except Exception:
        pass

    # Manual: center on parent if given, else on screen
    if parent is not None:
        parent.update_idletasks()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        ww, wh = win.winfo_width(), win.winfo_height()
        if ww <= 1 or wh <= 1:  # not realized yet
            win.geometry("+0+0")
            win.update_idletasks()
            ww, wh = win.winfo_width(), win.winfo_height()
        x = px + max((pw - ww)//2, 0)
        y = py + max((ph - wh)//2, 0)
    else:
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        ww, wh = win.winfo_width(), win.winfo_height()
        x = max((sw - ww)//2, 0)
        y = max((sh - wh)//2, 0)

    win.geometry(f"+{x}+{y}")

def fit_sheet_fullwidth(sheet, min_px=60, max_px=700, pad_px=0):
    try:
        try:
            sheet.set_all_cell_sizes_to_text(redraw=False)
        except Exception:
            pass

        try:
            widths = list(sheet.get_column_widths())
        except Exception:
            return
        if not widths:
            return

        n = len(widths)
        widths = [max(min_px, min(max_px, w + pad_px)) for w in widths]

        # --- visible width = min(MT, CH) - RI - MT's vertical scrollbar - borders/highlight - guard
        def _w(w): 
            try: return int(w.winfo_width())
            except Exception: return 0

        MT = getattr(sheet, "MT", None)
        CH = getattr(sheet, "CH", None)
        RI = getattr(sheet, "RI", None)

        mt_w = _w(MT) if MT else _w(sheet)
        ch_w = _w(CH)
        base_w = mt_w if ch_w == 0 else min(mt_w, ch_w)

        ri_w = _w(RI) if (RI and RI.winfo_ismapped()) else 0

        vsb_w = 0
        try:
            sb = getattr(MT, "v_scrollbar", None)
            if sb and sb.winfo_ismapped():
                vsb_w = int(sb.winfo_width())
        except Exception:
            pass

        try:
            bd = int(sheet.cget("bd") or 0)
        except Exception:
            bd = 0
        try:
            hl = int(sheet.cget("highlightthickness") or 0)
        except Exception:
            hl = 0

        GUARD = 18
        avail = max(0, base_w - ri_w - vsb_w - 2*bd - 2*hl - GUARD)
        if avail <= 0: 
            return

        # --- scale to avail, then FORCE last column to take remaining space
        total = sum(widths)
        if total == 0:
            return

        scale = avail / total
        scaled = [max(min_px, min(max_px, int(w * scale))) for w in widths]

        if n == 1:
            scaled[0] = min(max_px, max(min_px, avail))
        else:
            rem = avail - sum(scaled[:-1])
            scaled[-1] = max(min_px, min(max_px, rem))

        # final safety: if still a hair over, trim from right
        over = sum(scaled) - avail
        i = n - 1
        while over > 0 and i >= 0:
            can = max(0, scaled[i] - min_px)
            if can:
                take = min(can, over)
                scaled[i] -= take
                over -= take
            i -= 1

        for c, w in enumerate(scaled):
            sheet.column_width(c, w, only_set_if_too_small=False)

        try:
            sheet.redraw()
        except Exception:
            pass
    except Exception:
        pass


# -------------------- LOGIN --------------------
class Login(tk.Toplevel):
    def __init__(self, master, on_login):
        super().__init__(master)
        self.title("Login")
        self.resizable(False, False)
        self.on_login = on_login

        # on top & modal
        self.transient(master)
        self.attributes("-topmost", True)
        self.protocol("WM_DELETE_WINDOW", self._close)

        frm = ttk.Frame(self, padding=12); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Username").grid(row=0, column=0, sticky="e", pady=4, padx=4)
        ttk.Label(frm, text="Password").grid(row=1, column=0, sticky="e", pady=4, padx=4)
        self.ent_u = ttk.Entry(frm, width=24)
        self.ent_p = ttk.Entry(frm, width=24, show="*")
        self.ent_u.grid(row=0, column=1); self.ent_p.grid(row=1, column=1)
        # Focus username after the dialog is idle/visible

        ttk.Button(frm, text="Sign in", command=self._try_login).grid(row=2, column=0, columnspan=2, pady=8)


        center(self)          # center after widgets exist
        self.lift()           # raise above parent
        self.attributes("-topmost", True)   # ensure on top NOW
        self.after(0, lambda: self.attributes("-topmost", False))  # then release topmost so other dialogs can be on top later
        self.grab_set()

        
        self.bind("<Return>", lambda e: self._try_login())
        self.update_idletasks()
        self.ent_u.focus_set()
        self.after_idle(lambda: (self.ent_u.focus_set(), self.ent_u.icursor("end")))


    def _try_login(self):
        u = self.ent_u.get().strip()
        p = self.ent_p.get().strip()
        user = auth.authenticate(u, p)
        if not user:
            messagebox.showerror("Login failed", "Invalid credentials")
            return
        # audit.set_actor(user.username)
        # audit.log("login_ok", {"username": user.username})
        self.on_login(user)
        self.grab_release()
        self.destroy()

    def _close(self):
        self.master.destroy()

# -------------------- SETTINGS --------------------
class SettingsDialog(tk.Toplevel):
    def __init__(self, master, cfg: dict, on_save):
        super().__init__(master)
        self.withdraw() 
        self.title("Settings ⚙️")
        self.resizable(False, False)
        self.on_save = on_save
        self.cfg = cfg
        self.transient(master)
        self.protocol("WM_DELETE_WINDOW", self._close)

        s = cfg["serial"]
        eth = cfg.get("ethernet", {})
        io_mode = (cfg.get("io_mode", "serial") or "serial").lower()
        if io_mode not in ("serial", "ethernet"):
            io_mode = "serial"

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)
        # 0: radio, 1: label, 2: input
        frm.columnconfigure(0, weight=0)
        frm.columnconfigure(1, weight=0)
        frm.columnconfigure(2, weight=1)

        # ---------------- IO MODE RADIO STATE ----------------
        self.io_mode_var = tk.StringVar(value=io_mode)

        # ---------------- SERIAL SECTION ----------------
        # Row 0 – Serial radio + Port
        self.rb_serial = ttk.Radiobutton(
            frm,
            text="Serial",
            variable=self.io_mode_var,
            value="serial",
            command=self._apply_io_mode,
        )
        self.rb_serial.grid(row=0, column=0, sticky="w", pady=4, padx=(0, 4))

        ttk.Label(frm, text="Port").grid(row=0, column=1, sticky="e", pady=4, padx=4)
        ports = TMC470.list_ports()
        self.cb_port = ttk.Combobox(frm, width=22, values=ports, state="readonly")
        self.cb_port.set(s.get("port", "") or (ports[0] if ports else ""))
        self.cb_port.grid(row=0, column=2, sticky="we")

        # Row 1 – Baud
        ttk.Label(frm, text="Baud").grid(row=1, column=1, sticky="e", pady=4, padx=4)
        self.ent_baud = ttk.Entry(frm, width=24)
        self.ent_baud.insert(0, str(s.get("baud", SERIAL_DEFAULTS["baudrate"])))
        self.ent_baud.grid(row=1, column=2, sticky="we")

        # Row 2 – Parity
        ttk.Label(frm, text="Parity").grid(row=2, column=1, sticky="e", pady=4, padx=4)
        self.cb_parity = ttk.Combobox(
            frm, width=22, values=list(PARITY_MAP.keys()), state="readonly"
        )
        self.cb_parity.set(s.get("parity", "N"))
        self.cb_parity.grid(row=2, column=2, sticky="we")

        # Row 3 – Stop bits
        ttk.Label(frm, text="Stop bits").grid(row=3, column=1, sticky="e", pady=4, padx=4)
        self.cb_stop = ttk.Combobox(
            frm, width=22, values=[str(x) for x in STOPBITS_CHOICES], state="readonly"
        )
        self.cb_stop.set(str(s.get("stopbits", 1)))
        self.cb_stop.grid(row=3, column=2, sticky="we")

        # Row 4 – Data bits
        ttk.Label(frm, text="Data bits").grid(row=4, column=1, sticky="e", pady=4, padx=4)
        self.cb_data = ttk.Combobox(
            frm, width=22, values=[str(x) for x in DATABITS_CHOICES], state="readonly"
        )
        self.cb_data.set(str(s.get("databits", 8)))
        self.cb_data.grid(row=4, column=2, sticky="we")

        # ---------------- ETHERNET SECTION ----------------
        # Row 5 – Ethernet radio + IP
        self.rb_ethernet = ttk.Radiobutton(
            frm,
            text="Ethernet",
            variable=self.io_mode_var,
            value="ethernet",
            command=self._apply_io_mode,
        )
        self.rb_ethernet.grid(row=5, column=0, sticky="w", pady=4, padx=(0, 4))

        ttk.Label(frm, text="IP address").grid(row=5, column=1, sticky="e", pady=4, padx=4)

        vcmd_ip = self.register(self._vc_ip)
        self.ent_ip = ttk.Entry(
            frm,
            width=24,
            validate="key",
            validatecommand=(vcmd_ip, "%P"),
        )
        self.ent_ip.insert(0, eth.get("host", ""))
        self.ent_ip.grid(row=5, column=2, sticky="we")
        # Auto insert dots after 3 digits in a block
        self.ent_ip.bind("<KeyRelease>", self._on_ip_key)

        # Row 6 – Ethernet port
        ttk.Label(frm, text="TCP port").grid(row=6, column=1, sticky="e", pady=4, padx=4)
        self.ent_eport = ttk.Entry(frm, width=24)
        self.ent_eport.insert(0, str(eth.get("port", 10000)))
        self.ent_eport.grid(row=6, column=2, sticky="we")

        # ---------------- COMMON SECTION ----------------
        # Row 7 – Default pattern
        ttk.Label(frm, text="Default pattern").grid(row=7, column=1, sticky="e", pady=4, padx=4)
        self.ent_pattern = ttk.Entry(frm, width=24)
        self.ent_pattern.insert(0, cfg.get("pattern", ""))
        self.ent_pattern.grid(row=7, column=2, sticky="we")

        # Row 8 – Connection mode
        ttk.Label(frm, text="Connection mode").grid(row=8, column=1, sticky="e", pady=4, padx=4)
        self.cb_mode = ttk.Combobox(frm, width=22, state="readonly", values=["test", "live"])
        self.cb_mode.set(cfg.get("connection_mode", "test"))
        self.cb_mode.grid(row=8, column=2, sticky="we")

        # Row 9 – Data send mode
        ttk.Label(frm, text="Data send mode").grid(row=9, column=1, sticky="e", pady=4, padx=4)
        self.cb_data_mode = ttk.Combobox(
            frm, width=22, state="readonly", values=["V", "Q", "CUSTOM"]
        )
        self.cb_data_mode.set(cfg.get("data_send_mode", "Q"))
        self.cb_data_mode.grid(row=9, column=2, sticky="we")

        # Print trigger mode (automatic/manual)
        ttk.Label(frm, text="Print trigger mode").grid(row=10, column=1, sticky="e", pady=4, padx=4)
        self.cb_trigger_mode = ttk.Combobox(frm, width=22, state="readonly",
                                            values=["automatic", "manual"])
        self.cb_trigger_mode.set(cfg.get("print_trigger_mode", "automatic"))
        self.cb_trigger_mode.grid(row=10, column=2, sticky="we")


        # Row 10 – Buttons
        btns = ttk.Frame(frm)
        btns.grid(row=11, column=0, columnspan=3, pady=10)
        ttk.Button(btns, text="Save", command=self._save).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancel", command=self._close).pack(side="left", padx=6)

        self.update_idletasks()
        try:
            center(self)  # same helper you already use elsewhere
        except Exception:
            pass
        self.deiconify()               # show the dialog
        self.lift()
        self.attributes("-topmost", True)
        self.after(0, lambda: self.attributes("-topmost", False))
        self.grab_set() 

        # Apply initial mode (enables/disables fields)
        self._apply_io_mode()

    # ---------- IO MODE HANDLER ----------
    def _apply_io_mode(self):
        mode = (self.io_mode_var.get() or "serial").lower()

        if mode == "ethernet":
            # disable serial fields
            self.cb_port.configure(state="disabled")
            self.ent_baud.configure(state="disabled")
            self.cb_parity.configure(state="disabled")
            self.cb_stop.configure(state="disabled")
            self.cb_data.configure(state="disabled")

            # enable ethernet fields
            self.ent_ip.configure(state="normal")
            self.ent_eport.configure(state="normal")
        else:
            # serial
            self.cb_port.configure(state="readonly")
            self.ent_baud.configure(state="normal")
            self.cb_parity.configure(state="readonly")
            self.cb_stop.configure(state="readonly")
            self.cb_data.configure(state="readonly")

            # disable ethernet fields
            self.ent_ip.configure(state="disabled")
            self.ent_eport.configure(state="disabled")

    # ---------- IP VALIDATOR ----------
    def _vc_ip(self, new_value: str) -> bool:
        """
        Allow only digits and dots.
        Max 4 blocks, each 0–3 digits.
        """
        s = new_value
        if s == "":
            return True

        # Only digits and dots
        for ch in s:
            if not (ch.isdigit() or ch == "."):
                return False

        parts = s.split(".")
        if len(parts) > 4:
            return False

        for part in parts:
            if len(part) > 3:
                return False
            if part and not part.isdigit():
                return False

        return True

    def _on_ip_key(self, event):
        """
        Auto insert '.' after 3 digits in a block, up to 3 dots.
        """
        # ignore navigation / deletion keys
        if event.keysym in ("BackSpace", "Delete", "Left", "Right", "Home", "End"):
            return
        if not event.char or not event.char.isdigit():
            return

        s = self.ent_ip.get()
        if not s:
            return

        parts = s.split(".")
        # if last block has length 3 and we still have less than 4 blocks, append '.'
        if len(parts) < 4 and len(parts[-1]) == 3 and not s.endswith("."):
            # avoid messing when field is disabled
            if str(self.ent_ip["state"]) == "normal":
                self.ent_ip.insert("end", ".")

    # ---------- SAVE / CLOSE ----------
    def _save(self):
        # Serial section
        s = self.cfg["serial"]
        s["port"] = self.cb_port.get().strip()
        s["baud"] = int(self.ent_baud.get().strip() or "9600")
        s["parity"] = self.cb_parity.get().strip()
        s["stopbits"] = int(self.cb_stop.get().strip() or "1")
        s["databits"] = int(self.cb_data.get().strip() or "8")

        # Ethernet section
        e = self.cfg.setdefault("ethernet", {})
        e["host"] = self.ent_ip.get().strip()
        try:
            e["port"] = int(self.ent_eport.get().strip() or "10000")
        except ValueError:
            e["port"] = 10000

        # Common
        self.cfg["pattern"] = self.ent_pattern.get().strip()
        self.cfg["connection_mode"] = self.cb_mode.get().strip()
        self.cfg["data_send_mode"] = self.cb_data_mode.get().strip()
        self.cfg["io_mode"] = (self.io_mode_var.get() or "serial").lower()
        self.cfg["print_trigger_mode"]=self.cb_trigger_mode.get().strip()

        self.on_save(self.cfg)
        self._close()

    def _close(self):
        self.grab_release()
        self.destroy()


#----------TIMEOUT DECISION DIALOG----------
class TimeoutDialog(tk.Toplevel):
    """Modal dialog asking what to do on a timeout."""
    def __init__(self, master, row_idx: int, stage: str, seconds: float, on_choice):
        super().__init__(master)
        self.title("Timeout")
        self.resizable(False, False)
        self.transient(master)
        self.protocol("WM_DELETE_WINDOW", lambda: on_choice("exit"))
        self.on_choice = on_choice

        # Decide wording
        try:
            cfg = getattr(master, "cfg", {})
            mode = str(cfg.get("data_send_mode", "V")).strip().upper()
        except Exception:
            mode = "V"

        # For V-mode:
        # - VSET stage => field semantics
        # - READY / G / DONE/READY => row semantics (we print once per row)
        if mode == "V" and stage.upper() in ("VSET", "FIELD"):
            unit = "field"
            btn_continue = "Continue (next field)"
            btn_repeat   = "Repeat (same field)"
            extra = "\n\nVariable (V) mode: this decision applies to one FIELD."
        else:
            unit = "row"
            btn_continue = "Continue (next row)"
            btn_repeat   = "Repeat (same row)"
            extra = "\n\nThis decision applies to the whole ROW."

        msg = (
            f"Timeout at stage: {stage}\n"
            f"No response within {seconds:.1f} seconds."
            f"{extra}\n\nWhat do you want to do?"
        )

        frm = ttk.Frame(self, padding=12); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text=msg, justify="left").pack(anchor="w", pady=(0,8))

        btns = ttk.Frame(frm); btns.pack(fill="x")
        ttk.Button(btns, text=btn_continue, command=lambda: self._choose("continue")).pack(side="left", padx=4)
        ttk.Button(btns, text=btn_repeat,   command=lambda: self._choose("repeat")).pack(side="left", padx=4)
        ttk.Button(btns, text="Exit",       command=lambda: self._choose("exit")).pack(side="left", padx=4)

        try:
            self.update_idletasks()
            self.tk.call('tk::PlaceWindow', str(self), 'center')
        except Exception:
            pass
        self.grab_set(); self.lift()
        self.attributes("-topmost", True)
        self.after(0, lambda: self.attributes("-topmost", False))

    def _choose(self, what: str):
        try: self.grab_release()
        except Exception: pass
        self.on_choice(what)
        self.destroy()

class UserManagementDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.withdraw()
        self.title("Users")
        self.resizable(False, False)
        self.transient(master)   # tie to parent
        self.protocol("WM_DELETE_WINDOW", self._close)

        frm = ttk.Frame(self, padding=12); frm.pack(fill="both", expand=True)

        # Two columns: Username + Role
        self.tree = ttk.Treeview(frm, columns=("username","role"), show="headings", height=10)
        self.tree.heading("username", text="Username")
        self.tree.heading("role", text="Role")
        self.tree.column("username", width=220, anchor="w")
        self.tree.column("role", width=120, anchor="w")
        self.tree.grid(row=0, column=0, columnspan=4, sticky="nsew")

        sb_y = ttk.Scrollbar(frm, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb_y.set)
        sb_y.grid(row=0, column=4, sticky="ns")

        # frame grow
        frm.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        btns = ttk.Frame(frm); btns.grid(row=1, column=0, columnspan=5, pady=8)
        ttk.Button(btns, text="Add…", command=self._add).pack(side="left", padx=4)
        ttk.Button(btns, text="Change password…", command=self._change_pwd).pack(side="left", padx=4)
        ttk.Button(btns, text="Change role…", command=self._change_role).pack(side="left", padx=4)
        ttk.Button(btns, text="Delete", command=self._delete).pack(side="left", padx=4)
        ttk.Button(btns, text="Close", command=self._close).pack(side="left", padx=12)

        self._reload()

        # ---- Center AFTER layout & make sure it's visible on top ----
               # ----- final: center like login, then show -----
        self.update_idletasks()
        try:
            center(self)
        except Exception:
            pass
        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)
        self.after(0, lambda: self.attributes("-topmost", False))
        self.grab_set()


    def _reload(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        users = auth.list_users()
        # insert username + role; use username as iid so selection still returns it
        for uname, rec in sorted(users.items()):
            role = rec.get("role", "")
            self.tree.insert("", "end", iid=uname, values=(uname, role))

    def _sel(self):
        sel = self.tree.selection()
        return sel[0] if sel else None  # iid is the username

    def _add(self):
        SimpleAddUser(self, self._added)

    def _added(self, username, password, role):
        try:
            # audit.log("user_create", {"username": username, "role": role})
            auth.create_user(username, password, role)
            self._reload()
        except Exception as e:
            messagebox.showerror("Add user", str(e))

    def _change_pwd(self):
        u = self._sel()
        if not u:
            messagebox.showinfo("Users","Select a user"); return
        SimpleChangePassword(self, u, self._pwd_changed)

    def _pwd_changed(self, username, newpwd):
        try:
            auth.change_password(username, newpwd)
            # audit.log("user_change_password", {"username": username})
            messagebox.showinfo("Users","Password changed.")
        except Exception as e:
            # audit.log("user_change_password_fail", {"username": username, "error": str(e)}, level="ERROR")
            messagebox.showerror("Change password", str(e))


    def _change_role(self):
        u = self._sel()
        if not u:
            messagebox.showinfo("Users","Select a user"); return
        SimpleChangeRole(self, u, self._role_changed)


    def _role_changed(self, username, role):
        try:
            old = auth.get_user(username).role if auth.get_user(username) else None
            auth.set_role(username, role)
            # audit.log("user_set_role", {"username": username, "old": old, "new": role})
            self._reload()
        except Exception as e:
            # audit.log("user_set_role_fail", {"username": username, "error": str(e)}, level="ERROR")
            messagebox.showerror("Change role", str(e))

    
    def _delete(self):
        u = self._sel()
        if not u:
            messagebox.showinfo("Users","Select a user"); return
        if not messagebox.askyesno("Delete user", f"Delete '{u}'?"):
            return
        try:
            auth.delete_user(u)
            # audit.log("user_delete", {"username": u})
            self._reload()
        except Exception as e:
            # audit.log("user_delete_fail", {"username": u, "error": str(e)}, level="ERROR")
            messagebox.showerror("Delete user", str(e))
    def _close(self):
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

class SimpleAddUser(tk.Toplevel):
    def __init__(self, master, on_ok):
        super().__init__(master)
        self.title("Add user")
        self.resizable(False, False)
        self.on_ok = on_ok

        root_parent = master.winfo_toplevel()
        self.transient(root_parent)

        frm = ttk.Frame(self, padding=12); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Username").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Label(frm, text="Password").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        ttk.Label(frm, text="Role").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        self.e_u = ttk.Entry(frm, width=24); self.e_u.grid(row=0, column=1)
        self.e_p = ttk.Entry(frm, width=24, show="*"); self.e_p.grid(row=1, column=1)
        self.cb  = ttk.Combobox(frm, width=22, values=["admin","operator"], state="readonly")
        self.cb.set("operator"); self.cb.grid(row=2, column=1)
        bar = ttk.Frame(frm); bar.grid(row=3, column=0, columnspan=2, pady=8)
        ttk.Button(bar, text="Create", command=self._ok).pack(side="left", padx=6)
        ttk.Button(bar, text="Cancel", command=self._close).pack(side="left", padx=6)
        self.e_u.focus_force()

        self.protocol("WM_DELETE_WINDOW", self._close)

        self.update_idletasks()
        self.wait_visibility()
        center_on_parent(self, root_parent)
        self.lift()
        self.grab_set()

    def _ok(self):
        u = self.e_u.get().strip(); p = self.e_p.get().strip(); r = self.cb.get().strip()
        if not u or not p:
            messagebox.showerror("Add user", "Username and password required"); return
        self.on_ok(u, p, r); self._close()
    def _close(self): self.grab_release(); self.destroy()

class SimpleChangePassword(tk.Toplevel):
    def __init__(self, master, username, on_ok):
        super().__init__(master)
        self.title(f"Change password — {username}")
        self.resizable(False, False)
        self.on_ok = on_ok
        self.u = username

        # --- use the true root/top-level as the parent for transient/centering ---
        root_parent = master.winfo_toplevel()
        self.transient(root_parent)

        frm = ttk.Frame(self, padding=12); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="New password").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Label(frm, text="Confirm").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        self.e1 = ttk.Entry(frm, width=24, show="*"); self.e1.grid(row=0, column=1)
        self.e2 = ttk.Entry(frm, width=24, show="*"); self.e2.grid(row=1, column=1)
        bar = ttk.Frame(frm); bar.grid(row=2, column=0, columnspan=2, pady=8)
        ttk.Button(bar, text="Save", command=self._ok).pack(side="left", padx=6)
        ttk.Button(bar, text="Cancel", command=self._close).pack(side="left", padx=6)
        self.e1.focus_force()

        self.protocol("WM_DELETE_WINDOW", self._close)

        # ---- center AFTER it's visible, relative to ROOT, not the Users window ----
        self.update_idletasks()
        self.wait_visibility()
        center_on_parent(self, root_parent)  # or: center(self) if you only screen-center
        self.lift()
        self.grab_set()


    def _ok(self):
        p1 = self.e1.get().strip(); p2 = self.e2.get().strip()
        if not p1 or p1 != p2:
            messagebox.showerror("Change password", "Passwords do not match"); return
        self.on_ok(self.u, p1); self._close()

    def _close(self):
        try: self.grab_release()
        except Exception: pass
        self.destroy()


class SimpleChangeRole(tk.Toplevel):
    def __init__(self, master, username, on_ok):
        super().__init__(master)
        self.title(f"Change role — {username}")
        self.resizable(False, False)
        self.on_ok = on_ok
        self.u = username

        root_parent = master.winfo_toplevel()
        self.transient(root_parent)

        frm = ttk.Frame(self, padding=12); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Role").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        self.cb = ttk.Combobox(frm, width=22, values=["admin","operator"], state="readonly")
        self.cb.set("operator"); self.cb.grid(row=0, column=1)
        bar = ttk.Frame(frm); bar.grid(row=1, column=0, columnspan=2, pady=8)
        ttk.Button(bar, text="Save", command=self._ok).pack(side="left", padx=6)
        ttk.Button(bar, text="Cancel", command=self._close).pack(side="left", padx=6)
        self.cb.focus_force()

        self.protocol("WM_DELETE_WINDOW", self._close)

        self.update_idletasks()
        self.wait_visibility()
        center_on_parent(self, root_parent)
        self.lift()
        self.grab_set()

    def _ok(self):
        self.on_ok(self.u, self.cb.get().strip()); self._close()
    def _close(self): self.grab_release(); self.destroy()
#--------------------- LOG VIEWER ---------------------
class LogViewer(tk.Toplevel):
    def __init__(self, master,  can_clear: bool = True):
        super().__init__(master)
        self.withdraw()
        self._can_clear = bool(can_clear)
        try:
            self.geometry("1200x800"); self.minsize(900, 600)
        except Exception:
            pass
        self.title("Logs")
        self.resizable(True, True)
        self.transient(master)
        self.grab_set()

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        # ---------- ROW 1: State + Apply (search-only) + Tag + Search + Export/Clear ----------
        bar1 = ttk.Frame(outer)
        bar1.pack(fill="x", side="top")

        ttk.Label(bar1, text="Filter state:").pack(side="left")
        self.cb_state = ttk.Combobox(
            bar1,
            state="readonly",
            width=20,
            values=["(all)"],  # dynamic list is filled after load
        )
        self.cb_state.set("(all)")
        self.cb_state.pack(side="left", padx=6)
        self.cb_state.bind("<<ComboboxSelected>>", lambda _e=None: self._apply_filter())


 
        # Tag filter (auto-applies)
        ttk.Label(bar1, text="Tag filter").pack(side="left", padx=(12, 4))
        self._filter_var = tk.StringVar(value="(all)")
        self._filter_cb = ttk.Combobox(
            bar1, state="readonly", width=24,
            textvariable=self._filter_var, values=["(all)"],  # filled after load
        )
        self._filter_cb.pack(side="left", padx=6)
        self._filter_cb.bind("<<ComboboxSelected>>", lambda _e=None: self._apply_filter())

        # Search (Apply affects this only)
        ttk.Label(bar1, text="Search:").pack(side="left", padx=(12, 4))
        self.ent_search = ttk.Entry(bar1, width=24)
        self.ent_search.pack(side="left")
        
        # Apply button (SEARCH ONLY)
        ttk.Button(bar1, text="Apply", command=self._apply_search).pack(side="left", padx=6)

        ttk.Button(bar1, text="Export XLSX…", command=self._handle_export).pack(side="left", padx=6)
        self.btn_clear = ttk.Button(bar1, text="Clear (archive)", command=self._clear_backup)
        if not self._can_clear:
            self.btn_clear.config(state="disabled")
        self.btn_clear.pack(side="right")

        # ---------- ROW 2: Date filter (mode + arrows + range + custom From/To) ----------
        # requires: import datetime (top of file) and the helper methods you already added:
        # _compute_range, _shift_anchor, _on_date_mode, _on_custom_dates_changed,
        # _row_in_date_range, and that _apply_filter() considers date via _row_in_date_range().
        bar2 = ttk.Frame(outer)
        bar2.pack(fill="x", side="top", pady=(6, 0))

        self._date_mode = tk.StringVar(value="(all)")          # "(all)" | "Day" | "Week" | "Custom"
        self._date_label = tk.StringVar(value="")
        self._anchor = datetime.date.today()                   # center day for Day/Week steps
        self._date_start = None
        self._date_end = None

        ttk.Label(bar2, text="Filter date:").pack(side="left", padx=(4, 4))
        self.cb_date_mode = ttk.Combobox(
            bar2, state="readonly", width=10,
            values=["(all)", "Day", "Week", "Custom"],
            textvariable=self._date_mode,
        )
        self.cb_date_mode.pack(side="left")
        self.cb_date_mode.bind("<<ComboboxSelected>>", lambda _e=None: self._on_date_mode())

        ttk.Button(bar2, text="<<", width=3, command=lambda: self._shift_anchor(-7)).pack(side="left", padx=2)
        ttk.Button(bar2, text="<",  width=3, command=lambda: self._shift_anchor(-1)).pack(side="left", padx=2)
        ttk.Label(bar2, textvariable=self._date_label).pack(side="left", padx=6)
        ttk.Button(bar2, text=">",  width=3, command=lambda: self._shift_anchor(+1)).pack(side="left", padx=2)
        ttk.Button(bar2, text=">>", width=3, command=lambda: self._shift_anchor(+7)).pack(side="left", padx=2)

        ttk.Label(bar2, text="From").pack(side="left", padx=(12, 4))
        self.ent_from = ttk.Entry(bar2, width=11)  # YYYY.MM.DD
        self.ent_from.pack(side="left")

        ttk.Label(bar2, text="To").pack(side="left", padx=(8, 4))
        self.ent_to = ttk.Entry(bar2, width=11)
        self.ent_to.pack(side="left")

                # Date Apply button – only meaningful in Custom mode
        self.btn_date_apply = ttk.Button(
            bar2,
            text="Apply date filter",
            command=self._on_custom_dates_changed
        )
        self.btn_date_apply.pack(side="left", padx=6)
        self.btn_date_apply.configure(state="disabled")  # only enabled in Custom

        # keep your Enter-to-apply
        self.ent_from.bind("<Return>", lambda _e=None: self._on_custom_dates_changed())
        self.ent_to.bind("<Return>",   lambda _e=None: self._on_custom_dates_changed())

        # NEW: per-field keypress handlers (no StringVar traces)
        self.ent_from.bind("<KeyPress>", lambda e: self._on_date_key(e, self.ent_from))
        self.ent_to.bind("<KeyPress>",   lambda e: self._on_date_key(e, self.ent_to))

        # Optional: tidy on focus out (does not fight typing)
        self.ent_from.bind("<FocusOut>", lambda _e=None: self._normalize_date_field(self.ent_from))
        self.ent_to.bind("<FocusOut>",   lambda _e=None: self._normalize_date_field(self.ent_to))

        # Key typing (you already added these)
        self.ent_from.bind("<KeyPress>", lambda e: self._on_date_key(e, self.ent_from))
        self.ent_to.bind("<KeyPress>",   lambda e: self._on_date_key(e, self.ent_to))

        # Enter -> apply (you already have)
        self.ent_from.bind("<Return>", lambda _e=None: self._on_custom_dates_changed())
        self.ent_to.bind("<Return>",   lambda _e=None: self._on_custom_dates_changed())

        # Paste sanitize (Ctrl+V, Shift+Insert, menu paste)
        self.ent_from.bind("<<Paste>>",   lambda e: self._on_date_paste(e, self.ent_from))
        self.ent_from.bind("<Control-v>", lambda e: self._on_date_paste(e, self.ent_from))
        self.ent_from.bind("<Shift-Insert>", lambda e: self._on_date_paste(e, self.ent_from))

        self.ent_to.bind("<<Paste>>",   lambda e: self._on_date_paste(e, self.ent_to))
        self.ent_to.bind("<Control-v>", lambda e: self._on_date_paste(e, self.ent_to))
        self.ent_to.bind("<Shift-Insert>", lambda e: self._on_date_paste(e, self.ent_to))

        # Hard validation (rejects invalid edits even if injected)
        vc_from = (self.register(self._vc_date), "%P")
        vc_to   = (self.register(self._vc_date), "%P")
        self.ent_from.configure(validate="key", validatecommand=vc_from)
        self.ent_to.configure(validate="key",   validatecommand=vc_to)

        # ---------- Table ----------
        frm = ttk.Frame(outer)
        frm.pack(fill="both", expand=True, pady=(8, 0))
        frm.rowconfigure(0, weight=1); frm.columnconfigure(0, weight=1)
        frm.pack(fill="both", expand=True) 
        
        self.sheet = Sheet(
            frm, data=[],
            headers=["timestamp", "user", "state", "row", "line_content", "error"],
            show_row_index=False, show_top_left_corner=False,
        )
        # --- sorting state + header click binding ---
        self._sort_col = None
        self._sort_asc = True
        self.sheet.extra_bindings([("header_left_click", self._on_header_click)])

        self.sheet.grid(row=0, column=0, sticky="nsew")
        self.sheet.MT.bind("<Configure>", lambda e: fit_sheet_fullwidth(self.sheet))
        self.sheet.CH.bind("<Configure>", lambda e: fit_sheet_fullwidth(self.sheet))

#                 ^ ‘self’ here is your Tk app (no _fit_sheet_fullwidth attr)


        self.sheet.readonly = True
        self.sheet.enable_bindings((
            "single_select","row_select","column_select","arrowkeys","drag_select","copy",
            "column_width_resize","row_height_resize","sort"
        ))
        # self.sheet.pack(fill="both", expand=True)
        # Load, build tag list, init date range, show filtered view
        self._load()                   # should set self._all_rows and call _rebuild_filter_options(...)
        # If your _load() doesn't call these, ensure:
        # self._date_mode.set("(all)"); self._compute_range(); self._apply_filter()

       # ----- final: center like login, then show -----
        self.update_idletasks()
        try:
            center(self)
        except Exception:
            pass
        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)
        self.after(0, lambda: self.attributes("-topmost", False))
        self.grab_set()


    def _on_header_click(self, event):
        """
        tksheet sends dict-like event: {'column': int, ...}
        Toggle asc/desc on repeated clicks; otherwise sort asc first time.
        """
        try:
            col = event.get("column", None)
        except Exception:
            col = None
        if col is None:
            return
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True
        self._sort_by(self._sort_col, self._sort_asc)

    def _sort_by(self, col: int, asc: bool):
        """
        Sorts the table by column index `col`, ascending or descending.
        Handles timestamp column intelligently; falls back to string compare.
        Updates header with ▲ / ▼ on the active column.
        """
        # get current data from the sheet (what you see)
        try:
            rows = self.sheet.get_sheet_data()
        except Exception:
            rows = []

        # choose key function
        def keyfunc(r):
            try:
                val = r[col]
            except Exception:
                return ""
            # try parse timestamp if this looks like the ts column
            if col == 0:
                dt = self._parse_any_datetime(val)
                if dt is not None:
                    return dt
            # numeric fallback
            try:
                return float(str(val).replace(",", "."))
            except Exception:
                return str(val)

        rows_sorted = sorted(rows, key=keyfunc, reverse=not asc)
        # update sheet
        try:
            self.sheet.set_sheet_data(rows_sorted, redraw=True)
        except Exception:
            # old tksheet
            self.sheet.set_sheet_data(rows_sorted)
            self.sheet.redraw()

        # update header arrow
        self._set_headers_with_arrow(col, asc)

    def _set_headers_with_arrow(self, col: int, asc: bool):
        """
        Writes headers with ▲ / ▼ on the active column.
        Preserves original header titles if you have them cached.
        """
        # get original headers, or read current then strip old arrows
        base_headers = []
        try:
            hdrs = getattr(self.sheet, "headers", None)
            base_headers = list(hdrs()) if callable(hdrs) else list(hdrs) if hdrs else []
        except Exception:
            pass
        if not base_headers:
            # infer from what the sheet currently shows
            try:
                base_headers = list(self.sheet.headers())
            except Exception:
                base_headers = ["timestamp","user","state","row","line_content","error"]

        cleaned = []
        for h in base_headers:
            s = str(h)
            # remove any existing arrow suffixes
            if s.endswith(" ▲") or s.endswith(" ▼"):
                s = s[:-2]
            cleaned.append(s)

        # add arrow to active column
        arrow = "▲" if asc else "▼"
        if 0 <= col < len(cleaned):
            cleaned[col] = f"{cleaned[col]} {arrow}"

        try:
            self.sheet.headers(cleaned)
        except Exception:
            # some versions expose setter differently
            try:
                self.sheet.set_headers(cleaned)
            except Exception:
                pass

    def _parse_any_datetime(self, s):
        """
        Robust timestamp parser for your logs:
        supports 'YYYY-MM-DD HH:MM:SS', 'YYYY.MM.DD HH:MM:SS', and ISO with 'T'.
        Returns a datetime or None.
        """
        from datetime import datetime
        txt = str(s).strip()
        fmts = ("%Y-%m-%d %H:%M:%S",
                "%Y.%m.%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S")
        for f in fmts:
            try:
                return datetime.strptime(txt, f)
            except Exception:
                continue
        return None

    
    def _load(self):
        rows = logs.read_all()
        self._all_rows = rows  # keep cache for filter
        # Build choices dynamically from line_content and render table
        self._rebuild_filter_options(rows)
        self._rebuild_state_options(rows) 
        # init date filter: default (all)
        self._date_mode.set("(all)")
        self._compute_range()

        self._apply_filter()   # this calls _show(...) with the right subset

        # default: newest first by timestamp (column 0, descending)
        self._sort_col, self._sort_asc = 0, False
        self._sort_by(0, asc=False)

        # self._show(rows)

    def _show(self, rows):
        headers = ["timestamp", "user", "state", "row", "line_content", "error"]
        self.sheet.headers(headers)
        data = [[r.get(h, "") for h in headers] for r in rows]
        self.sheet.set_sheet_data(data or [])
        self.after_idle(lambda: fit_sheet_fullwidth(self.sheet))
        # 1) let tksheet compute content-based widths
        try:
            self.sheet.set_all_cell_sizes_to_text(redraw=False)
        except Exception:
            pass
        # 2) now fill remaining space across columns
        fit_sheet_fullwidth(self.sheet)
        try:
            self.sheet.refresh()
        except Exception:
            pass

   

    def _extract_tags(self, text: str) -> set[str]:
        # everything between '[' and ']'
        return set(re.findall(r"\[([^\[\]]+)\]", text or ""))
    def _rebuild_filter_options(self, rows):
        # collect unique [TAGS] from the "line_content" field of dict rows
        tags = set()
        for r in rows:
            text = r.get("line_content", "") if isinstance(r, dict) else (r[4] if len(r) > 4 else "")
            tags |= self._extract_tags(text)
        items = ["(all)"] + sorted(tags, key=str.lower)
        self._filter_cb["values"] = items
        if self._filter_var.get() not in items:
            self._filter_var.set("(all)")

    def _apply_filter(self):
        """Auto-apply for State / Tag / Date (Search stays Apply-only)."""
        st  = self.cb_state.get().strip() if hasattr(self, "cb_state") else "(all)"
        tag = self._filter_var.get().strip() if hasattr(self, "_filter_var") else "(all)"

        def _state_ok(r):
            return True if st == "(all)" else ((r.get("state", "") if isinstance(r, dict) else "") == st)

        def _tag_ok(r):
            if tag == "(all)":
                return True
            text = r.get("line_content", "") if isinstance(r, dict) else (r[4] if len(r) > 4 else "")
            return tag in set(re.findall(r"\[([^\[\]]+)\]", text or ""))

        rows = [r for r in getattr(self, "_all_rows", []) if _state_ok(r) and _tag_ok(r) and self._row_in_date_range(r)]
        self._show(rows)

    def _apply_search(self):
        q = self.ent_search.get().strip().lower()
        # start from the base (state+tag+date) view
        st_view = []
        st  = self.cb_state.get().strip() if hasattr(self, "cb_state") else "(all)"
        tag = self._filter_var.get().strip() if hasattr(self, "_filter_var") else "(all)"
        for r in getattr(self, "_all_rows", []):
            if ( (st == "(all)" or (r.get("state","") == st)) and
                (tag == "(all)" or tag in set(re.findall(r"\[([^\[\]]+)\]", (r.get("line_content","") or "")))) and
                self._row_in_date_range(r) ):
                st_view.append(r)
        if q:
            st_view = [r for r in st_view if q in ((r.get("line_content","") + " " + r.get("error","")).lower())]
        self._show(st_view)

    def _parse_timestamp(self, ts: str):
        """Return datetime.date or None from 'timestamp' field."""
        if not ts:
            return None
        ts = ts.strip()
        # try common formats you use in logs.csv (extend if needed)
        for fmt in ("%Y.%m.%d %H:%M:%S", "%Y.%m.%d %H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                    "%Y-%m-%d %H:%M:%S", "%Y.%m.%d"):
            try:
                return datetime.datetime.strptime(ts, fmt).date()
            except Exception:
                pass
        # ISO-ish fallback
        try:
            return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).date()
        except Exception:
            return None

    def _compute_range(self):
        """Recompute _date_start/_date_end + label from mode/anchor/custom."""
        mode = self._date_mode.get()
        if mode == "(all)":
            self._date_start = self._date_end = None
            self._date_label.set("(all)")
            # disable custom boxes
            self.ent_from.configure(state="disabled")
            self.ent_to.configure(state="disabled")
            return

        if mode == "Day":
            d0 = self._anchor
            d1 = self._anchor
            self._date_start, self._date_end = d0, d1
            self._date_label.set(d0.strftime("%Y.%m.%d"))
            self.ent_from.configure(state="disabled")
            self.ent_to.configure(state="disabled")
            return

        if mode == "Week":
            # Monday..Sunday span around anchor (ISO week)
            monday = self._anchor - datetime.timedelta(days=self._anchor.weekday())
            sunday = monday + datetime.timedelta(days=6)
            self._date_start, self._date_end = monday, sunday
            self._date_label.set(f"{monday:%Y.%m.%d} - {sunday:%Y.%m.%d}")
            self.ent_from.configure(state="disabled")
            self.ent_to.configure(state="disabled")
            return

        # Custom
        self.ent_from.configure(state="normal")
        self.ent_to.configure(state="normal")
        # parse boxes; if empty, default to anchor..anchor
        def _parse_box(e):
            txt = e.get().strip()
            if not txt:
                return None
            # accept YYYY.MM.DD and YYYY-MM-DD
            for fmt in ("%Y.%m.%d", "%Y-%m-%d"):
                try:
                    return datetime.datetime.strptime(txt, fmt).date()
                except Exception:
                    continue
            return None
        d0 = _parse_box(self.ent_from)
        d1 = _parse_box(self.ent_to)
        if not d0 and not d1:
            d0 = d1 = self._anchor
        elif d0 and not d1:
            d1 = d0
        elif d1 and not d0:
            d0 = d1
        if d0 > d1:
            d0, d1 = d1, d0
        self._date_start, self._date_end = d0, d1
        self._date_label.set(f"{d0:%Y.%m.%d} - {d1:%Y.%m.%d}")

    def _on_date_mode(self):
        """Mode changed: compute range and auto-apply (state+tag+date)."""
        mode = self._date_mode.get()

        # Enable the date-Apply button only in Custom mode
        try:
            self.btn_date_apply.configure(
                state="normal" if mode == "Custom" else "disabled"
            )
        except Exception:
            # button might not exist yet during very early init; ignore
            pass

        self._compute_range()
        self._apply_filter()   # your existing auto-filter (state+tag already)

    def _shift_anchor(self, delta_days: int):
        """Move anchor by +/- days; applies only in Day/Week/Custom."""
        mode = self._date_mode.get()
        if mode == "(all)":
            return  # arrows do nothing in (all)
        # in Week mode, left/right arrows step 1 day; << >> step 7 — already passed in
        self._anchor = self._anchor + datetime.timedelta(days=delta_days)
        # if Custom and boxes filled, shift both by same delta
        if mode == "Custom":
            def _shift_box(e):
                txt = e.get().strip()
                if not txt:
                    return
                d = None
                # accept YYYY.MM.DD and YYYY-MM-DD
                for fmt in ("%Y.%m.%d", "%Y-%m-%d"):
                    try:
                        d = datetime.datetime.strptime(txt, fmt).date()
                        break
                    except Exception:
                        d = None
                if not d:
                    return
                d2 = d + datetime.timedelta(days=delta_days)
                e.delete(0, "end")
                e.insert(0, d2.strftime("%Y.%m.%d"))

            _shift_box(self.ent_from)
            _shift_box(self.ent_to)

        self._compute_range()
        self._apply_filter()

    def _on_custom_dates_changed(self):
        """Enter pressed in From/To: recompute + apply."""
        if self._date_mode.get() != "Custom":
            return
        self._compute_range()
        self._apply_filter()

    def _row_in_date_range(self, row) -> bool:
        """True if row's timestamp is within current range (inclusive)."""
        # (all) => no date filter
        if self._date_start is None and self._date_end is None:
            return True
        ts = row.get("timestamp", "") if isinstance(row, dict) else (row[0] if row else "")
        d = self._parse_timestamp(ts)
        if not d:
            return False
        if self._date_start and d < self._date_start:
            return False
        if self._date_end and d > self._date_end:
            return False
        return True
    def _handle_export(self):
        """
            Always ask: Yes = Filtered, No = Full, Cancel = Abort (nice layout, even buttons).
        """
        choice = self._ask_export_choice()  # 'filtered' | 'full' | None
        if choice is None:
            return
        if choice == "filtered":
            return self._export_filtered_xlsx()
        return self._export()   # full, your existing XLSX export

    def _ask_export_choice(self):
        """
        White dialog, message centered both horizontally and vertically.
        Buttons: Yes (left) • No (center) • Cancel (right).
        Returns: 'filtered' | 'full' | None
        """
        import tkinter as tk
        from tkinter import ttk

        dlg = tk.Toplevel(self)
        dlg.title("Export logs")
        dlg.transient(self)
        dlg.grab_set()
        dlg.resizable(False, False)
        dlg.configure(bg="white")

        # center on parent
        self.update_idletasks()
        px = self.winfo_rootx() + self.winfo_width() // 2
        py = self.winfo_rooty() + self.winfo_height() // 2
        w, h = 420, 180
        dlg.geometry(f"{w}x{h}+{px - w//2}+{py - h//2}")

        # content area (white) that will hold the vertically centered message
        content = tk.Frame(dlg, bg="white")
        content.pack(fill="both", expand=True, padx=16, pady=(12, 0))

        # message centered H+V using place()
        msg = tk.Label(
            content,
            text="Export the currently visible (filtered) rows?",
            bg="white", fg="#1f1f1f",
            justify="center", wraplength=380
        )
        msg.place(relx=0.5, rely=0.5, anchor="center")  # <-- perfect center

        # button bar at the bottom
        btnbar = tk.Frame(dlg, bg="white")
        btnbar.pack(fill="x", side="bottom", padx=12, pady=12)

        # 3 equal columns; left/center/right alignment via sticky
        btnbar.grid_columnconfigure(0, weight=1, uniform="btns")
        btnbar.grid_columnconfigure(1, weight=1, uniform="btns")
        btnbar.grid_columnconfigure(2, weight=1, uniform="btns")

        choice = {"val": None}
        def _yes():    choice["val"] = "filtered"; dlg.destroy()
        def _no():     choice["val"] = "full";     dlg.destroy()
        def _cancel(): choice["val"] = None;       dlg.destroy()

        ttk.Button(btnbar, text="Yes = Export filtered",    command=_yes).grid(   row=0, column=0, sticky="w", padx=6)
        ttk.Button(btnbar, text="No = Export full",     command=_no).grid(    row=0, column=1, sticky="",  padx=6)
        ttk.Button(btnbar, text="Cancel = Abort", command=_cancel).grid(row=0, column=2, sticky="e", padx=6)

        # keys: Enter => Yes, Esc => Cancel
        dlg.bind("<Return>", lambda e: _yes())
        dlg.bind("<Escape>", lambda e: _cancel())
        dlg.protocol("WM_DELETE_WINDOW", _cancel)

        # focus default on center "No"
        for child in btnbar.grid_slaves(row=0, column=1):
            try:
                child.focus_set()
                break
            except Exception:
                pass

        dlg.wait_window()
        return choice["val"]

    def _export_filtered_xlsx(self):
        """
        Export exactly what is visible in the sheet to XLSX.
        """
        from tkinter import filedialog, messagebox

        # get visible data from tksheet
        try:
           # tksheet (your version) → no kwargs
            visible_rows = self.sheet.get_sheet_data() or []

            # headers: prefer sheet.headers() if it exists, else a stored list, else infer
            headers = []
            try:
                hdrs = getattr(self.sheet, "headers", None)
                headers = list(hdrs()) if callable(hdrs) else list(hdrs) if hdrs else []
            except Exception:
                headers = getattr(self, "_headers", [])

        except Exception as e:
            messagebox.showerror("Export", f"Cannot read visible rows from table:\n{e}")
            return

        # pick destination
        path = filedialog.asksaveasfilename(
            title="Save filtered logs",
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook","*.xlsx"), ("All files","*.*")]
        )
        if not path:
            return

        # write XLSX
        try:
            from openpyxl import Workbook
            wb = Workbook()
            ws = wb.active
            ws.title = "logs (filtered)"

            # header
            if headers:
                ws.append(headers)

            # rows
            for r in visible_rows:
                ws.append(list(r))

            # quick autosize
            if headers:
                for c in range(1, len(headers) + 1):
                    col_letter = ws.cell(row=1, column=c).column_letter
                    maxlen = max(
                        [len(str(headers[c-1]))]
                        + [len(str(row[c-1])) for row in visible_rows if len(row) >= c]
                    ) if visible_rows else len(str(headers[c-1]))
                    ws.column_dimensions[col_letter].width = min(80, max(12, maxlen + 2))

            wb.save(path)
            messagebox.showinfo("Export", f"Filtered logs exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export", f"Failed to export filtered logs:\n{e}")

    def _apply(self):
        st = self.cb_state.get().strip()
        q  = self.ent_search.get().strip().lower()
        rows = self._all_rows
        if st and st != "(all)":
            rows = [r for r in rows if r.get("state","") == st]
        if q:
            rows = [r for r in rows if q in (r.get("line_content","") + " " + r.get("error","")).lower()]
        self._show(rows)

    def _export(self):
        from tkinter import filedialog, messagebox
        path = filedialog.asksaveasfilename(
            title="Export logs",
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook","*.xlsx"), ("All files","*.*")]
        )
        if not path:
            return
        try:
            out = logs.export_xlsx(path)
            messagebox.showinfo("Logs", f"Exported to:\n{out}")
        except Exception as e:
            messagebox.showerror("Export", str(e))

    def _clear_backup(self):
        from tkinter import messagebox

        if not getattr(self, "_can_clear", True):
            messagebox.showerror("Logs", "Only admin can backup and clear the log.")
            return


        if not messagebox.askyesno("Logs", "Backup current log and clear?"):
            return
        try:
            bpath = logs.clear_with_backup()
            self._load()
            if bpath:
                messagebox.showinfo("Logs", f"Backup saved:\n{bpath}\nLog cleared.")
            else:
                messagebox.showinfo("Logs", "Log cleared (backup unavailable).")
        except Exception as e:
            messagebox.showerror("Logs", str(e))

    def _rebuild_state_options(self, rows):
        # rows are dicts: {"timestamp","user","state","row","line_content","error", ...}
        states = set()
        for r in rows:
            if isinstance(r, dict):
                s = (r.get("state") or "").strip()
                if s:
                    states.add(s)
        items = ["(all)"] + sorted(states, key=str.lower)
        self.cb_state["values"] = items
        if self.cb_state.get() not in items:
            self.cb_state.set("(all)")
    def _mask_date_text(self, raw: str) -> str:
        """Return text formatted as YYYY-MM-DD from arbitrary input; allow partials."""
        digits = "".join(ch for ch in (raw or "") if ch.isdigit())[:8]  # up to YYYYMMDD
        y = digits[0:4]
        m = digits[4:6]
        d = digits[6:8]
        if len(digits) <= 4:
            return y
        if len(digits) <= 6:
            return f"{y}.{m}"
        return f"{y}.{m}.{d}"

    def _digits_only(self, s: str) -> str:
        return "".join(ch for ch in (s or "") if ch.isdigit())

    def _format_digits_ymd(self, digits: str) -> str:
        d = digits[:8]
        y, m, d2 = d[0:4], d[4:6], d[6:8]
        if len(d) <= 4:  return y
        if len(d) <= 6:  return f"{y}.{m}"
        return f"{y}.{m}.{d2}"

    def _normalize_date_field(self, entry: ttk.Entry):
        # On focus out: coerce to canonical YYYY-MM-DD if possible; leave partials as-is
        raw = entry.get()
        digits = self._digits_only(raw)
        if not digits:
            return
        entry.delete(0, "end")
        entry.insert(0, self._format_digits_ymd(digits))

    def _on_date_key(self, e, entry: ttk.Entry):
        """
        Intercept typing:
        - Allow digits; auto-insert '-' at positions 4 and 7.
        - Allow '-' only at positions 4 or 7.
        - Handle BackSpace/Delete across '-' nicely.
        - Block overflow beyond YYYY-MM-DD.
        Return "break" to stop Tk default insertion when we insert ourselves.
        """
        ks = e.keysym
        ch = e.char

        # navigation & tabbing unchanged
        if ks in ("Left","Right","Home","End","Tab","Shift_L","Shift_R","Control_L","Control_R"):
            return

        # allow BackSpace/Delete with dash-skip behavior
        if ks == "BackSpace":
            idx = entry.index("insert")
            if idx > 0:
                # if cursor is just after a '-', erase the '-' first
                if entry.get()[idx-1:idx] == ".":
                    entry.delete(idx-1)
                    return "break"
            return  # default backspace after our dash handling
        if ks == "Delete":
            idx = entry.index("insert")
            text = entry.get()
            if idx < len(text) and text[idx:idx+1] == ".":
                entry.delete(idx)
                return "break"
            return  # default delete

        # handle digits
        if ch.isdigit():
            # maximum 8 digits (YYYYMMDD)
            if len(self._digits_only(entry.get())) >= 8:
                return "break"
            idx = entry.index("insert")
            # insert dash at 4 or 7 before digit if cursor is at those positions
            if idx in (4, 7):
                entry.insert(idx, ".")
                idx += 1
                entry.icursor(idx)
            entry.insert(idx, ch)
            entry.icursor(idx + 1)
            return "break"

        # handle '-' explicitly: only at positions 4 or 7 and not duplicated
        if ch == ".":
            idx = entry.index("insert")
            if idx in (4, 7):
                text = entry.get()
                if not (idx < len(text) and text[idx] == "."):
                    entry.insert(idx, ".")
                    entry.icursor(idx + 1)
                # if a dash is already there, just move past it
                else:
                    entry.icursor(idx + 1)
                return "break"
            return "break"  # disallow dash elsewhere

        # block everything else
        return "break"
    
    def _is_real_date(self, s: str) -> bool:
        # Accept only full YYYY-MM-DD here
        if len(s) != 10 or s[4] != "." or s[7] != ".":
            return False
        y, m, d = s[0:4], s[5:7], s[8:10]
        if not (y.isdigit() and m.isdigit() and d.isdigit()):
            return False
        try:
            import datetime
            datetime.date(int(y), int(m), int(d))
            return True
        except Exception:
            return False

    def _vc_date(self, proposed: str) -> bool:
        """
        Tk validatecommand for date entries: allow only
        - empty or partial 'YYYY', 'YYYY-MM', 'YYYY-MM-DD'
        - '-' only at positions 4 and 7
        - at full length, it must be a real calendar date
        """
        if proposed == "":
            return True
        # length cap
        if len(proposed) > 10:
            return False
        # allowed chars and positions
        for i, ch in enumerate(proposed):
            if ch == ".":
                if i not in (4, 7):
                    return False
            elif not ch.isdigit():
                return False
        # don't allow too-short segments like 'YYYY-' (OK) but block 'YYYY-M-'
        if len(proposed) >= 5 and proposed[4] != ".":
            return False
        if len(proposed) >= 8 and proposed[7] != ".":
            return False
        # basic month/day bounds on partials (so '2025-19' is rejected)
        parts = proposed.split(".")
        if len(parts) >= 2 and parts[1]:
            mm = parts[1]
            if not mm.isdigit() or not (1 <= int(mm) <= 12):
                # allow partial month like '2' or '0' while typing first char
                if not (len(mm) == 1 and mm in "01"):
                    return False
        if len(parts) == 3 and parts[2]:
            dd = parts[2]
            # allow '0'..'3' for first digit while typing
            if not dd.isdigit():
                return False
            # if full date len==10, require real calendar date
            if len(proposed) == 10:
                if not self._is_real_date(proposed):
                    return False
            else:
                # partial day sanity: 1..31 with len 1..2
                if len(dd) == 1 and dd not in "0123":
                    return False
                if len(dd) == 2 and not (1 <= int(dd) <= 31):
                    return False
        return True

    def _on_date_paste(self, e, entry):
        """Sanitize pasted content into YYYY-MM-DD (or best partial)."""
        try:
            txt = self.clipboard_get()
        except Exception:
            return "break"
        digits = self._digits_only(txt)
        if not digits:
            return "break"
        formatted = self._format_digits_ymd(digits)
        # If full length, enforce real date; else allow partial
        if len(formatted) == 10 and not self._is_real_date(formatted):
            # try trimming to a valid partial (YYYY-MM or YYYY)
            if len(digits) >= 6:
                formatted = f"{digits[:4]}.{digits[4:6]}"
            else:
                formatted = digits[:4]
        entry.delete(0, "end")
        entry.insert(0, formatted)
        entry.icursor("end")
        return "break"


class ColumnModeDialog(tk.Toplevel):
    """
    Lets the user choose, for each CSV column, whether it should send
    Variable (V) or Query (Q) text.
    """
    def __init__(self, master, headers, default_mode: str, on_ok):
        super().__init__(master)
        self.title("Column data modes")
        self.resizable(False, False)
        self.transient(master)
        self.on_ok = on_ok

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(
            frm,
            text="For each CSV column, choose whether to send it as\n"
                 "Variable text (V) or Query text (Q).",
            justify="left"
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        self._combos: list[ttk.Combobox] = []
        mode_values = ["V", "Q"]

        # normalize default mode
        default_mode = "Q" if (default_mode or "").upper() == "Q" else "V"

        # try to get per-column current/saved modes from master
        initial_modes: list[str]
        try:
            col_modes = list(getattr(master, "column_modes", []))
        except Exception:
            col_modes = []

        if col_modes and len(col_modes) == len(headers):
            # use existing mapping, normalize each to V/Q
            initial_modes = [
                "Q" if (m or "").upper() == "Q" else "V"
                for m in col_modes
            ]
        else:
            # no valid stored mapping → all default
            initial_modes = [default_mode] * len(headers)

        for i, h in enumerate(headers):
            ttk.Label(frm, text=h or f"Col {i+1}").grid(
                row=i+1, column=0, sticky="e", padx=(0, 6), pady=2
            )
            cb = ttk.Combobox(frm, width=5, state="readonly", values=mode_values)
            cb.set(initial_modes[i] if i < len(initial_modes) else default_mode)
            cb.grid(row=i+1, column=1, sticky="w", pady=2)
            self._combos.append(cb)

        btns = ttk.Frame(frm)
        btns.grid(row=len(headers) + 1, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(btns, text="OK", command=self._ok).pack(side="left", padx=4)
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="left", padx=4)

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.update_idletasks()
        try:
            center_on_parent(self, master)
        except Exception:
            pass
        self.grab_set()
        self.lift()
        self.focus_force()


    def _ok(self):
        modes = []
        for cb in self._combos:
            m = (cb.get() or "").upper()
            modes.append("Q" if m == "Q" else "V")
        try:
            self.on_ok(modes)
        except Exception:
            pass
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def _cancel(self):
        # Signal cancel with None – caller decides fallback
        try:
            self.on_ok(None)
        except Exception:
            pass
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()


# -------------------- MAIN APP --------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TMC470 CSV Sender")
        self.geometry("1100x700")
        self.cfg = cs.load_config()
        auth.init_seed_admin()
        auth.init_seed_admin()
        if not auth.list_users():           # <— add this line
            auth.init_seed_admin(force=True)

        self.user = None
        self.dev = TMC470()
        self.running = False
        self.paused = False
        self.current_index = -1
        self.current_field = 0     
        self.resume_index = 0  # next index to send if resuming
        self.override_start_index: Optional[int] = None  # operator-chosen start row (session only)
        self.var_start_from = tk.StringVar(value="Start from: auto")  # UI hint

        self.timeout_q = queue.Queue()  
        self.worker: Optional[threading.Thread] = None
        self.q = queue.Queue()

        self.header: List[str] = []
        self.data: List[List[str]] = []

        self.header: List[str] = []
        self.data: List[List[str]] = []
        self.column_modes: List[str] = []  # "V" or "Q" per column
        self.custom_column_modes = None   

        self._build_ui()
        center(self)   
        # Hide main until login succeeds
        # self.withdraw()
        self._show_login()

    def _ask_column_modes(self):
        """
        Ask the user per-column whether to send as V or Q for the CURRENT CSV.
        Stores result in:
          - self.column_modes           -> effective modes used by the worker
          - self.custom_column_modes    -> remembered CUSTOM setup for this CSV
          - self.cfg["column_modes_*"] -> persisted across app restarts
        """
        headers = self.header or []
        if not headers:
            n = len(self.data[0]) if self.data else 0
            headers = [f"Col {i+1}" for i in range(n)]

        try:
            mode = str(self.cfg.get("data_send_mode", "Q")).strip().upper()
        except Exception:
            mode = "Q"

        default_mode = "Q" if mode == "Q" else "V"

        result = {"modes": None}

        def _on_ok(modes):
            result["modes"] = modes

        dlg = ColumnModeDialog(self, headers, default_mode, _on_ok)
        self.wait_window(dlg)

        modes = result["modes"]
        if not modes:
            # user cancelled → fall back to all-default
            n = len(headers)
            modes = [default_mode] * n

        normalized = [("Q" if (m or "").upper() == "Q" else "V") for m in modes]
        self.column_modes = normalized
        self.custom_column_modes = list(normalized)

        # 🔴 PERSIST FOR NEXT RESTART
        try:
            self.cfg["column_modes_header"] = list(self.header or headers)
            self.cfg["column_modes"] = list(self.column_modes)
            cs.save_config(self.cfg)
            self._log("[COLUMNS] Column modes saved to config for reuse on next start.")
        except Exception as e:
            self._log(f"[COLUMNS] Could not save column modes to config: {e}")

        self._log(
            "[COLUMNS] Modes set: "
            + ", ".join(f"{h}={m}" for h, m in zip(headers, self.column_modes))
        )


    def _apply_data_send_mode(self, prev_cfg: Optional[dict] = None):
        """
        Recalculate column_modes and update the table immediately
        when data_send_mode changes.

        - If mode = V → all columns V
        - If mode = Q → all columns Q
        - If mode = CUSTOM:
            - if we already have custom modes for this CSV, reuse them
            - otherwise open the column-mode dialog once
        - Keep current start row / selection visible.
        """
        if not self.data:
            # nothing loaded, nothing to update
            return

        # Remember row info so we can restore it after header rebuild
        prev_row = getattr(self, "current_index", -1)
        prev_override = self.override_start_index

        # How many columns?
        ncols = len(self.header) if self.header else (len(self.data[0]) if self.data else 0)
        if ncols <= 0:
            return

        try:
            new_mode = str(self.cfg.get("data_send_mode", "Q")).strip().upper()
        except Exception:
            new_mode = "Q"
        if new_mode not in ("V", "Q", "CUSTOM"):
            new_mode = "Q"

        if new_mode == "CUSTOM":
            # same CSV: if we already have a custom setup, just reuse it
            if self.custom_column_modes and len(self.custom_column_modes) == ncols:
                self.column_modes = list(self.custom_column_modes)
                self._log("[COLUMNS] Restored saved CUSTOM modes for current CSV.")
            else:
                # no valid custom setup yet → ask user once
                try:
                    self._ask_column_modes()
                except Exception as e:
                    self._log(f"[COLUMNS] Could not open column mode dialog: {e}")
                    default_mode = "Q"
                    self.column_modes = [default_mode] * ncols
        else:
            default_mode = "Q" if new_mode == "Q" else "V"
            self.column_modes = [default_mode] * ncols
            self._log(f"[COLUMNS] Global mode {new_mode}: all columns → {default_mode}.")

        # Rebuild table so header marks ([V]/[Q]) update
        self._rebuild_table()

        # Restore row highlight / start info
        if prev_override is not None and 0 <= prev_override < len(self.data):
            # Manual "Start from row" should stay the same
            self._highlight(prev_override)
        elif 0 <= prev_row < len(self.data):
            # No manual override; just keep the previous highlighted row
            self._highlight(prev_row)

    def _build_ui(self):
        # Menubar
        base = self.cget("background")
        ttk.Style(self).configure("FlatBar.TFrame", background=base)

        self.mbar = tk.Menu(self)

        # App menu
        self.menu_app = tk.Menu(self.mbar, tearoff=0)
        self.menu_app.add_command(label="Logout", command=self._logout)
        self.menu_app.add_command(label="Exit", command=self.destroy)
        self.mbar.add_cascade(label="App", menu=self.menu_app)

        # Settings menu
        self.menu_settings = tk.Menu(self.mbar, tearoff=0)
        self.menu_settings.add_command(label="Serial…", command=self._open_serial_settings)
        self.menu_settings.add_command(label="Users…", command=self._open_user_settings)
        self.menu_settings.add_command(label="Logs…", command=self._open_logs)
        self.mbar.add_cascade(label="Settings", menu=self.menu_settings)

        # self.config(menu=self.mbar)
        
        # ---- Faux menubar strip (colorable) ----
        _bar_bg = self.cget("bg")  # exactly the same as the main window background
        bar = tk.Frame(self, bg=_bar_bg, bd=0, highlightthickness=0)
        bar.pack(fill="x", side="top")

        # Two menubuttons that reuse the SAME dropdown menus
        mb_app = tk.Label(bar, text="App", bg=_bar_bg, padx=10, pady=4, cursor="hand2")
        mb_app.pack(side="left")

        mb_settings = tk.Label(bar, text="Settings", bg=_bar_bg, padx=10, pady=4, cursor="hand2")
        mb_settings.pack(side="left")
    
    # keep handles + remember original colors (for restore)
        self.mb_app = mb_app
        self.mb_settings = mb_settings
        self._mb_app_fg = self.mb_app.cget("fg") or "#000000"
        self._mb_settings_fg = self.mb_settings.cget("fg") or "#000000"

        # # Hook the real menus to the menubuttons
        # mb_app["menu"] = self.menu_app
        # mb_settings["menu"] = self.menu_settings

        # --- hover highlight only (no other behavior) ---
        _bar_bg   = str(bar["bg"])      # match the strip
        _hover_bg = "#e6e6e6"           # light gray like native hot-track

        def _hover_on(e):  e.widget.configure(bg=_hover_bg)
        def _hover_off(e): e.widget.configure(bg=_bar_bg)

        for _mb in (mb_app, mb_settings):
            # keep visuals flat and ensure base bg matches the strip
            _mb.configure(bg=_bar_bg, activebackground=_bar_bg, relief="flat", bd=0, highlightthickness=0)
            _mb.bind("<Enter>", _hover_on)
            _mb.bind("<Leave>", _hover_off)


        # ---- Open dropdowns on click (and with ↓ key) ----
        def _popup_under(widget, menu):
            # position the menu right under the menubutton, not at the mouse
            x = widget.winfo_rootx()
            y = widget.winfo_rooty() + widget.winfo_height()
            menu.tk_popup(x, y)    # show
            menu.grab_release()    # let clicks pass after popup

        mb_app.bind("<Button-1>",      lambda e: _popup_under(mb_app, self.menu_app))
        mb_settings.bind("<Button-1>", lambda e: _popup_under(mb_settings, self.menu_settings))
        mb_app.bind("<Key-Down>",      lambda e: _popup_under(mb_app, self.menu_app))
        mb_settings.bind("<Key-Down>", lambda e: _popup_under(mb_settings, self.menu_settings))


        # # Faux menubar with same bg as window
        # bar = tk.Frame(self, bg=self.cget("bg"), bd=0, highlightthickness=0); bar.pack(fill="x", side="top")
        # mb_app = tk.Menubutton(bar, text="App", bg=self.cget("bg"), activebackground=self.cget("bg"), relief="flat"); mb_app["menu"] = self.menu_app; mb_app.pack(side="left", padx=6, pady=3)
        # mb_settings = tk.Menubutton(bar, text="Settings", bg=self.cget("bg"), activebackground=self.cget("bg"), relief="flat"); mb_settings["menu"] = self.menu_settings; mb_settings.pack(side="left", padx=6, pady=3)


        base = self.cget("background")
        ttk.Style(self).configure("FlatBar.TFrame", background=base)

        top = ttk.Frame(self, padding=8, style="FlatBar.TFrame"); top.pack(fill="x")


        self.lbl_role = ttk.Label(top, text="Role: -")
        self.lbl_role.pack(side="left", padx=(0, 8))

        self.btn_load_csv = ttk.Button(top, text="Load CSV", command=self._load_csv)
        self.btn_load_csv.pack(side="left", padx=6)


        ttk.Label(top, text="Pattern:").pack(side="left", padx=(12, 4))
        self.ent_pattern = ttk.Entry(top, width=24)
        pat_active = (self.cfg.get("pattern_active") or "").strip()
        pat_default = (self.cfg.get("pattern") or "").strip()
        pat_initial = pat_active if pat_active else pat_default
        if pat_initial:
            self.ent_pattern.insert(0, pat_initial)

        self.ent_pattern.pack(side="left")
        self._pattern_last = pat_initial
        # click opens the same dropdown menus under each label
        def _popup_under(widget, menu):
            x = widget.winfo_rootx()
            y = widget.winfo_rooty() + widget.winfo_height()
            menu.tk_popup(x, y); menu.grab_release()

        mb_app.bind("<Button-1>",      lambda e: _popup_under(mb_app, self.menu_app))
        mb_settings.bind("<Button-1>", lambda e: _popup_under(mb_settings, self.menu_settings))

        # hover highlight only
        _hover_bg = "#e6e6e6"
        def _hover_on(e):  e.widget.configure(bg=_hover_bg)
        def _hover_off(e): e.widget.configure(bg=_bar_bg)

        mb_app.bind("<Enter>", _hover_on);     mb_app.bind("<Leave>", _hover_off)
        mb_settings.bind("<Enter>", _hover_on);mb_settings.bind("<Leave>", _hover_off)
        self._menus_enabled = True

        def _popup_under(widget, menu):
            # hard-disable menubar by gate flag
            if not getattr(self, "_menus_enabled", True):
                return
            x = widget.winfo_rootx()
            y = widget.winfo_rooty() + widget.winfo_height()
            menu.tk_popup(x, y); menu.grab_release()

        def _pattern_changed(_evt=None):
            new = self.ent_pattern.get().strip()
            if new != self._pattern_last:
                # Update active pattern in config (do NOT touch default pattern here)
                self.cfg["pattern_active"] = new
                try:
                    cs.save_config(self.cfg)
                except Exception:
                    pass
                self._pattern_last = new


        self.ent_pattern.bind("<FocusOut>", _pattern_changed)
        self.ent_pattern.bind("<Return>",   _pattern_changed)


        self.btn_connect = ttk.Button(top, text="Connect", command=self._connect)
        self.btn_disconnect = ttk.Button(top, text="Disconnect", command=self._disconnect, state="disabled")
        self.btn_connect.pack(side="left", padx=6)
        self.btn_disconnect.pack(side="left")

        self.btn_start = ttk.Button(top, text="Start", command=self._start, state="disabled")
        self.btn_pause = ttk.Button(top, text="Pause", command=self._pause, state="disabled")
        self.btn_stop  = ttk.Button(top, text="Stop", command=self._stop, state="disabled")
        # show current start point + a button to use the selected row as start
        ttk.Label(top, textvariable=self.var_start_from).pack(side="left", padx=(12, 4))
        self.btn_use_selected = ttk.Button(top, text="Use Selected Start", command=self._use_selected_start, state="disabled")
        self.btn_use_selected.pack(side="left", padx=6)

        self.btn_start.pack(side="left", padx=6)
        self.btn_pause.pack(side="left", padx=6)
        self.btn_stop.pack(side="left", padx=6)


        self.var_status = tk.StringVar(value="Not connected")
        ttk.Label(self, textvariable=self.var_status, anchor="w").pack(fill="x", padx=8)

        # ---- REAL TABLE via tksheet ----
        frame_tbl = ttk.Frame(self); frame_tbl.pack(fill="both", expand=True, padx=8, pady=8)
        frame_tbl.rowconfigure(0, weight=1); frame_tbl.columnconfigure(0, weight=1)

        self.sheet = Sheet(
            frame_tbl,
            data=[],
            headers=[],
            show_row_index=False,
            show_top_left_corner=False,
        )
        self.sheet.grid(row=0, column=0, sticky="nsew")
        # self.sheet.bind("<Configure>", lambda e: fit_sheet_fullwidth(self.sheet))
        self.sheet.MT.bind("<Configure>", lambda e: fit_sheet_fullwidth(self.sheet))
        self.sheet.CH.bind("<Configure>", lambda e: fit_sheet_fullwidth(self.sheet))


        self.sheet.readonly = True  # prevent edits

        self.sheet.enable_bindings((
            "single_select", "row_select", "column_select",
            "arrowkeys", "drag_select",
            "sort", "copy",
            "column_width_resize", "row_height_resize",
            "right_click_popup_menu",
        ))

        # aesthetics
        self.sheet.set_options(
            table_grid_fg="#d0d0d0",
            table_selected_rows_bg="#cbe8ff",
            table_selected_rows_border_fg="#3399ff",
            header_bg="#f2f2f2",
            header_fg="#000000",
            header_border_fg="#c8c8c8",
            table_selected_cells_border_fg="#3399ff",
        )
        try:
            self.sheet.extra_bindings([("cell_select", self._on_sheet_select),
                                    ("row_select",  self._on_sheet_select)])
        except Exception:
            pass
                # Log
        self.txt_log = tk.Text(self, height=10, state="disabled")
        self.txt_log.pack(fill="x", padx=8, pady=(0, 8))

        # Pump queue
        self.after(80, self._pump)
    def _menubar_set_disabled_color(self, disabled: bool):
        """Only change the color of 'App' and 'Settings' when disabled/enabled."""
        try:
            self.mb_app.configure(fg=("#888888" if disabled else self._mb_app_fg))
        except Exception:
            pass
        try:
            self.mb_settings.configure(fg=("#888888" if disabled else self._mb_settings_fg))
        except Exception:
            pass

    # ---------- LOGIN FLOW ----------
    def _show_login(self):
        def on_ok(user):
            self.user = user
            self.lbl_role.config(text=f"Role: {user.role}")
            self._update_admin_controls()
            try:
                logs.append_event(user.username, "login", -1, "user logged in", None)
            except Exception:
                pass
            self.deiconify()  # show main now
            # audit.set_actor(user.username)
            # audit.log("login", {})

            # Auto-load last CSV and apply resume marker, if any
            last = self.cfg.get("last_csv")
            if last and os.path.exists(last):
                try:
                    self._load_csv_path(last)
                    self._apply_resume_after_csv_load()
                except Exception as e:
                    self._log(f"[RESUME] Could not auto-load last CSV: {e}")
        dlg = Login(self, on_ok)
        dlg.wait_visibility()
        dlg.focus_force()
        dlg.lift()
        # ensure caret ends up in the field even on Windows
        dlg.after(0, lambda: (dlg.ent_u.focus_set(), dlg.ent_u.icursor("end")))

    def _logout(self):
        if self.running:
            messagebox.showwarning("Busy", "Stop the batch first.")
            return
        u = getattr(self.user, "username", "")
        self._disconnect()
        if u:
            try:
                logs.append_event(u, "logout", -1, "user logged out", None)
            except Exception:
                pass
        # audit.log("logout", {})
        # audit.set_actor("system")

        self.user = None
        self.lbl_role.config(text="Role: -")
        self._update_admin_controls()
        # self.withdraw()
        self._show_login()

    def _update_admin_controls(self):
        is_admin = bool(self.user and self.user.role == "admin")
        state = "normal" if is_admin else "disabled"
        self.menu_settings.entryconfig("Configuration", state=state)
        self.menu_settings.entryconfig("Users…", state=state)

        logs_state = "normal" if self.user else "disabled"
        self.menu_settings.entryconfig("Logs…", state=logs_state)

        # ---------- SETTINGS ----------
    def _open_serial_settings(self):
        if not (self.user and self.user.role == "admin"):
            messagebox.showerror("Restricted", "Only admin can open Serial Settings.")
            return

        def save(cfg):
            # compare old vs new and log
            old = self.cfg
            oser = old.get("serial", {})
            nser = cfg.get("serial", {})
            self._audit(
                "settings saved",
                "serial_port: {} -> {}; baud: {} -> {}; parity: {} -> {}; stopbits: {} -> {}; pattern: {} -> {}".format(
                    oser.get("port",""), nser.get("port",""),
                    oser.get("baud",""), nser.get("baud",""),
                    oser.get("parity",""), nser.get("parity",""),
                    oser.get("stopbits",""), nser.get("stopbits",""),
                    old.get("pattern",""), cfg.get("pattern",""),
                )
            )

            cs.save_config(cfg)
            self.cfg = cfg
            self._log("[SETTINGS] Serial saved")

            # Only data_send_mode is re-applied; default pattern stays separate
            try:
                self._apply_data_send_mode(prev_cfg=old)
            except Exception as e:
                self._log(f"[SETTINGS] Could not apply data send mode: {e}")

        SettingsDialog(self, self.cfg, save)


    def _open_user_settings(self):
        if not (self.user and self.user.role == "admin"):
            messagebox.showerror("Restricted", "Only admin can open Users.")
            return
        dlg = UserManagementDialog(self)
        self.wait_window(dlg)

    # ---------- CSV ----------
    def _load_csv(self):
        path = filedialog.askopenfilename(
            title="CSV",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return
        self.cfg["last_csv"] = path
        cs.save_config(self.cfg)
        try:
            self._load_csv_path(path)              # parse + fill table + log
            self._apply_resume_after_csv_load()    # highlight + set resume_index if pending
            self._update_start_enabled()
        except Exception as e:
            messagebox.showerror("CSV error", str(e))

    # def _load_csv_path(self, path: str):
    #     with open(path, "r", encoding="utf-8-sig", newline="") as f:
    #         text = f.read()
    #     header, rows, used_delim = self._parse_csv_text(text)
    #     self.header = header
    #     self.data   = rows
    #     self._rebuild_table()
    #     self._log(f"[CSV] Loaded {len(self.data)} rows (delimiter='{used_delim}')")

    def _apply_resume_after_csv_load(self):
        """If resume info matches current CSV, highlight + set next index; else reset."""
        res = self.cfg.get("resume", {})
        last = self.cfg.get("last_csv", "")
        if not (res and res.get("pending") and res.get("path") and last):
            self.resume_index = 0
            return
        try:
            import os
            same = os.path.abspath(res["path"]) == os.path.abspath(last)
        except Exception:
            same = False
        if same and self.data:
            hi = max(0, min(int(res.get("highlight", 0)), len(self.data)-1))
            nx = max(0, min(int(res.get("next", 0)),      len(self.data)))
            self._highlight(hi)
            self.resume_index = nx
            self._log(f"[RESUME] Highlight row {hi+1}, next to send: row {nx+1}")
        else:
            self.resume_index = 0

    def _wait_for_external_go(self):
        """
        Dynamic Java-equivalent:
        External GO = controller transitions to MACHINE_STATUS_PRINTING.
        No static mapping, no wiring, pure protocol.
        """
        while self.running and not self.paused:
            try:
                status, raw = self.dev.poll_machine_status()
                if status == "MACHINE_STATUS_PRINTING":
                    self.q.put(("log", f"[MANUAL] External GO detected → {raw.strip()}"))
                    return True
            except Exception as e:
                self.q.put(("log", f"[ERROR] wait_for_external_go: {e}"))
            time.sleep(0.05)
        return False


    def _parse_csv_text(self, text: str):
        """
        Auto-detect delimiter (tries csv.Sniffer, then [';', ',', '\\t', '|']).
        Returns (header, rows, delimiter_used).
        """
        import csv
        sample = text[:4096]

        # 1) Try Sniffer
        delim = None
        try:
            sniffer = csv.Sniffer()
            # prefer ; in EU locales: if both ; and , appear, bias to ;
            sniffed = sniffer.sniff(sample, delimiters=";,|\t")
            delim = sniffed.delimiter
        except Exception:
            pass

        # 2) If Sniffer failed, try common delimiters and pick the one with max columns
        if not delim:
            candidates = [";", ",", "\t", "|"]
            best = (";", 1)  # default to semicolon
            for cand in candidates:
                try:
                    r = csv.reader(text.splitlines(), delimiter=cand)
                    first = next(iter(r), [])
                    cols = len(first)
                    if cols > best[1]:
                        best = (cand, cols)
                except Exception:
                    continue
            delim = best[0]

        # 3) Parse with the chosen delimiter
        r = csv.reader(text.splitlines(), delimiter=delim)
        header = next(r, [])
        rows = [[c if c is not None else "" for c in row] for row in r]

        return header, rows, delim

    def _rebuild_table(self):
        if self.header:
            headers = list(self.header)
        else:
            n = len(self.data[0]) if self.data else 0
            headers = [f"Col {i+1}" for i in range(n)]

        # Add a visible mark: [V] or [Q] in front of each header
        col_modes = getattr(self, "column_modes", None)
        if col_modes:
            decorated = []
            for i, h in enumerate(headers):
                mark = ""
                if i < len(col_modes):
                    m = (col_modes[i] or "").upper()
                    if m == "V":
                        mark = "[V] "
                    elif m == "Q":
                        mark = "[Q] "
                decorated.append(f"{mark}{h}")
            headers = decorated

        self.sheet.headers(headers)
        self.sheet.set_sheet_data(self.data or [])

        # (keep the rest of your _rebuild_table as it was: column widths, readonly, etc.)



        # ---------- SERIAL ----------
    def _connect(self):
        io_mode = (self.cfg.get("io_mode", "serial") or "serial").lower()

        if io_mode == "ethernet":
            eth = self.cfg.get("ethernet", {})
            host = (eth.get("host") or "").strip()
            try:
                port = int(eth.get("port", 10000))
            except ValueError:
                port = 10000

            if not host:
                messagebox.showerror("Ethernet", "Admin must set Ethernet host in Settings first.")
                return

            try:
                self.dev.connect_tcp(host, port)
            except Exception as e:
                messagebox.showerror("Ethernet", f"Could not connect to {host}:{port}\n{e}")
                return

            self._set_status(f"Connected (TCP) {host}:{port}")
            self.btn_connect["state"] = "disabled"
            self.btn_disconnect["state"] = "normal"
            self._update_start_enabled()
            self._menubar_set_disabled_color(True)

            # DISABLE top menus + Load CSV + Pattern (same as before)
            self._menus_enabled = False
            try: self.btn_load_csv["state"] = "disabled"
            except Exception: pass
            try: self.ent_pattern["state"] = "disabled"
            except Exception: pass

            try:
                logs.append_event(
                    getattr(self.user, "username", ""),
                    "ethernet connected",
                    -1,
                    f"{host}:{port}",
                    None,
                )
            except Exception:
                pass

        else:
            # SERIAL branch (original behavior)
            serial_config = self.cfg["serial"]
            port = serial_config.get("port","")
            if not port:
                messagebox.showerror("Serial", "Admin must set Port in Settings first.")
                return
            kwargs = {
                "baudrate": int(serial_config.get("baud", 9600)),
                "parity":   {"N": "N", "E": "E", "O": "O"}[serial_config.get("parity","N")],
                "stopbits": int(serial_config.get("stopbits", 1)),
                "bytesize": int(serial_config.get("databits", 8)),
            }
            from serial import (
                PARITY_NONE, PARITY_EVEN, PARITY_ODD,
                STOPBITS_ONE, STOPBITS_TWO,
                SEVENBITS, EIGHTBITS,
            )
            kwargs["parity"] = {
                "N": PARITY_NONE,
                "E": PARITY_EVEN,
                "O": PARITY_ODD,
            }[serial_config.get("parity", "N")]
            kwargs["stopbits"] = {
                1: STOPBITS_ONE,
                2: STOPBITS_TWO,
            }[int(serial_config.get("stopbits", 1))]
            kwargs["bytesize"] = {
                7: SEVENBITS,
                8: EIGHTBITS,
            }[int(serial_config.get("databits", 8))]

            try:
                self.dev.connect(port, **kwargs)
            except Exception as e:
                messagebox.showerror("Serial", f"Could not open {port}\n{e}")
                return

            self._set_status(f"Connected (serial) {port} @ {self.cfg['serial']['baud']}")
            self.btn_connect["state"] = "disabled"
            self.btn_disconnect["state"] = "normal"
            self._update_start_enabled()
            self._menubar_set_disabled_color(True)

            # DISABLE top menus + Load CSV + Pattern (same as before)
            self._menus_enabled = False
            try: self.btn_load_csv["state"] = "disabled"
            except Exception: pass
            try: self.ent_pattern["state"] = "disabled"
            except Exception: pass

            # original audit/logging
            self._audit("serial connect",
                        f"port={port}; baud={serial_config.get('baud')}; "
                        f"parity={serial_config.get('parity')}; "
                        f"stopbits={serial_config.get('stopbits')}; "
                        f"bytesize={serial_config.get('databits')}")
            try:
                logs.append_event(
                    getattr(self.user,"username",""),
                    "serial connected",
                    -1,
                    f"{port}@{serial_config.get('baud')} parity={serial_config.get('parity')} "
                    f"stopbits={serial_config.get('stopbits')} bytesize={serial_config.get('databits')}",
                    None,
                )
                # live verification unchanged
                mode = self.cfg.get("connection_mode", "test")
                if mode == "live":
                    ok, status, raw = self.dev.verify_live_connection(tries=2, sleep_ms=120)
                    if not ok:
                        try:
                            user = getattr(self.user, "username", "") if self.user else ""
                            logs.append_event(
                                user,
                                "serial verification FAILED",
                                -1,
                                f"{port}@{serial_config.get('baud')} parity={serial_config.get('parity')} "
                                f"stopbits={serial_config.get('stopbits')} bytesize={serial_config.get('databits')}",
                                "no CR-terminated status"
                            )
                        except Exception:
                            pass
                        # DO NOT disconnect or disable Start.
                        # Printer is clearly reachable; we just note that live verify failed.
                        self._set_status("Connected (live verify failed – using port anyway)")

            except Exception:
                pass



    def _disconnect(self):
        try:
            self.dev.disconnect()
            try:
                logs.append_event(getattr(self.user,"username",""), "serial disconnected", -1, "", None)
            except Exception:
                pass
        except:
            pass
        self._set_status("Not connected")
        self.btn_connect["state"] = "normal"; self.btn_disconnect["state"] = "disabled"
        self.btn_start["state"] = "disabled"
        # color only: if your logic re-enables menus here, restore color now
        # (if you only re-enable after STOP, you can skip this and do it in _stop)
        self._menubar_set_disabled_color(False)

        # ENABLE top menus + Load CSV + Pattern
        self._menus_enabled = True
        try: self.btn_load_csv["state"] = "normal"
        except Exception: pass
        try: self.ent_pattern["state"] = "normal"
        except Exception: pass
                
        # in _disconnect()
        self._audit("serial disconnect", "")

       
    def _update_start_enabled(self):
        dev = getattr(self, "dev", None)
        connected = False

        if dev is not None:
            # If the driver *does* provide is_connected(), use it.
            is_conn_attr = getattr(dev, "is_connected", None)
            if callable(is_conn_attr):
                try:
                    connected = bool(is_conn_attr())
                except Exception:
                    connected = False
            else:
                # Fallback for current TMC470: check underlying serial.
                ser = getattr(dev, "ser", None)
                try:
                    connected = bool(ser and ser.is_open)
                except Exception:
                    connected = bool(ser)

        ok = connected and bool(self.data)
        self.btn_start["state"] = ("normal" if ok and not self.running else "disabled")

    # ---------- BATCH ----------
    def _start(self):
        if self.running:
            return
        pat = self.ent_pattern.get().strip()
        if not pat:
            pat = (self.cfg.get("pattern") or "").strip()
            if not pat:
                messagebox.showerror("Pattern", "No pattern specified and no default in settings!")
                return
            # Update UI + remember last pattern
            self.ent_pattern.delete(0, "end")
            self.ent_pattern.insert(0, pat)
        old_active = (self.cfg.get("pattern_active") or "").strip()
        if old_active != pat:
            try:
                logs.append_event(getattr(self.user,"username",""), "pattern changed", -1,
                                f"{old_active}→{pat}", None)
            except Exception:
                pass
        self.cfg["pattern_active"] = pat
        try:
            cs.save_config(self.cfg)
        except Exception:
            pass
        self._audit("batch start", f"pattern={pat}")

        self.paused = False
        self.running = True
        self.btn_start["state"] = "disabled"
        if hasattr(self, "btn_pause"): self.btn_pause["state"] = "normal"
        self.btn_stop["state"]  = "normal"
        try:
            logs.append_event(getattr(self.user,"username",""), "print started", -1,
                            f"rows={len(self.data)} pattern={pat}", None)
        except Exception:
            pass
              # operator override beats persisted resume; else compute from resume
        # operator override beats persisted resume; else compute from resume
        if self.override_start_index is not None:
            start_idx = int(self.override_start_index)
            start_field = 0
        else:
            start_idx, start_field = self._compute_start_index()

        # highlight immediately (turns selected row green right away)
        try:
            self._highlight(start_idx)
        except Exception:
            pass

        self._log(f"[START] Starting at row {start_idx+1}, field {start_field+1}")
        self.worker = threading.Thread(
            target=self._batch_worker,
            args=(pat, start_idx, start_field),
            daemon=True,
        )
        self.worker.start()



        # reset override label to auto once we actually start
        self.override_start_index = None
        self.var_start_from.set("Start from: auto")

    def _stop(self):
        if not self.running:
            return
        # Treat Stop as a pause unless we're at the very end already
        self._log("[STOP] Converting to pause (saving resume point)…")
        self.paused = True
        self.stopped = True 
        self.btn_stop["state"] = "disabled"
        # If your policy is "enable back only after STOP + DISCONNECT", restore color here
        is_connected = bool(
            getattr(self, "dev", None)
            and getattr(self.dev, "is_connected", None)
            and self.dev.is_connected()
        )
        if not is_connected:
            self._menubar_set_disabled_color(False)
        try:
            logs.append_event(getattr(self.user,"username",""), "print paused", -1, "operator requested stop", None)
        except Exception:
            pass

    def _pause(self):
        if not self.running:
            return
        self.paused = True
        self.stopped = False
        self._log("[PAUSE] Requested by user…")
        # worker will notice and exit loop; buttons update in _pump on 'done'

    def _on_sheet_select(self, *args, **kwargs):
        """Enable 'Use Selected Start' when a row/cell is selected."""
        try:
            sel = self.sheet.get_currently_selected()
            has_sel = bool(sel) and sel[0] is not None and sel[0] >= 0
        except Exception:
            has_sel = False
        self.btn_use_selected["state"] = ("normal" if has_sel and not self.running and bool(self.data) else "disabled")

    def _get_selected_row(self) -> Optional[int]:
        """Return selected row index from tksheet, or None if nothing selected."""
        try:
            sel = self.sheet.get_currently_selected()  # (row, col)
            if sel and sel[0] is not None and sel[0] >= 0:
                return int(sel[0])
        except Exception:
            pass
        return None

    def _set_start_from(self, idx: int):
        """Set operator override start row, update label and highlight."""
        if not self.data:
            return
        idx = max(0, min(idx, len(self.data) - 1))
        self.override_start_index = idx
        self.var_start_from.set(f"Start from: row {idx+1} (manual)")
        # show the operator what will be used
        self._highlight(idx)
        self._log(f"[OVERRIDE] Operator set start row -> {idx+1}")
        self._audit("start row override", f"row={idx+1}", row=idx)

    def _use_selected_start(self):
        """Command for the 'Use Selected Start' button."""
        if self.running:
            return
        idx = self._get_selected_row()
        if idx is None:
            messagebox.showinfo("Start from row", "Please select a row first.")
            return
        self._set_start_from(idx)

    def _batch_worker(self, pattern: Optional[str], start_index: Optional[int] = None, start_field: Optional[int] = None):
        """
        Batch sender with:
        - Correct highlight timing (immediate)
        - Resume by (row, field)
        - Per-column V/Q mode:
            * For each column:
                - if mode_for_field == 'V' → send Variable text (Vnn via set_var)
                - if mode_for_field == 'Q' → send Query text  (Qnn via provide_query_text)
            * Separate index spaces for V and Q:
                - first V-field in row -> V01
                - first Q-field in row -> Q01
            * After all fields of the row are sent, ONE print (G) per row.
        """
        user_name = getattr(self.user, "username", "") if self.user else ""

        # global data_send_mode: V, Q or CUSTOM
        try:
            mode = str(self.cfg.get("data_send_mode", "Q")).strip().upper()
        except Exception:
            mode = "Q"

        is_custom = (mode == "CUSTOM")
        if mode not in ("V", "Q", "CUSTOM"):
            mode = "Q"

        # default field mode if column_modes is missing/short
        default_mode = "Q" if mode == "Q" else "V"

        try:
            # --- PUT ONLINE ---
            try:
                self.q.put(("log", f"[FRAME] {self._preview_extended_frame('O', '', '')}"))
            except Exception:
                pass
            r = self.dev.put_online()
            self.q.put(("log", f"[PUT ONLINE] {repr(r)}"))

            # --- PATTERN LOAD/VERIFY (if any) ---
            if pattern:
                try:
                    self.q.put(("log", f"[FRAME] {self._preview_extended_frame('P', '', pattern)}"))
                except Exception:
                    pass
                r1 = self.dev.load_pattern(pattern)
                self.q.put(("log", f"[LOAD] {repr(r1)}"))

                try:
                    self.q.put(("log", f"[FRAME] {self._preview_extended_frame('P', '', '')}"))
                except Exception:
                    pass
                rv = self.dev.verify_pattern()
                self.q.put(("log", f"[VERIFY] {repr(rv)}"))

            row0   = start_index if start_index is not None else 0
            field0 = start_field if start_field is not None else 0

            idx = row0
            while idx < len(self.data):
                if not self.running:
                    break

                # highlight row immediately
                self.q.put(("hl", idx))

                # handle pause before doing anything with this row
                if getattr(self, "paused", False):
                    self._save_resume(idx, idx, field0 if idx == row0 else 0)
                    break

                row = self.data[idx]
                line_text = ";".join("" if c is None else str(c) for c in row)

                total_fields = len(row)
                # if resuming in the middle of a row, continue from that field
                field_idx = field0 if idx == row0 else 0

                # local copy of column_modes
                col_modes = list(getattr(self, "column_modes", [])) if hasattr(self, "column_modes") else []

                # compute V/Q counters for fields that were already sent in this row
                v_index = 0
                q_index = 0
                if field_idx > 0:
                    for ci in range(field_idx):
                        # determine mode for column ci
                        if is_custom and col_modes and ci < len(col_modes):
                            m_ci = (col_modes[ci] or "").upper()
                            if m_ci in ("V", "Q"):
                                mode_ci = m_ci
                            else:
                                mode_ci = default_mode
                        else:
                            mode_ci = default_mode

                        if mode_ci == "Q":
                            q_index += 1
                        else:
                            v_index += 1

                # ---------- 1) SEND ALL FIELDS (V or Q) FOR THIS ROW ----------
                while field_idx < total_fields:
                    if not self.running:
                        break
                    if getattr(self, "paused", False):
                        # paused while sending fields → remember exact field
                        self._save_resume(idx, idx, field_idx)
                        break

                    value = "" if row[field_idx] is None else str(row[field_idx])

                    # Decide mode for this column: 'V' or 'Q'
                    if is_custom and col_modes and field_idx < len(col_modes):
                        m = (col_modes[field_idx] or "").upper()
                        if m in ("V", "Q"):
                            mode_for_field = m
                        else:
                            mode_for_field = default_mode
                    else:
                        # global V or Q for the whole table
                        mode_for_field = default_mode

                    # --- Send according to mode_for_field ---
                    if mode_for_field == "Q":
                        # QUERY TEXT: Qnn, with its own index
                        q_index += 1
                        buf_no = q_index

                        try:
                            self.q.put(("log", f"[FRAME] {self._preview_extended_frame('Q', f'{buf_no:02d}', value)}"))
                        except Exception:
                            pass
                        try:
                            resp = self.dev.provide_query_text(buf_no, value)
                            self.q.put(("log", f"[Q] buf {buf_no:02d} <- {value} | {self._short(resp)}"))
                        except Exception as e:
                            msg = f"provide_query_text({buf_no}) error: {e}"
                            self.q.put(("log", f"[ERROR] {msg}"))
                            logs.append_event(
                                user_name,
                                "data partially transferred",
                                idx,
                                f"{line_text} [Q field {buf_no}]",
                                msg,
                            )
                            self._save_resume(idx, idx, field_idx)
                            # field-level decision
                            decision = self._timeout_decision(idx, "VSET", 0.0)
                            if decision == "repeat":
                                # repeat SAME FIELD (q_index already incremented; roll back)
                                q_index -= 1
                                continue
                            elif decision == "continue":
                                field_idx += 1
                                self._save_resume(idx, idx, field_idx if field_idx < total_fields else 0)
                                continue
                            elif decision == "exit":
                                self.paused = True
                                break
                    else:
                        # VARIABLE TEXT: Vnn, with its own index
                        v_index += 1
                        buf_no = v_index

                        try:
                            self.q.put(("log", f"[FRAME] {self._preview_extended_frame('V', f'{buf_no:02d}', value)}"))
                        except Exception:
                            pass
                        try:
                            resp = self.dev.set_var(buf_no, value)
                            self.q.put(("log", f"[V] var {buf_no:02d} <- {value} | {self._short(resp)}"))
                        except Exception as e:
                            msg = f"set_var({buf_no}) error: {e}"
                            self.q.put(("log", f"[ERROR] {msg}"))
                            logs.append_event(
                                user_name,
                                "data partially transferred",
                                idx,
                                f"{line_text} [V field {buf_no}]",
                                msg,
                            )
                            self._save_resume(idx, idx, field_idx)
                            # field-level decision
                            decision = self._timeout_decision(idx, "VSET", 0.0)
                            if decision == "repeat":
                                # repeat SAME FIELD (v_index already incremented; roll back)
                                v_index -= 1
                                continue
                            elif decision == "continue":
                                field_idx += 1
                                self._save_resume(idx, idx, field_idx if field_idx < total_fields else 0)
                                continue
                            elif decision == "exit":
                                self.paused = True
                                break

                    # success → next field
                    field_idx += 1
                    self._save_resume(
                        idx,
                        idx if field_idx < total_fields else idx,
                        field_idx if field_idx < total_fields else 0,
                    )

                # paused/stopped during field sending
                if getattr(self, "paused", False) or not self.running:
                    break

                # if incomplete (error/continue advanced), let the loop handle resume
                if field_idx < total_fields:
                    continue

                # all fields done for this row
                logs.append_event(user_name, "data transferred", idx, line_text, None)

                # ---------- 2) PRINT ONCE FOR THE WHOLE ROW ----------

                # READY (row-level)
                if not self.dev.wait_ready(READY_TIMEOUT_S):
                    self.q.put(("log", "[TIMEOUT] READY timeout"))
                    logs.append_event(user_name, "print started", idx, line_text, "READY timeout")
                    decision = self._timeout_decision(idx, "READY", READY_TIMEOUT_S)
                    if decision == "repeat":
                        # repeat SAME ROW print; V/Q buffers already in device
                        continue
                    elif decision == "continue":
                        self._save_resume(idx, idx + 1, 0)
                        idx += 1
                        field0 = 0
                        continue
                    elif decision == "exit":
                        self._save_resume(idx, idx, 0)
                        self.paused = True
                        break

                # START PRINT (G)
                # try:
                #     try:
                #         self.q.put(("log", f"[FRAME] {self._preview_extended_frame('G', '', '')}"))
                #     except Exception:
                #         pass
                #     rs = self.dev.start_print()
                #     self.q.put(("log", f"[START] {self._short(rs)}"))
                #     logs.append_event(user_name, "print started", idx, line_text, None)
                # except Exception as e:
                #     msg = f"start_print error: {e}"
                #     self.q.put(("log", f"[ERROR] {msg}"))
                #     logs.append_event(user_name, "print started", idx, line_text, msg)
                #     decision = self._timeout_decision(idx, "G", 0.0)
                #     if decision == "repeat":
                #         # retry SAME ROW print (V/Q content is already there)
                #         continue
                #     elif decision == "continue":
                #         self._save_resume(idx, idx + 1, 0)
                #         idx += 1
                #         field0 = 0
                #         continue
                #     elif decision == "exit":
                #         self._save_resume(idx, idx, 0)
                #         self.paused = True
                #         break

                trigger_mode = self.cfg.get("print_trigger_mode", "automatic").strip().lower()

                if trigger_mode == "automatic":
                    # --- AUTOMATIC MODE (unchanged) ---
                    try:
                        try:
                            self.q.put(("log", f"[FRAME] {self._preview_extended_frame('G', '', '')}"))
                        except Exception:
                            pass
                        rs = self.dev.start_print()
                        self.q.put(("log", f"[START] {self._short(rs)}"))
                        logs.append_event(user_name, "print started", idx, line_text, None)
                    except Exception as e:
                        msg = f"start_print error: {e}"
                        self.q.put(("log", f"[ERROR] {msg}"))
                        logs.append_event(user_name, "print started", idx, line_text, msg)
                        decision = self._timeout_decision(idx, "G", 0.0)
                        if decision == "repeat":
                            self._save_resume(idx, idx, 0)
                            continue
                        elif decision == "continue":
                            self._save_resume(idx, idx + 1, 0)
                            idx += 1
                            continue
                        elif decision == "exit":
                            self._save_resume(idx, idx, 0)
                            self.paused = True
                            break

                else:
                    # --- MANUAL MODE (JAVA EQUIVALENT) ---
                    self.q.put(("log", "[MANUAL] Waiting for external GO (PRINTING)…"))
                    logs.append_event(user_name, "print waiting external GO", idx, line_text, None)

                    if not self._wait_for_external_go():
                        self.q.put(("log", "[MANUAL] External GO aborted/cancelled"))
                        self._save_resume(idx, idx, 0)
                        break

                    logs.append_event(user_name, "print started (external GO)", idx, line_text, None)


                if getattr(self, "paused", False) or not self.running:
                    self._save_resume(idx, idx, 0)
                    break

                # DONE/READY (row-level)
                if not self.dev.wait_done_or_ready(DONE_TIMEOUT_S):
                    self.q.put(("log", "[TIMEOUT] DONE/READY timeout"))
                    logs.append_event(user_name, "print finished", idx, line_text, "DONE/READY timeout")
                    decision = self._timeout_decision(idx, "DONE/READY", DONE_TIMEOUT_S)
                    if decision == "repeat":
                        # retry SAME ROW print
                        continue
                    elif decision == "continue":
                        self._save_resume(idx, idx + 1, 0)
                        idx += 1
                        field0 = 0
                        continue
                    elif decision == "exit":
                        self._save_resume(idx, idx, 0)
                        self.paused = True
                        break
                else:
                    logs.append_event(user_name, "print finished", idx, line_text, None)
                    # row complete → next row
                    self._save_resume(idx, idx + 1, 0)
                    idx += 1
                    field0 = 0

        except Exception as e:
            self.q.put(("log", f"[ERROR] {e}"))
        finally:
            if getattr(self, "paused", False):
                self.q.put(("log", "[PAUSE] Batch paused, use Start to resume."))
            else:
                self.q.put(("log", "[DONE] Batch complete"))
            self.q.put(("done", None))

        # ---------- UI PUMP / HELPERS ----------
    def _pump(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "hl":
                    self._highlight(payload)
                elif kind == "log":
                    self._log(payload)
                elif kind == "ask_timeout":
                    # payload: dict(idx=..., stage=..., seconds=...)
                    self._ask_timeout_decision(payload["idx"], payload["stage"], payload["seconds"])
                elif kind == "done":
                    self.running = False
                    self.btn_pause["state"] = "disabled" if hasattr(self, "btn_pause") else "disabled"
                    self.btn_stop["state"]  = "disabled"
                    self._update_start_enabled()
        except queue.Empty:
            pass
        self.after(80, self._pump)



    def _highlight(self, idx: int):
        # clear previous highlight, then highlight the active row in green
        try:
            self.sheet.dehighlight_all()
        except Exception:
            pass
        self.sheet.highlight_rows(rows=[idx], bg="#d8ffd8", redraw=True)
        try:
            self.sheet.see(row=idx, column=0)
        except Exception:
            pass

    def _set_status(self, s: str):
        self.var_status.set(s)

    def _log(self, s: str):
        # GUI log (unchanged)
        self.txt_log.config(state="normal")
        self.txt_log.insert("end", s + "\n")
        self.txt_log.see("end")
        self.txt_log.config(state="disabled")

        # Mirror the SAME line into logs.csv so it appears in the Logs window
        try:
            username = getattr(self.user, "username", "") if self.user else ""
            row_idx  = getattr(self, "current_index", -1)
            state    = "screen"              # generic state for UI log lines
            error    = s if s.strip().lower().startswith("[error]") else None
            logs.append_event(username, state, row_idx, s, error)
        except Exception:
            pass

        # (optional) keep your system log file mirror if you want it too
        try:
            import os
            from pathlib import Path
            if os.name == "nt":
                base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "tmc470"
            else:
                preferred = Path("/var/log/tmc470")
                base = preferred if preferred.exists() or preferred.parent.exists() else Path.home() / ".tmc470"
            base.mkdir(parents=True, exist_ok=True)
            with open(base / "system.log", "a", encoding="utf-8") as f:
                f.write(s + "\n")
        except Exception:
            pass


    def _short(self, s: Optional[str]) -> str:
        if s is None: return "None"
        s = s.replace("\r", "\\r")
        return s if len(s) <= 160 else s[:157] + "..."

    def _save_resume(self, highlight_idx: int, next_idx: int, field_idx: int = 0):
            """Persist + update in-memory resume pointer."""
            self.cfg["resume"] = {
                "path": self.cfg.get("last_csv", ""),
                "highlight": int(highlight_idx),
                "next": int(next_idx),
                "pending": True,
                "field": field_idx,
            }
            cs.save_config(self.cfg)
            self.resume_index = int(next_idx)
            try:
                self.current_field = int(field_idx)
            except Exception:
                self.current_field = 0

    def _clear_resume(self):
        """Clear persist + in-memory resume pointer."""
        self.cfg["resume"] = {"path": "", "highlight": 0, "next": 0, "pending": False, "field": 0}
        cs.save_config(self.cfg)
        self.resume_index = 0

    def _compute_start_index(self):
        """
        Return (row_idx, field_idx) start point.
        Prefers persisted resume if it matches the current CSV; otherwise uses in-memory pointers.
        """
        res  = self.cfg.get("resume", {})
        last = self.cfg.get("last_csv", "")

        # defaults from memory
        row   = int(getattr(self, "resume_index", 0) or 0)
        field = int(getattr(self, "current_field", 0) or 0)

        if res and res.get("pending") and res.get("path") and last and self.data:
            try:
                import os
                if os.path.abspath(res["path"]) == os.path.abspath(last):
                    row = max(0, min(int(res.get("next", 0)), len(self.data)))
                    if self.data and 0 <= row < len(self.data):
                        row_len = len(self.data[row])
                        field = max(0, min(int(res.get("field", 0)), max(0, row_len - 1)))
                    else:
                        field = 0
            except Exception:
                pass

        if self.data and 0 <= row < len(self.data):
            row_len = len(self.data[row])
            field = 0 if row_len == 0 else max(0, min(field, row_len - 1))
        else:
            row = 0
            field = 0

        self.resume_index = row
        self.current_field = field
        return row, field

    def _apply_resume_after_csv_load(self):
        """If a pending resume matches the loaded CSV, highlight it and remember next row+field."""
        res = self.cfg.get("resume", {})
        path_ok = res.get("path") and os.path.abspath(res["path"]) == os.path.abspath(self.cfg.get("last_csv", ""))
        if res.get("pending") and path_ok and self.data:
            hi = max(0, min(int(res.get("highlight", 0)), len(self.data)-1))
            nx = max(0, min(int(res.get("next", 0)), len(self.data)))
            field = max(0, int(res.get("field", 0)))

            self._highlight(hi)
            self.resume_index = nx
            self.current_field = field
            self._log(f"[RESUME] Highlight row {hi+1}, next to send: row {nx+1}, field {field+1}")
            self._update_start_enabled()
        else:
            self.resume_index = 0
            self.current_field = 0

    def _load_csv_path(self, path: str):
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            text = f.read()
        header, rows, used_delim = self._parse_csv_text(text)
        self.header = header
        self.data = rows

        # New CSV loaded → reset runtime custom cache
        self.custom_column_modes = None
        self.column_modes = []

        ncols = len(self.header) if self.header else (len(self.data[0]) if self.data else 0)

        # Global data_send_mode
        try:
            mode = str(self.cfg.get("data_send_mode", "Q")).strip().upper()
        except Exception:
            mode = "Q"
        if mode not in ("V", "Q", "CUSTOM"):
            mode = "Q"

        # Check if we have a saved mapping for THIS header
        saved_hdr   = self.cfg.get("column_modes_header") or []
        saved_modes = self.cfg.get("column_modes") or []
        have_saved = (
            saved_hdr
            and saved_modes
            and ncols == len(saved_hdr) == len(saved_modes)
            and all((h1 or "") == (h2 or "") for h1, h2 in zip(saved_hdr, self.header or saved_hdr))
        )

        if ncols > 0:
            if mode == "CUSTOM":
                if have_saved:
                    # reuse previously saved mapping for this header
                    self.column_modes = [
                        ("Q" if (m or "").upper() == "Q" else "V") for m in saved_modes
                    ]
                    self.custom_column_modes = list(self.column_modes)
                    self._log("[COLUMNS] Reused saved CUSTOM column modes from config.")
                else:
                    # first time for this CSV → ask and persist
                    try:
                        self._ask_column_modes()
                    except Exception as e:
                        self._log(f"[COLUMNS] Could not open column mode dialog: {e}")
                        default_mode = "Q"
                        self.column_modes = [default_mode] * ncols
            else:
                # simple global mode (V or Q)
                default_mode = "Q" if mode == "Q" else "V"
                self.column_modes = [default_mode] * ncols

        # build table with [V]/[Q] headers
        self._rebuild_table()
        self._log(f"[CSV] Loaded {len(self.data)} rows (delimiter='{used_delim}')")

        # Persist whatever modes we ended up with for this CSV
        try:
            self.cfg["column_modes_header"] = list(self.header or [])
            self.cfg["column_modes"] = list(self.column_modes or [])
            cs.save_config(self.cfg)
        except Exception as e:
            self._log(f"[COLUMNS] Could not persist column modes after CSV load: {e}")

        # audit log
        logs.append_event(
            getattr(self.user, "username", ""),
            "data stream loaded",
            -1,
            f"CSV loaded: {self.cfg.get('last_csv', '')}",
            None,
        )

    def _ask_column_modes(self):
        """
        Ask the user per-column whether to send as V or Q for the CURRENT CSV.
        Stores result in:
          - self.column_modes           -> effective modes used by the worker
          - self.custom_column_modes    -> remembered CUSTOM setup for this CSV
        """
        headers = self.header or []
        if not headers:
            n = len(self.data[0]) if self.data else 0
            headers = [f"Col {i+1}" for i in range(n)]

        try:
            mode = str(self.cfg.get("data_send_mode", "Q")).strip().upper()
        except Exception:
            mode = "Q"

        default_mode = "Q" if mode == "Q" else "V"

        result = {"modes": None}

        def _on_ok(modes):
            result["modes"] = modes

        dlg = ColumnModeDialog(self, headers, default_mode, _on_ok)
        self.wait_window(dlg)

        modes = result["modes"]
        if not modes:
            # user cancelled → fall back to all-default
            n = len(headers)
            modes = [default_mode] * n

        normalized = [("Q" if (m or "").upper() == "Q" else "V") for m in modes]
        self.column_modes = normalized
        # remember CUSTOM setup for this CSV
        self.custom_column_modes = list(normalized)

        self._log("[COLUMNS] Modes set: " + ", ".join(
            f"{h}={m}" for h, m in zip(headers, self.column_modes)
        ))


    def _mark_timeout_row(self, idx: int):
        """Highlight timed-out/stopped row in a distinct color."""
        try:
            self.sheet.dehighlight_all()
        except Exception:
            pass
        # orange for timeout/stopped
        self.sheet.highlight_rows(rows=[idx], bg=TIMEOUT_ROW_BG, redraw=True)
        try:
            self.sheet.see(row=idx, column=0)
        except Exception:
            pass

    def _ask_timeout_decision(self, idx: int, stage: str, seconds: float):
        """Open modal dialog; when user chooses, put decision into self.timeout_q."""
        self._mark_timeout_row(idx)
        def _chosen(decision: str):
            # send to worker
            self.timeout_q.put(decision)
            self._log(f"[TIMEOUT] Row {idx+1}: user chose {decision.upper()}")
        TimeoutDialog(self, idx, stage, seconds, _chosen)
    def _open_logs(self):
        if not self.user:
            messagebox.showerror("Restricted", "Must be logged in to open the logs")
            return
        can_clear = bool(self.user and self.user.role == "admin") or False
        LogViewer(self, can_clear=can_clear)

    def _audit(self, state: str, detail: str = "", row: int = -1, error: str | None = None):
        try:
            username = getattr(self.user, "username", "") if self.user else ""
            logs.append_event(username, state, row, detail, error)
        except Exception:
            pass

    def _timeout_decision(self, idx: int, stage: str, seconds: float) -> str:
        """
        Ask the UI what to do and block the worker until a choice is made.
        Returns one of: "continue" | "repeat" | "exit".
        """
        # Tell the UI thread to open the dialog
        self.q.put(("ask_timeout", {"idx": idx, "stage": stage, "seconds": seconds}))
        # Wait for the decision from UI
        try:
            decision = self.timeout_q.get()  # blocks
        except Exception:
            decision = "continue"
        return decision
    def _preview_extended_frame(self, message_type: str, field: str, data: str) -> str:
        """
        Build a human-readable preview of the exact extended protocol frame:
        <SOH> message_type <STX> field+data <ETX> BCC(3-dec) <CR>
        BCC is sum of ASCII codes of (message_type + field + data) & 0xFF, then 3-digit decimal.
        """
        field = field or ""
        data  = data or ""
        payload = f"{message_type}{field}{data}"
        bcc = sum(ord(ch) for ch in payload) & 0xFF
        bcc_str = f"{bcc:03d}"
        # Pretty text form with tokens
        return f"<SOH>{message_type}<STX>{field}{data}<ETX>{bcc_str}<CR>"


if __name__ == "__main__":
    app = App()
    app.mainloop()
