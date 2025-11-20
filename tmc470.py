# tmc470.py
# RS-232 driver for TMC-470/520 extended protocol
# Mirrors the dynamic command framing/mapping of the Java PrinterConnectionManager.

from __future__ import annotations
import time
import threading
from dataclasses import dataclass
from typing import Optional, Tuple, List

import serial
import serial.tools.list_ports
import socket

# ------------------ Control chars ------------------
SOH = b'\x01'
STX = b'\x02'
ETX = b'\x03'
ACK = b'\x06'
NAK = b'\x15'
CR  = b'\x0D'

# ------------------ Defaults ------------------
SERIAL_DEFAULTS = {
    "baudrate": 9600,
    "bytesize": serial.EIGHTBITS,
    "parity":   serial.PARITY_NONE,
    "stopbits": serial.STOPBITS_ONE,
    "timeout":  0.05,   # non-blocking small read
    "write_timeout": 1,
}

# ------------------ Protocol command map ------------------
# These are the TMC "extended" message types (your Java used Config getters).
# Keys are high-level ops -> (messageType, verifyPrefixIfAny)
# ------------------ Protocol command map (from config.properties) ------------------
# printer.put.markeronline = O
# printer.start.print      = G
# printer.send.pattern     = P
# printer.verify.pattern   = ~
# printer.verify.common    = ?
# printer.send.variabletext= V
# printer.send.querytext   = Q
# printer.send.directdata  = 1
# printer.poll.io          = I
# printer.poll.status      = S

COMMANDS = {
    # Marker online
    "PUT_ONLINE":           ("O", None),

    # Pattern (load / verify)
    "LOAD_PATTERN":         ("P", None),
    "VERIFY_PATTERN":       ("P", "~"),     # pattern-specific verify marker

    # Variable text (set / verify)
    "SET_VARIABLE":         ("V", None),
    "VERIFY_VARIABLE":      ("V", "?"),     # common verify marker

    # Query text (provide / poll)
    "QUERY_PROVIDE":        ("Q", None),
    "QUERY_POLL":           ("Q", "?"),

    # Direct data
    "DIRECT_DATA":          ("1", None),

    # Polls
    "POLL_IO":              ("I", None),
    "POLL_STATUS":          ("S", None),

    # Start print
    "START_PRINT":          ("G", None),
}

# ------------------ IO “ready/done” codes from config.properties ------------------
# printer.done      = 42
# printer.readydone = 43
PRINTER_READY_AND_DONE = "43"   # ready+done
PRINTER_DONE_ONLY      = "42"   # done-only


# Poll IO expected snippets (mirror Java: READY+DONE "43;" in sim, "03;" in manual, DONE-only etc.)
# Make these configurable if needed; here we keep the strings used in your Java config.
PRINTER_READY_AND_DONE = "43;"  # simulation
PRINTER_DONE_ONLY      = "40;"  # example; adjust if your real controller reports different

# Status translation (exact bit strings copied from Java translateStatusResponse)
MACHINE_STATUS_MAP = {
    "00000000": "MACHINE_STATUS_OFFLINE",
    "00000001": "MACHINE_STATUS_ABORTED",
    "00000002": "MACHINE_STATUS_BUSY",
    "00000004": "MACHINE_STATUS_LOCKED",
    "00000010": "MACHINE_STATUS_ONLINE",
    "00000020": "MACHINE_STATUS_HOMING",
    "00000040": "MACHINE_STATUS_PRINTING",
    "00000080": "MACHINE_STATUS_DRYRUN",
    "00000100": "MACHINE_STATUS_PAUSED",
    "00000200": "MACHINE_STATUS_PARKING",
    "00000400": "MACHINE_STATUS_BATCH",
    "00000800": "MACHINE_STATUS_REPEAT",
    "00001000": "MACHINE_STATUS_PREVIEW",
    "00002000": "MACHINE_STATUS_PREPOSITION",
    "00004000": "MACHINE_STATUS_INPUT",
    "00008000": "MACHINE_STATUS_SERIAL_TOOL",
    "00010000": "MACHINE_STATUS_PULSING",
    "00020000": "MACHINE_STATUS_EXERCISE",
    "00040000": "MACHINE_STATUS_AUTO_SENSE",
}

# ------------------ helpers ------------------

def list_ports() -> list[str]:
    return [p.device for p in serial.tools.list_ports.comports()]

def format_field_id(value: int) -> str:
    """
    EXACTLY as requested:
    public static String formatFieldId(int value){
        String format = "%02d";
        return String.format(format, value);
    }
    """
    return f"{value:02d}"

def format_counter(value: int) -> str:
    # If you need zero pad elsewhere, adapt. Keep simple here.
    return str(value)

def calc_bcc(payload: str) -> int:
    """
    Java did: sum of chars, then & 0xFF.
    NOTE: In Java implementation, BCC is computed over messageType+fieldOrBuffer+data (without SOH/STX/ETX),
    and then formatted as 3 decimal digits.
    """
    total = 0
    for ch in payload:
        total = (total + ord(ch)) & 0xFF
    return total

def _encode_frame(message_type: str, field_or_buffer: str, data: str) -> bytes:
    """
    Build frame:
      <SOH> message_type <STX> field_or_buffer + data <ETX> BCC(3-dec) <CR>
    BCC computed over (message_type + field_or_buffer + data) ONLY.
    """
    field_or_buffer = field_or_buffer or ""
    data = data or ""
    payload = f"{message_type}{field_or_buffer}{data}"
    bcc = calc_bcc(payload)
    bcc_str = f"{bcc:03d}"
    return b"".join([
        SOH,
        message_type.encode("ascii"),
        STX,
        (field_or_buffer + data).encode("ascii"),
        ETX,
        bcc_str.encode("ascii"),
        CR
    ])

def _pretty_dump(buf: bytes) -> str:
    """
    Mirror Java handlePrinterResponse formatting for diagnostics (optional).
    """
    out = []
    for b in buf:
        if   b == 0x01: out.append("<SOH>")
        elif b == 0x02: out.append("<STX>")
        elif b == 0x03: out.append("<ETX>")
        elif b == 0x06: out.append("<ACK>")
        elif b == 0x0D: out.append("<CR>")
        elif b == 0x15: out.append("<NAK>")
        else:
            out.append(chr(b))
    return "".join(out)

def _extract_status_bits(resp: str) -> str:
    """
    Java split: message = response.substring(16,24);
    We replicate defensively: find an 8-char 0/1 sequence.
    """
    # Try exact window first if long enough
    if len(resp) >= 24:
        cand = resp[16:24]
        if len(cand) == 8 and all(c in "01" for c in cand):
            return cand
    # Fallback: scan for 8-bit window
    for i in range(len(resp) - 7):
        chunk = resp[i:i+8]
        if all(c in "01" for c in chunk):
            return chunk
    return ""

def _translate_status(resp: str) -> str:
    bits = _extract_status_bits(resp)
    return MACHINE_STATUS_MAP.get(bits, "")

# ------------------ Driver ------------------

@dataclass
class TMC470:
    ser: Optional[serial.Serial] = None
    sock: Optional[socket.socket] = None
    _lock: threading.Lock = threading.Lock()

    # ------------- lifecycle -------------
    @staticmethod
    def list_ports() -> List[str]:
        return list_ports()

    def connect(self, port: str, **serial_kwargs) -> None:
        if self.ser and self.ser.is_open:
            return
        kwargs = SERIAL_DEFAULTS.copy()
        kwargs.update(serial_kwargs or {})
        self.ser = serial.Serial(port=port, **kwargs)
        # small settle time
        time.sleep(0.15)

    def disconnect(self) -> None:
        if self.ser:
            try:
                self.ser.close()
            finally:
                self.ser = None
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None


    def is_connected(self) -> bool:
        """True if either serial or TCP socket is connected."""
        if self.ser and getattr(self.ser, "is_open", False):
            return True
        if self.sock is not None:
            try:
                self.sock.getpeername()
                return True
            except OSError:
                return False
        return False

    def connect_tcp(self, host: str, port: int, timeout: float = 1.0) -> None:
        """
        Connect to TMC470 via TCP (Ethernet).
        """
        # if already connected, do nothing
        if self.sock is not None:
            try:
                self.sock.getpeername()
                return
            except OSError:
                self.sock = None

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # for read loops we use short timeouts
        s.settimeout(0.05)
        self.sock = s

    # ------------- low-level I/O -------------
    def _clear_input(self) -> None:
        # Serial
        if self.ser and getattr(self.ser, "in_waiting", None) is not None:
            try:
                while self.ser.in_waiting:
                    self.ser.read(self.ser.in_waiting or 1)
            except Exception:
                pass
            return

        # TCP socket – best effort, non-blocking drain
        if self.sock:
            try:
                self.sock.settimeout(0.0)
                while True:
                    try:
                        chunk = self.sock.recv(4096)
                        if not chunk:
                            break
                    except BlockingIOError:
                        break
            except Exception:
                pass
            finally:
                try:
                    self.sock.settimeout(0.05)
                except Exception:
                    pass


    def _send(self, frame: bytes) -> None:
        if not self.is_connected():
            raise RuntimeError("Device not connected")
        with self._lock:
            self._clear_input()
            if self.ser and getattr(self.ser, "is_open", False):
                self.ser.reset_output_buffer()
                self.ser.write(frame)
                self.ser.flush()
            elif self.sock:
                self.sock.sendall(frame)


    def _read_until_cr(self, timeout_ms: int = 3000) -> Optional[str]:
        """
        Read ASCII until CR, or timeout.
        Works for both serial and TCP.
        """
        if not self.is_connected():
            return None

        end = time.time() + (timeout_ms / 1000.0)
        buf = bytearray()

        while time.time() < end:
            if self.ser and getattr(self.ser, "is_open", False):
                n = self.ser.in_waiting
                if n:
                    chunk = self.ser.read(n)
                    buf.extend(chunk)
                    if buf.endswith(CR):
                        break
                else:
                    time.sleep(0.01)
            elif self.sock:
                try:
                    chunk = self.sock.recv(4096)
                    if chunk:
                        buf.extend(chunk)
                        if buf.endswith(CR):
                            break
                    else:
                        # peer closed
                        break
                except socket.timeout:
                    # no data yet, keep waiting until timeout
                    pass
                except BlockingIOError:
                    pass
                time.sleep(0.01)
            else:
                break

        if not buf:
            return None

        try:
            return buf.decode("ascii", errors="ignore")
        except Exception:
            return "".join(chr(b) for b in buf if 32 <= b < 127)


    def _txrx(self, op_key: str, field: str = "", data: str = "", timeout_ms: int = 3000) -> Optional[str]:
        """
        Dynamic command send + read.
        """
        if op_key not in COMMANDS:
            raise ValueError(f"Unknown command key: {op_key}")
        msg_type, verify_prefix = COMMANDS[op_key]
        # If verify command, prefix field with '?'
        if verify_prefix:
            field = f"{verify_prefix}{field or ''}"
        frame = _encode_frame(msg_type, field, data)
        # (Optional) print(_pretty_dump(frame))
        self._send(frame)
        resp = self._read_until_cr(timeout_ms=timeout_ms)
        # (Optional) print(_pretty_dump(resp.encode('ascii', 'ignore')) if resp else "No resp")
        return resp

    # ------------- High-level ops (mirror Java) -------------

    # Online
    def put_online(self) -> Optional[str]:
        return self._txrx("PUT_ONLINE")

    # Pattern
    def load_pattern(self, pattern: str) -> Optional[str]:
        # In your Java you sent raw pattern name (controller appends ".TTP" on verify)
        return self._txrx("LOAD_PATTERN", "", pattern)

    def verify_pattern(self) -> Optional[str]:
        resp = self._txrx("VERIFY_PATTERN")
        return resp

    def load_pattern_and_verify(self, pattern: str, delay_ms: int = 100) -> bool:
        self.load_pattern(pattern)
        time.sleep(delay_ms / 1000.0)
        r = self.verify_pattern() or ""
        return (pattern + ".TTP") in r

    # Variables (T fields)
    def set_var(self, field_number_1based: int, value: str) -> Optional[str]:
        field = format_field_id(field_number_1based)  # EXACTLY "%02d"
        return self._txrx("SET_VARIABLE", field, value)

    def verify_var(self, field_number_1based: int) -> bool:
        field = format_field_id(field_number_1based)
        r = self._txrx("VERIFY_VARIABLE", field) or ""
        # Java: if any response, you assumed success
        return len(r) > 0

    # Direct data (D fields)
    def send_direct(self, field_number_1based: int, value: str) -> Optional[str]:
        field = format_field_id(field_number_1based)
        return self._txrx("DIRECT_DATA", field, value)

    # Query buffers (Q)
    def provide_query_text(self, buffer_number_1based: int, value: str) -> Optional[str]:
        buf_id = format_field_id(buffer_number_1based)
        return self._txrx("QUERY_PROVIDE", buf_id, value)

    def poll_query_text(self, buffer_number_1based: int) -> Optional[str]:
        buf_id = format_field_id(buffer_number_1based)
        return self._txrx("QUERY_POLL", buf_id)
    
    def provide_and_verify_query_text(self, buffer_number_1based: int, value: str) -> bool:
        self.provide_query_text(buffer_number_1based, value)
        r = self.poll_query_text(buffer_number_1based) or ""
        return value in r


    # Poll IO / Status
    def poll_io(self) -> Tuple[bool, str]:
        """
        Returns (ready_or_done, raw_response).
        Accepts '43' (ready+done) or '42' (done) with or without a trailing ';'.
        """
        r = self._txrx("POLL_IO") or ""
        rr = r.replace("\r", "")
        # Normalize to tokens split by non-digits, then join to search
        # but a simple 'in' check is usually enough:
        if "00;000" in rr:
            return (False, r)
        if PRINTER_READY_AND_DONE in rr or (PRINTER_READY_AND_DONE + ";") in rr:
            return (True, r)
        if PRINTER_DONE_ONLY in rr or (PRINTER_DONE_ONLY + ";") in rr:
            return (True, r)
        return (False, r)

    def poll_machine_status(self) -> Tuple[str, str]:
        """
        Returns (translated_status, raw_response).
        """
        r = self._txrx("POLL_STATUS") or ""
        trans = _translate_status(r)
        return (trans, r)

    # Start print
    def start_print(self) -> Optional[str]:
        return self._txrx("START_PRINT")

    # Waiters (READY / DONE-ish based on poll methods)
    def wait_ready(self, timeout_s: float = 10.0, interval_s: float = 0.2) -> bool:
        t0 = time.time()
        while (time.time() - t0) < timeout_s:
            ok, _ = self.poll_io()
            # READY heuristics: many controllers report READY via the same IO data (e.g., 43;)
            if ok:
                # but ensure we’re ONLINE too (optional)
                status, _ = self.poll_machine_status()
                if status in ("MACHINE_STATUS_ONLINE", "MACHINE_STATUS_PRINTING", "MACHINE_STATUS_PAUSED"):
                    return True
            time.sleep(interval_s)
        return False

    def wait_done_or_ready(self, timeout_s: float = 10.0, interval_s: float = 0.2) -> bool:
        t0 = time.time()
        while (time.time() - t0) < timeout_s:
            ok, _ = self.poll_io()
            if ok:
                return True
            time.sleep(interval_s)
        return False

    # ------------------ Composite job stream (mirror of Java sendJobStream) ------------------
    def send_job_stream(self,
                        product_name: str,
                        variable_field_id_1based: int,
                        counter: int,
                        pattern: str = "",
                        direct_data: str = "",
                        query_id_1based: int = 0,
                        query_content: str = "") -> None:
        """
        Mirrors your Java sendJobStream:
          - If query buffer present, provide & verify
          - If pattern present, load & verify
          - Then set variable counter into variable field id
          - If direct data present, send direct with counter appended
        """
        # Query buffer
        if query_id_1based > 0 and query_content:
            self.provide_and_verify_query_text(query_id_1based, query_content)

        # Pattern
        if pattern:
            if self.load_pattern_and_verify(pattern):
                # Variable counter
                cnt_str = format_counter(counter)
                self.set_var(variable_field_id_1based, cnt_str)

        # Direct data
        if direct_data:
            # Append counter to direct data as the Java did for direct line
            self.send_direct(variable_field_id_1based,
                             f"{direct_data}{format_counter(counter)}")
      # ---------- “sendCommandWithResponse” equivalent ----------
    def send_command_with_response(
        self,
        message_type: str,
        field_or_buffer: str = "",
        data: str = "",
        timeout_ms: int = 3000
    ) -> Optional[str]:
        """
        1:1 with the Java method:
          - assumes connected
          - build frame
          - send
          - read with timeout
          - if no response, try one more read
          - return the ASCII string (or None)
        """
        frame = _encode_frame(message_type, field_or_buffer, data)
        self._send(frame)

        resp = self._read_until_cr(timeout_ms)
        if resp is None:
            resp = self._read_until_cr(timeout_ms)

        # _read_until_cr already returns str (ASCII), so just return it
        return resp

        
        # --- compatibility aliases so existing call sites in your file keep working ---
    def encode_frame(message_type: str, field_or_buffer: str, data: str) -> bytes:
        # public alias that forwards to the real builder you already have
        return _encode_frame(message_type, field_or_buffer, data)
    
    def _send_raw(self, frame: bytes) -> None:
        self._send(frame)

    def verify_live_connection(self, tries: int = 2, sleep_ms: int = 120) -> tuple[bool, str, str]:
        """
        Prove a real TMC-470/520 is on the other end:
        - (optionally) nudge ONLINE
        - poll machine status which returns ASCII + CR
        Returns (ok, translated_status, raw_response)
        """
        last_raw = ""
        for _ in range(max(1, tries)):
            try:
                # This may return None (ACK-only path); that's fine — we just nudge.
                self.put_online()
            except Exception:
                pass

            status, raw = self.poll_machine_status() or ("", "")
            last_raw = raw or ""
            # Accept any CR-terminated ASCII as proof of life; status map is a bonus.
            if raw and raw.endswith("\r"):
                return True, status, raw
            time.sleep(sleep_ms / 1000.0)
        return False, "", last_raw
