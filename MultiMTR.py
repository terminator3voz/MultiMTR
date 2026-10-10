#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MultiMTR - Giống WinMTR nhưng theo dõi NHIỀU host cùng lúc.

- Không cần cài thêm thư viện (chỉ dùng thư viện chuẩn: tkinter, ctypes, socket).
- Windows: dùng iphlpapi.IcmpSendEcho (không cần quyền Administrator).
- Linux/macOS: dùng raw ICMP socket (cần chạy bằng root/sudo).

Chạy:  python multimtr.py
"""

import ipaddress
import itertools
import json
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import tkinter as tk
import urllib.request
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from tkinter import filedialog, messagebox, ttk
from xml.sax.saxutils import escape as _xesc

IS_WIN = sys.platform.startswith("win")
# Khi đóng gói PyInstaller (--onefile), __file__ trỏ vào thư mục tạm bị xóa khi thoát,
# nên phải dùng thư mục chứa file exe (sys.executable).
APP_DIR = (os.path.dirname(os.path.abspath(sys.executable)) if getattr(sys, "frozen", False)
           else os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(APP_DIR, "multimtr.json")
DEFAULT_HOSTS = ["192.168.1.1", "203.113.131.1", "youtube.com", "facebook.com", "voz.vn"]

# Kết quả một lần probe: (kind, ip, rtt_ms)
#   kind: "dest" (tới đích), "hop" (TTL hết hạn tại router), "unreach", "timeout"
TIMEOUT_RESULT = ("timeout", None, None)


# --------------------------------------------------------------------------
# ICMP engine
# --------------------------------------------------------------------------
if IS_WIN:
    import ctypes

    class _IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Ttl", ctypes.c_ubyte),
            ("Tos", ctypes.c_ubyte),
            ("Flags", ctypes.c_ubyte),
            ("OptionsSize", ctypes.c_ubyte),
            ("OptionsData", ctypes.c_void_p),
        ]

    class _ICMP_ECHO_REPLY(ctypes.Structure):
        _fields_ = [
            ("Address", ctypes.c_uint32),
            ("Status", ctypes.c_uint32),
            ("RoundTripTime", ctypes.c_uint32),
            ("DataSize", ctypes.c_ushort),
            ("Reserved", ctypes.c_ushort),
            ("Data", ctypes.c_void_p),
            ("Options", _IP_OPTION_INFORMATION),
        ]

    _iphlp = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _iphlp.IcmpCreateFile.restype = ctypes.c_void_p
    _iphlp.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    _iphlp.IcmpSendEcho.restype = ctypes.c_uint32
    _iphlp.IcmpSendEcho.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_ushort,
        ctypes.POINTER(_IP_OPTION_INFORMATION), ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32,
    ]

    def probe(ip, ttl, timeout_ms, size):
        handle = _iphlp.IcmpCreateFile()
        if not handle or handle == ctypes.c_void_p(-1).value:
            return TIMEOUT_RESULT
        try:
            payload = b"x" * size
            opt = _IP_OPTION_INFORMATION(Ttl=ttl)
            buf = ctypes.create_string_buffer(ctypes.sizeof(_ICMP_ECHO_REPLY) + size + 128)
            dest = struct.unpack("<I", socket.inet_aton(ip))[0]
            t0 = time.perf_counter()
            n = _iphlp.IcmpSendEcho(handle, dest, payload, size, ctypes.byref(opt),
                                    buf, ctypes.sizeof(buf), int(timeout_ms))
            rtt = (time.perf_counter() - t0) * 1000.0
            if n == 0:
                return TIMEOUT_RESULT
            rep = _ICMP_ECHO_REPLY.from_buffer_copy(buf)
            addr = socket.inet_ntoa(struct.pack("<I", rep.Address))
            if rep.Status == 0:
                return ("dest", addr, rtt)
            if rep.Status in (11013, 11014):      # TTL expired in transit / reassembly
                return ("hop", addr, rtt)
            return ("unreach", addr, rtt)
        finally:
            _iphlp.IcmpCloseHandle(handle)

else:
    _seq_counter = itertools.count(1)
    _seq_lock = threading.Lock()

    def _checksum(data):
        if len(data) % 2:
            data += b"\0"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def probe(ip, ttl, timeout_ms, size):
        ident = os.getpid() & 0xFFFF
        with _seq_lock:
            seq = next(_seq_counter) & 0xFFFF
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            payload = b"x" * size
            hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
            pkt = struct.pack("!BBHHH", 8, 0, _checksum(hdr + payload), ident, seq) + payload
            t0 = time.perf_counter()
            s.sendto(pkt, (ip, 0))
            deadline = t0 + timeout_ms / 1000.0
            while True:
                remain = deadline - time.perf_counter()
                if remain <= 0:
                    return TIMEOUT_RESULT
                s.settimeout(remain)
                try:
                    data, addr = s.recvfrom(2048)
                except socket.timeout:
                    return TIMEOUT_RESULT
                rtt = (time.perf_counter() - t0) * 1000.0
                icmp = data[(data[0] & 0x0F) * 4:]
                if len(icmp) < 8:
                    continue
                typ = icmp[0]
                if typ == 0:
                    i, q = struct.unpack("!HH", icmp[4:8])
                    if i == ident and q == seq:
                        return ("dest", addr[0], rtt)
                elif typ in (3, 11):
                    inner = icmp[8:]
                    if not inner:
                        continue
                    ic = inner[(inner[0] & 0x0F) * 4:][:8]
                    if len(ic) >= 8 and ic[0] == 8:
                        i, q = struct.unpack("!HH", ic[4:8])
                        if i == ident and q == seq:
                            return ("hop" if typ == 11 else "unreach", addr[0], rtt)
        finally:
            s.close()


# --------------------------------------------------------------------------
# Reverse DNS (nền, có cache)
# --------------------------------------------------------------------------
class Resolver:
    def __init__(self):
        self.cache = {}
        self._pending = set()
        self._q = queue.Queue()
        for _ in range(4):
            threading.Thread(target=self._worker, daemon=True).start()

    def get(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        if ip not in self._pending:
            self._pending.add(ip)
            self._q.put(ip)
        return ip

    def _worker(self):
        while True:
            ip = self._q.get()
            try:
                name = socket.gethostbyaddr(ip)[0]
            except OSError:
                name = ip
            self.cache[ip] = name


# --------------------------------------------------------------------------
# Tra cứu vị trí địa lý của IP (nền, có cache) - dùng ip-api.com (miễn phí, không cần key)
# --------------------------------------------------------------------------
class GeoLocator:
    RETRY_AFTER = 30.0      # giây, thử lại nếu tra cứu lỗi (mất mạng, bị giới hạn 45 req/phút...)

    def __init__(self):
        self.cache = {}
        self._pending = set()
        self._retry_at = {}
        self._q = queue.Queue()
        threading.Thread(target=self._worker, daemon=True).start()

    @staticmethod
    def _is_local(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return a.is_private or a.is_loopback or a.is_link_local

    def get(self, ip):
        if not ip:
            return ""
        if ip in self.cache:
            return self.cache[ip]
        if self._is_local(ip):
            self.cache[ip] = "Mạng nội bộ (LAN)"
            return self.cache[ip]
        if ip not in self._pending and time.monotonic() >= self._retry_at.get(ip, 0):
            self._pending.add(ip)
            self._q.put(ip)
        return "..."

    def _lookup(self, ip):
        url = "http://ip-api.com/json/%s?fields=status,country,regionName,city" % ip
        with urllib.request.urlopen(url, timeout=6) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        if d.get("status") != "success":
            return None
        parts = [d.get("city"), d.get("country")]
        return ", ".join(p for p in parts if p) or d.get("regionName") or "?"

    def _worker(self):
        while True:
            ip = self._q.get()
            try:
                loc = self._lookup(ip)
            except Exception:  # noqa: BLE001
                loc = None
            if loc is None:
                self._retry_at[ip] = time.monotonic() + self.RETRY_AFTER
            else:
                self.cache[ip] = loc
            self._pending.discard(ip)
            time.sleep(1.4)         # giữ dưới giới hạn 45 request/phút của ip-api


# --------------------------------------------------------------------------
# Thống kê và monitor cho từng host
# --------------------------------------------------------------------------
class HopStats:
    __slots__ = ("ip", "sent", "recv", "best", "worst", "total", "last")

    def __init__(self):
        self.ip = None
        self.sent = 0
        self.recv = 0
        self.best = None
        self.worst = None
        self.total = 0.0
        self.last = None

    def add(self, rtt, ip):
        self.sent += 1
        if rtt is None:
            return
        self.recv += 1
        self.ip = ip or self.ip
        self.last = rtt
        self.total += rtt
        self.best = rtt if self.best is None else min(self.best, rtt)
        self.worst = rtt if self.worst is None else max(self.worst, rtt)

    def as_dict(self):
        return {
            "ip": self.ip, "sent": self.sent, "recv": self.recv,
            "loss": (100.0 * (self.sent - self.recv) / self.sent) if self.sent else 0.0,
            "best": self.best, "worst": self.worst, "last": self.last,
            "avg": (self.total / self.recv) if self.recv else None,
        }


class HostMonitor:
    def __init__(self, target, cfg):
        self.target = target
        self.cfg = cfg                      # dict dùng chung: interval, timeout, size, maxhops
        self.lock = threading.Lock()
        self.state = "Chờ"
        self.ip = None
        self.hops = []
        self.nhops = 0
        self.history = deque(maxlen=300)    # RTT hop cuối (None = mất gói)
        self.log = deque(maxlen=100000)     # (epoch, rtt) từng lần ping tới đích, để xuất CSV
        self._evt = None
        self.running = False

    # ---- điều khiển ----
    def start(self):
        self.stop()
        self._reset_data()
        evt = threading.Event()
        self._evt = evt
        self.running = True
        threading.Thread(target=self._run, args=(evt,), daemon=True).start()

    def stop(self):
        if self._evt:
            self._evt.set()
        if self.running:
            self._set("Đã dừng")
        self.running = False

    def _reset_data(self):
        with self.lock:
            self.hops = []
            self.nhops = 0
            self.history.clear()
            self.log.clear()
            self.ip = None

    def _set(self, s):
        with self.lock:
            self.state = s

    # ---- luồng chính ----
    def _run(self, evt):
        pool = None
        try:
            self._set("Phân giải DNS")
            try:
                ip = socket.gethostbyname(self.target)
            except OSError:
                self._set("Lỗi DNS")
                self.running = False
                return
            with self.lock:
                self.ip = ip
            self._set("Dò đường (trace)")
            self._discover(evt, ip)
            if evt.is_set():
                return
            self._set("Đang chạy")
            with self.lock:
                n = max(self.nhops, 1)
            pool = ThreadPoolExecutor(max_workers=min(32, n))
            while not evt.is_set():
                t0 = time.monotonic()
                futs = [pool.submit(self._probe_hop, evt, ip, ttl) for ttl in range(1, n + 1)]
                for f in futs:
                    f.result()
                evt.wait(max(0.0, self.cfg["interval"] / 1000.0 - (time.monotonic() - t0)))
        except PermissionError:
            self._set("Cần quyền root (sudo)")
            self.running = False
        except Exception as ex:  # noqa: BLE001
            self._set("Lỗi: %s" % ex)
            self.running = False
        finally:
            if pool:
                pool.shutdown(wait=False)

    def _discover(self, evt, ip):
        last_resp = 0
        reached = False
        ttl = 0
        while ttl < self.cfg["maxhops"] and not evt.is_set():
            ttl += 1
            res = TIMEOUT_RESULT
            for _ in range(2):
                res = probe(ip, ttl, self.cfg["timeout"], self.cfg["size"])
                if res[0] != "timeout" or evt.is_set():
                    break
            self._record(evt, ttl, res)
            if res[0] != "timeout":
                last_resp = ttl
            if res[0] in ("dest", "unreach"):
                reached = True
                break
            if ttl - last_resp >= 5:
                break
        with self.lock:
            self.nhops = ttl if reached else max(last_resp, 1)
            del self.hops[self.nhops:]

    def _probe_hop(self, evt, ip, ttl):
        if evt.is_set():
            return
        res = probe(ip, ttl, self.cfg["timeout"], self.cfg["size"])
        self._record(evt, ttl, res)

    def _record(self, evt, ttl, res):
        kind, addr, rtt = res
        if evt.is_set():
            return
        with self.lock:
            while len(self.hops) < ttl:
                self.hops.append(HopStats())
            self.hops[ttl - 1].add(rtt if kind != "timeout" else None, addr)
            if ttl == self.nhops:
                val = rtt if kind != "timeout" else None
                self.history.append(val)
                self.log.append((time.time(), val))

    # ---- đọc dữ liệu cho GUI ----
    def log_snapshot(self):
        with self.lock:
            return self.ip, list(self.log)

    def snapshot(self):
        with self.lock:
            return {
                "state": self.state, "ip": self.ip,
                "hops": [h.as_dict() for h in self.hops],
                "history": list(self.history),
            }


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
def _col_letter(n):
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def write_xlsx(path, sheets):
    """Ghi file .xlsx tối giản. sheets = [(tên_sheet, [hàng...])]; hàng đầu là tiêu đề (in đậm)."""
    names, used = [], set()
    for name, *_rest in sheets:
        base = re.sub(r"[\[\]:*?/\\]", "_", name).strip("'")[:31] or "Sheet"
        nm, i = base, 2
        while nm.lower() in used:
            suf = "_%d" % i
            nm, i = base[:31 - len(suf)] + suf, i + 1
        used.add(nm.lower())
        names.append(nm)

    def sheet_xml(rows, widths):
        out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
               '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
               'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
               '<cols>' + "".join('<col min="%d" max="%d" width="%s" customWidth="1"/>' % (i, i, w)
                                  for i, w in enumerate(widths, 1)) + '</cols><sheetData>']
        for r, row in enumerate(rows, 1):
            out.append('<row r="%d">' % r)
            for c, v in enumerate(row):
                if v is None or v == "":
                    continue
                ref = "%s%d" % (_col_letter(c), r)
                if isinstance(v, (int, float)):
                    out.append('<c r="%s"><v>%s</v></c>' % (ref, v))
                else:
                    st = ' s="1"' if r == 1 else ""
                    out.append('<c r="%s"%s t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>'
                               % (ref, st, _xesc(str(v))))
            out.append("</row>")
        out.append("</sheetData></worksheet>")
        return "".join(out)

    n = len(sheets)
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
          + "".join('<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % i
                    for i in range(1, n + 1))
          + "</Types>")
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>")
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
          + "".join('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (_xesc(nm, {'"': "&quot;"}), i, i)
                    for i, nm in enumerate(names, 1))
          + "</sheets></workbook>")
    wb_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               + "".join('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i, i)
                         for i in range(1, n + 1))
               + '<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' % (n + 1)
               + "</Relationships>")
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
              '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
              '<fills count="2"><fill><patternFill patternType="none"/></fill>'
              '<fill><patternFill patternType="gray125"/></fill></fills>'
              '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
              '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
              '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
              '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
              '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
              "</styleSheet>")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/styles.xml", styles)
        for i, sh in enumerate(sheets, 1):
            widths = sh[2] if len(sh) > 2 else [24, 16, 16, 16, 16]
            z.writestr("xl/worksheets/sheet%d.xml" % i, sheet_xml(sh[1], widths))


def fmt(v, digits=0):
    return "-" if v is None else ("%.*f" % (digits, v))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MultiMTR by Terminator3 @ voz.vn")
        self.geometry("1220x820")
        self.minsize(900, 560)
        self.cfg = {"interval": 1000, "timeout": 1000, "size": 32, "maxhops": 30}
        self.monitors = {}
        self.resolver = Resolver()
        self.geo = GeoLocator()
        self.var_dns = tk.BooleanVar(value=True)
        self.vars = {k: tk.IntVar(value=v) for k, v in self.cfg.items()}
        for k, var in self.vars.items():
            var.trace_add("write", lambda *_a, key=k: self._sync_cfg(key))
        self._build_ui()
        self._load()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(500, self._refresh)

    # ---- dựng giao diện ----
    def _build_ui(self):
        try:
            ttk.Style().theme_use("vista" if IS_WIN else "clam")
        except tk.TclError:
            pass

        top = ttk.Frame(self, padding=(8, 8, 8, 2))
        top.pack(fill="x")
        ttk.Label(top, text="Host / IP:").pack(side="left")
        self.entry = ttk.Entry(top, width=42)
        self.entry.pack(side="left", padx=4)
        self.entry.bind("<Return>", lambda _e: self.add_hosts())
        self.entry.focus_set()
        ttk.Button(top, text="Thêm", command=self.add_hosts).pack(side="left")
        ttk.Label(top, text="(nhiều host: cách nhau bằng dấu cách / phẩy)",
                  foreground="#666").pack(side="left", padx=8)

        bar = ttk.Frame(self, padding=(8, 2))
        bar.pack(fill="x")
        for text, cmd in [("▶ Chạy tất cả", self.start_all), ("■ Dừng tất cả", self.stop_all),
                          ("▶ Chạy host chọn", self.start_sel), ("■ Dừng host chọn", self.stop_sel),
                          ("↺ Reset / Trace lại", self.reset_sel), ("✕ Xóa host", self.remove_sel)]:
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=2)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Button(bar, text="Copy text", command=self.copy_text).pack(side="left", padx=2)
        ttk.Button(bar, text="Xuất log", command=self.export_log).pack(side="left", padx=2)

        opt = ttk.Frame(self, padding=(8, 2, 8, 6))
        opt.pack(fill="x")
        for label, key, lo, hi, inc in [("Chu kỳ (ms)", "interval", 200, 60000, 100),
                                        ("Timeout (ms)", "timeout", 100, 10000, 100),
                                        ("Kích thước gói (B)", "size", 0, 1400, 8),
                                        ("Max hops", "maxhops", 1, 64, 1)]:
            ttk.Label(opt, text=label + ":").pack(side="left", padx=(0, 2))
            ttk.Spinbox(opt, from_=lo, to=hi, increment=inc, width=6,
                        textvariable=self.vars[key]).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(opt, text="Phân giải tên (DNS)", variable=self.var_dns).pack(side="left")

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        # danh sách host
        hf = ttk.LabelFrame(paned, text="Các host đang theo dõi (chọn 1 dòng để xem chi tiết từng hop)")
        cols = ("host", "location", "ip", "state", "hops", "loss", "avg", "worst", "last")
        self.host_tree = ttk.Treeview(hf, columns=cols, show="headings", height=6, selectmode="extended")
        heads = [("host", "Host", 130), ("location", "Location", 200), ("ip", "IP", 130), ("state", "Trạng thái", 150),
                 ("hops", "Số hop", 60), ("loss", "Loss % (đích)", 100), ("avg", "Avg", 70),
                 ("worst", "Worst", 70), ("last", "Last", 70)]
        for c, t, w in heads:
            self.host_tree.heading(c, text=t)
            self.host_tree.column(c, width=w, anchor="w" if c in ("host", "location", "ip", "state") else "e")
        self.host_tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(hf, command=self.host_tree.yview)
        sb.pack(side="right", fill="y")
        self.host_tree.configure(yscrollcommand=sb.set)
        self.host_tree.bind("<<TreeviewSelect>>", lambda _e: self._refresh_detail())
        # bấm vào chỗ trống -> bỏ chọn (bỏ highlight)
        self.host_tree.bind("<Button-1>", self._on_host_click, add="+")
        self.bind_all("<ButtonPress-1>", self._on_global_click, add="+")
        self.host_tree.tag_configure("bad", background="#ffd6d6")
        self.host_tree.tag_configure("warn", background="#fff1cc")
        paned.add(hf, weight=1)

        # chi tiết hop
        df = ttk.LabelFrame(paned, text="Chi tiết hop")
        hcols = ("nr", "host", "loss", "sent", "recv", "best", "avg", "worst", "last")
        self.hop_tree = ttk.Treeview(df, columns=hcols, show="headings", height=12)
        for c, t, w in [("nr", "Nr", 40), ("host", "Hostname", 380), ("loss", "Loss %", 70),
                        ("sent", "Sent", 65), ("recv", "Recv", 65), ("best", "Best", 65),
                        ("avg", "Avrg", 65), ("worst", "Wrst", 65), ("last", "Last", 65)]:
            self.hop_tree.heading(c, text=t)
            self.hop_tree.column(c, width=w, anchor="w" if c == "host" else "e")
        self.hop_tree.pack(fill="both", expand=True, side="left")
        sb2 = ttk.Scrollbar(df, command=self.hop_tree.yview)
        sb2.pack(side="right", fill="y")
        self.hop_tree.configure(yscrollcommand=sb2.set)
        self.hop_tree.tag_configure("bad", background="#ffd6d6")
        self.hop_tree.tag_configure("warn", background="#fff1cc")
        self.hop_tree.tag_configure("silent", foreground="#888")
        paned.add(df, weight=3)

        # đồ thị
        gf = ttk.LabelFrame(self, text="Độ trễ hop cuối (đích) - 300 mẫu gần nhất")
        gf.pack(fill="x", padx=8, pady=(0, 8))
        self.graph = tk.Canvas(gf, height=110, bg="white", highlightthickness=0)
        self.graph.pack(fill="x", padx=4, pady=4)

        self.status = ttk.Label(self, anchor="w", relief="sunken",
                                text="Windows: không cần admin. Linux/macOS: chạy bằng sudo.")
        self.status.pack(fill="x", side="bottom")

    # ---- cấu hình ----
    def _sync_cfg(self, key):
        try:
            v = int(self.vars[key].get())
            if v >= 0:
                self.cfg[key] = max(1, v) if key != "size" else v
        except (tk.TclError, ValueError):
            pass

    def _load(self):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.get("cfg", {}).items():
                if k in self.vars:
                    self.vars[k].set(int(v))
            self.var_dns.set(bool(data.get("dns", True)))
            for h in data.get("hosts", []):
                self._add_host(h, autostart=False)
        except (OSError, ValueError):
            for h in DEFAULT_HOSTS:
                self._add_host(h, autostart=False)

    def _on_close(self):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump({"cfg": self.cfg, "dns": self.var_dns.get(),
                           "hosts": list(self.monitors)}, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
        for m in self.monitors.values():
            m.stop()
        self.destroy()

    # ---- thao tác host ----
    def _add_host(self, name, autostart=True):
        if not name or name in self.monitors:
            return
        m = HostMonitor(name, self.cfg)
        self.monitors[name] = m
        self.host_tree.insert("", "end", iid=name, values=(name, "", "", "Chờ", "", "", "", "", ""))
        if autostart:
            m.start()

    def add_hosts(self):
        for h in re.split(r"[,\s;]+", self.entry.get().strip()):
            self._add_host(h)
        self.entry.delete(0, "end")
        if self.host_tree.get_children() and not self.host_tree.selection():
            self.host_tree.selection_set(self.host_tree.get_children()[0])

    def _on_host_click(self, event):
        # bấm vào vùng trống của bảng (dưới các dòng) -> bỏ chọn
        if self.host_tree.identify_region(event.x, event.y) == "nothing" \
                and not self.host_tree.identify_row(event.y):
            self.host_tree.selection_set(())
            return "break"

    def _on_global_click(self, event):
        # bấm vào vùng trống của cửa sổ (frame, label, đồ thị...) -> bỏ chọn host
        w = event.widget
        if not isinstance(w, tk.Misc):
            return
        if w.winfo_class() in ("Tk", "Toplevel", "TFrame", "Frame", "TLabelframe",
                               "TLabel", "Label", "Canvas"):
            if self.host_tree.selection():
                self.host_tree.selection_set(())

    def _selected(self):
        return [self.monitors[i] for i in self.host_tree.selection() if i in self.monitors]

    def start_all(self):
        for m in self.monitors.values():
            m.start()

    def stop_all(self):
        for m in self.monitors.values():
            m.stop()

    def start_sel(self):
        for m in self._selected():
            m.start()

    def stop_sel(self):
        for m in self._selected():
            m.stop()

    def reset_sel(self):
        for m in (self._selected() or self.monitors.values()):
            m.start()

    def remove_sel(self):
        for iid in self.host_tree.selection():
            m = self.monitors.pop(iid, None)
            if m:
                m.stop()
            self.host_tree.delete(iid)
        self._refresh_detail()

    # ---- cập nhật giao diện ----
    def _refresh(self):
        try:
            for name, m in self.monitors.items():
                s = m.snapshot()
                hops = s["hops"]
                if self.var_dns.get():
                    for h in hops:
                        if h["ip"]:
                            self.resolver.get(h["ip"])
                dest = hops[-1] if hops else None
                loss = dest["loss"] if dest else None
                tag = ()
                if loss is not None:
                    tag = ("bad",) if loss >= 5 else (("warn",) if loss > 0 else ())
                self.host_tree.item(name, tags=tag, values=(
                    name, self.geo.get(s["ip"]), s["ip"] or "", s["state"], len(hops) or "",
                    fmt(loss, 1), fmt(dest["avg"] if dest else None, 1),
                    fmt(dest["worst"] if dest else None, 1), fmt(dest["last"] if dest else None, 1)))
            self._refresh_detail()
        finally:
            self.after(500, self._refresh)

    def _current(self):
        sel = self.host_tree.selection()
        return self.monitors.get(sel[0]) if sel else None

    def _refresh_detail(self):
        m = self._current()
        if not m:
            self.hop_tree.delete(*self.hop_tree.get_children())
            self.graph.delete("all")
            return
        s = m.snapshot()
        hops = s["hops"]
        existing = list(self.hop_tree.get_children())
        for i, h in enumerate(hops, start=1):
            if h["ip"]:
                name = self.resolver.get(h["ip"]) if self.var_dns.get() else h["ip"]
                shown = name if name == h["ip"] else "%s (%s)" % (name, h["ip"])
            else:
                shown = "No response from host"
            tag = ("silent",) if not h["ip"] else (
                ("bad",) if h["loss"] >= 5 else (("warn",) if h["loss"] > 0 else ()))
            vals = (i, shown, fmt(h["loss"], 1), h["sent"], h["recv"], fmt(h["best"], 1),
                    fmt(h["avg"], 1), fmt(h["worst"], 1), fmt(h["last"], 1))
            iid = "h%d" % i
            if iid in existing:
                self.hop_tree.item(iid, values=vals, tags=tag)
            else:
                self.hop_tree.insert("", "end", iid=iid, values=vals, tags=tag)
        for iid in existing:
            if int(iid[1:]) > len(hops):
                self.hop_tree.delete(iid)
        self._draw_graph(s["history"])

    def _draw_graph(self, hist):
        c = self.graph
        c.delete("all")
        w, h = max(c.winfo_width(), 100), max(c.winfo_height(), 60)
        vals = [v for v in hist if v is not None]
        if len(hist) < 2:
            return
        top = max(max(vals) * 1.2, 10.0) if vals else 10.0
        pad_l, pad_b = 46, 4
        gh = h - pad_b - 8
        step = (w - pad_l - 6) / (len(hist) - 1)
        c.create_text(4, 8, text="%.0f ms" % top, anchor="w", fill="#666", font=("TkDefaultFont", 8))
        c.create_text(4, h - 8, text="0", anchor="w", fill="#666", font=("TkDefaultFont", 8))
        c.create_line(pad_l, h - pad_b, w, h - pad_b, fill="#ccc")
        prev = None
        for i, v in enumerate(hist):
            x = pad_l + i * step
            if v is None:
                c.create_line(x, 6, x, h - pad_b, fill="#e33")
                prev = None
                continue
            y = h - pad_b - (v / top) * gh
            if prev:
                c.create_line(prev[0], prev[1], x, y, fill="#1a73e8", width=1.5)
            prev = (x, y)

    # ---- xuất dữ liệu ----
    def _text_report(self, only=None):
        lines = []
        for name, m in self.monitors.items():
            if only and m is not only:
                continue
            s = m.snapshot()
            lines.append("Host: %s (%s)  [%s]" % (name, s["ip"] or "?", s["state"]))
            lines.append("%-3s %-44s %7s %6s %6s %7s %7s %7s %7s" %
                         ("Nr", "Hostname", "Loss%", "Sent", "Recv", "Best", "Avrg", "Wrst", "Last"))
            for i, h in enumerate(s["hops"], 1):
                lines.append("%-3d %-44s %7s %6d %6d %7s %7s %7s %7s" % (
                    i, (h["ip"] and (self.resolver.cache.get(h["ip"], h["ip"]))) or "No response from host",
                    fmt(h["loss"], 1), h["sent"], h["recv"], fmt(h["best"], 1),
                    fmt(h["avg"], 1), fmt(h["worst"], 1), fmt(h["last"], 1)))
            lines.append("")
        return "\n".join(lines)

    def copy_text(self):
        txt = self._text_report(self._current())
        self.clipboard_clear()
        self.clipboard_append(txt)
        self.status.config(text="Đã copy báo cáo vào clipboard.")

    def export_log(self):
        """Xuất Excel: sheet 1 = Summary (thống kê từng hop), các sheet sau = log ping từng host.
        Xuất host đang chọn, hoặc tất cả nếu không chọn gì."""
        mons = self._selected() or list(self.monitors.values())
        if not mons:
            messagebox.showinfo("Xuất log", "Chưa có host nào.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")],
            initialfile="multimtr_%s.xlsx" % time.strftime("%Y%m%d_%H%M%S"))
        if not path:
            return
        try:
            ips = {h["ip"] for m in mons for h in m.snapshot()["hops"] if h["ip"]}
            missing = [ip for ip in ips if ip not in self.resolver.cache]
            for ip in missing:
                self.resolver.get(ip)
            deadline = time.monotonic() + 8
            while missing and time.monotonic() < deadline \
                    and any(ip not in self.resolver.cache for ip in missing):
                self.status.config(text="Đang phân giải tên hop...")
                self.update_idletasks()
                time.sleep(0.05)

            def num(v, d):
                return None if v is None else round(v, d)

            summary = [["target", "target_ip", "hop", "hop_ip", "hop_name", "loss_pct", "sent",
                        "recv", "best_ms", "avg_ms", "worst_ms", "last_ms"]]
            logs, total = [], 0
            for m in mons:
                s = m.snapshot()
                for i, h in enumerate(s["hops"], 1):
                    summary.append([m.target, s["ip"] or "", i, h["ip"] or "",
                                    self.resolver.cache.get(h["ip"], h["ip"]) if h["ip"] else "",
                                    num(h["loss"], 1), h["sent"], h["recv"], num(h["best"], 1),
                                    num(h["avg"], 1), num(h["worst"], 1), num(h["last"], 1)])
                ip, log = m.log_snapshot()
                rows = [["time", "target_ip", "status", "rtt_ms"]]
                for ts, rtt in log:
                    stamp = "%s.%03d" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                                         int((ts % 1) * 1000))
                    rows.append([stamp, ip or "", "timeout" if rtt is None else "ok",
                                 None if rtt is None else round(rtt,1)])
                total += len(rows) - 1
                logs.append((m.target, rows))
            sheets = [("Summary", summary, [22, 16, 6, 16, 40, 10, 8, 8, 10, 10, 10, 10])] + logs
            write_xlsx(path, sheets)
            self.status.config(text="Đã xuất %d host (%d dòng log ping): %s" % (len(logs), total, path))
        except OSError as ex:
            messagebox.showerror("Lỗi", str(ex))

def main():
    if IS_WIN:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            pass
    App().mainloop()


if __name__ == "__main__":
    main()
