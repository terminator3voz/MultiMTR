#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MultiMTR - Giống WinMTR nhưng theo dõi NHIỀU host cùng lúc.

- Không cần cài thêm thư viện (chỉ dùng thư viện chuẩn: tkinter, ctypes, socket).
- Windows: dùng iphlpapi.IcmpSendEcho (không cần quyền Administrator).
- Linux/macOS: dùng raw ICMP socket (cần chạy bằng root/sudo).

Chạy:  python multimtr.py
"""

import bisect
import ipaddress
import itertools
import json
import math
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
import zipfile
import zlib
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
WARN_LOSS = 0.333    # % mất gói từ mức này trở lên -> tô vàng
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
# Vị trí địa lý của IP (nền, có cache)
#  1) Host chạy sau Cloudflare: hỏi https://<host>/cdn-cgi/trace -> lấy "colo" (datacenter
#     thực sự đang phục vụ bạn, ví dụ HKG/SIN) -> chính xác.
#  2) Còn lại: tra ip-api.com. Nếu RTT đo được NHỎ HƠN giới hạn vật lý tới vị trí đó
#     (ánh sáng trong cáp quang ~200 km/ms) thì vị trí trong CSDL chắc chắn sai -> IP anycast/CDN.
# --------------------------------------------------------------------------
def _haversine_km(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 12742.0 * math.asin(math.sqrt(h))


class GeoLocator:
    RETRY_AFTER = 30.0      # giây, thử lại nếu tra cứu lỗi (mất mạng, bị giới hạn 45 req/phút...)
    COLOS = {
        "HAN": "Hanoi", "SGN": "Ho Chi Minh City", "DAD": "Da Nang", "HKG": "Hong Kong",
        "SIN": "Singapore", "BKK": "Bangkok", "KUL": "Kuala Lumpur", "CGK": "Jakarta",
        "MNL": "Manila", "TPE": "Taipei", "NRT": "Tokyo", "KIX": "Osaka", "ICN": "Seoul",
        "BOM": "Mumbai", "DEL": "Delhi", "MAA": "Chennai", "SYD": "Sydney", "MEL": "Melbourne",
        "LAX": "Los Angeles", "SJC": "San Jose", "SEA": "Seattle", "ORD": "Chicago",
        "DFW": "Dallas", "IAD": "Ashburn", "EWR": "Newark", "MIA": "Miami", "ATL": "Atlanta",
        "YYZ": "Toronto", "YVR": "Vancouver", "LHR": "London", "FRA": "Frankfurt",
        "AMS": "Amsterdam", "CDG": "Paris", "MAD": "Madrid", "MXP": "Milan", "DXB": "Dubai",
        "GRU": "Sao Paulo", "JNB": "Johannesburg",
    }

    def __init__(self):
        self.cache = {}         # ip -> "City, Country"
        self.rdns = {}          # ip -> tên reverse DNS ("" nếu không có)
        self.coords = {}        # ip -> (lat, lon)
        self.cf = {}            # host -> mã colo Cloudflare, hoặc "" nếu không phải Cloudflare
        self.me = None          # (lat, lon) của chính máy này
        self._pending = set()
        self._retry_at = {}
        self._q = queue.Queue()
        threading.Thread(target=self._worker, daemon=True).start()

    @classmethod
    def _colo_from_name(cls, name):
        """Rút mã sân bay (HKG, SIN...) từ reverse DNS của Google/Meta."""
        name = (name or "").lower()
        code = None
        if name.endswith(".1e100.net"):                  # Google
            first = name.split(".")[0]
            for rx in (r"^([a-z]{3})\d+s\d+-",           # hkg07s52-in-f14
                       r"^[a-z]{2}([a-z]{3})[a-z]?-"):   # nchkgb-am-in-f14
                m = re.match(rx, first)
                if m:
                    code = m.group(1).upper()
                    break
        elif name.endswith(".tfbnw.net"):                # Meta/Facebook
            m = re.search(r"\.([a-z]{3})\d+\.tfbnw\.net$", name)
            if m:
                code = m.group(1).upper()
        return code if code in cls.COLOS else None

    def _guess_colo(self, ip, hints):
        """Thử rDNS của IP đích, rồi của các hop gần đích nhất."""
        for x in (ip, *hints):
            if self._is_local(x):
                continue
            if x not in self.rdns:
                self._request(("rdns", x))
                continue
            c = self._colo_from_name(self.rdns[x])
            if c:
                return c
        return None

    @staticmethod
    def _is_ip(text):
        try:
            ipaddress.ip_address(text)
            return True
        except ValueError:
            return False

    def _is_local(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return a.is_private or a.is_loopback or a.is_link_local

    def _request(self, key):
        if key in self._pending or time.monotonic() < self._retry_at.get(key, 0):
            return
        self._pending.add(key)
        self._q.put(key)

    def get(self, ip, target=None, rtt=None, hints=()):
        """ip: IP đích; target: tên host người dùng nhập; rtt: RTT tốt nhất (ms) tới đích;
        hints: IP các hop gần đích nhất (dùng khi đích không có rDNS)."""
        if not ip:
            return ""
        if self._is_local(ip):
            return "Mạng nội bộ (LAN)"
        if self.me is None:
            self._request(("me",))
        if target and not self._is_ip(target) and re.fullmatch(r"[A-Za-z0-9.-]+", target) \
                and target not in self.cf:
            self._request(("cf", target))
        colo = self.cf.get(target)
        if colo:
            return "%s (%s) - Cloudflare" % (self.COLOS.get(colo, colo), colo)
        if ip not in self.cache:
            self._request(("geo", ip))
            return "..."
        loc = self.cache[ip]
        if rtt is not None and self.me and ip in self.coords:
            min_rtt = _haversine_km(self.me, self.coords[ip]) / 100.0   # RTT tối thiểu theo vật lý
            if rtt < 0.8 * min_rtt:
                colo = self._guess_colo(ip, hints)
                if colo:
                    return "%s (%s) - theo rDNS" % (self.COLOS[colo], colo)
                return "Anycast/CDN (%s)" % loc
        return loc

    # ---- các loại tra cứu (chạy ở luồng nền) ----
    def _fetch_json(self, url):
        with urllib.request.urlopen(url, timeout=6) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def _do_geo(self, ip):
        d = self._fetch_json("http://ip-api.com/json/%s?fields=status,country,city,lat,lon" % ip)
        if d.get("status") != "success":
            return False
        self.cache[ip] = ", ".join(p for p in (d.get("city"), d.get("country")) if p) or "?"
        if "lat" in d and "lon" in d:
            self.coords[ip] = (d["lat"], d["lon"])
        return True

    def _do_rdns(self, ip):
        try:
            self.rdns[ip] = socket.gethostbyaddr(ip)[0]
        except OSError:
            self.rdns[ip] = ""
        return True

    def _do_me(self):
        d = self._fetch_json("http://ip-api.com/json/?fields=status,lat,lon")
        if d.get("status") != "success":
            return False
        self.me = (d["lat"], d["lon"])
        return True

    def _do_cf(self, host):
        req = urllib.request.Request("https://%s/cdn-cgi/trace" % host,
                                     headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=6) as r:
                body = r.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as ex:
            if ex.code == 429 or ex.code >= 500:
                return False
            self.cf[host] = ""          # 403/404...: không phải Cloudflare
            return True
        m = re.search(r"^colo=(\w+)", body, re.M)
        self.cf[host] = m.group(1).upper() if m else ""
        return True

    def _worker(self):
        while True:
            key = self._q.get()
            kind = key[0]
            try:
                if kind == "geo":
                    ok = self._do_geo(key[1])
                elif kind == "me":
                    ok = self._do_me()
                elif kind == "rdns":
                    ok = self._do_rdns(key[1])
                else:
                    ok = self._do_cf(key[1])
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                self._retry_at[key] = time.monotonic() + self.RETRY_AFTER
            self._pending.discard(key)
            if kind in ("geo", "me"):
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


# --------------------------------------------------------------------------
# Xuất biểu đồ RTT ra ảnh PNG (chỉ dùng thư viện chuẩn: zlib + struct, tự vẽ)
# --------------------------------------------------------------------------
_FONT_5X7 = {
    "A": "01110|10001|10001|11111|10001|10001|10001", "B": "11110|10001|10001|11110|10001|10001|11110",
    "C": "01110|10001|10000|10000|10000|10001|01110", "D": "11110|10001|10001|10001|10001|10001|11110",
    "E": "11111|10000|10000|11110|10000|10000|11111", "F": "11111|10000|10000|11110|10000|10000|10000",
    "G": "01110|10001|10000|10111|10001|10001|01111", "H": "10001|10001|10001|11111|10001|10001|10001",
    "I": "01110|00100|00100|00100|00100|00100|01110", "J": "00111|00010|00010|00010|00010|10010|01100",
    "K": "10001|10010|10100|11000|10100|10010|10001", "L": "10000|10000|10000|10000|10000|10000|11111",
    "M": "10001|11011|10101|10101|10001|10001|10001", "N": "10001|11001|10101|10011|10001|10001|10001",
    "O": "01110|10001|10001|10001|10001|10001|01110", "P": "11110|10001|10001|11110|10000|10000|10000",
    "Q": "01110|10001|10001|10001|10101|10010|01101", "R": "11110|10001|10001|11110|10100|10010|10001",
    "S": "01111|10000|10000|01110|00001|00001|11110", "T": "11111|00100|00100|00100|00100|00100|00100",
    "U": "10001|10001|10001|10001|10001|10001|01110", "V": "10001|10001|10001|10001|10001|01010|00100",
    "W": "10001|10001|10001|10101|10101|10101|01010", "X": "10001|10001|01010|00100|01010|10001|10001",
    "Y": "10001|10001|01010|00100|00100|00100|00100", "Z": "11111|00001|00010|00100|01000|10000|11111",
    "0": "01110|10001|10011|10101|11001|10001|01110", "1": "00100|01100|00100|00100|00100|00100|01110",
    "2": "01110|10001|00001|00010|00100|01000|11111", "3": "11110|00001|00001|01110|00001|00001|11110",
    "4": "00010|00110|01010|10010|11111|00010|00010", "5": "11111|10000|11110|00001|00001|10001|01110",
    "6": "00110|01000|10000|11110|10001|10001|01110", "7": "11111|00001|00010|00100|01000|01000|01000",
    "8": "01110|10001|10001|01110|10001|10001|01110", "9": "01110|10001|10001|01111|00001|00010|01100",
    ".": "00000|00000|00000|00000|00000|01100|01100", ",": "00000|00000|00000|00000|01100|00100|01000",
    ":": "00000|01100|01100|00000|01100|01100|00000", "-": "00000|00000|00000|11111|00000|00000|00000",
    "(": "00010|00100|01000|01000|01000|00100|00010", ")": "01000|00100|00010|00010|00010|00100|01000",
    "%": "11001|11010|00010|00100|01000|01011|10011", "/": "00001|00010|00010|00100|01000|01000|10000",
    "_": "00000|00000|00000|00000|00000|00000|11111", " ": "00000|00000|00000|00000|00000|00000|00000",
    "?": "01110|10001|00001|00010|00100|00000|00100",
}
_FONT_5X7 = {k: v.split("|") for k, v in _FONT_5X7.items()}


class _Img:
    """Ảnh RGB tối giản: vẽ chữ bitmap, đường thẳng khử răng cưa, lưu PNG."""

    def __init__(self, w, h, bg=(255, 255, 255)):
        self.w, self.h = w, h
        self.buf = bytearray(bytes(bg) * (w * h))

    def px(self, x, y, col, a=1.0):
        if 0 <= x < self.w and 0 <= y < self.h and a > 0:
            i = (y * self.w + x) * 3
            b = self.buf
            if a >= 1.0:
                b[i], b[i + 1], b[i + 2] = col
            else:
                b[i] = int(b[i] + (col[0] - b[i]) * a)
                b[i + 1] = int(b[i + 1] + (col[1] - b[i + 1]) * a)
                b[i + 2] = int(b[i + 2] + (col[2] - b[i + 2]) * a)

    def rect(self, x0, y0, x1, y1, col):
        x0, x1 = max(0, int(x0)), min(self.w - 1, int(x1))
        for y in range(max(0, int(y0)), min(self.h - 1, int(y1)) + 1):
            i = (y * self.w + x0) * 3
            self.buf[i:i + (x1 - x0 + 1) * 3] = bytes(col) * (x1 - x0 + 1)

    def hline(self, x0, x1, y, col):
        self.rect(x0, y, x1, y, col)

    def vline(self, x, y0, y1, col):
        self.rect(x, y0, x, y1, col)

    def line(self, x0, y0, x1, y1, col):
        """Đường Wu (khử răng cưa)."""
        steep = abs(y1 - y0) > abs(x1 - x0)
        if steep:
            x0, y0, x1, y1 = y0, x0, y1, x1
        if x0 > x1:
            x0, y0, x1, y1 = x1, y1, x0, y0
        dx = x1 - x0
        grad = (y1 - y0) / dx if dx > 1e-9 else 0.0
        for x in range(int(math.floor(x0)), int(math.floor(x1)) + 1):
            y = y0 + grad * (x - x0) if dx > 1e-9 else y0
            yi = int(math.floor(y))
            f = y - yi
            if steep:
                self.px(yi, x, col, 1 - f)
                self.px(yi + 1, x, col, f)
            else:
                self.px(x, yi, col, 1 - f)
                self.px(x, yi + 1, col, f)

    def text(self, x, y, s, col, scale=2, anchor="l"):
        s = str(s).upper()
        width = len(s) * 6 * scale - scale
        if anchor == "r":
            x -= width
        elif anchor == "c":
            x -= width // 2
        for ch in s:
            rows = _FONT_5X7.get(ch, _FONT_5X7["?"])
            for ry, row in enumerate(rows):
                for rx, bit in enumerate(row):
                    if bit == "1":
                        self.rect(x + rx * scale, y + ry * scale,
                                  x + rx * scale + scale - 1, y + ry * scale + scale - 1, col)
            x += 6 * scale

    def save_png(self, path):
        raw = bytearray()
        stride = self.w * 3
        for y in range(self.h):
            raw.append(0)
            raw += self.buf[y * stride:(y + 1) * stride]

        def chunk(tag, data):
            c = struct.pack(">I", len(data)) + tag + data
            return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

        with open(path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n")
            f.write(chunk(b"IHDR", struct.pack(">IIBBBBB", self.w, self.h, 8, 2, 0, 0, 0)))
            f.write(chunk(b"IDAT", zlib.compress(bytes(raw), 6)))
            f.write(chunk(b"IEND", b""))


def _nice_step(span, want=4):
    raw = span / want
    mag = 10 ** math.floor(math.log10(raw)) if raw > 0 else 1
    for m in (1, 2, 2.5, 5, 10):
        if raw <= m * mag:
            return m * mag
    return 10 * mag


def render_rtt_png(path, series, width=1800):
    """series = [(tên_host, ip, [(epoch, rtt_ms|None), ...]), ...]
    Mỗi host một khung: đường RTT (xanh), dấu x đỏ = gói timeout, chung trục thời gian."""
    BG, GRID, AXIS = (255, 255, 255), (228, 232, 236), (90, 98, 108)
    LINE, RED, TXT, TITLE = (43, 108, 176), (197, 48, 48), (70, 78, 88), (31, 58, 95)
    left, right, top = 100, 30, 24
    ph, title_h, gap, bottom = 170, 30, 22, 34
    n = len(series)
    height = top + n * (title_h + ph + gap) + bottom
    img = _Img(width, height, BG)
    pw = width - left - right

    stamps = [t for _, _, log in series for t, _ in log]
    t0, t1 = min(stamps), max(stamps)
    span = max(t1 - t0, 1.0)
    # bước chia trục thời gian
    ivs = (60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)
    iv = next((v for v in ivs if span / v <= 10), ivs[-1])
    off = time.localtime(t0).tm_gmtoff or 0
    ticks, t = [], math.ceil((t0 + off) / iv) * iv - off
    while t <= t1:
        ticks.append(t)
        t += iv
    tfmt = "%H:%M"

    def xpos(ts):
        return left + (ts - t0) / span * (pw - 1)

    for idx, (name, ip, log) in enumerate(series):
        y0 = top + idx * (title_h + ph + gap) + title_h        # đỉnh khung vẽ
        y1 = y0 + ph - 1
        oks = [(ts, v) for ts, v in log if v is not None]
        lost = [ts for ts, v in log if v is None]
        vmax = max((v for _, v in oks), default=10.0)
        step = _nice_step(max(vmax * 1.08, 5.0))
        ymax = math.ceil(vmax * 1.08 / step) * step
        ymax = max(ymax, step)

        def ypos(v):
            return y1 - (v / ymax) * (ph - 1)

        # tiêu đề (tên host)
        img.text(left, y0 - 24, name, TITLE, 2)
        # lưới ngang + nhãn Y
        v = 0.0
        while v <= ymax + 1e-9:
            yy = int(round(ypos(v)))
            img.hline(left, left + pw, yy, GRID)
            lab = "%d" % round(v) if step >= 1 else "%.1f" % v
            img.text(left - 8, yy - 7, lab, AXIS, 2, anchor="r")
            v += step
        # lưới dọc
        for tk_ in ticks:
            img.vline(int(xpos(tk_)), y0, y1, GRID)
        img.vline(left, y0, y1, AXIS)
        img.hline(left, left + pw, y1, AXIS)
        img.text(10, y0 + ph // 2 - 7, "MS", AXIS, 2)

        # đường RTT; nếu quá dày thì gộp theo cột pixel (first/min/max/last)
        pts = [(xpos(ts), ypos(v), v) for ts, v in oks]
        if len(pts) > 3 * pw:
            cols = {}
            for p in pts:
                cols.setdefault(int(p[0]), []).append(p)
            pts = []
            for cx in sorted(cols):
                c = cols[cx]
                lo, hi = min(c, key=lambda q: q[2]), max(c, key=lambda q: q[2])
                seq = [c[0], lo, hi, c[-1]]
                for q in seq:
                    if not pts or pts[-1] is not q:
                        pts.append(q)
        for a, b in zip(pts, pts[1:]):
            img.line(a[0], a[1], b[0], b[1], LINE)
        # dấu x đỏ cho timeout (sát đỉnh khung)
        seen = set()
        for ts in lost:
            x = int(round(xpos(ts)))
            if x in seen:
                continue
            seen.add(x)
            for d in range(-3, 4):
                img.px(x + d, y0 + 6 + d, RED)
                img.px(x + d, y0 + 6 - d, RED)

    # nhãn thời gian ở đáy
    yb = top + n * (title_h + ph + gap) - gap + 8
    for tk_ in ticks:
        img.text(int(xpos(tk_)), yb, time.strftime(tfmt, time.localtime(tk_)), AXIS, 2, anchor="c")
    img.save_png(path)


# --------------------------------------------------------------------------
# Phân tích thống kê từng host (dùng cho ảnh thống kê)
# --------------------------------------------------------------------------
SPIKE_MS = 20.0        # spike = RTT cao hơn trung vị trượt quanh nó quá ngần này (ms)
EVENT_GAP_S = 30.0     # các spike/timeout cách nhau <= ngần này giây thuộc cùng một sự kiện


def _f1(v, d=1):
    return "-" if v is None else ("%.*f" % (d, v)).replace(".", ",")


def _is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _pctl(sv, p):
    if not sv:
        return None
    k = (len(sv) - 1) * p / 100.0
    f = int(math.floor(k))
    c = min(f + 1, len(sv) - 1)
    return sv[f] + (sv[c] - sv[f]) * (k - f)


def _rolling_median(vals, win):
    n = len(vals)
    half = win // 2
    out = [0.0] * n
    if not n:
        return out
    hi = min(n, half + 1)
    w = sorted(vals[:hi])
    lo = 0
    for i in range(n):
        want_lo, want_hi = max(0, i - half), min(n, i + half + 1)
        while hi < want_hi:
            bisect.insort(w, vals[hi])
            hi += 1
        while lo < want_lo:
            w.pop(bisect.bisect_left(w, vals[lo]))
            lo += 1
        m = len(w)
        out[i] = w[m // 2] if m % 2 else (w[m // 2 - 1] + w[m // 2]) / 2.0
    return out


RATINGS = ["Rất kém", "Kém", "Khá", "Tốt", "Rất tốt"]
RATING_FILL = {"Rất tốt": (224, 242, 228), "Tốt": (224, 242, 228), "Khá": (255, 243, 205),
               "Kém": (248, 215, 218), "Rất kém": (248, 215, 218), "Chưa đủ dữ liệu": (238, 238, 238)}


def _analyze_host(h, interval_ms):
    log = h["log"]
    oks = [(t, v) for t, v in log if v is not None]
    lost = [t for t, v in log if v is None]
    n = len(log)
    st = {"target": h["target"], "ip": h.get("ip") or "", "n": n, "lost": len(lost),
          "loss": 100.0 * len(lost) / n if n else 0.0, "local": _is_private(h.get("ip") or "")}
    times = [t for t, _ in oks]
    vals = [v for _, v in oks]
    sv = sorted(vals)
    st.update(avg=(sum(vals) / len(vals)) if vals else None, med=_pctl(sv, 50), p95=_pctl(sv, 95),
              p99=_pctl(sv, 99), max=sv[-1] if sv else None, min=sv[0] if sv else None)
    diffs = [abs(b[1] - a[1]) for a, b in zip(log, log[1:]) if a[1] is not None and b[1] is not None]
    st["jitter"] = sum(diffs) / len(diffs) if diffs else None
    win = max(11, min(121, int(round(60000.0 / max(interval_ms, 1))))) | 1
    base = _rolling_median(vals, win)
    spikes = [(times[i], vals[i], vals[i] - base[i]) for i in range(len(vals)) if vals[i] - base[i] > SPIKE_MS]
    st["spikes"] = spikes
    st["spike_pct"] = 100.0 * len(spikes) / len(vals) if vals else 0.0
    # mức nền theo cửa sổ 5 phút
    groups = {}
    if times:
        t0 = times[0]
        for t, v in oks:
            groups.setdefault(int((t - t0) // 300), []).append(v)
    meds = [_pctl(sorted(g), 50) for g in groups.values() if len(g) >= 30]
    st["base_min"], st["base_max"] = (min(meds), max(meds)) if meds else (None, None)
    st["base_shift"] = bool(meds) and (max(meds) - min(meds) >= 8.0) and max(meds) >= 1.3 * min(meds)
    # sự kiện (cụm spike/timeout)
    bad = sorted([(t, "t", 0.0) for t in lost] + [(t, "s", ex) for t, _, ex in spikes])
    clusters, cur = [], []
    for b in bad:
        if cur and b[0] - cur[-1][0] > EVENT_GAP_S:
            clusters.append(cur)
            cur = []
        cur.append(b)
    if cur:
        clusters.append(cur)
    events = []
    med = st["med"] or 0.0
    for c in clusters:
        s0, s1 = c[0][0], c[-1][0]
        to = sum(1 for x in c if x[1] == "t")
        pex = max((x[2] for x in c), default=0.0)
        i0, i1 = bisect.bisect_left(times, s0), bisect.bisect_right(times, s1)
        seg = vals[i0:i1]
        peak = max(seg) if seg else None
        winloss = to / float(len(seg) + to) if (len(seg) + to) else 0.0
        severe = (peak is not None and peak >= 100 and peak >= 3 * med) or (to >= 5 and winloss >= 0.05)
        sig = severe or to >= 3 or pex >= 50 or (len(c) >= 10 and pex >= 30)
        level = "Nghiêm trọng" if severe else ("Trung bình" if (to >= 3 or pex >= 50) else "Nhẹ")
        events.append({"start": s0, "end": s1, "n": len(c), "timeouts": to, "peak": peak, "pex": pex,
                       "avg": (sum(seg) / len(seg)) if seg else None, "severe": severe, "sig": sig,
                       "level": level, "winloss": winloss * 100.0})
    st["events"] = events
    st["sig_events"] = [e for e in events if e["sig"]]
    st["has_severe"] = any(e["severe"] for e in events)
    # đánh giá
    if n < 30:
        st["rating"] = "Chưa đủ dữ liệu"
    elif st["loss"] > 5:
        st["rating"] = "Rất kém"
    elif st["loss"] > 1:
        st["rating"] = "Kém"
    elif st["has_severe"] or st["loss"] > 0.1:
        st["rating"] = "Khá"
    elif st["loss"] <= 0.05 and st["spike_pct"] <= 0.5:
        st["rating"] = "Rất tốt"
    else:
        st["rating"] = "Tốt"
    return st



# --------------------------------------------------------------------------
# Xuất ảnh thống kê (bảng) ra PNG
# Vẽ chữ có dấu tiếng Việt bằng: GDI (Windows) -> Pillow (nếu có) -> font bitmap (không dấu)
# --------------------------------------------------------------------------
class _GdiText:
    """Vẽ chữ bằng GDI của Windows (Arial) vào DIB 32-bit, trả về mặt nạ alpha 8-bit."""

    def __init__(self):
        if not IS_WIN:
            raise OSError("not windows")
        from ctypes import wintypes
        self.wt = wintypes
        g = ctypes.WinDLL("gdi32", use_last_error=True)
        self.g = g
        V = ctypes.c_void_p
        g.CreateCompatibleDC.restype, g.CreateCompatibleDC.argtypes = V, [V]
        g.DeleteDC.argtypes = [V]
        g.CreateFontW.restype = V
        g.CreateFontW.argtypes = [ctypes.c_int] * 5 + [ctypes.c_ulong] * 8 + [ctypes.c_wchar_p]
        g.SelectObject.restype, g.SelectObject.argtypes = V, [V, V]
        g.DeleteObject.argtypes = [V]
        g.GetTextExtentPoint32W.argtypes = [V, ctypes.c_wchar_p, ctypes.c_int, ctypes.c_void_p]
        g.CreateDIBSection.restype = V
        g.CreateDIBSection.argtypes = [V, ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(V), V, ctypes.c_uint]
        g.SetBkMode.argtypes = [V, ctypes.c_int]
        g.SetBkColor.argtypes = [V, ctypes.c_ulong]
        g.SetTextColor.argtypes = [V, ctypes.c_ulong]
        g.TextOutW.argtypes = [V, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p, ctypes.c_int]
        g.GdiFlush.argtypes = []
        self.hdc = g.CreateCompatibleDC(None)
        if not self.hdc:
            raise OSError("CreateCompatibleDC")
        self.fonts = {}
        self.render("Ag", 15, False)           # thử một lần, lỗi thì chuyển sang backend khác

    def _font(self, px, bold):
        key = (px, bold)
        if key not in self.fonts:
            f = self.g.CreateFontW(-px, 0, 0, 0, 700 if bold else 400, 0, 0, 0, 1, 0, 0, 4, 0, "Arial")
            if not f:
                raise OSError("CreateFontW")
            self.fonts[key] = f
        return self.fonts[key]

    def render(self, text, px, bold):
        g = self.g
        old = g.SelectObject(self.hdc, self._font(px, bold))
        try:
            sz = (ctypes.c_long * 2)()
            g.GetTextExtentPoint32W(self.hdc, text, len(text), ctypes.byref(sz))
            w, h = max(1, sz[0] + 2), max(1, int(px * 1.3) + 1)

            class BIH(ctypes.Structure):
                _fields_ = [("biSize", ctypes.c_ulong), ("biWidth", ctypes.c_long), ("biHeight", ctypes.c_long),
                            ("biPlanes", ctypes.c_ushort), ("biBitCount", ctypes.c_ushort),
                            ("biCompression", ctypes.c_ulong), ("biSizeImage", ctypes.c_ulong),
                            ("biXPelsPerMeter", ctypes.c_long), ("biYPelsPerMeter", ctypes.c_long),
                            ("biClrUsed", ctypes.c_ulong), ("biClrImportant", ctypes.c_ulong)]

            bmi = BIH(ctypes.sizeof(BIH), w, -h, 1, 32, 0, 0, 0, 0, 0, 0)
            bits = ctypes.c_void_p()
            bmp = g.CreateDIBSection(self.hdc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
            if not bmp or not bits.value:
                raise OSError("CreateDIBSection")
            oldbmp = g.SelectObject(self.hdc, bmp)
            try:
                ctypes.memset(bits, 0, w * h * 4)
                g.SetBkMode(self.hdc, 2)               # OPAQUE
                g.SetBkColor(self.hdc, 0x000000)
                g.SetTextColor(self.hdc, 0xFFFFFF)
                g.TextOutW(self.hdc, 0, 0, text, len(text))
                g.GdiFlush()
                raw = ctypes.string_at(bits.value, w * h * 4)
            finally:
                g.SelectObject(self.hdc, oldbmp)
                g.DeleteObject(bmp)
            return w, h, bytes(raw[1::4])               # kênh G của BGRA = độ phủ chữ
        finally:
            g.SelectObject(self.hdc, old)


class _PilText:
    def __init__(self):
        from PIL import Image, ImageDraw, ImageFont
        self.Image, self.ImageDraw, self.ImageFont = Image, ImageDraw, ImageFont
        self.fonts = {}
        self.render("Ag", 15, False)

    def _font(self, px, bold):
        key = (px, bold)
        if key not in self.fonts:
            names = (["arialbd.ttf", "Arial Bold.ttf", "LiberationSans-Bold.ttf", "DejaVuSans-Bold.ttf"] if bold
                     else ["arial.ttf", "Arial.ttf", "LiberationSans-Regular.ttf", "DejaVuSans.ttf"])
            font = None
            for nm in names:
                try:
                    font = self.ImageFont.truetype(nm, px)
                    break
                except OSError:
                    continue
            if font is None:
                raise OSError("no TTF font")
            self.fonts[key] = font
        return self.fonts[key]

    def render(self, text, px, bold):
        f = self._font(px, bold)
        w, h = int(f.getlength(text)) + 3, int(px * 1.3) + 1
        im = self.Image.new("L", (w, h), 0)
        self.ImageDraw.Draw(im).text((0, 0), text, font=f, fill=255)
        return w, h, im.tobytes()


class _BitmapText:
    """Dự phòng cuối: font 5x7 tự vẽ, không có dấu, chỉ chữ HOA."""

    def render(self, text, px, bold):
        import unicodedata
        s = unicodedata.normalize("NFD", str(text).replace("Đ", "D").replace("đ", "d"))
        s = "".join(c for c in s if not unicodedata.combining(c)).upper()
        sc = max(1, int(round(px / 9.0)))
        w, h = max(1, len(s) * 6 * sc), int(px * 1.3) + 1
        buf = bytearray(w * h)
        x0 = 0
        y0 = max(0, (px - 7 * sc) // 2 + sc)
        for ch in s:
            for ry, row in enumerate(_FONT_5X7.get(ch, _FONT_5X7["?"])):
                for rx, bit in enumerate(row):
                    if bit == "1":
                        for dy in range(sc):
                            for dx in range(sc):
                                xx, yy = x0 + rx * sc + dx, y0 + ry * sc + dy
                                if 0 <= xx < w and 0 <= yy < h:
                                    buf[yy * w + xx] = 255
            x0 += 6 * sc
        return w, h, bytes(buf)


class _TextEngine:
    def __init__(self):
        self.impl = None
        for cls in (_GdiText, _PilText):
            try:
                self.impl = cls()
                break
            except Exception:  # noqa: BLE001
                continue
        if self.impl is None:
            self.impl = _BitmapText()
        self.cache = {}

    def mask(self, text, px, bold=False):
        key = (text, px, bold)
        if key not in self.cache:
            self.cache[key] = self.impl.render(text, px, bold)
        return self.cache[key]

    def width(self, text, px, bold=False):
        return self.mask(text, px, bold)[0] - 2


def _blit_mask(img, x, y, mask, col):
    w, h, alpha = mask
    for j in range(h):
        row = j * w
        for i in range(w):
            a = alpha[row + i]
            if a:
                img.px(x + i, y + j, col, a / 255.0)


def _wrap_cell(eng, text, px, bold, avail):
    """Ngắt dòng theo từ cho vừa chiều rộng ô (giống bảng HTML)."""
    words, lines, cur = str(text).split(" "), [], ""
    for wd in words:
        trial = wd if not cur else cur + " " + wd
        if cur and eng.width(trial, px, bold) > avail:
            lines.append(cur)
            cur = wd
        else:
            cur = trial
    lines.append(cur)
    return lines


def render_stats_png(path, hosts, interval_ms):
    """Ảnh bảng thống kê: Host | IP | Mẫu | Mất gói | RTT TB | Max | Ping Spike | Jitter | Đánh giá.
    hosts = [{target, ip, log:[(epoch, rtt|None)]}]. Giao diện theo ảnh mẫu (vẽ ở độ phân giải x3)."""
    S = 3                                           # hệ số phóng (càng lớn ảnh càng nét)
    FONT = 15 * S
    PAD, LINE_H, CELL_PAD = 8 * S, 21 * S, 8 * S
    NAVY, BORDER, ZEBRA, TXT = (31, 58, 95), (197, 198, 200), (245, 246, 248), (33, 37, 41)
    heads = ["Host", "IP", "Mẫu", "Mất gói", "RTT TB", "Max", "Ping Spike", "Jitter", "Đánh giá"]
    base_w = [117, 133, 58, 67, 63, 58, 58, 59, 124]         # độ rộng cột theo ảnh mẫu (px gốc)
    eng = _TextEngine()

    rows = []
    for h in hosts:
        a = _analyze_host(h, interval_ms)
        if a["n"] < 2:
            continue
        rows.append([a["target"], a["ip"] or "-", str(a["n"]), _f1(a["loss"], 2) + "%", _f1(a["avg"]),
                     _f1(a["max"]), str(len(a["spikes"])), _f1(a["jitter"]), a["rating"]])
    if not rows:
        raise ValueError("Chưa có dữ liệu ping.")

    # độ rộng cột: không nhỏ hơn mẫu, tự nở ra nếu nội dung dài (tên host dài...)
    widths = []
    for c in range(len(heads)):
        need = max(eng.width(r[c], FONT, c == 8) for r in rows) + 2 * PAD + 2 * S
        widths.append(max(base_w[c] * S, need))
    # ô tiêu đề được ngắt dòng theo độ rộng cột
    hlines = [_wrap_cell(eng, t, FONT, True, widths[c] - 2 * PAD) for c, t in enumerate(heads)]
    head_h = (8 * S) + LINE_H * max(len(x) for x in hlines)
    row_h = 8 * S + LINE_H

    mx, my = 2 * S, 2 * S
    tw = sum(widths)
    W = mx + tw + 4 * S
    H = my + head_h + S + len(rows) * (row_h + S) + 2 * S
    img = _Img(W, H, (255, 255, 255))
    xs = [mx]
    for w in widths:
        xs.append(xs[-1] + w)

    # tiêu đề
    img.rect(mx, my, xs[-1], my + head_h - 1, NAVY)
    for x in xs:                                    # vạch dọc trắng phân tách các cột tiêu đề
        img.rect(x - S // 2, my, x - S // 2 + S - 1, my + head_h - 1, (255, 255, 255))
    for c, lines in enumerate(hlines):
        for k, ln in enumerate(lines):
            _blit_mask(img, xs[c] + PAD, my + 4 * S + k * LINE_H, eng.mask(ln, FONT, True), (255, 255, 255))

    # dữ liệu
    y = my + head_h
    img.rect(mx, y, xs[-1], y + S - 1, BORDER)
    y += S
    for ri, r in enumerate(rows):
        top = y
        bot = top + row_h - 1
        if ri % 2:
            img.rect(mx, top, xs[-1], bot, ZEBRA)
        fill = RATING_FILL.get(r[8], (238, 238, 238))
        img.rect(xs[8], top, xs[9], bot, fill)
        for c, txt in enumerate(r):
            _blit_mask(img, xs[c] + PAD, top + 4 * S, eng.mask(txt, FONT, c == 8), TXT)
        img.rect(mx, bot + 1, xs[-1], bot + S, BORDER)
        y = bot + 1 + S
    for x in xs:
        img.rect(x - S // 2, my + head_h, x - S // 2 + S - 1, y - 1, BORDER)
    img.save_png(path)


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
        ttk.Button(bar, text="Xuất biểu đồ RTT", command=self.export_chart).pack(side="left", padx=2)

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
        heads = [("host", "Host", 140), ("location", "Location", 240), ("ip", "IP", 120), ("state", "Trạng thái", 120),
                 ("hops", "Số hop", 50), ("loss", "Loss %", 70), ("avg", "Avg", 70),
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
                        ("sent", "Sent", 65), ("recv", "Receive", 65), ("best", "Best", 65),
                        ("avg", "Avg", 65), ("worst", "Worst", 65), ("last", "Last", 65)]:
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
                near = [h["ip"] for h in reversed(hops[:-1]) if h["ip"]][:3]
                loss = dest["loss"] if dest else None
                tag = ()
                if loss is not None:
                    tag = ("bad",) if loss >= 5 else (("warn",) if loss >= WARN_LOSS else ())
                self.host_tree.item(name, tags=tag, values=(
                    name, self.geo.get(s["ip"], name, dest["best"] if dest else None, near), s["ip"] or "", s["state"], len(hops) or "",
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
                ("bad",) if h["loss"] >= 5 else (("warn",) if h["loss"] >= WARN_LOSS else ()))
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
        Luôn xuất Summary và TẤT CẢ host, không phụ thuộc host đang chọn."""
        mons = list(self.monitors.values())
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

    def export_chart(self):
        """Luôn xuất TOÀN BỘ host (không phụ thuộc host đang chọn), ra 2 file ảnh PNG:
        1) biểu đồ RTT theo thời gian; 2) ảnh bảng thống kê (cùng tên, thêm hậu tố _thongke)."""
        series, stats = [], []
        for m in list(self.monitors.values()):
            ip, log = m.log_snapshot()
            if len(log) >= 2:
                series.append((m.target, ip, log))
                stats.append({"target": m.target, "ip": ip, "log": log})
        if not series:
            messagebox.showinfo("Xuất biểu đồ RTT", "Chưa có dữ liệu ping. Hãy chạy theo dõi một lúc rồi thử lại.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".png", filetypes=[("Ảnh PNG", "*.png")],
            initialfile="rtt_%s.png" % time.strftime("%Y%m%d_%H%M%S"))
        if not path:
            return
        root, ext = os.path.splitext(path)
        stats_path = root + "_thongke" + (ext or ".png")
        try:
            self.status.config(text="Đang vẽ biểu đồ và bảng thống kê...")
            self.update_idletasks()
            render_rtt_png(path, series)
            render_stats_png(stats_path, stats, self.cfg["interval"])
            self.status.config(text="Đã xuất %d host: %s  +  %s" % (
                len(series), path, os.path.basename(stats_path)))
        except (OSError, ValueError) as ex:
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
