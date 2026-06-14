#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STB boot capture and channel list discovery via tcpdump + TCP stream reassembly."""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from services.log_service import AppLogger


def _parse_ip(data: bytes, off: int) -> str:
    return ".".join(str(b) for b in data[off : off + 4])


# ── DHCP helpers ─────────────────────────────────────────────────────────────

def _parse_dhcp_options(options_bytes: bytes) -> dict[int, bytes]:
    """Parse DHCP options TLV into {code: value_bytes}."""
    opts: dict[int, bytes] = {}
    i = 0
    while i < len(options_bytes):
        code = options_bytes[i]
        i += 1
        if code == 0:   # PAD
            continue
        if code == 255:  # END
            break
        if i >= len(options_bytes):
            break
        length = options_bytes[i]
        i += 1
        if i + length > len(options_bytes):
            break
        opts[code] = options_bytes[i : i + length]
        i += length
    return opts


def _parse_opt125(data: bytes) -> str:
    """Parse DHCP Option 125 (Vendor-Identifying Vendor-Specific)."""
    _ENTERPRISE_NAMES = {2011: "中兴ZTE", 3561: "Broadcom/TR-069", 4491: "CableLabs"}
    parts: list[str] = []
    i = 0
    while i + 5 <= len(data):
        enterprise = struct.unpack(">I", data[i : i + 4])[0]
        data_len = data[i + 4]
        i += 5
        if i + data_len > len(data):
            break
        sub_data = data[i : i + data_len]
        i += data_len
        sub_parts: list[str] = []
        j = 0
        while j + 2 <= len(sub_data):
            sub_code = sub_data[j]
            sub_len = sub_data[j + 1]
            j += 2
            if j + sub_len > len(sub_data):
                break
            raw = sub_data[j : j + sub_len]
            j += sub_len
            try:
                sv = raw.decode("utf-8", errors="replace").strip("\x00").strip()
                if not all(c.isprintable() or c in "\t\n" for c in sv):
                    sv = raw.hex()
            except Exception:
                sv = raw.hex()
            sub_parts.append(f"sub{sub_code}={sv}")
        label = _ENTERPRISE_NAMES.get(enterprise, str(enterprise))
        parts.append(f"Enterprise({label}): " + "; ".join(sub_parts))
    return "\n".join(parts)


def _parse_dhcp_packet(payload: bytes) -> dict[str, Any] | None:
    """Parse a DHCP packet from UDP payload. Returns None if not valid DHCP."""
    if len(payload) < 240:
        return None
    if payload[236:240] != b"\x63\x82\x53\x63":  # magic cookie
        return None
    op = payload[0]
    hlen = min(payload[2], 16)
    xid = struct.unpack(">I", payload[4:8])[0]
    yiaddr = _parse_ip(payload, 16)
    mac = ":".join(f"{b:02x}" for b in payload[28 : 28 + hlen]) if hlen >= 6 else ""
    options = _parse_dhcp_options(payload[240:])
    msg_type = options.get(53, b"\x00")[0] if 53 in options else 0
    return {"op": op, "xid": xid, "yiaddr": yiaddr, "mac": mac,
            "msg_type": msg_type, "options": options}


def _extract_dhcp_from_pcap(pcap_path: str) -> dict[str, Any]:
    """Extract STB DHCP auth info from a pcap file."""
    _VLAN_ETYPES = {0x8100, 0x88A8, 0x9100}
    _DLT_LINUX_SLL = 113
    _DLT_LINUX_SLL2 = 276
    requests: dict[int, dict] = {}
    responses: dict[int, dict] = {}
    with open(pcap_path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return {}
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in (0xA1B2C3D4, 0xD3B4A1B2):
            return {}
        linktype = struct.unpack("<I", header[20:24])[0]
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            inc_len = struct.unpack("<I", hdr[8:12])[0]
            pkt = f.read(inc_len)
            if linktype == _DLT_LINUX_SLL:
                if len(pkt) < 16:
                    continue
                if struct.unpack(">H", pkt[14:16])[0] != 0x0800:
                    continue
                ip_start = 16
            elif linktype == _DLT_LINUX_SLL2:
                if len(pkt) < 20:
                    continue
                if struct.unpack(">H", pkt[0:2])[0] != 0x0800:
                    continue
                ip_start = 20
            else:
                if len(pkt) < 14:
                    continue
                p = 12
                if p + 2 > len(pkt):
                    continue
                etype = struct.unpack(">H", pkt[p : p + 2])[0]
                while etype in _VLAN_ETYPES:
                    p += 4
                    if p + 2 > len(pkt):
                        break
                    etype = struct.unpack(">H", pkt[p : p + 2])[0]
                if etype != 0x0800:
                    continue
                ip_start = p + 2
            if ip_start + 20 > len(pkt):
                continue
            if pkt[ip_start + 9] != 17:  # not UDP
                continue
            ip_ihl = (pkt[ip_start] & 0x0F) * 4
            udp_off = ip_start + ip_ihl
            if udp_off + 8 > len(pkt):
                continue
            src_port = struct.unpack(">H", pkt[udp_off : udp_off + 2])[0]
            dst_port = struct.unpack(">H", pkt[udp_off + 2 : udp_off + 4])[0]
            if src_port not in (67, 68) and dst_port not in (67, 68):
                continue
            parsed = _parse_dhcp_packet(pkt[udp_off + 8:])
            if not parsed:
                continue
            xid = parsed["xid"]
            if parsed["op"] == 1:
                requests.setdefault(xid, parsed)
            elif parsed["op"] == 2:
                responses.setdefault(xid, parsed)

    # Pick best matched request+response pair
    best_req, best_resp = None, None
    for xid, req in requests.items():
        if xid in responses:
            best_req, best_resp = req, responses[xid]
            break
    if best_req is None and requests:
        best_req = next(iter(requests.values()))
    if best_req is None:
        return {}

    opts_req = best_req["options"]
    opts_resp = best_resp["options"] if best_resp else {}

    def _str(opts: dict, code: int) -> str:
        val = opts.get(code)
        if not val:
            return ""
        try:
            s = val.decode("utf-8", errors="replace").strip("\x00").strip()
            return s if all(c.isprintable() or c in " \t" for c in s) else val.hex()
        except Exception:
            return val.hex()

    def _ip(opts: dict, code: int) -> str:
        val = opts.get(code)
        return ".".join(str(b) for b in val[:4]) if val and len(val) >= 4 else ""

    def _ips(opts: dict, code: int) -> list[str]:
        val = opts.get(code)
        if not val:
            return []
        return [".".join(str(b) for b in val[i : i + 4])
                for i in range(0, len(val) - 3, 4)]

    raw61 = opts_req.get(61, b"")
    if raw61 and raw61[0] == 1 and len(raw61) == 7:
        client_id = "01:" + ":".join(f"{b:02x}" for b in raw61[1:])
    elif raw61:
        client_id = raw61.hex()
    else:
        client_id = ""

    assigned_ip = ""
    if best_resp:
        yi = best_resp.get("yiaddr", "")
        if yi and yi != "0.0.0.0":
            assigned_ip = yi

    return {
        "mac": best_req.get("mac", ""),
        "assigned_ip": assigned_ip,
        "gateway": _ip(opts_resp, 3),
        "netmask": _ip(opts_resp, 1),
        "dns": _ips(opts_resp, 6),
        "dhcp_server": _ip(opts_resp, 54),
        "vendor_class": _str(opts_req, 60),
        "hostname": _str(opts_req, 12),
        "client_id": client_id,
        "vendor_specific_125": _parse_opt125(opts_req[125]) if 125 in opts_req else "",
        "vendor_specific_125_raw": opts_req[125].hex() if 125 in opts_req else "",
    }


def _unchunk(data: bytes) -> bytes:
    """Strip HTTP chunked transfer encoding."""
    out = bytearray()
    i = 0
    while i < len(data):
        nl = data.find(b"\r\n", i)
        if nl == -1:
            break
        try:
            size = int(data[i:nl], 16)
        except ValueError:
            break
        if size == 0:
            break
        out.extend(data[nl + 2 : nl + 2 + size])
        i = nl + 2 + size + 2
    return bytes(out)


def _split_http_responses(raw: bytes) -> list[tuple[str, bytes]]:
    """Split a TCP stream into individual (headers, body) HTTP response pairs."""
    responses: list[tuple[str, bytes]] = []
    i = 0
    while i < len(raw):
        if not raw[i : i + 5].startswith(b"HTTP/"):
            i += 1
            continue
        hdr_end = raw.find(b"\r\n\r\n", i)
        if hdr_end == -1:
            break
        headers_str = raw[i:hdr_end].decode("utf-8", errors="replace")
        body_start = hdr_end + 4
        cl_match = re.search(r"[Cc]ontent-[Ll]ength:\s*(\d+)", headers_str)
        te_match = re.search(r"[Tt]ransfer-[Ee]ncoding:\s*chunked", headers_str, re.IGNORECASE)
        if cl_match:
            body_len = int(cl_match.group(1))
            body = raw[body_start : body_start + body_len]
            next_i = body_start + body_len
        elif te_match:
            body_raw = raw[body_start:]
            body = _unchunk(body_raw)
            chunk_end = body_raw.find(b"\r\n0\r\n")
            next_i = body_start + chunk_end + 7 if chunk_end != -1 else len(raw)
        else:
            body = b""
            next_i = body_start
        is_gzip = "content-encoding: gzip" in headers_str.lower()
        if is_gzip and len(body) > 10:
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        responses.append((headers_str, body))
        i = next_i
    return responses


def _reassemble_tcp_streams(pcap_path: str) -> dict[tuple[str, int, str, int], bytes]:
    """Read a pcap file and reassemble TCP payload streams by 4-tuple key.

    Handles Ethernet (DLT=1), Linux cooked SLL (DLT=113), and SLL2 (DLT=276)
    link types so captures on the ``any`` interface work correctly.  Also
    handles 802.1Q / QinQ VLAN tags on Ethernet frames.  Packets are sorted by
    TCP sequence number and retransmissions are deduplicated.
    """
    _VLAN_ETYPES = {0x8100, 0x88A8, 0x9100}
    _DLT_LINUX_SLL = 113
    _DLT_LINUX_SLL2 = 276
    stream_seqs: dict[tuple[str, int, str, int], dict[int, bytes]] = {}
    with open(pcap_path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return {}
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in (0xA1B2C3D4, 0xD3B4A1B2):
            return {}
        linktype = struct.unpack("<I", header[20:24])[0]
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            inc_len = struct.unpack("<I", hdr[8:12])[0]
            pkt = f.read(inc_len)
            if linktype == _DLT_LINUX_SLL:
                # SLL v1: 16-byte cooked header; EtherType at bytes 14-15
                if len(pkt) < 16:
                    continue
                if struct.unpack(">H", pkt[14:16])[0] != 0x0800:
                    continue
                ip_start = 16
            elif linktype == _DLT_LINUX_SLL2:
                # SLL v2: 20-byte cooked header; EtherType at bytes 0-1
                if len(pkt) < 20:
                    continue
                if struct.unpack(">H", pkt[0:2])[0] != 0x0800:
                    continue
                ip_start = 20
            else:
                # Ethernet (DLT=1) — walk past 802.1Q / QinQ VLAN tags
                if len(pkt) < 14:
                    continue
                p = 12
                if p + 2 > len(pkt):
                    continue
                etype = struct.unpack(">H", pkt[p : p + 2])[0]
                while etype in _VLAN_ETYPES:
                    p += 4
                    if p + 2 > len(pkt):
                        break
                    etype = struct.unpack(">H", pkt[p : p + 2])[0]
                if etype != 0x0800:
                    continue
                ip_start = p + 2
            if ip_start + 20 > len(pkt):
                continue
            if pkt[ip_start + 9] != 6:
                continue  # not TCP
            ip_ihl = (pkt[ip_start] & 0x0F) * 4
            src_ip = _parse_ip(pkt, ip_start + 12)
            dst_ip = _parse_ip(pkt, ip_start + 16)
            tcp_off = ip_start + ip_ihl
            if tcp_off + 20 > len(pkt):
                continue
            src_port = struct.unpack(">H", pkt[tcp_off : tcp_off + 2])[0]
            dst_port = struct.unpack(">H", pkt[tcp_off + 2 : tcp_off + 4])[0]
            seq = struct.unpack(">I", pkt[tcp_off + 4 : tcp_off + 8])[0]
            data_off = tcp_off + ((pkt[tcp_off + 12] >> 4) * 4)
            payload = pkt[data_off:]
            if not payload:
                continue
            key = (src_ip, src_port, dst_ip, dst_port)
            seqs = stream_seqs.setdefault(key, {})
            if seq not in seqs:  # skip retransmits with identical seq
                seqs[seq] = payload
    streams: dict[tuple[str, int, str, int], bytes] = {}
    for key, seq_map in stream_seqs.items():
        streams[key] = b"".join(payload for _, payload in sorted(seq_map.items()))
    return streams


def _parse_chanlist_html(html: bytes) -> list[dict[str, Any]]:
    """Parse getchannellistHWCU.jsp HTML response into channel dicts."""
    text = html.decode("utf-8", errors="replace")
    # Single-quote outer delimiter allows double quotes inside (typical format)
    blocks = re.findall(r"CUSetConfig\('Channel',\s*'([^']+)'\)", text)
    # Double-quote outer delimiter allows single quotes inside
    blocks += re.findall(r'CUSetConfig\("Channel",\s*"([^"]+)"\)', text)
    channels: list[dict[str, Any]] = []
    for block in blocks:
        raw = re.findall(r"""(\w+)=(?:"([^"]*)"|'([^']*)')""", block)
        pairs = {k: (dq or sq) for k, dq, sq in raw}
        chan_name = pairs.get("ChannelName", "").strip()
        user_chan_id = pairs.get("UserChannelID", "")
        channel_url = pairs.get("ChannelURL", "")
        chan_id = pairs.get("ChannelID", "")
        is_hd = pairs.get("IsHDChannel", "0") == "2"
        time_shift = pairs.get("TimeShift", "0") == "1"
        time_shift_days_s = pairs.get("TimeShiftLength", "")
        fcc_ip = pairs.get("ChannelFCCIP", "").strip()
        fcc_port_s = pairs.get("ChannelFCCPort", "")
        fec_port_s = pairs.get("ChannelFECPort", "")
        backtv_url = (
            pairs.get("TimeShiftURL") or pairs.get("BacktimeURL") or
            pairs.get("BackUrl") or pairs.get("TimeshiftUrl") or
            pairs.get("startOverUrl") or ""
        ).strip()
        m = re.match(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", channel_url)
        ip, port = (m.group(1), int(m.group(2))) if m else ("", 0)
        if not ip or not port or not chan_name:
            continue
        channels.append(
            {
                "num": int(user_chan_id) if user_chan_id.isdigit() else 0,
                "name": chan_name,
                "ip": ip,
                "port": port,
                "channel_id": chan_id,
                "is_hd": is_hd,
                "time_shift": time_shift,
                "time_shift_days": int(time_shift_days_s) if time_shift_days_s.isdigit() else None,
                "fcc_ip": fcc_ip,
                "fcc_port": int(fcc_port_s) if fcc_port_s.isdigit() else None,
                "fec_port": int(fec_port_s) if fec_port_s.isdigit() else None,
                "backtv_url": backtv_url,
            }
        )
    channels.sort(key=lambda x: x["num"])
    return channels


def _parse_vsp_json(body: bytes) -> list[dict[str, Any]]:
    """Parse /VSP/V3/QueryChannelListBySubject JSON response."""
    channels: list[dict[str, Any]] = []
    try:
        data = json.loads(body)
    except Exception:
        return channels
    for ch in data.get("channelDetails") or []:
        if not isinstance(ch, dict):
            continue
        name = str(ch.get("name", "")).strip()
        chan_no = ch.get("channelNO", "")
        chan_id = str(ch.get("ID", "")).strip()
        if not name:
            continue
        # Extract multicast URL from physicalChannels
        for pc in ch.get("physicalChannels") or []:
            if not isinstance(pc, dict):
                continue
            btv = pc.get("btvCR") or {}
            if isinstance(btv, dict):
                url = str(btv.get("mediaURL", "") or btv.get("broadcastURL", "")).strip()
                m = re.match(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", url)
                if m:
                    channels.append(
                        {
                            "num": int(chan_no) if str(chan_no).isdigit() else 0,
                            "name": name,
                            "ip": m.group(1),
                            "port": int(m.group(2)),
                            "channel_id": chan_id,
                            "is_hd": False,
                            "time_shift": False,
                            "fcc_ip": "",
                            "fcc_port": None,
                            "fec_port": None,
                        }
                    )
    return channels


_TIMESHIFT_URL_RE = re.compile(
    rb"https?://([\d.]+(?::\d+)?)/[^\s\"'<>]*(?:timeshift|backtv|backtime|catchup)[^\s\"'<>]*",
    re.IGNORECASE,
)


def _extract_epg_credentials(streams: dict[Any, bytes], stb_ip: str) -> dict[str, str]:
    """
    Scan STB→server TCP streams for EPG auth requests and extract:
    user_id, stb_id, epg_auth_host (ip:port).
    """
    result: dict[str, str] = {}
    request_streams = {k: v for k, v in streams.items() if k[0] == stb_ip}
    for (src_ip, src_port, dst_ip, dst_port), data in request_streams.items():
        text = data.decode("utf-8", errors="replace")
        # UserID from /EDS/jsp/AuthenticationURL?UserID=...
        if not result.get("epg_user_id"):
            m = re.search(r"/EDS/jsp/AuthenticationURL[^\r\n]*[?&]UserID=([^&\s\r\n/]+)", text)
            if m:
                uid = urllib.parse.unquote(m.group(1)).strip()
                if uid:
                    result["epg_user_id"] = uid
                    result.setdefault("epg_auth_host", f"{dst_ip}:{dst_port}")
        # STBID from POST body to ValidAuthenticationHWCTC
        if not result.get("epg_stb_id"):
            if "ValidAuthenticationHWCTC" in text or "authLoginHWCTC" in text:
                m = re.search(r"[?&]?STBID=([^&\s\r\n]+)", text)
                if m:
                    stbid = urllib.parse.unquote(m.group(1)).strip()
                    if stbid:
                        result["epg_stb_id"] = stbid
                result.setdefault("epg_auth_host", f"{dst_ip}:{dst_port}")
        # EPG host from any /EPG/jsp/ or /EDS/jsp/ request
        if not result.get("epg_auth_host"):
            if b"/EPG/jsp/" in data or b"/EDS/jsp/" in data:
                result["epg_auth_host"] = f"{dst_ip}:{dst_port}"
    return result


def _detect_timeshift_host(streams: dict[Any, bytes], channels: list[dict[str, Any]]) -> str:
    """Return first timeshift server host:port found in channels or HTTP traffic."""
    # 1. Check backtv_url field captured from channel list (may be rtsp:// or http://)
    for ch in channels:
        url = ch.get("backtv_url", "")
        if url:
            m = re.match(r"(?:https?|rtsp)://([\d.]+(?::\d+)?)/", url)
            if m:
                return m.group(1)
    # 2. Scan all HTTP traffic bodies for timeshift URLs
    for raw in streams.values():
        m = _TIMESHIFT_URL_RE.search(raw)
        if m:
            return m.group(1).decode("utf-8", errors="replace")
    return ""




def analyze_pcap_for_channels(pcap_path: str, stb_ip: str) -> list[dict[str, Any]]:
    """Main analysis entry point: returns channel list extracted from pcap."""
    streams = _reassemble_tcp_streams(pcap_path)

    # Find all response streams (server -> STB)
    response_streams = {
        k: v
        for k, v in streams.items()
        if k[2] == stb_ip and k[0] != stb_ip
    }

    all_channels: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for key, raw in response_streams.items():
        responses = _split_http_responses(raw)
        for headers, body in responses:
            if not body:
                continue
            # Look for getchannellistHWCU.jsp response (has CUSetConfig Channel calls)
            if b"CUSetConfig('Channel'" in body or b'CUSetConfig("Channel"' in body:
                parsed = _parse_chanlist_html(body)
                for ch in parsed:
                    k = f"{ch['ip']}:{ch['port']}"
                    if k not in seen_keys:
                        seen_keys.add(k)
                        all_channels.append(ch)
            # Look for VSP JSON channel list
            elif b'"channelDetails"' in body and b'"channelNO"' in body:
                parsed = _parse_vsp_json(body)
                for ch in parsed:
                    k = f"{ch['ip']}:{ch['port']}"
                    if k not in seen_keys:
                        seen_keys.add(k)
                        all_channels.append(ch)

    all_channels.sort(key=lambda x: x["num"])
    return all_channels


class StbDiscoveryService:
    STATUS_IDLE = "idle"
    STATUS_CAPTURING = "capturing"
    STATUS_ANALYZING = "analyzing"
    STATUS_DONE = "done"
    STATUS_ERROR = "error"

    def __init__(self, logger: AppLogger) -> None:
        self.logger = logger
        self._lock = threading.RLock()
        self._state: dict[str, Any] = {
            "status": self.STATUS_IDLE,
            "stb_ip": None,
            "interface": None,
            "started_at": None,
            "stopped_at": None,
            "error": None,
            "channels": [],
            "channel_count": 0,
            "auth_info": {},
        }
        self._proc: subprocess.Popen | None = None
        self._pcap_path: str | None = None
        self._worker_thread: threading.Thread | None = None

    def _live_watcher(self, pcap_path: str, stb_ip: str) -> None:
        while True:
            time.sleep(3)
            with self._lock:
                if self._state["status"] != self.STATUS_CAPTURING:
                    break
            try:
                channels = analyze_pcap_for_channels(pcap_path, stb_ip)
                auth_info = _extract_dhcp_from_pcap(pcap_path)
                has_auth = bool(auth_info.get("mac") or auth_info.get("assigned_ip"))
                with self._lock:
                    if self._state["status"] == self.STATUS_CAPTURING:
                        self._state["live_channel_count"] = len(channels)
                        self._state["live_has_auth"] = has_auth
            except Exception:
                pass

    def runtime_check(self) -> dict[str, Any]:
        ok = shutil.which("tcpdump") is not None
        return {"ok": ok, "errors": [] if ok else ["缺少依赖命令：tcpdump"]}

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._state)

    def start(self, stb_ip: str, interface: str = "any") -> None:
        rt = self.runtime_check()
        if not rt["ok"]:
            raise RuntimeError("；".join(rt["errors"]))
        with self._lock:
            if self._state["status"] == self.STATUS_CAPTURING:
                raise RuntimeError("已有一个捕获任务正在进行")
            self._pcap_path = tempfile.mktemp(suffix=".pcap", prefix="stb_discovery_")
            self._state = {
                "status": self.STATUS_CAPTURING,
                "stb_ip": stb_ip,
                "interface": interface,
                "started_at": time.time(),
                "stopped_at": None,
                "error": None,
                "channels": [],
                "channel_count": 0,
                "live_channel_count": 0,
                "live_has_auth": False,
                "auth_info": {},
            }
        cmd = [
            "tcpdump",
            "-i", interface,
            "-s", "0",
            "-w", self._pcap_path,
            f"(host {stb_ip} and tcp) or (udp and (port 67 or port 68))",
        ]
        self.logger.info(f"开始捕获 STB 开机流量：STB={stb_ip}，接口={interface}，文件={self._pcap_path}")
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as exc:
            with self._lock:
                self._state["status"] = self.STATUS_ERROR
                self._state["error"] = str(exc)
            raise
        threading.Thread(
            target=self._live_watcher,
            args=(self._pcap_path, stb_ip),
            daemon=True,
            name="stb-live-watcher",
        ).start()

    def stop(self) -> dict[str, Any]:
        proc = None
        pcap_path = None
        stb_ip = None
        with self._lock:
            if self._state["status"] != self.STATUS_CAPTURING:
                return dict(self._state)
            proc = self._proc
            pcap_path = self._pcap_path
            stb_ip = self._state["stb_ip"]
            self._state["status"] = self.STATUS_ANALYZING
            self._state["stopped_at"] = time.time()

        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        def _analyze() -> None:
            try:
                time.sleep(0.5)  # let pcap flush
                channels: list[dict[str, Any]] = []
                auth_info: dict[str, Any] = {}
                timeshift_host: str = ""
                epg_creds: dict[str, str] = {}
                if pcap_path and os.path.exists(pcap_path):
                    streams = _reassemble_tcp_streams(pcap_path)
                    channels = analyze_pcap_for_channels(pcap_path, stb_ip or "")
                    timeshift_host = _detect_timeshift_host(streams, channels)
                    auth_info = _extract_dhcp_from_pcap(pcap_path)
                    epg_creds = _extract_epg_credentials(streams, stb_ip or "")
                    try:
                        os.unlink(pcap_path)
                    except Exception:
                        pass
                with self._lock:
                    self._state["status"] = self.STATUS_DONE
                    self._state["channels"] = channels
                    self._state["channel_count"] = len(channels)
                    self._state["auth_info"] = auth_info
                    self._state["timeshift_host"] = timeshift_host
                    self._state["epg_creds"] = epg_creds
                has_auth = bool(auth_info.get("mac") or auth_info.get("assigned_ip"))
                self.logger.info(
                    f"STB 频道发现完成：共发现 {len(channels)} 个频道，"
                    f"认证信息：{'已提取（MAC=' + auth_info.get('mac','') + '）' if has_auth else '未捕获到 DHCP'}"
                    + (f"，EPG 认证信息：UserID={epg_creds.get('epg_user_id','')} STBID={epg_creds.get('epg_stb_id','')} Host={epg_creds.get('epg_auth_host','')}" if epg_creds else "")
                )
            except Exception as exc:
                self.logger.error(f"STB 频道发现分析失败：{exc}")
                with self._lock:
                    self._state["status"] = self.STATUS_ERROR
                    self._state["error"] = str(exc)

        t = threading.Thread(target=_analyze, daemon=True)
        t.start()
        with self._lock:
            return dict(self._state)

    def reset(self) -> None:
        with self._lock:
            if self._proc:
                try:
                    self._proc.terminate()
                except Exception:
                    pass
                self._proc = None
            if self._pcap_path and os.path.exists(self._pcap_path or ""):
                try:
                    os.unlink(self._pcap_path)
                except Exception:
                    pass
                self._pcap_path = None
            self._state = {
                "status": self.STATUS_IDLE,
                "stb_ip": None,
                "interface": None,
                "started_at": None,
                "stopped_at": None,
                "error": None,
                "channels": [],
                "channel_count": 0,
                "auth_info": {},
            }
