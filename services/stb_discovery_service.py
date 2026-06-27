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
        "vendor_class": opts_req[60].hex() if 60 in opts_req else "",
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
        group_name = (
            pairs.get("GroupName") or pairs.get("ChannelGroupName") or pairs.get("ChannelGroup") or
            pairs.get("CategoryName") or pairs.get("Category") or pairs.get("ChannelTypeName") or ""
        ).strip()
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
                "category": _channel_category_from_group(group_name, chan_name),
                "operator_group": _clean_group_name(group_name),
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
        group_name = str(ch.get("groupName") or ch.get("subjectName") or ch.get("categoryName") or "").strip()
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
                            "category": _channel_category_from_group(group_name, name),
                            "operator_group": _clean_group_name(group_name),
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


def _decode_payload_text(body: bytes) -> str:
    """Decode STB HTTP payloads that may be UTF-8 or GB18030."""
    for encoding in ("utf-8", "gb18030"):
        try:
            return body.decode(encoding)
        except UnicodeDecodeError:
            continue
    return body.decode("utf-8", errors="replace")


def _safe_int(value: Any) -> int | None:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 65535 else None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "2", "true", "yes", "y", "on", "enable", "enabled"}


def _first_text(obj: dict[str, Any], *keys: str) -> str:
    lowered = {str(k).lower(): v for k, v in obj.items()}
    for key in keys:
        val = lowered.get(key.lower())
        if val not in (None, ""):
            return str(val).strip()
    return ""


def _first_int(obj: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = _first_text(obj, key)
        number = _safe_int(value)
        if number is not None:
            return number
    return None


def _clean_group_name(value: str) -> str:
    group = re.sub(r"[\x00-\x1f\x7f]+", "", str(value or "")).strip()
    group = re.sub(r"\s+", " ", group).strip(" ,;，；/\\")
    return group[:40]


def _channel_category_from_group(group: str, name: str) -> str:
    raw = _clean_group_name(group)
    if raw:
        upper = raw.upper()
        if "CCTV" in upper or "央视" in raw or "中央" in raw:
            return "央视频道"
        if "卫视" in raw:
            return "卫视频道"
        if raw in {"央视频道", "卫视频道", "其它频道"}:
            return raw
        return raw
    return "其它频道" if not name else _fallback_classify_channel_name(name)


def _fallback_classify_channel_name(name: str) -> str:
    normalized = str(name or "").strip().upper()
    if not normalized:
        return "其它频道"
    if "CCTV" in normalized or "央视" in name or "中央" in name:
        return "央视频道"
    if "卫视" in name:
        return "卫视频道"
    return "其它频道"


def _parse_multicast_url(url: str) -> tuple[str, int]:
    match = re.search(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", str(url or ""), re.IGNORECASE)
    return (match.group(1), int(match.group(2))) if match else ("", 0)


def _parse_stream_params(ch: dict[str, Any]) -> tuple[str, int | None, int | None]:
    """Extract FCC/FEC params from direct fields, query strings, or SDP snippets."""
    fcc_ip = _first_text(ch, "channelFCCIP", "ChannelFCCIP", "fccIP", "fcc_ip")
    fcc_port = _first_int(ch, "channelFCCPort", "ChannelFCCPort", "fccPort", "fcc_port")
    fec_port = _first_int(ch, "channelFECPort", "ChannelFECPort", "fecPort", "fec_port")
    raw_parts = [
        _first_text(ch, "channelURL", "ChannelURL", "url", "mediaURL", "broadcastURL"),
        _first_text(ch, "channelSDP", "ChannelSDP", "sdp"),
    ]
    for raw in raw_parts:
        if not raw:
            continue
        parsed = urllib.parse.urlparse(raw)
        query = urllib.parse.parse_qs(parsed.query)
        if not fcc_ip:
            fcc_val = (query.get("fcc") or [""])[0]
            if ":" in fcc_val:
                fcc_ip = fcc_val.split(":", 1)[0].strip()
                if fcc_port is None:
                    fcc_port = _safe_int(fcc_val.split(":", 1)[1])
            else:
                fcc_ip = (query.get("ChannelFCCIP") or query.get("fcc_ip") or [""])[0].strip()
        if fcc_port is None:
            fcc_port = _safe_int((query.get("ChannelFCCPort") or query.get("fcc_port") or [""])[0])
        if fec_port is None:
            fec_port = _safe_int((query.get("fec") or query.get("ChannelFECPort") or query.get("fec_port") or [""])[0])
        if not fcc_ip:
            m = re.search(r"(?:ChannelFCCIP|fcc[_-]?ip)\s*[=:]\s*([0-9.]+)", raw, re.IGNORECASE)
            if m:
                fcc_ip = m.group(1)
        if fcc_port is None:
            m = re.search(r"(?:ChannelFCCPort|fcc[_-]?port)\s*[=:]\s*(\d{1,5})", raw, re.IGNORECASE)
            if m:
                fcc_port = _safe_int(m.group(1))
        if fec_port is None:
            m = re.search(r"(?:ChannelFECPort|fec[_-]?port)\s*[=:]\s*(\d{1,5})", raw, re.IGNORECASE)
            if m:
                fec_port = _safe_int(m.group(1))
    return fcc_ip, fcc_port, fec_port


def _iter_channel_dicts(data: Any):
    """Yield likely channel entries from regional JSON payloads."""
    if isinstance(data, dict):
        for key in (
            "channleInfoStruct",  # Beijing Unicom / Hisense IP811N typo
            "channelInfoStruct",
            "channelDetails",
            "channelList",
            "channels",
            "ChannelList",
        ):
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
        for value in data.values():
            if isinstance(value, (dict, list)):
                yield from _iter_channel_dicts(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                if any(k.lower() in {"channelurl", "channelname", "channelid", "userchannelid"} for k in item):
                    yield item
                else:
                    yield from _iter_channel_dicts(item)
            elif isinstance(item, list):
                yield from _iter_channel_dicts(item)


def _extract_channel_objects_from_partial_json(text: str) -> list[dict[str, Any]]:
    """Extract individual channel JSON objects from truncated or malformed JSON.

    Used when the HTTP response headers and the opening of the JSON array are
    missing (e.g. the first N TCP segments were not captured).  Uses brace
    counting so each top-level ``{\u2026}`` object is extracted and parsed
    independently; objects that look like channel entries are returned.
    """
    result: list[dict[str, Any]] = []
    depth = 0
    start = -1
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    obj_text = text[start : i + 1]
                    try:
                        obj = json.loads(obj_text)
                    except Exception:
                        start = -1
                        continue
                    if isinstance(obj, dict) and any(
                        k.lower() in {
                            "channelurl", "channelname", "channelid", "userchannelid"
                        }
                        for k in obj
                    ):
                        result.append(obj)
                    start = -1
    return result


def _parse_channel_acquire_json(body: bytes) -> list[dict[str, Any]]:
    """Parse Beijing Unicom /bj_stb/V1/STB/channelAcquire channel list JSON."""
    text = _decode_payload_text(body).lstrip("\ufeff").strip()
    # Strip HTTP chunked transfer-encoding size lines embedded in body fragments
    # (e.g. "\r\n2000\r\n" appearing mid-string when first TCP segments are missing).
    text = re.sub(r"\r\n[0-9a-fA-F]{1,8}\r\n", "", text)
    if not text or "channel" not in text.lower():
        return []

    data: Any = None
    try:
        data = json.loads(text)
    except Exception:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start : end + 1])
            except Exception:
                pass

    if data is None:
        # Last resort: brace-counted per-object extraction for partially captured
        # responses where the JSON array opening is in the missing TCP segments.
        channel_list = _extract_channel_objects_from_partial_json(text)
        if not channel_list:
            return []
        data = channel_list  # treat as a flat list of channel dicts

    channels: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ch in _iter_channel_dicts(data):
        name = _first_text(ch, "channelName", "ChannelName", "name", "Name")
        channel_url = _first_text(ch, "channelURL", "ChannelURL", "url", "mediaURL", "broadcastURL")
        ip, port = _parse_multicast_url(channel_url)
        if not ip or not port:
            ip, port = _parse_multicast_url(_first_text(ch, "channelSDP", "ChannelSDP", "sdp"))
        if not ip or not port or not name:
            continue
        key = f"{ip}:{port}"
        if key in seen:
            continue
        seen.add(key)
        user_chan_id = _first_text(ch, "userChannelID", "UserChannelID", "channelNO", "channelNum", "num")
        channel_id = _first_text(ch, "channelID", "ChannelID", "id", "ID")
        time_shift_days = _first_int(ch, "timeShiftLength", "TimeShiftLength", "timeShiftDuration")
        fcc_ip, fcc_port, fec_port = _parse_stream_params(ch)
        group_name = _first_text(
            ch,
            "groupName",
            "GroupName",
            "channelGroup",
            "ChannelGroup",
            "channelGroupName",
            "ChannelGroupName",
            "category",
            "Category",
            "categoryName",
            "CategoryName",
            "channelTypeName",
            "ChannelTypeName",
            "subjectName",
            "SubjectName",
            "genre",
            "Genre",
        )
        channels.append({
            "num": int(user_chan_id) if user_chan_id.isdigit() else 0,
            "name": name,
            "category": _channel_category_from_group(group_name, name),
            "operator_group": _clean_group_name(group_name),
            "ip": ip,
            "port": port,
            "channel_id": channel_id,
            "user_channel_id": user_chan_id,
            "is_hd": _truthy(_first_text(ch, "isHDChannel", "IsHDChannel", "isHD", "hd")),
            "time_shift": _truthy(_first_text(ch, "timeShift", "TimeShift", "timeshift")),
            "time_shift_days": time_shift_days,
            "fcc_ip": fcc_ip,
            "fcc_port": fcc_port,
            "fec_port": fec_port,
            "backtv_url": _first_text(ch, "timeShiftURL", "TimeShiftURL", "backtvURL", "BacktimeURL", "BackUrl"),
        })
    channels.sort(key=lambda x: (x["num"] or 9999, x["name"], x["ip"], x["port"]))
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


def _extract_ctc_portal_auth(streams: dict[Any, bytes], stb_ip: str) -> dict[str, Any]:
    """Extract CTC portal auth crumbs from STB boot traffic.

    Enshan's Jiangsu Telecom flow obtains a portal UserToken through:
    CTCGetAuthInfo -> Authenticator -> /uploadAuthInfo.  We do not actively
    replay that regional flow here; this parser only records values already
    visible in STB traffic so the Web UI can show whether they were captured.
    """
    result: dict[str, Any] = {}
    if not stb_ip:
        return result

    def _host_from_request(text: str) -> str:
        m = re.search(r"(?im)^Host:\s*([^\r\n]+)", text)
        return m.group(1).strip() if m else ""

    def _header(text: str, name: str) -> str:
        m = re.search(rf"(?im)^{re.escape(name)}:\s*([^\r\n]+)", text)
        return m.group(1).strip() if m else ""

    def _remember_server(dst_ip: str, dst_port: int, text: str) -> None:
        if not result.get("portal_auth_host"):
            result["portal_auth_host"] = _host_from_request(text) or f"{dst_ip}:{dst_port}"
        result.setdefault("server_ip", dst_ip)
        result.setdefault("server_port", dst_port)

    for (src_ip, _src_port, dst_ip, dst_port), raw in streams.items():
        if src_ip != stb_ip:
            continue
        text = _decode_payload_text(raw)
        if "/auth?" in text or "/uploadAuthInfo" in text or "/getServiceList" in text or "/iptvepg/" in text:
            _remember_server(dst_ip, dst_port, text)
        if "/bj_stb/V1/STB/channelAcquire" in text or "channelAcquire" in text:
            _remember_server(dst_ip, dst_port, text)
            if not result.get("token_path"):
                m = re.search(r"(?im)^(?:POST|GET)\s+([^\s]+channelAcquire[^\s]*)", text)
                result["token_path"] = m.group(1).strip() if m else "/bj_stb/V1/STB/channelAcquire"
            if not result.get("user_token"):
                m = re.search(r'"UserToken"\s*:\s*"([^"]+)"', text)
                if m:
                    result["user_token"] = m.group(1).strip()
        if not result.get("epg_user_agent"):
            ua = _header(text, "User-Agent")
            if ua:
                result["epg_user_agent"] = ua
                if not result.get("epg_stb_type"):
                    stb_model = re.search(r"\b(?:IP811N|[A-Z]{2,}\d{3,}[A-Z0-9]*)\b", ua)
                    if stb_model:
                        result["epg_stb_type"] = stb_model.group(0)
        if not result.get("epg_user_id"):
            m = re.search(r"(?:/auth[^\r\n]*[?&]UserID=|[?&]UserID=)([^&\s\r\n]+)", text)
            if not m:
                m = re.search(r'"(?:UserID|userID|userId)"\s*:\s*"([^"]+)"', text)
            if m:
                result["epg_user_id"] = urllib.parse.unquote(m.group(1)).strip()
        if not result.get("epg_stb_id"):
            m = re.search(r"[?&]STBID=([^&\s\r\n]+)", text)
            if m:
                result["epg_stb_id"] = urllib.parse.unquote(m.group(1)).strip()
        if not result.get("access_user_name"):
            m = re.search(r"[?&]AccessUserName=([^&\s\r\n]+)", text)
            if m:
                result["access_user_name"] = urllib.parse.unquote(m.group(1)).strip()
        if not result.get("epg_stb_type"):
            m = re.search(r"[?&]STBType=([^&\s\r\n]+)", text)
            if m:
                result["epg_stb_type"] = urllib.parse.unquote(m.group(1)).strip()
        if not result.get("epg_stb_version"):
            m = re.search(r"[?&]STBVersion=([^&\s\r\n]+)", text)
            if m:
                result["epg_stb_version"] = urllib.parse.unquote(m.group(1)).strip()
        if "/uploadAuthInfo" in text:
            result.setdefault("token_path", "/uploadAuthInfo")

    for (src_ip, src_port, dst_ip, _dst_port), raw in streams.items():
        if dst_ip != stb_ip:
            continue
        headers_bodies = _split_http_responses(raw)
        chunks = []
        if headers_bodies:
            for headers, body in headers_bodies:
                chunks.append(headers)
                chunks.append(body.decode("utf-8", errors="replace"))
        else:
            chunks.append(_decode_payload_text(raw))
        for text in chunks:
            if not result.get("ctc_auth_info"):
                m = re.search(r"CTCGetAuthInfo\(['\"]([^'\"]+)['\"]\)", text)
                if m:
                    result["ctc_auth_info"] = m.group(1).strip()
                    result.setdefault("server_ip", src_ip)
                    result.setdefault("server_port", src_port)
            if not result.get("user_token"):
                m = re.search(r"(?im)^Set-Cookie:\s*UserToken=([^;\r\n]+)", text)
                if not m:
                    m = re.search(r"CTCSetConfig\s*\(\s*['\"]UserToken['\"]\s*,\s*['\"]([^'\"]+)['\"]", text)
                if not m:
                    m = re.search(r'"(?:userToken|UserToken)"\s*:\s*"([^"]+)"', text)
                if m:
                    result["user_token"] = urllib.parse.unquote(m.group(1)).strip()
                    result.setdefault("token_path", "/uploadAuthInfo")
                    result.setdefault("server_ip", src_ip)
                    result.setdefault("server_port", src_port)
            if not result.get("epg_auth_host"):
                m = re.search(r'"epgDomain"\s*:\s*"(https?://[^"/]+(?::\d+)?)', text)
                if m:
                    result["epg_auth_host"] = urllib.parse.urlparse(m.group(1)).netloc
            if not result.get("token_expired_time"):
                m = re.search(r'"tokenExpiredTime"\s*:\s*"([^"]+)"', text)
                if m:
                    result["token_expired_time"] = m.group(1).strip()
            if not result.get("x_frame_session_id"):
                m = re.search(r"(?im)^X-Frame-Sessionid:\s*([^\r\n]+)", text)
                if m:
                    result["x_frame_session_id"] = m.group(1).strip()
                    result.setdefault("server_ip", src_ip)
                    result.setdefault("server_port", src_port)
    return result




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
            # Beijing Unicom / Hisense IP811N channelAcquire JSON response
            # uses the misspelled channleInfoStruct field.
            if (
                b"channleInfoStruct" in body
                or b"channelInfoStruct" in body
                or (b"channelURL" in body and b"channelName" in body)
            ):
                parsed = _parse_channel_acquire_json(body)
                for ch in parsed:
                    k = f"{ch['ip']}:{ch['port']}"
                    if k not in seen_keys:
                        seen_keys.add(k)
                        all_channels.append(ch)
            # Look for getchannellistHWCU.jsp response (has CUSetConfig Channel calls)
            elif b"CUSetConfig('Channel'" in body or b'CUSetConfig("Channel"' in body:
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

        # Fallback: no complete HTTP responses found in this stream, but the raw
        # bytes contain channel URL data.  This happens when the first TCP
        # segments of the response (carrying HTTP headers + JSON array opening)
        # were not captured, leaving only the body fragment starting mid-array.
        if not responses and b"channelURL" in raw and b"channelName" in raw:
            parsed = _parse_channel_acquire_json(raw)
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

    def __init__(self, logger: AppLogger, token_store: Any | None = None) -> None:
        self.logger = logger
        self.token_store = token_store
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

    def _pcap_meta_locked(self) -> dict[str, Any]:
        path = self._pcap_path
        if not path or not os.path.exists(path):
            return {"pcap_available": False, "pcap_size": 0}
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        return {"pcap_available": size > 0, "pcap_size": size}

    def pcap_path(self) -> str:
        with self._lock:
            path = self._pcap_path or ""
            if path and os.path.exists(path):
                return path
            return ""

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
            state = dict(self._state)
            state.update(self._pcap_meta_locked())
            return state

    def start(self, stb_ip: str, interface: str = "any") -> None:
        rt = self.runtime_check()
        if not rt["ok"]:
            raise RuntimeError("；".join(rt["errors"]))
        with self._lock:
            if self._state["status"] == self.STATUS_CAPTURING:
                raise RuntimeError("已有一个捕获任务正在进行")
            if self._pcap_path and os.path.exists(self._pcap_path):
                try:
                    os.unlink(self._pcap_path)
                except Exception:
                    pass
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
                "pcap_available": False,
                "pcap_size": 0,
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
                portal_auth: dict[str, Any] = {}
                if pcap_path and os.path.exists(pcap_path):
                    streams = _reassemble_tcp_streams(pcap_path)
                    channels = analyze_pcap_for_channels(pcap_path, stb_ip or "")
                    timeshift_host = _detect_timeshift_host(streams, channels)
                    auth_info = _extract_dhcp_from_pcap(pcap_path)
                    epg_creds = _extract_epg_credentials(streams, stb_ip or "")
                    portal_auth = _extract_ctc_portal_auth(streams, stb_ip or "")
                    if portal_auth.get("epg_user_id") and not epg_creds.get("epg_user_id"):
                        epg_creds["epg_user_id"] = str(portal_auth.get("epg_user_id") or "")
                    if portal_auth.get("epg_stb_id") and not epg_creds.get("epg_stb_id"):
                        epg_creds["epg_stb_id"] = str(portal_auth.get("epg_stb_id") or "")
                    if portal_auth.get("portal_auth_host") and not epg_creds.get("epg_auth_host"):
                        epg_creds["epg_auth_host"] = str(portal_auth.get("portal_auth_host") or "")
                    for key in ("epg_user_agent", "epg_stb_type", "epg_stb_version", "access_user_name"):
                        if portal_auth.get(key) and not epg_creds.get(key):
                            epg_creds[key] = str(portal_auth.get(key) or "")
                    token = str(portal_auth.get("user_token") or "").strip()
                    if token and self.token_store:
                        self.token_store.save_token({
                            "token": token,
                            "sip": stb_ip or "",
                            "sport": None,
                            "dip": portal_auth.get("server_ip", ""),
                            "dport": portal_auth.get("server_port"),
                            "path": portal_auth.get("token_path") or "/uploadAuthInfo",
                            "captured_at": int(time.time()),
                        })
                    # Keep the latest pcap for one-click export. Reset or a new capture removes it.
                safe_portal_auth: dict[str, Any] = {}
                for key in ("portal_auth_host", "server_ip", "server_port", "token_path"):
                    if portal_auth.get(key):
                        safe_portal_auth[key] = portal_auth[key]
                safe_portal_auth["has_ctc_auth_info"] = bool(portal_auth.get("ctc_auth_info"))
                safe_portal_auth["has_upload_user_token"] = bool(portal_auth.get("user_token"))
                safe_portal_auth["has_x_frame_session_id"] = bool(portal_auth.get("x_frame_session_id"))
                with self._lock:
                    self._state["status"] = self.STATUS_DONE
                    self._state["channels"] = channels
                    self._state["channel_count"] = len(channels)
                    self._state["auth_info"] = auth_info
                    self._state["timeshift_host"] = timeshift_host
                    self._state["epg_creds"] = epg_creds
                    self._state["portal_auth"] = safe_portal_auth
                    self._state.update(self._pcap_meta_locked())
                has_auth = bool(auth_info.get("mac") or auth_info.get("assigned_ip"))
                self.logger.info(
                    f"STB 频道发现完成：共发现 {len(channels)} 个频道，"
                    f"认证信息：{'已提取（MAC=' + auth_info.get('mac','') + '）' if has_auth else '未捕获到 DHCP'}"
                    + (f"，EPG 认证信息：UserID={epg_creds.get('epg_user_id','')} STBID={epg_creds.get('epg_stb_id','')} Host={epg_creds.get('epg_auth_host','')}" if epg_creds else "")
                    + (f"，CTC门户：CTCGetAuthInfo={'已捕获' if portal_auth.get('ctc_auth_info') else '未捕获'} UserToken={'已捕获' if portal_auth.get('user_token') else '未捕获'}" if portal_auth else "")
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
                "pcap_available": False,
                "pcap_size": 0,
            }
