#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STB boot capture and channel list discovery via tcpdump + TCP stream reassembly."""
from __future__ import annotations
from services.io_limits import iter_pcap_packets, gunzip_bounded, MAX_PCAP_BYTES

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
from services.media_task_service import reap_process
from collections import deque


def _probe_tcpdump_interfaces():
    result = subprocess.run(["tcpdump", "-D"], capture_output=True, text=True, timeout=5, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "tcpdump 无法列出接口")
    return result.stdout


def _capture_diagnostics(path, stb_ip, streams, channels, mac=""):
    count, seen, supported = 0, 0, None
    target = bytes.fromhex(mac.replace(":", "")) if mac else b""
    if path and Path(path).exists():
        for linktype, packet in iter_pcap_packets(path):
            count += 1
            supported = linktype == 1
            if target and supported and len(packet) >= 14 and target in (packet[:6], packet[6:12]):
                seen += 1
    result = {"pcap_size": Path(path).stat().st_size if path and Path(path).exists() else 0,
            "packet_count": count, "stream_count": len(streams),
            "matched_response_streams": sum(1 for key in streams if key[2] == stb_ip and key[0] != stb_ip),
            "channels": len(channels), "effective_stb_ip": stb_ip}
    if mac:
        result.update(mac_requested=mac, mac_supported=supported is True,
                      mac_not_seen=supported is True and seen == 0)
        if supported:
            result["mac_seen_count"] = seen
    return result


def _validate_mac_filter(interface, expression):
    if interface.lower() == "any":
        raise ValueError("按 MAC 过滤需要以太网接口，请选择实际接口；any 可用于按 IP 或全量捕获")
    # Compiles for the interface's actual DLT without starting a capture.
    result = subprocess.run(["tcpdump", "-i", interface, "-d", expression],
                            capture_output=True, text=True, timeout=5, check=False)
    if result.returncode:
        raise ValueError(f"该接口无法使用 MAC 过滤：{result.stderr.strip()[-2048:]}")


def _capture_identity(path, requested_ip, mac):
    auth = _extract_dhcp_from_pcap(path, requested_ip, mac)
    # A matched ACK proves assignment; a request or offer alone does not.
    effective_ip = auth.get("assigned_ip") if mac and auth.get("lease_confirmed") else requested_ip
    return effective_ip or "", auth


def _parse_ip(data: bytes, off: int) -> str:
    return ".".join(str(b) for b in data[off : off + 4])


_MAC_PLAIN = re.compile(r"^[0-9a-fA-F]{12}$")
_MAC_COLON = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_MAC_DASH = re.compile(r"^[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}$")
_MAC_CISCO = re.compile(r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$")


def normalize_mac(value: str | None) -> str:
    """把常见 MAC 写法统一成小写冒号分隔；空值返回空串。

    接受 `aa:bb:cc:dd:ee:ff`、`aa-bb-cc-dd-ee-ff` 与 Cisco 风格 `aabb.ccdd.eeff`。
    格式非法时抛 ValueError，避免把 tcpdump 语法错误的表达式交给它——
    那会让 tcpdump 启动即退出，而旧实现不会报告任何原因。
    """
    text = str(value or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if _MAC_COLON.match(lowered):
        return lowered
    if _MAC_DASH.match(lowered):
        return lowered.replace("-", ":")
    if _MAC_CISCO.match(lowered):
        compact = lowered.replace(".", "")
        return ":".join(compact[i : i + 2] for i in range(0, 12, 2))
    if _MAC_PLAIN.match(lowered):
        return ":".join(lowered[i : i + 2] for i in range(0, 12, 2))
    raise ValueError(
        f"MAC 地址格式无效：{value!r}（示例：48:57:02:25:bb:e3、48-57-02-25-bb-e3 或 4857.0225.bbe3）"
    )


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
    msg_type = (options.get(53) or b"\x00")[0]
    return {"op": op, "xid": xid, "yiaddr": yiaddr, "mac": mac,
            "ciaddr": _parse_ip(payload, 12), "msg_type": msg_type, "options": options}


def _extract_dhcp_from_pcap(pcap_path: str, stb_ip: str = "", stb_mac: str = "") -> dict[str, Any]:
    """Extract STB DHCP auth info from a pcap file."""
    _VLAN_ETYPES = {0x8100, 0x88A8, 0x9100}
    _DLT_LINUX_SLL = 113
    _DLT_LINUX_SLL2 = 276
    requests: dict[tuple[int, str], dict] = {}
    responses: dict[tuple[int, str], dict] = {}
    for packet_index, (linktype, pkt) in enumerate(iter_pcap_packets(pcap_path)):
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
        if stb_mac and parsed["mac"] != stb_mac:
            continue
        parsed["observed_order"] = packet_index
        # Transaction IDs alone can collide across different clients.
        xid = (parsed["xid"], parsed["mac"])
        if parsed["op"] == 1:
            previous = requests.get(xid)
            if not previous or parsed["msg_type"] == 3:
                requests[xid] = parsed
        elif parsed["op"] == 2:
            previous = responses.get(xid)
            if not previous or parsed["msg_type"] in (5, 6):
                responses[xid] = parsed

    candidates = []
    for xid, req in requests.items():
        resp = responses.get(xid)
        if resp and resp["msg_type"] == 6:  # A rejected lease is not an identity match.
            continue
        requested = req["options"].get(50, b"")
        requested_ip = ".".join(str(b) for b in requested) if len(requested) == 4 else ""
        assigned = resp["yiaddr"] if resp else ""
        known_ip = assigned if assigned and assigned != "0.0.0.0" else requested_ip or req["ciaddr"]
        if not stb_mac and stb_ip and known_ip != stb_ip:
            continue
        candidates.append((req, resp))
    # Without a unique terminal identity, do not autofill another device's MAC.
    if not candidates or len({req["mac"] for req, _ in candidates}) != 1:
        return {}
    best_req, best_resp = max(candidates, key=lambda pair: (
        int(bool(pair[1] and pair[1]["msg_type"] == 5)), (pair[1] or pair[0])["observed_order"]))

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
        "lease_confirmed": bool(best_resp and best_resp["msg_type"] == 5 and assigned_ip),
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
                body = gunzip_bounded(body, 16 * 1024 * 1024)
            except Exception:
                pass
        responses.append((headers_str, body))
        i = next_i
    return responses


def _iter_http_requests(raw: bytes) -> list[tuple[str, str, bytes, list[str], list[str]]]:
    """Return complete HTTP requests with only cookie *names* as metadata.

    The raw request is deliberately returned as bytes so it can be preserved
    in the private STB evidence archive.  Callers must never place it in an
    API response, log line, or global JSON backup because forms may contain
    Authenticator, UserToken, and passwords.
    """
    found: list[tuple[str, str, bytes, list[str], list[str]]] = []
    cursor = 0
    request_re = re.compile(br"(?:GET|POST)\s+([^\s]+)\s+HTTP/[0-9.]+\r\n")
    while cursor < len(raw):
        match = request_re.search(raw, cursor)
        if not match:
            break
        start = match.start()
        header_end = raw.find(b"\r\n\r\n", start)
        if header_end < 0:
            break
        header_text = raw[start:header_end].decode("latin1", errors="replace")
        lines = header_text.split("\r\n")
        first = lines[0].split()
        method = first[0] if first else ""
        path = first[1] if len(first) > 1 else ""
        content_length = 0
        cookie_names: list[str] = []
        header_names: list[str] = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            name = name.strip().lower()
            header_names.append(name)
            if name == "content-length":
                try:
                    content_length = max(0, int(value.strip()))
                except ValueError:
                    content_length = 0
            elif name == "cookie":
                cookie_names.extend(
                    item.split("=", 1)[0].strip()
                    for item in value.split(";") if "=" in item
                )
        end = header_end + 4 + content_length
        if end > len(raw):
            cursor = header_end + 4
            continue
        found.append((method, path, raw[start:end], sorted(set(cookie_names)), header_names))
        cursor = end
    return found


def _response_cookie_names(raw: bytes) -> list[str]:
    """Extract only cookie names from a raw server stream for safe manifests."""
    names: list[str] = []
    for headers, _body in _split_http_responses(raw):
        for line in headers.split("\r\n")[1:]:
            if line.lower().startswith("set-cookie:") and "=" in line:
                names.append(line.split(":", 1)[1].strip().split("=", 1)[0])
    return sorted(set(name for name in names if name))


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
    total_payload = 0
    total_segments = 0
    for linktype, pkt in iter_pcap_packets(pcap_path):
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
        if key not in stream_seqs and len(stream_seqs) >= 4096:
            raise ValueError("TCP 流数量超过 4096 上限")
        seqs = stream_seqs.setdefault(key, {})
        # A partial retransmission can arrive before the full segment.
        # Keep the longest payload for a sequence number; keeping the
        # first packet caused form fields (STBID/STBType/STBVersion) to
        # disappear from otherwise complete boot captures.
        if seq not in seqs or len(payload) > len(seqs[seq]):
            total_payload += len(payload) - len(seqs.get(seq, b""))
            total_segments += int(seq not in seqs)
            if total_payload > 32 * 1024 * 1024 or total_segments > 262144:
                raise ValueError("TCP 重组超过 32 MiB 或 262144 段上限")
            seqs[seq] = payload
    streams: dict[tuple[str, int, str, int], bytes] = {}
    for key, seq_map in stream_seqs.items():
        merged = bytearray()
        next_seq: int | None = None
        for seq, payload in sorted(seq_map.items()):
            if next_seq is None:
                merged.extend(payload)
                next_seq = seq + len(payload)
                continue
            if seq >= next_seq:
                # Preserve a capture gap rather than inventing bytes.  Later
                # HTTP parsing can still use the complete following segment.
                merged.extend(payload)
                next_seq = seq + len(payload)
                continue
            overlap = next_seq - seq
            if overlap < len(payload):
                merged.extend(payload[overlap:])
                next_seq = seq + len(payload)
        streams[key] = bytes(merged)
    return streams


from services.parsers import ADAPTERS, _parse_chanlist_html, _parse_vsp_json, _parse_channel_acquire_json
from services.parsers.common import (_extract_json_object, _parse_pc_channel_catalog, _decode_payload_text, _safe_int, _truthy, _first_text, _first_int, _clean_group_name, _channel_category_from_group, _fallback_classify_channel_name, _parse_multicast_url, _parse_stream_params, _iter_channel_dicts, _extract_channel_objects_from_partial_json)



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
    epg_hosts: list[str] = []
    request_streams = {k: v for k, v in streams.items() if k[0] == stb_ip}
    for (src_ip, src_port, dst_ip, dst_port), data in request_streams.items():
        text = data.decode("utf-8", errors="replace")
        if b"/EPG/jsp/" in data or b"/EDS/jsp/" in data:
            epg_hosts.append(f"{dst_ip}:{dst_port}")
        # UserID from /EDS/jsp/AuthenticationURL?UserID=...
        if not result.get("epg_user_id"):
            m = re.search(r"/EDS/jsp/AuthenticationURL[^\r\n]*[?&]UserID=([^&\s\r\n/]+)", text, re.IGNORECASE)
            if m:
                uid = urllib.parse.unquote(m.group(1)).strip()
                if uid:
                    result["epg_user_id"] = uid
                    result.setdefault("epg_auth_host", f"{dst_ip}:{dst_port}")
        # STBID from POST body to ValidAuthenticationHWCTC.  Operators use
        # both URL query strings and x-www-form-urlencoded POST bodies, and
        # some firmwares lowercase every field name.
        if not result.get("epg_stb_id"):
            if any(marker in text for marker in (
                "ValidAuthenticationHWCU", "authLoginHWCU",
                "ValidAuthenticationHWCTC", "authLoginHWCTC",
            )):
                stbid = _extract_request_field(text, "STBID", "DeviceID", "TerminalID")
                if stbid:
                    result["epg_stb_id"] = stbid
                result.setdefault("epg_auth_host", f"{dst_ip}:{dst_port}")
        # The HWCU validation POST carries the device/profile fields required
        # to refresh a future legal session.  Persist field values only in
        # owner-local state; the status API and protocol manifest stay redacted.
        if any(marker in text for marker in (
            "ValidAuthenticationHWCU", "authLoginHWCU",
            "ValidAuthenticationHWCTC", "authLoginHWCTC",
        )):
            for source, destination in (
                ("STBType", "epg_stb_type"),
                ("STBVersion", "epg_stb_version"),
                ("SoftwareVersion", "epg_software_version"),
                ("NetUserID", "epg_net_user_id"),
                ("conntype", "epg_conn_type"),
                ("Lang", "epg_lang"),
                ("AccessUserName", "access_user_name"),
            ):
                if not result.get(destination):
                    value = _extract_request_field(text, source)
                    if value:
                        result[destination] = value
            if not result.get("epg_user_agent"):
                user_agent = re.search(r"(?im)^User-Agent:\s*([^\r\n]+)", text)
                if user_agent:
                    result["epg_user_agent"] = user_agent.group(1).strip()
        # EPG host from any /EPG/jsp/ or /EDS/jsp/ request
        if not result.get("epg_auth_host"):
            if b"/EPG/jsp/" in data or b"/EDS/jsp/" in data:
                result["epg_auth_host"] = f"{dst_ip}:{dst_port}"
    if epg_hosts:
        def _epg_host_priority(host: str) -> tuple[int, str]:
            try:
                port = int(host.rsplit(":", 1)[1])
            except (IndexError, ValueError):
                port = 0
            # 8082 is the standard IPTV EDS port.  A boot capture can also
            # contain SOAP/control traffic on another port before the EDS GET.
            return ({8082: 0, 80: 1, 8080: 2}.get(port, 10), host)
        result["epg_auth_host"] = sorted(set(epg_hosts), key=_epg_host_priority)[0]
    return result


def _extract_request_field(text: str, *field_names: str) -> str:
    """Return a URL/form/JSON request value without making field names case-sensitive."""
    if not text or not field_names:
        return ""
    names = "|".join(re.escape(name) for name in field_names)
    patterns = (
        # Query string and application/x-www-form-urlencoded body.
        rf"(?im)(?:^|[?&\r\n])(?:{names})=([^&\s\r\n]+)",
        # JSON portal payloads used by newer STB firmware.
        rf"(?is)\"(?:{names})\"\s*:\s*\"([^\"]+)\"",
    )
    for pattern in patterns:
        m = re.search(pattern, text)
        if m:
            value = urllib.parse.unquote_plus((m.group(1) or "").strip())
            if value:
                return value
    return ""


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
            user_id = _extract_request_field(text, "UserID", "NetUserID")
            if user_id:
                result["epg_user_id"] = user_id
        if not result.get("epg_stb_id"):
            stb_id = _extract_request_field(text, "STBID", "DeviceID", "TerminalID")
            if stb_id:
                result["epg_stb_id"] = stb_id
        if not result.get("access_user_name"):
            access_user_name = _extract_request_field(text, "AccessUserName")
            if access_user_name:
                result["access_user_name"] = access_user_name
        if not result.get("epg_net_user_id"):
            net_user_id = _extract_request_field(text, "NetUserID")
            if net_user_id:
                result["epg_net_user_id"] = net_user_id
        if not result.get("epg_conn_type"):
            conn_type = _extract_request_field(text, "conntype", "ConnType")
            if conn_type:
                result["epg_conn_type"] = conn_type
        if not result.get("epg_lang"):
            lang = _extract_request_field(text, "Lang", "lang")
            if lang:
                result["epg_lang"] = lang
        if not result.get("epg_stb_type"):
            stb_type = _extract_request_field(text, "STBType", "DeviceType", "TerminalType")
            if stb_type:
                result["epg_stb_type"] = stb_type
        if not result.get("epg_stb_version"):
            stb_version = _extract_request_field(text, "STBVersion", "DeviceVersion", "TerminalVersion")
            if stb_version:
                result["epg_stb_version"] = stb_version
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

    import hashlib
    channels = {}
    catalog = {}
    for stream, raw in streams.items():
        if stream[2] != stb_ip or stream[0] == stb_ip:
            continue
        responses = _split_http_responses(raw)
        bodies = [body for _, body in responses] or [raw]
        for index, body in enumerate(bodies):
            source = {"pcap": Path(pcap_path).name, "stream": list(stream),
                      "response_index": index, "body_sha256": hashlib.sha256(body).hexdigest(),
                      "partial": not bool(responses), "protocol": "HTTP/TCP"}
            if b"PC_ChannelList" in body and b"channelAllList" in body:
                evidence = {**source, "parser": "pc-channel-catalog", "parser_version": "1"}
                for channel_id, value in _parse_pc_channel_catalog(body).items():
                    catalog[channel_id] = (value, evidence)
            for adapter in ADAPTERS:
                if not adapter.matches(body):
                    continue
                evidence = {**source, "parser": adapter.name, "parser_version": adapter.version}
                for channel in adapter.parse(body):
                    key = f"{channel['ip']}:{channel['port']}"
                    if key in channels:
                        continue
                    channel["provenance"] = {"sources": [evidence],
                        "fields": {field: 0 for field in channel}, "method": "parser_output"}
                    channels[key] = channel
                break
    all_channels = list(channels.values())
    for channel in all_channels:
        metadata, evidence = catalog.get(str(channel.get("channel_id") or ""), ({}, {}))
        for field in ("name", "category", "operator_group"):
            if metadata.get(field) and (not channel.get(field) or (field == "category" and channel[field] == "其它频道")):
                channel[field] = metadata[field]
                channel["provenance"]["sources"].append(evidence)
                channel["provenance"]["fields"][field] = len(channel["provenance"]["sources"])-1

    all_channels.sort(key=lambda x: x["num"])
    return all_channels


class StbDiscoveryService:
    STATUS_IDLE = "idle"
    STATUS_CAPTURING = "capturing"
    STATUS_ANALYZING = "analyzing"
    STATUS_DONE = "done"
    STATUS_ERROR = "error"

    def __init__(
        self,
        logger: AppLogger,
        token_store: Any | None = None,
        archive_dir: Path | None = None,
    ) -> None:
        self.logger = logger
        self.token_store = token_store
        token_path = getattr(token_store, "path", None)
        self.archive_dir = archive_dir or (
            Path(token_path).parent / "stb-captures" if token_path else None
        )
        self._lock = threading.RLock()
        self._generation = 0
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
            "archived_pcap": "",
            "protocol_artifacts": {"saved": False},
        }
        self._proc: subprocess.Popen | None = None
        self._pcap_path: str | None = None
        self._worker_thread: threading.Thread | None = None
        self._stderr_tail = deque(maxlen=8)
        self._state.update(diagnostics={}, live_watcher_errors=0, live_last_error=None, stb_mac="", detected_mac="")

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

    def archive_path(self, name: str) -> Path | None:
        """Resolve one persisted capture without accepting path traversal."""
        name = str(name or "").strip()
        if not self.archive_dir or not name or Path(name).name != name:
            return None
        if not name.startswith("stb-boot-") or not name.endswith(".pcap"):
            return None
        path = self.archive_dir / name
        return path if path.is_file() else None

    def list_archives(self) -> list[dict[str, Any]]:
        """Return only non-sensitive metadata for locally persisted captures."""
        if not self.archive_dir:
            return []
        result: list[dict[str, Any]] = []
        for path in self.archive_dir.glob("stb-boot-*.pcap"):
            try:
                stat = path.stat()
            except OSError:
                continue
            result.append({
                "name": path.name,
                "size": stat.st_size,
                "created_at": int(stat.st_mtime),
                "has_manifest": (self.archive_dir / f"{path.stem}.artifacts" / "manifest.json").is_file(),
            })
        return sorted(result, key=lambda item: (item["created_at"], item["name"]), reverse=True)

    def delete_archive(self, name: str) -> dict[str, Any]:
        """Delete one explicitly selected persisted capture and its metadata."""
        path = self.archive_path(name)
        if path is None:
            raise FileNotFoundError("历史抓包不存在")
        size = path.stat().st_size
        artifact_dir = path.parent / f"{path.stem}.artifacts"
        path.unlink()
        artifacts_deleted = False
        if artifact_dir.is_dir():
            shutil.rmtree(artifact_dir)
            artifacts_deleted = True
        with self._lock:
            if self._state.get("archived_pcap") == path.name:
                self._state["archived_pcap"] = ""
                self._state["protocol_artifacts"] = {"saved": False}
        return {
            "name": path.name,
            "size": size,
            "artifacts_deleted": artifacts_deleted,
        }

    def latest_archive_path(self) -> Path | None:
        archives = self.list_archives()
        return self.archive_path(str(archives[0]["name"])) if archives else None

    def _archive_pcap(self, pcap_path: str | None, stopped_at: float) -> str:
        """Persist a completed raw capture in the data volume for offline replay.

        PCAP files can contain IPTV credentials.  They are therefore kept
        locally only, permissioned for the container user, excluded from the
        JSON global backup, and never emitted through status/log responses.
        """
        if not self.archive_dir or not pcap_path or not os.path.isfile(pcap_path):
            return ""
        try:
            self.archive_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(stopped_at))
            suffix = f"-{time.time_ns() % 1_000_000_000:09d}"
            target = self.archive_dir / f"stb-boot-{stamp}{suffix}.pcap"
            shutil.copy2(pcap_path, target)
            os.chmod(target, 0o600)
            return target.name
        except Exception as exc:
            self.logger.warning(f"STB 原始抓包归档失败：{exc}")
            return ""

    @staticmethod
    def _write_private_artifact(path: Path, content: bytes) -> None:
        """Atomically write a credential-bearing artifact with owner-only mode."""
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp_path = path.with_name(f".{path.name}.{time.time_ns()}.tmp")
        try:
            temp_path.write_bytes(content)
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, path)
            os.chmod(path, 0o600)
        finally:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass

    def _persist_protocol_artifacts(
        self,
        pcap_path: str,
        archive_name: str,
        streams: dict[tuple[str, int, str, int], bytes] | None = None,
    ) -> dict[str, Any]:
        """Persist only a redacted protocol-capture summary beside a PCAP.

        The raw PCAP remains the user-controlled local capture.  This helper
        deliberately does *not* duplicate request bodies, authentication
        forms, token values, cookies, or complete response streams.  That
        keeps restart diagnostics useful without creating a new credential
        export surface; the summary is also excluded from global JSON backup.
        """
        if not self.archive_dir:
            return {"saved": False, "reason": "archive_unconfigured"}
        streams = streams if streams is not None else _reassemble_tcp_streams(pcap_path)
        artifact_dir = self.archive_dir / f"{Path(archive_name).stem}.artifacts"
        artifact_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        selected: list[dict[str, Any]] = []
        response_stream_keys: set[tuple[str, int, str, int]] = set()
        auth_paths = (
            "/eds/jsp/authenticationurl",
            "/epg/jsp/authlogin",
            "/epg/jsp/validauthentication",
            "/uploadauthinfo",
            "/getservicelist",
        )
        channel_paths = ("channelacquire", "getchannellist", "getallchannel")
        for stream_key, raw in streams.items():
            src_ip, src_port, dst_ip, dst_port = stream_key
            for method, path, request_raw, cookie_names, header_names in _iter_http_requests(raw):
                normalized_path = urllib.parse.urlsplit(path).path
                lowered = normalized_path.lower()
                category = ""
                if any(marker in lowered for marker in auth_paths):
                    category = "auth_form"
                elif any(marker in lowered for marker in channel_paths):
                    category = "channel_request"
                if not category:
                    continue
                reverse_key = (dst_ip, dst_port, src_ip, src_port)
                response_raw = streams.get(reverse_key, b"")
                if response_raw:
                    response_stream_keys.add(reverse_key)
                selected.append({
                    "kind": category,
                    "method": method,
                    "path": normalized_path,
                    "request_bytes": len(request_raw),
                    "request_has_cookie": bool(cookie_names),
                    "request_header_names": header_names,
                    "response_observed": bool(response_raw),
                    "response_sets_cookie": bool(_response_cookie_names(response_raw)),
                })
        manifest = {
            "schema_version": 1,
            "source_pcap": Path(archive_name).name,
            "created_at": int(time.time()),
            "global_backup_excluded": True,
            "auth_form_count": sum(item["kind"] == "auth_form" for item in selected),
            "channel_request_count": sum(item["kind"] == "channel_request" for item in selected),
            "response_stream_count": len(response_stream_keys),
            "artifacts": selected,
        }
        self._write_private_artifact(
            artifact_dir / "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
        )
        return {
            "saved": bool(selected),
            "auth_forms": manifest["auth_form_count"],
            "channel_requests": manifest["channel_request_count"],
            "response_streams": manifest["response_stream_count"],
        }

    def reanalyze_latest_archive(self, stb_ip: str) -> dict[str, Any]:
        """Rebuild discovery state from the newest persisted PCAP.

        This is intentionally offline: it does not start tcpdump or touch the
        network interface, so parser improvements can be tested without
        requiring the user to reboot the STB again.
        """
        if not self.archive_dir:
            raise RuntimeError("未配置 STB 抓包归档目录")
        archives = sorted(
            self.archive_dir.glob("stb-boot-*.pcap"),
            key=lambda path: path.stat().st_mtime,
        )
        if not archives:
            raise RuntimeError("暂无已归档的 STB 抓包文件")
        with self._lock:
            if self._state["status"] in {self.STATUS_CAPTURING, self.STATUS_ANALYZING}:
                raise RuntimeError("正在捕获 STB 流量，请停止后再离线解析")

            self._generation += 1
            generation = self._generation
            self._state["status"] = self.STATUS_ANALYZING
        try:
            return self._reanalyze_archive(archives[-1], stb_ip, generation)
        except Exception as exc:
            with self._lock:
                if generation == self._generation:
                    self._state.update(status=self.STATUS_ERROR, error=str(exc))
            raise

    def _reanalyze_archive(self, archive, stb_ip, generation):
        pcap_path = str(archive)
        streams = _reassemble_tcp_streams(pcap_path)
        protocol_artifacts = self._persist_protocol_artifacts(pcap_path, archive.name, streams)
        channels = analyze_pcap_for_channels(pcap_path, stb_ip)
        diagnostics = _capture_diagnostics(pcap_path, stb_ip, streams, channels)
        timeshift_host = _detect_timeshift_host(streams, channels)
        auth_info = _extract_dhcp_from_pcap(pcap_path, stb_ip)
        epg_creds = _extract_epg_credentials(streams, stb_ip)
        portal_auth = _extract_ctc_portal_auth(streams, stb_ip)
        if portal_auth.get("epg_user_id") and not epg_creds.get("epg_user_id"):
            epg_creds["epg_user_id"] = str(portal_auth["epg_user_id"])
        if portal_auth.get("epg_stb_id") and not epg_creds.get("epg_stb_id"):
            epg_creds["epg_stb_id"] = str(portal_auth["epg_stb_id"])
        if portal_auth.get("portal_auth_host") and not epg_creds.get("epg_auth_host"):
            epg_creds["epg_auth_host"] = str(portal_auth["portal_auth_host"])
        for key in ("epg_user_agent", "epg_stb_type", "epg_stb_version", "access_user_name"):
            if portal_auth.get(key) and not epg_creds.get(key):
                epg_creds[key] = str(portal_auth[key])
        token = str(portal_auth.get("user_token") or "").strip()
        with self._lock:
            if generation != self._generation:
                return dict(self._state)
            if token and self.token_store:
                self.token_store.save_token({
                "token": token,
                "sip": stb_ip,
                "sport": None,
                "dip": portal_auth.get("server_ip", ""),
                "dport": portal_auth.get("server_port"),
                "path": portal_auth.get("token_path") or "/uploadAuthInfo",
                "captured_at": int(time.time()),
            })
        safe_portal_auth: dict[str, Any] = {}
        for key in ("portal_auth_host", "server_ip", "server_port", "token_path"):
            if portal_auth.get(key):
                safe_portal_auth[key] = portal_auth[key]
        safe_portal_auth["has_ctc_auth_info"] = bool(portal_auth.get("ctc_auth_info"))
        safe_portal_auth["has_upload_user_token"] = bool(portal_auth.get("user_token"))
        safe_portal_auth["has_x_frame_session_id"] = bool(portal_auth.get("x_frame_session_id"))
        with self._lock:
            if generation != self._generation:
                return dict(self._state)
            self._state.update({
                "status": self.STATUS_DONE if diagnostics["packet_count"] else self.STATUS_ERROR,
                "stb_ip": stb_ip,
                "stopped_at": time.time(),
                "error": None if diagnostics["packet_count"] else "未捕获到任何完整数据包，请检查抓包点和过滤条件",
                "diagnostics": diagnostics,
                "channels": channels,
                "channel_count": len(channels),
                "auth_info": auth_info,
                "timeshift_host": timeshift_host,
                "epg_creds": epg_creds,
                "portal_auth": safe_portal_auth,
                "archived_pcap": archive.name,
                "protocol_artifacts": protocol_artifacts,
            })
            self._state.update(self._pcap_meta_locked())
            return dict(self._state)

    def _live_watcher(self, pcap_path: str, stb_ip: str, generation: int) -> None:
        last_size = -1
        while True:
            time.sleep(1)
            with self._lock:
                if self._state["status"] != self.STATUS_CAPTURING or generation != self._generation:
                    break
                proc = self._proc
                mac = self._state.get("stb_mac", "")
            if proc is not None and proc.poll() is not None:
                self._capture_failed(proc, generation, f"tcpdump 意外退出（退出码 {proc.returncode}）")
                return
            try:
                size = Path(pcap_path).stat().st_size
                if size >= MAX_PCAP_BYTES:
                    self.logger.warning("捕获达到 128 MiB 阈值，自动停止；保留 PCAP 供拆分分析")
                    self.stop()
                    return
                if size == last_size or size > 16 * 1024 * 1024:
                    continue  # Large captures are parsed once after stopping.
                last_size = size
                effective_ip, auth_info = _capture_identity(pcap_path, stb_ip, mac)
                channels = analyze_pcap_for_channels(pcap_path, effective_ip)
                has_auth = bool(auth_info.get("mac") or auth_info.get("assigned_ip"))
                with self._lock:
                    if self._state["status"] == self.STATUS_CAPTURING and generation == self._generation:
                        self._state["live_channel_count"] = len(channels)
                        self._state["live_has_auth"] = has_auth
                        self._state["detected_mac"] = normalize_mac(auth_info.get("mac", ""))
                        self._state["stb_ip"] = effective_ip
                        self._state["live_last_error"] = None
            except Exception as exc:
                with self._lock:
                    if generation != self._generation or self._state["status"] != self.STATUS_CAPTURING:
                        return
                    count = self._state.get("live_watcher_errors", 0) + 1
                    self._state.update(live_watcher_errors=count, live_last_error=str(exc)[:2048])
                if count <= 3 or count % 10 == 0:
                    self.logger.warning(f"STB 实时分析失败（第 {count} 次）：{exc}")

    def _stderr_reader(self, proc, generation):
        stream = getattr(proc, "stderr", None)
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read1(1024) if hasattr(stream, "read1") else stream.read(1024)
                if not chunk:
                    break
                text = chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else chunk
                with self._lock:
                    if generation != self._generation:
                        continue
                    self._stderr_tail.append(text[-1024:])
                self.logger.info(f"tcpdump: {text.strip()}")
        except (ValueError, OSError):
            # reset/stop closes the pipe after terminating the owned process.
            return

    def _capture_failed(self, proc, generation, reason):
        with self._lock:
            if generation != self._generation or self._proc is not proc or self._state["status"] != self.STATUS_CAPTURING:
                return False
            detail = "".join(self._stderr_tail).strip()[-4096:]
            self._state.update(status=self.STATUS_ERROR, error=f"{reason}：{detail}" if detail else reason,
                               stopped_at=time.time())
            self._proc = None
            message = self._state["error"]
        reap_process(proc)
        self.logger.error(message)
        return True

    def runtime_check(self) -> dict[str, Any]:
        if shutil.which("tcpdump") is None:
            return {"ok": False, "errors": ["缺少依赖命令：tcpdump"]}
        try:
            _probe_tcpdump_interfaces()
        except Exception as exc:
            return {"ok": False, "errors": [f"无法枚举抓包接口：{exc}；请检查容器网络与 NET_RAW/NET_ADMIN 配置"]}
        return {"ok": True, "errors": [], "detail": "接口枚举成功，实际抓包权限将在启动时验证"}

    def status(self) -> dict[str, Any]:
        with self._lock:
            state = dict(self._state)
            state.update(self._pcap_meta_locked())
        archives = self.list_archives()
        state["archive_count"] = len(archives)
        state["latest_archive"] = archives[0] if archives else None
        return state

    def start(self, stb_ip: str, interface: str = "any", full_capture: bool = False, stb_mac: str = "") -> None:
        mac = normalize_mac(stb_mac)
        expression = f"{'ether host ' + mac if mac else 'host ' + stb_ip} or (udp and (port 67 or port 68))"
        if not stb_ip and not mac:
            raise ValueError("请填写机顶盒 IP 或 MAC 地址")
        if mac and not full_capture:
            _validate_mac_filter(interface, expression)
        if self.archive_dir and sum(p.stat().st_size for p in self.archive_dir.glob("stb-boot-*.pcap")) >= 1024*1024*1024:
            raise RuntimeError("PCAP 归档达到 1 GiB，请先导出或清理旧归档再开始捕获")
        rt = self.runtime_check()
        if not rt["ok"]:
            raise RuntimeError("；".join(rt["errors"]))
        with self._lock:
            if self._state["status"] in {self.STATUS_CAPTURING, self.STATUS_ANALYZING}:
                raise RuntimeError("已有一个捕获任务正在进行")
            if self._pcap_path and os.path.exists(self._pcap_path):
                try:
                    os.unlink(self._pcap_path)
                except Exception:
                    pass
            self._generation += 1
            self._stderr_tail.clear()
            generation = self._generation
            fd, self._pcap_path = tempfile.mkstemp(suffix=".pcap", prefix="stb_discovery_")
            os.close(fd)
            pcap_path = self._pcap_path
            self._state = {
                "status": self.STATUS_CAPTURING,
                "stb_ip": stb_ip,
                "requested_stb_ip": stb_ip,
                "stb_mac": mac,
                "detected_mac": "",
                "interface": interface,
                "full_capture": bool(full_capture),
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
                "protocol_artifacts": {"saved": False},
                "diagnostics": {},
                "live_watcher_errors": 0,
                "live_last_error": None,
            }
        cmd = [
            "tcpdump",
            "-i", interface,
            "-s", "0",
            "-w", pcap_path,
        ]
        if not full_capture:
            # Keep the complete STB session for later offline analysis: RTSP
            # control is TCP, while the negotiated media path can be UDP/RTP.
            # DHCP is included before the STB address is assigned.
            cmd.append(expression)
        self.logger.info(f"开始捕获 STB 开机流量：STB={stb_ip}，接口={interface}，文件={self._pcap_path}")
        try:
            with self._lock:
                if generation != self._generation or self._state["status"] != self.STATUS_CAPTURING:
                    return
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    env={**os.environ, "LC_ALL": "C"},
                )
                proc = self._proc
        except Exception as exc:
            with self._lock:
                if generation != self._generation:
                    raise
                self._state["status"] = self.STATUS_ERROR
                self._state["error"] = str(exc)
            raise
        reader = threading.Thread(target=self._stderr_reader, args=(proc, generation), daemon=True, name="stb-stderr-reader")
        reader.start()
        time.sleep(0.25)
        if proc.poll() is not None:
            reader.join(timeout=0.2)
            if self._capture_failed(proc, generation, f"tcpdump 启动后退出（退出码 {proc.returncode}）"):
                raise RuntimeError(self.status()["error"])
            return
        threading.Thread(
            target=self._live_watcher,
            args=(pcap_path, stb_ip, generation),
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
            generation = self._generation
            proc = self._proc
            pcap_path = self._pcap_path
            stb_ip = self._state["stb_ip"]
            mac = self._state.get("stb_mac", "")
            self._state["status"] = self.STATUS_ANALYZING
            self._state["stopped_at"] = time.time()

        if proc:
            reap_process(proc)

        archived_pcap = self._archive_pcap(pcap_path, float(self._state.get("stopped_at") or time.time()))
        if archived_pcap:
            with self._lock:
                if generation != self._generation:
                    return dict(self._state)
                self._state["archived_pcap"] = archived_pcap

        def _analyze() -> None:
            nonlocal stb_ip
            try:
                time.sleep(0.5)  # let pcap flush
                channels: list[dict[str, Any]] = []
                auth_info: dict[str, Any] = {}
                timeshift_host: str = ""
                epg_creds: dict[str, str] = {}
                portal_auth: dict[str, Any] = {}
                protocol_artifacts: dict[str, Any] = {"saved": False}
                streams = {}
                if pcap_path and os.path.exists(pcap_path):
                    stb_ip, auth_info = _capture_identity(pcap_path, stb_ip or "", mac)
                    streams = _reassemble_tcp_streams(pcap_path)
                    protocol_artifacts = self._persist_protocol_artifacts(
                        pcap_path,
                        archived_pcap or Path(pcap_path).name,
                        streams,
                    )
                    channels = analyze_pcap_for_channels(pcap_path, stb_ip or "")
                    if archived_pcap:
                        for channel in channels:
                            for source in channel.get("provenance", {}).get("sources", []):
                                source["pcap"] = archived_pcap
                    timeshift_host = _detect_timeshift_host(streams, channels)
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
                    with self._lock:
                        if generation != self._generation:
                            return
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
                diagnostics = _capture_diagnostics(pcap_path, stb_ip or "", streams, channels, mac)
                diagnostics["identity_source"] = "dhcp_ack" if mac and auth_info.get("lease_confirmed") else "provided_ip" if stb_ip else "unresolved"
                with self._lock:
                    if generation != self._generation:
                        return
                    self._state["status"] = self.STATUS_DONE if diagnostics["packet_count"] else self.STATUS_ERROR
                    self._state["error"] = None if diagnostics["packet_count"] else "未捕获到任何完整数据包，请检查抓包点和过滤条件"
                    self._state["diagnostics"] = diagnostics
                    self._state["stb_ip"] = stb_ip
                    self._state["detected_mac"] = normalize_mac(auth_info.get("mac", ""))
                    self._state["channels"] = channels
                    self._state["channel_count"] = len(channels)
                    self._state["auth_info"] = auth_info
                    self._state["timeshift_host"] = timeshift_host
                    self._state["epg_creds"] = epg_creds
                    self._state["portal_auth"] = safe_portal_auth
                    self._state["protocol_artifacts"] = protocol_artifacts
                    self._state.update(self._pcap_meta_locked())
                has_auth = bool(auth_info.get("mac") or auth_info.get("assigned_ip"))
                self.logger.info(
                    f"STB 频道发现完成：共发现 {len(channels)} 个频道，"
                    f"DHCP认证字段：{'已捕获' if has_auth else '未捕获'}，"
                    f"EPG字段：{'已捕获' if epg_creds else '未捕获'}，"
                    f"门户会话字段：{'已捕获' if portal_auth else '未捕获'}，"
                    f"原始PCAP归档：{'已保存' if archived_pcap else '失败'}"
                )
            except Exception as exc:
                self.logger.error(f"STB 频道发现分析失败：{exc}")
                with self._lock:
                    if generation != self._generation:
                        return
                    self._state["status"] = self.STATUS_ERROR
                    self._state["error"] = str(exc)

        t = threading.Thread(target=_analyze, daemon=True)
        t.start()
        with self._lock:
            return dict(self._state)

    def reset(self) -> None:
        with self._lock:
            self._generation += 1
            self._stderr_tail.clear()
            if self._proc:
                try:
                    reap_process(self._proc)
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
                "stb_mac": "",
                "detected_mac": "",
                "interface": None,
                "started_at": None,
                "stopped_at": None,
                "error": None,
                "channels": [],
                "channel_count": 0,
                "auth_info": {},
                "archived_pcap": "",
                "protocol_artifacts": {"saved": False},
                "pcap_available": False,
                "pcap_size": 0,
                "diagnostics": {},
                "live_watcher_errors": 0,
                "live_last_error": None,
            }
