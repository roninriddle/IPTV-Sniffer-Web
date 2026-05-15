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
from pathlib import Path
from typing import Any

from services.log_service import AppLogger


def _parse_ip(data: bytes, off: int) -> str:
    return ".".join(str(b) for b in data[off : off + 4])


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

    Packets are sorted by TCP sequence number before concatenation so that
    out-of-order delivery and retransmissions don't corrupt the stream.
    """
    # Map from 4-tuple to {seq: payload} for ordering
    stream_seqs: dict[tuple[str, int, str, int], dict[int, bytes]] = {}
    with open(pcap_path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return {}
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in (0xA1B2C3D4, 0xD3B4A1B2):
            return {}
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            inc_len = struct.unpack("<I", hdr[8:12])[0]
            pkt = f.read(inc_len)
            if len(pkt) < 54:
                continue
            if pkt[12:14] != b"\x08\x00":
                continue  # not IPv4
            if pkt[23] != 6:
                continue  # not TCP
            ip_ihl = (pkt[14] & 0x0F) * 4
            src_ip = _parse_ip(pkt, 26)
            dst_ip = _parse_ip(pkt, 30)
            tcp_off = 14 + ip_ihl
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
            if seq not in seqs:  # skip retransmits (same seq, same data)
                seqs[seq] = payload
    # Sort each stream by seq number and concatenate
    streams: dict[tuple[str, int, str, int], bytes] = {}
    for key, seq_map in stream_seqs.items():
        streams[key] = b"".join(payload for _, payload in sorted(seq_map.items()))
    return streams


def _parse_chanlist_html(html: bytes) -> list[dict[str, Any]]:
    """Parse getchannellistHWCU.jsp HTML response into channel dicts."""
    text = html.decode("utf-8", errors="replace")
    blocks = re.findall(r"CUSetConfig\('Channel','([^']+)'\)", text)
    channels: list[dict[str, Any]] = []
    for block in blocks:
        pairs = dict(re.findall(r"(\w+)=\"([^\"]*)\"", block))
        chan_name = pairs.get("ChannelName", "").strip()
        user_chan_id = pairs.get("UserChannelID", "")
        channel_url = pairs.get("ChannelURL", "")
        chan_id = pairs.get("ChannelID", "")
        is_hd = pairs.get("IsHDChannel", "0") == "2"
        time_shift = pairs.get("TimeShift", "0") == "1"
        fcc_ip = pairs.get("ChannelFCCIP", "").strip()
        fcc_port_s = pairs.get("ChannelFCCPort", "")
        fec_port_s = pairs.get("ChannelFECPort", "")
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
                "fcc_ip": fcc_ip,
                "fcc_port": int(fcc_port_s) if fcc_port_s.isdigit() else None,
                "fec_port": int(fec_port_s) if fec_port_s.isdigit() else None,
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
        }
        self._proc: subprocess.Popen | None = None
        self._pcap_path: str | None = None
        self._worker_thread: threading.Thread | None = None

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
            }
        cmd = [
            "tcpdump",
            "-i", interface,
            "-s", "0",
            "-w", self._pcap_path,
            f"host {stb_ip} and tcp",
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
                if pcap_path and os.path.exists(pcap_path):
                    channels = analyze_pcap_for_channels(pcap_path, stb_ip or "")
                    try:
                        os.unlink(pcap_path)
                    except Exception:
                        pass
                with self._lock:
                    self._state["status"] = self.STATUS_DONE
                    self._state["channels"] = channels
                    self._state["channel_count"] = len(channels)
                self.logger.info(f"STB 频道发现完成：共发现 {len(channels)} 个频道")
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
            }
