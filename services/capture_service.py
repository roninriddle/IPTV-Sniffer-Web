#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Live tcpdump capture service with thread-safe runtime state."""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import threading
import time
from typing import Any, Sequence
from urllib.parse import unquote

from config import (
    CAPTURE_FILTER,
    DEFAULT_CAPTURE_SECONDS,
    DEFAULT_RTP2HTTP_PORT,
    MAX_TIMED_CAPTURE_SECONDS,
    MIN_PACKET_COUNT,
)
from models import StreamRecord
from services.log_service import AppLogger
from services.storage_service import DiscoveryStore, FccStore, StbTokenStore
from utils import is_probable_iptv_stream, stream_static_filter_reason, valid_ip_or_host, valid_ipv4_multicast

# Typical tcpdump lines:
# IP 192.168.1.20.55555 > 239.1.1.1.5140: UDP, length 1316
# IP 10.0.0.2.49152 > 239.10.10.10.5000: UDP, length 1316
DESTINATION_RE = re.compile(
    r">\s*(?P<host>(?:\d{1,3}\.){3}\d{1,3})\.(?P<port>\d+)\s*:\s*UDP",
    re.IGNORECASE,
)
TCP_PEER_RE = re.compile(
    r"IP\s+(?P<sip>(?:\d{1,3}\.){3}\d{1,3})\.(?P<sport>\d+)\s*>\s*"
    r"(?P<dip>(?:\d{1,3}\.){3}\d{1,3})\.(?P<dport>\d+)\s*:",
    re.IGNORECASE,
)
CHANNEL_ACQUIRE_RE = re.compile(r"POST\s+(?P<path>/bj_stb/V1/STB/channelAcquire[^\s]*)", re.IGNORECASE)
STREAM_URL_RE = re.compile(
    r"(?P<url>(?:igmp|rtp|udp)://(?P<host>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d+)(?:\?[^\"'\s,;)<>{}]{0,1200})?)",
    re.IGNORECASE,
)
FCC_IP_RE = re.compile(
    r"(?:ChannelFCCIP\s*(?:=|:)\s*[\"']?|<ChannelFCCIP>\s*)(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
FCC_PORT_RE = re.compile(
    r"(?:ChannelFCCPort\s*(?:=|:)\s*[\"']?|<ChannelFCCPort>\s*)(?P<port>\d{1,5})",
    re.IGNORECASE,
)
CHANNEL_NAME_RE = re.compile(
    r"\"(?P<json_key>ChannelName|ChannelNameCN|UserChannelName|channelName|name|Name|title|ChannelTitle)\"\s*:\s*\"(?P<json_value>[^\"\r\n]{1,120})\""
    r"|(?:\b(?P<query_key>ChannelName|ChannelNameCN|UserChannelName|channelName|name|Name|title|ChannelTitle)\s*(?:=|:)\s*[\"']?)(?P<query_value>[^&<>\r\n\"']{1,120})"
    r"|<(?P<xml_key>ChannelName|ChannelNameCN|UserChannelName|channelName|Name|title|ChannelTitle)>\s*(?P<xml_value>[^<\r\n]{1,120})",
    re.IGNORECASE,
)
CHANNEL_ID_RE = re.compile(
    r"\"(?P<json_key>ChannelID|channelId|channel_id|ChannelNumber|chno|UserChannelID)\"\s*:\s*\"?(?P<json_value>[^\",\s\r\n]{1,40})\"?"
    r"|(?:\b(?P<query_key>ChannelID|channelId|channel_id|ChannelNumber|chno|UserChannelID)\s*(?:=|:)\s*[\"']?)(?P<query_value>[^&<>\s\"']{1,40})"
    r"|<(?P<xml_key>ChannelID|channelId|channel_id|ChannelNumber|chno|UserChannelID)>\s*(?P<xml_value>[^<\s]{1,40})",
    re.IGNORECASE,
)
BAD_CHANNEL_NAME_TOKENS = {
    "channelname",
    "channelid",
    "channelfccip",
    "channelfccport",
    "usertoken",
    "rtp",
    "igmp",
    "udp",
    "http",
    "https",
}


def _run_text(cmd: Sequence[str]) -> str:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"命令执行失败：{' '.join(cmd)}")
    return proc.stdout


class CaptureService:
    def __init__(
        self,
        logger: AppLogger,
        fcc_store: FccStore | None = None,
        token_store: StbTokenStore | None = None,
        discovery_store: DiscoveryStore | None = None,
    ) -> None:
        self.logger = logger
        self.fcc_store = fcc_store
        self.token_store = token_store
        self.discovery_store = discovery_store
        self._lock = threading.RLock()
        self._proc: subprocess.Popen[str] | None = None
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._watcher_thread: threading.Thread | None = None
        self._timer_thread: threading.Thread | None = None
        self._streams: dict[str, StreamRecord] = {}
        self._fcc_buffer = ""
        self._fcc_seen: set[str] = set()
        self._metadata_buffer = ""
        self._metadata_seen: set[str] = set()
        self._http_buffer = ""
        self._last_tcp_peer: dict[str, Any] = {}
        self._token_seen: set[str] = set()
        self._runtime_check: dict[str, Any] = {"ok": False, "errors": ["尚未检查运行环境"]}
        self._state: dict[str, Any] = {
            "state": "idle",  # idle, running, stopped, error
            "message": "等待开始抓包",
            "interface": "",
            "http_host": "",
            "http_port": DEFAULT_RTP2HTTP_PORT,
            "path_mode": "rtp",
            "duration": DEFAULT_CAPTURE_SECONDS,
            "started_at": None,
            "stopped_at": None,
            "last_error": None,
            "stop_reason": None,
            "total_packets": 0,
        }

    def validate_runtime(self) -> dict[str, Any]:
        errors: list[str] = []
        for binary in ("tcpdump", "ip"):
            if shutil.which(binary) is None:
                errors.append(f"缺少依赖命令：{binary}")
        if not errors:
            try:
                _run_text(["tcpdump", "-D"])
            except Exception as exc:
                errors.append(
                    f"tcpdump 无法列出抓包接口：{exc}。容器通常需要 network_mode: host + cap_add: NET_ADMIN, NET_RAW"
                )
        result = {"ok": not errors, "errors": errors}
        with self._lock:
            self._runtime_check = result
        if errors:
            for error in errors:
                self.logger.error(error)
        else:
            self.logger.info("运行环境检查通过：tcpdump、ip 与抓包权限可用")
        return result

    def runtime_check(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._runtime_check)

    def list_interfaces(self) -> list[str]:
        names: list[str] = []
        try:
            text = _run_text(["ip", "-o", "link", "show"])
            for line in text.splitlines():
                match = re.match(r"\d+:\s+([^:]+):\s+<([^>]*)>", line)
                if not match:
                    continue
                name = match.group(1).split("@")[0]
                if name != "lo" and name not in names:
                    names.append(name)
        except Exception as exc:
            self.logger.warning(f"通过 ip 命令列出接口失败：{exc}")
        try:
            text = _run_text(["tcpdump", "-D"])
            for line in text.splitlines():
                match = re.match(r"\d+\.([^\s]+)", line)
                if not match:
                    continue
                name = match.group(1)
                if name != "lo" and name not in names:
                    names.append(name)
        except Exception as exc:
            self.logger.warning(f"通过 tcpdump 列出接口失败：{exc}")
        if "any" not in names:
            names.append("any")
        return names

    def start(self, data: dict[str, Any]) -> dict[str, Any]:
        runtime = self.runtime_check()
        if not runtime.get("ok"):
            raise RuntimeError("运行环境检查未通过：" + "；".join(runtime.get("errors", [])))
        interface = str(data.get("interface", "")).strip()
        http_host = str(data.get("http_host", "")).strip()
        path_mode = str(data.get("path_mode", "rtp")).strip().lower()
        try:
            http_port = int(data.get("http_port", DEFAULT_RTP2HTTP_PORT))
            duration = int(data.get("duration", DEFAULT_CAPTURE_SECONDS))
        except (TypeError, ValueError) as exc:
            raise ValueError("端口或抓包时长不是有效整数") from exc

        interfaces = self.list_interfaces()
        if interface not in interfaces:
            raise ValueError("抓包网卡无效，请刷新接口列表后重试")
        if not valid_ip_or_host(http_host):
            raise ValueError("rtp2httpd 地址格式不正确")
        if not 1 <= http_port <= 65535:
            raise ValueError("端口必须位于 1-65535")
        if path_mode not in {"rtp", "udp"}:
            raise ValueError("路径模式只能是 rtp 或 udp")
        if duration < 0:
            raise ValueError("抓包时长不能为负数")
        if duration > MAX_TIMED_CAPTURE_SECONDS:
            raise ValueError(f"定时抓包最大支持 {MAX_TIMED_CAPTURE_SECONDS} 秒；需要更久请填写 0 后手动停止")

        with self._lock:
            if self._state["state"] == "running":
                raise RuntimeError("已有抓包任务正在运行")
            self._fcc_buffer = ""
            self._fcc_seen = set()
            self._metadata_buffer = ""
            self._metadata_seen = set()
            self._http_buffer = ""
            self._token_seen = set()
            self._last_tcp_peer = {}
            self._state.update({
                "state": "running",
                "message": "抓包进行中，请切换机顶盒频道",
                "interface": interface,
                "http_host": http_host,
                "http_port": http_port,
                "path_mode": path_mode,
                "duration": duration,
                "started_at": time.time(),
                "stopped_at": None,
                "last_error": None,
                "stop_reason": None,
                "total_packets": 0,
            })

        cmd = ["tcpdump", "-i", interface, "-n", "-l", "-s", "0", "-A", CAPTURE_FILTER]
        self.logger.info(
            f"开始抓包：接口={interface}，过滤条件={CAPTURE_FILTER}，rtp2httpd 地址前缀=http://{http_host}:{http_port}/{path_mode}/，时长={duration} 秒"
        )
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env={**os.environ, "LC_ALL": "C"},
        )
        time.sleep(0.25)
        if proc.poll() is not None:
            stderr = proc.stderr.read().strip() if proc.stderr else ""
            with self._lock:
                self._state.update({
                    "state": "error",
                    "message": "tcpdump 启动失败",
                    "last_error": stderr or "tcpdump 启动失败",
                    "stopped_at": time.time(),
                })
            self.logger.error(stderr or "tcpdump 启动失败")
            raise RuntimeError(stderr or "tcpdump 启动失败")

        with self._lock:
            self._proc = proc
        self._stdout_thread = threading.Thread(target=self._stdout_reader, args=(proc,), daemon=True)
        self._stderr_thread = threading.Thread(target=self._stderr_reader, args=(proc,), daemon=True)
        self._watcher_thread = threading.Thread(target=self._watch_process, args=(proc,), daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()
        self._watcher_thread.start()
        if duration > 0:
            self._timer_thread = threading.Thread(target=self._auto_stop_worker, args=(float(self._state["started_at"]), duration), daemon=True)
            self._timer_thread.start()
        self.logger.info("tcpdump 已启动；请在机顶盒上逐个切换频道，每个频道建议停留 2-3 秒")
        return self.status()

    def _stdout_reader(self, proc: subprocess.Popen[str]) -> None:
        if proc.stdout is None:
            return
        for line in proc.stdout:
            self._consume_tcpdump_line(line.rstrip())

    def _stderr_reader(self, proc: subprocess.Popen[str]) -> None:
        if proc.stderr is None:
            return
        for line in proc.stderr:
            clean = line.strip()
            if clean:
                self.logger.info(f"tcpdump: {clean}")

    def _consume_tcpdump_line(self, line: str) -> None:
        self._consume_http_text(line)
        self._consume_fcc_text(line)
        self._consume_channel_metadata_text(line)
        peer_match = TCP_PEER_RE.search(line)
        if peer_match:
            with self._lock:
                self._last_tcp_peer = {
                    "sip": peer_match.group("sip"),
                    "sport": int(peer_match.group("sport")),
                    "dip": peer_match.group("dip"),
                    "dport": int(peer_match.group("dport")),
                }
        match = DESTINATION_RE.search(line)
        if not match:
            return
        host = match.group("host")
        try:
            port = int(match.group("port"))
        except ValueError:
            return
        if not valid_ipv4_multicast(host) or not 1 <= port <= 65535:
            return
        if stream_static_filter_reason(host, port):
            return
        now = time.time()
        key = f"{host}:{port}"
        with self._lock:
            state_running = self._state["state"] == "running"
            if not state_running:
                return
            self._state["total_packets"] += 1
            existing = self._streams.get(key)
            if existing is None:
                self._streams[key] = StreamRecord(host=host, port=port, packets=1, first_seen=now, last_seen=now)
                self.logger.info(f"发现候选组播流：{key}")
            else:
                existing.packets += 1
                existing.last_seen = now

    def _consume_fcc_text(self, line: str) -> None:
        if "ChannelFCC" not in line and "channelFCC" not in line and "rtp://" not in line and "igmp://" not in line and "udp://" not in line:
            if self._fcc_buffer:
                self._fcc_buffer = (self._fcc_buffer + "\n" + line)[-16000:]
            return
        text = unquote(line)
        with self._lock:
            self._fcc_buffer = (self._fcc_buffer + "\n" + text)[-16000:]
            buffer = self._fcc_buffer
        for match in STREAM_URL_RE.finditer(buffer):
            host = match.group("host")
            try:
                port = int(match.group("port"))
            except ValueError:
                continue
            if not valid_ipv4_multicast(host) or not 1 <= port <= 65535:
                continue
            segment = buffer[max(0, match.start() - 2000): match.end() + 4000]
            ip_match = FCC_IP_RE.search(segment)
            port_match = FCC_PORT_RE.search(segment)
            if not ip_match or not port_match:
                continue
            fcc_ip = ip_match.group("ip")
            try:
                fcc_port = int(port_match.group("port"))
            except ValueError:
                continue
            if not valid_ip_or_host(fcc_ip) or not 1 <= fcc_port <= 65535:
                continue
            key = f"{host}:{port}"
            seen_token = f"{key}|{fcc_ip}:{fcc_port}"
            if seen_token in self._fcc_seen:
                continue
            self._fcc_seen.add(seen_token)
            record = {
                "key": key,
                "host": host,
                "port": port,
                "fcc_ip": fcc_ip,
                "fcc_port": fcc_port,
                "source_url": match.group("url"),
                "raw_field": f"ChannelFCCIP={fcc_ip}&ChannelFCCPort={fcc_port}",
                "discovered_at": int(time.time()),
            }
            if self.fcc_store and self.fcc_store.save_record(record):
                self.logger.info(f"发现 FCC 信息：{key} -> {fcc_ip}:{fcc_port}，已写入 fcc.json")

    def _consume_channel_metadata_text(self, line: str) -> None:
        text = unquote(line)
        if "\ufffd" in text:
            return
        interesting = any(token in text for token in ("rtp://", "igmp://", "Channel", "channel", "Name", "name", "title"))
        if not interesting and not self._metadata_buffer:
            return
        with self._lock:
            self._metadata_buffer = (self._metadata_buffer + "\n" + text)[-64000:]
            buffer = self._metadata_buffer
        if "rtp://" not in buffer and "igmp://" not in buffer:
            return
        for match in STREAM_URL_RE.finditer(buffer):
            host = match.group("host")
            try:
                port = int(match.group("port"))
            except ValueError:
                continue
            if not valid_ipv4_multicast(host) or not 1 <= port <= 65535:
                continue
            segment = buffer[max(0, match.start() - 2200): match.end() + 2200]
            name, raw_field = self._extract_channel_name(segment)
            if not name:
                continue
            channel_id = self._extract_channel_id(segment)
            key = f"{host}:{port}"
            seen_token = f"{key}|{name}|{channel_id}"
            if seen_token in self._metadata_seen:
                continue
            self._metadata_seen.add(seen_token)
            record = {
                "key": key,
                "host": host,
                "port": port,
                "name": name,
                "channel_id": channel_id,
                "source": "stb_payload",
                "source_url": match.group("url"),
                "raw_field": raw_field,
                "discovered_at": int(time.time()),
            }
            if self.discovery_store and self.discovery_store.save_record(record):
                suffix = f"（频道号 {channel_id}）" if channel_id else ""
                self.logger.info(f"自动识别频道名：{key} -> {name}{suffix}，已写入 discovered_channels.json")

    @staticmethod
    def _extract_channel_name(segment: str) -> tuple[str, str]:
        candidates: list[tuple[int, str, str]] = []
        for match in CHANNEL_NAME_RE.finditer(segment):
            key = match.group("json_key") or match.group("query_key") or match.group("xml_key") or ""
            value = match.group("json_value") or match.group("query_value") or match.group("xml_value") or ""
            name = CaptureService._clean_channel_name(value)
            if not name:
                continue
            key_lower = key.lower()
            score = 30 if "channel" in key_lower else 20
            if key_lower in {"name", "title"}:
                score -= 8
            if any(token in name.lower() for token in ("cctv", "卫视", "高清", "超清", "4k")):
                score += 5
            candidates.append((score, name, f"{key}={name}"))
        if not candidates:
            return "", ""
        candidates.sort(key=lambda item: (item[0], len(item[1])), reverse=True)
        return candidates[0][1], candidates[0][2]

    @staticmethod
    def _extract_channel_id(segment: str) -> str:
        for match in CHANNEL_ID_RE.finditer(segment):
            value = match.group("json_value") or match.group("query_value") or match.group("xml_value") or ""
            value = unquote(str(value)).strip().strip("\"'")
            if value and re.match(r"^[A-Za-z0-9_.:-]{1,40}$", value):
                return value
        return ""

    @staticmethod
    def _clean_channel_name(value: str) -> str:
        name = unquote(str(value or "")).strip().strip("\"'`")
        if "\\u" in name:
            try:
                name = name.encode("utf-8").decode("unicode_escape")
            except UnicodeError:
                pass
        name = re.sub(r"[\x00-\x1f\x7f]+", "", name).strip()
        name = re.sub(r"\s+", " ", name)
        name = name.strip(" ,;，；")
        lower = name.lower()
        if not name or len(name) > 80:
            return ""
        if lower in BAD_CHANNEL_NAME_TOKENS:
            return ""
        if any(token in lower for token in ("rtp://", "igmp://", "udp://", "http://", "https://", "usertoken")):
            return ""
        if re.match(r"^\d+$", name) or re.match(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$", name):
            return ""
        if "ChannelFCC" in name or "channelFCC" in name:
            return ""
        return name

    def _consume_http_text(self, line: str) -> None:
        text = unquote(line)
        if "\ufffd" in text:
            return
        with self._lock:
            self._http_buffer = (self._http_buffer + "\n" + text)[-64000:]
            buffer = self._http_buffer
            peer = dict(self._last_tcp_peer)
        if "channelAcquire" not in buffer or "UserToken" not in buffer:
            return
        path_match = CHANNEL_ACQUIRE_RE.search(buffer)
        token_match = re.search(r'"UserToken"\s*:\s*"(?P<token>[^"]+)"', buffer)
        if not path_match or not token_match:
            return
        token = token_match.group("token").strip()
        if not token or token in self._token_seen:
            return
        self._token_seen.add(token)
        record = {
            "token": token,
            "path": path_match.group("path"),
            "captured_at": int(time.time()),
            **peer,
        }
        if self.token_store and self.token_store.save_token(record):
            dip = f"{peer.get('dip', '-') if peer else '-'}:{peer.get('dport', '-') if peer else '-'}"
            self.logger.info(f"发现 channelAcquire UserToken，服务端={dip}，已写入 playlist_token.json")

    def _watch_process(self, proc: subprocess.Popen[str]) -> None:
        return_code = proc.wait()
        with self._lock:
            if self._proc is not proc:
                return
            if self._state["state"] == "running":
                if return_code == 0:
                    self._state.update({
                        "state": "stopped",
                        "message": "抓包已结束",
                        "stopped_at": time.time(),
                        "stop_reason": "tcpdump 已退出",
                    })
                    self.logger.info("tcpdump 已退出，抓包结束")
                else:
                    self._state.update({
                        "state": "error",
                        "message": "抓包进程异常退出",
                        "stopped_at": time.time(),
                        "last_error": f"tcpdump 退出码 {return_code}",
                        "stop_reason": "进程异常退出",
                    })
                    self.logger.error(f"tcpdump 异常退出，退出码 {return_code}")
            self._proc = None

    def _auto_stop_worker(self, started_at: float, duration: int) -> None:
        deadline = started_at + duration
        while time.time() < deadline:
            time.sleep(min(1.0, max(0.1, deadline - time.time())))
        with self._lock:
            if self._state["state"] != "running" or self._state["started_at"] != started_at:
                return
        self.stop(reason="定时抓包完成")

    def stop(self, reason: str = "用户手动停止") -> dict[str, Any]:
        with self._lock:
            if self._state["state"] != "running":
                return self.status()
            proc = self._proc
            self._state.update({
                "state": "stopped",
                "message": "抓包已停止，可开始编辑频道",
                "stopped_at": time.time(),
                "stop_reason": reason,
            })
        if proc is not None and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            except ProcessLookupError:
                pass
        self.logger.info(f"抓包停止：{reason}；累计捕获 {self.status()['total_packets']} 个候选 UDP 包，发现 {len(self.streams())} 个组播流")
        return self.status()

    def reset(self) -> dict[str, Any]:
        with self._lock:
            if self._state["state"] == "running":
                raise RuntimeError("抓包进行中，不能重置")
            self._streams = {}
            self._state.update({
                "state": "idle",
                "message": "等待开始抓包",
                "started_at": None,
                "stopped_at": None,
                "last_error": None,
                "stop_reason": None,
                "total_packets": 0,
            })
        self.logger.info("已重置抓包状态与候选流列表")
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            payload = dict(self._state)
            started_at = payload.get("started_at")
            stopped_at = payload.get("stopped_at")
            end_time = stopped_at or time.time()
            elapsed = int(end_time - started_at) if started_at else 0
            duration = int(payload.get("duration") or 0)
            payload["elapsed"] = max(0, elapsed)
            payload["remaining"] = max(0, duration - elapsed) if duration > 0 and payload["state"] == "running" else None
            payload["streams_found"] = len(self._streams)
            payload["eligible_streams"] = sum(
                1
                for item in self._streams.values()
                if is_probable_iptv_stream(item.host, item.port, item.packets, MIN_PACKET_COUNT)
            )
            payload["min_packet_count"] = MIN_PACKET_COUNT
            return payload

    def streams(self) -> list[dict[str, Any]]:
        with self._lock:
            records = [record.to_dict() for record in self._streams.values()]
        records.sort(key=lambda item: (-int(item["packets"]), item["host"], int(item["port"])))
        for item in records:
            item["eligible"] = is_probable_iptv_stream(
                str(item["host"]),
                int(item["port"]),
                int(item["packets"]),
                MIN_PACKET_COUNT,
            )
        return records

    def metrics(self) -> dict[str, Any]:
        status = self.status()
        return {
            "capture_running": status["state"] == "running",
            "capture_state": status["state"],
            "streams_found": status["streams_found"],
            "eligible_streams": status["eligible_streams"],
            "total_packets": status["total_packets"],
            "elapsed": status["elapsed"],
        }
