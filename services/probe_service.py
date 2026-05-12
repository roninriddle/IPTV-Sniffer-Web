#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Live stream probing via ffprobe for codec and resolution detection."""
from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from typing import Any

from config import (
    PROBE_ANALYZE_DURATION_US,
    PROBE_BUFFER_SIZE,
    PROBE_SIZE_BYTES,
    PROBE_TIMEOUT_SECONDS,
)
from services.log_service import AppLogger
from utils import resolution_label_from_size, stream_quality_group, valid_ipv4_multicast


class ProbeService:
    def __init__(self, logger: AppLogger) -> None:
        self.logger = logger
        self._lock = threading.RLock()
        self._cache: dict[str, dict[str, Any]] = {}
        self._runtime_check: dict[str, Any] = {"ok": False, "errors": ["尚未检查 ffprobe 运行环境"]}

    def validate_runtime(self) -> dict[str, Any]:
        errors: list[str] = []
        if shutil.which("ffprobe") is None:
            errors.append("缺少依赖命令：ffprobe")
        result = {"ok": not errors, "errors": errors}
        with self._lock:
            self._runtime_check = result
        if errors:
            for error in errors:
                self.logger.error(error)
        else:
            self.logger.info("流信息检测环境检查通过：ffprobe 可用")
        return result

    def runtime_check(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._runtime_check)

    def get_cached(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            data = self._cache.get(key)
            return dict(data) if data else None

    def merge_probe_data(self, key: str, stored: dict[str, Any] | None = None) -> dict[str, Any]:
        stored = stored or {}
        cached = self.get_cached(key) or {}
        merged = {
            "probe_status": stored.get("probe_status", "not_probed"),
            "probe_message": stored.get("probe_message", "未检测"),
            "codec_name": stored.get("codec_name", ""),
            "width": stored.get("width"),
            "height": stored.get("height"),
            "frame_rate": stored.get("frame_rate", ""),
            "resolution_label": stored.get("resolution_label", "未识别"),
            "quality_group": stored.get("quality_group", "未识别"),
            "probed_at": stored.get("probed_at"),
        }
        merged.update({k: v for k, v in cached.items() if v not in (None, "") or k in {"width", "height"}})
        return merged

    @staticmethod
    def _input_url(path_mode: str, host: str, port: int) -> str:
        scheme = "rtp" if path_mode == "rtp" else "udp"
        # FFmpeg UDP receive options reduce packet drops and bound idle waits.
        query = f"fifo_size={PROBE_BUFFER_SIZE}&overrun_nonfatal=1&timeout={PROBE_TIMEOUT_SECONDS * 1000000}"
        return f"{scheme}://{host}:{port}?{query}"

    def probe(self, key: str, host: str, port: int, path_mode: str) -> dict[str, Any]:
        runtime = self.runtime_check()
        if not runtime.get("ok"):
            raise RuntimeError("流信息检测环境检查未通过：" + "；".join(runtime.get("errors", [])))
        if not valid_ipv4_multicast(host):
            raise ValueError("仅支持探测 IPv4 组播地址")
        if not 1 <= int(port) <= 65535:
            raise ValueError("端口必须位于 1-65535")
        path_mode = str(path_mode or "rtp").strip().lower()
        if path_mode not in {"rtp", "udp"}:
            path_mode = "rtp"
        url = self._input_url(path_mode, host, int(port))
        cmd = [
            "ffprobe",
            "-v", "error",
            "-probesize", str(PROBE_SIZE_BYTES),
            "-analyzeduration", str(PROBE_ANALYZE_DURATION_US),
            "-select_streams", "v:0",
            "-show_entries", "stream=codec_name,width,height,r_frame_rate",
            "-of", "json",
            url,
        ]
        self.logger.info(f"开始检测流信息：{key}，请确保该频道当前仍在机顶盒播放")
        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=PROBE_TIMEOUT_SECONDS + 4,
            )
        except subprocess.TimeoutExpired:
            result = self._build_failure(key, "检测超时；请保持频道正在播放后重试", started)
            self._remember(key, result)
            self.logger.warning(f"流信息检测超时：{key}")
            return result
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0:
            message = stderr.splitlines()[-1] if stderr else "ffprobe 未能解析该流"
            result = self._build_failure(key, message, started)
            self._remember(key, result)
            self.logger.warning(f"流信息检测失败：{key}，{message}")
            return result
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            result = self._build_failure(key, "ffprobe 返回了无法解析的 JSON", started)
            self._remember(key, result)
            self.logger.warning(f"流信息检测失败：{key}，ffprobe JSON 无法解析")
            return result
        streams = payload.get("streams") or []
        if not streams:
            result = self._build_failure(key, "未识别到视频流；请切回该频道后重试", started)
            self._remember(key, result)
            self.logger.warning(f"流信息检测失败：{key}，未识别到视频流")
            return result
        stream = streams[0] if isinstance(streams[0], dict) else {}
        try:
            width = int(stream.get("width") or 0)
            height = int(stream.get("height") or 0)
        except (TypeError, ValueError):
            width, height = 0, 0
        codec_name = str(stream.get("codec_name") or "").strip()
        frame_rate = str(stream.get("r_frame_rate") or "").strip()
        resolution_label = resolution_label_from_size(width, height)
        quality_group = stream_quality_group(width, height)
        result = {
            "key": key,
            "probe_status": "ok" if width > 0 and height > 0 else "partial",
            "probe_message": "检测成功" if width > 0 and height > 0 else "检测到视频流，但分辨率不完整",
            "codec_name": codec_name,
            "width": width or None,
            "height": height or None,
            "frame_rate": frame_rate,
            "resolution_label": resolution_label,
            "quality_group": quality_group,
            "probed_at": int(time.time()),
            "probe_elapsed_ms": int((time.time() - started) * 1000),
        }
        self._remember(key, result)
        self.logger.info(
            f"流信息检测完成：{key}，编码={codec_name or '-'}，分辨率={width or '-'}x{height or '-'}，判定={quality_group}"
        )
        return result

    def _build_failure(self, key: str, message: str, started: float) -> dict[str, Any]:
        return {
            "key": key,
            "probe_status": "failed",
            "probe_message": message,
            "codec_name": "",
            "width": None,
            "height": None,
            "frame_rate": "",
            "resolution_label": "未识别",
            "quality_group": "未识别",
            "probed_at": int(time.time()),
            "probe_elapsed_ms": int((time.time() - started) * 1000),
        }

    def _remember(self, key: str, result: dict[str, Any]) -> None:
        with self._lock:
            self._cache[key] = dict(result)
