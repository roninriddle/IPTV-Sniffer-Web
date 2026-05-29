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
            self.logger.info("流信息自动识别环境检查通过：ffprobe 可用")
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
            "probe_message": stored.get("probe_message", "未识别"),
            "codec_name": stored.get("codec_name", ""),
            "width": stored.get("width"),
            "height": stored.get("height"),
            "frame_rate": stored.get("frame_rate", ""),
            "resolution_label": stored.get("resolution_label", "未识别"),
            "quality_group": stored.get("quality_group", "未识别"),
            "detected_name": stored.get("detected_name", ""),
            "detected_name_source": stored.get("detected_name_source", ""),
            "probed_at": stored.get("probed_at"),
            "service_provider": stored.get("service_provider", ""),
            "format_bit_rate": stored.get("format_bit_rate"),
            "nb_streams": stored.get("nb_streams", 0),
            "nb_programs": stored.get("nb_programs", 0),
            "audio_streams": stored.get("audio_streams", []),
            "video_profile": stored.get("video_profile", ""),
            "video_level": stored.get("video_level"),
            "pix_fmt": stored.get("pix_fmt", ""),
            "field_order": stored.get("field_order", ""),
            "avg_frame_rate": stored.get("avg_frame_rate", ""),
        }
        merged.update({k: v for k, v in cached.items() if v not in (None, "") or k in {"width", "height"}})
        return merged

    def remember_failure(self, key: str, message: str) -> dict[str, Any]:
        result = self._build_failure(key, message, time.time())
        self._remember(key, result)
        return result

    @staticmethod
    def _input_url(path_mode: str, host: str, port: int) -> str:
        scheme = "rtp" if path_mode == "rtp" else "udp"
        # FFmpeg UDP receive options reduce packet drops and bound idle waits.
        query = f"fifo_size={PROBE_BUFFER_SIZE}&overrun_nonfatal=1&timeout={PROBE_TIMEOUT_SECONDS * 1000000}"
        return f"{scheme}://{host}:{port}?{query}"

    def probe(self, key: str, host: str, port: int, path_mode: str) -> dict[str, Any]:
        runtime = self.runtime_check()
        if not runtime.get("ok"):
            raise RuntimeError("流信息自动识别环境检查未通过：" + "；".join(runtime.get("errors", [])))
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
            "-show_entries", "stream=codec_name,codec_type,width,height,r_frame_rate,avg_frame_rate,bit_rate,sample_rate,channels,channel_layout,profile,level,pix_fmt,field_order:program=program_id,program_num:program_tags=service_name,service_provider:format=bit_rate,nb_streams,nb_programs:format_tags=service_name,title",
            "-of", "json",
            url,
        ]
        self.logger.info(f"开始自动识别流信息：{key}，请确保该频道当前仍在机顶盒播放")
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
            result = self._build_failure(key, "自动识别超时；请保持频道正在播放后重试", started)
            self._remember(key, result)
            self.logger.warning(f"流信息自动识别超时：{key}")
            return result
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0:
            message = stderr.splitlines()[-1] if stderr else "ffprobe 未能解析该流"
            result = self._build_failure(key, message, started)
            self._remember(key, result)
            self.logger.warning(f"流信息自动识别失败：{key}，{message}")
            return result
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            result = self._build_failure(key, "ffprobe 返回了无法解析的 JSON", started)
            self._remember(key, result)
            self.logger.warning(f"流信息自动识别失败：{key}，ffprobe JSON 无法解析")
            return result
        streams = payload.get("streams") or []
        if not streams:
            result = self._build_failure(key, "未识别到视频流；请切回该频道后重试", started)
            self._remember(key, result)
            self.logger.warning(f"流信息自动识别失败：{key}，未识别到视频流")
            return result
        # Pick the video stream with the most pixels; avoids grabbing a low-res
        # secondary stream from a multi-program TS that carries the main 4K stream.
        def _px(s: dict) -> int:
            try:
                return int(s.get("width") or 0) * int(s.get("height") or 0)
            except (TypeError, ValueError):
                return 0
        video_streams = [s for s in streams if isinstance(s, dict) and (s.get("width") or s.get("height"))]
        stream = max(video_streams, key=_px) if video_streams else (streams[0] if isinstance(streams[0], dict) else {})
        try:
            width = int(stream.get("width") or 0)
            height = int(stream.get("height") or 0)
        except (TypeError, ValueError):
            width, height = 0, 0
        codec_name = str(stream.get("codec_name") or "").strip()
        frame_rate = str(stream.get("r_frame_rate") or "").strip()
        avg_frame_rate = str(stream.get("avg_frame_rate") or "").strip()
        video_profile = str(stream.get("profile") or "").strip()
        try:
            video_level = int(stream.get("level") or 0) or None
        except (TypeError, ValueError):
            video_level = None
        pix_fmt = str(stream.get("pix_fmt") or "").strip()
        field_order = str(stream.get("field_order") or "").strip()
        detected_name = self._extract_service_name(payload)
        resolution_label = resolution_label_from_size(width, height)
        quality_group = stream_quality_group(width, height)
        format_payload = payload.get("format") or {}
        try:
            format_bit_rate = int(format_payload.get("bit_rate") or 0) or None
        except (TypeError, ValueError):
            format_bit_rate = None
        try:
            nb_streams_count = int(format_payload.get("nb_streams") or 0)
        except (TypeError, ValueError):
            nb_streams_count = 0
        try:
            nb_programs_count = int(format_payload.get("nb_programs") or 0)
        except (TypeError, ValueError):
            nb_programs_count = 0
        service_provider = ""
        for _prog in payload.get("programs") or []:
            if not isinstance(_prog, dict):
                continue
            _ptags = _prog.get("tags") if isinstance(_prog.get("tags"), dict) else {}
            _sp = str(_ptags.get("service_provider", "")).strip()
            if _sp and _sp.lower() not in {"unknown", ""}:
                service_provider = _sp
                break
        audio_streams: list[dict[str, Any]] = []
        for _s in streams:
            if not isinstance(_s, dict) or str(_s.get("codec_type", "")).lower() != "audio":
                continue
            try:
                _sr = int(_s.get("sample_rate") or 0) or None
            except (TypeError, ValueError):
                _sr = None
            try:
                _ch = int(_s.get("channels") or 0) or None
            except (TypeError, ValueError):
                _ch = None
            try:
                _br = int(_s.get("bit_rate") or 0) or None
            except (TypeError, ValueError):
                _br = None
            audio_streams.append({
                "codec_name": str(_s.get("codec_name", "")).strip(),
                "sample_rate": _sr,
                "channels": _ch,
                "channel_layout": str(_s.get("channel_layout", "")).strip(),
                "bit_rate": _br,
            })
        result = {
            "key": key,
            "probe_status": "ok" if width > 0 and height > 0 else "partial",
            "probe_message": "自动识别成功" if width > 0 and height > 0 else "识别到视频流，但分辨率不完整",
            "codec_name": codec_name,
            "width": width or None,
            "height": height or None,
            "frame_rate": frame_rate,
            "resolution_label": resolution_label,
            "quality_group": quality_group,
            "detected_name": detected_name,
            "detected_name_source": "ffprobe_service_name" if detected_name else "",
            "probed_at": int(time.time()),
            "probe_elapsed_ms": int((time.time() - started) * 1000),
            "service_provider": service_provider,
            "format_bit_rate": format_bit_rate,
            "nb_streams": nb_streams_count,
            "nb_programs": nb_programs_count,
            "audio_streams": audio_streams,
            "video_profile": video_profile,
            "video_level": video_level,
            "pix_fmt": pix_fmt,
            "field_order": field_order,
            "avg_frame_rate": avg_frame_rate,
        }
        self._remember(key, result)
        self.logger.info(
            f"流信息自动识别完成：{key}，编码={codec_name or '-'}，分辨率={width or '-'}x{height or '-'}，判定={quality_group}"
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
            "detected_name": "",
            "detected_name_source": "",
            "probed_at": int(time.time()),
            "probe_elapsed_ms": int((time.time() - started) * 1000),
            "service_provider": "",
            "format_bit_rate": None,
            "nb_streams": 0,
            "nb_programs": 0,
            "audio_streams": [],
            "video_profile": "",
            "video_level": None,
            "pix_fmt": "",
            "field_order": "",
            "avg_frame_rate": "",
        }

    def _remember(self, key: str, result: dict[str, Any]) -> None:
        with self._lock:
            self._cache[key] = dict(result)

    @staticmethod
    def _extract_service_name(payload: dict[str, Any]) -> str:
        values: list[str] = []
        for program in payload.get("programs") or []:
            if not isinstance(program, dict):
                continue
            tags = program.get("tags") if isinstance(program.get("tags"), dict) else {}
            values.extend([str(tags.get("service_name", "")).strip(), str(tags.get("title", "")).strip()])
        format_payload = payload.get("format") if isinstance(payload.get("format"), dict) else {}
        tags = format_payload.get("tags") if isinstance(format_payload.get("tags"), dict) else {}
        values.extend([str(tags.get("service_name", "")).strip(), str(tags.get("title", "")).strip()])
        for value in values:
            if value and value.lower() not in {"unknown", "no name", "service01"}:
                return value
        return ""
