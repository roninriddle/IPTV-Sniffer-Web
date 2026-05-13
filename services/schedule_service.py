#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Periodic capture scheduler for unattended IPTV sniffing."""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta
from typing import Any

from config import DEFAULT_CAPTURE_SECONDS
from services.capture_service import CaptureService
from services.log_service import AppLogger
from services.storage_service import SettingsStore


class ScheduleService:
    def __init__(self, logger: AppLogger, settings_store: SettingsStore, capture_service: CaptureService) -> None:
        self.logger = logger
        self.settings_store = settings_store
        self.capture_service = capture_service
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._state: dict[str, Any] = {
            "enabled": False,
            "unit": "days",
            "every": 1,
            "hour": 3,
            "minute": 0,
            "next_run_at": None,
            "last_run_at": None,
            "last_message": "定时任务未启用",
            "last_error": None,
        }
        self.load_from_settings(reset_next=True)

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        status = self.status()
        if status["enabled"]:
            self.logger.info(f"定时嗅探任务已启用：{self._describe(status)}")

    def load_from_settings(self, reset_next: bool = False) -> dict[str, Any]:
        settings = self.settings_store.load()
        schedule = self._normalize(settings)
        with self._lock:
            self._state.update({
                "enabled": schedule["schedule_enabled"],
                "unit": schedule["schedule_unit"],
                "every": schedule["schedule_every"],
                "hour": schedule["schedule_hour"],
                "minute": schedule["schedule_minute"],
            })
            if reset_next:
                self._state["next_run_at"] = self._compute_next_run(schedule)
            if not schedule["schedule_enabled"]:
                self._state["next_run_at"] = None
                self._state["last_message"] = "定时任务未启用"
        return self.status()

    def configure(self, data: dict[str, Any]) -> dict[str, Any]:
        schedule = self._normalize(data, strict=True)
        payload = {
            "interface": str(data.get("interface", "")).strip(),
            "http_host": str(data.get("http_host", "")).strip(),
            "http_port": int(data.get("http_port", 5140) or 5140),
            "path_mode": str(data.get("path_mode", "rtp")).strip().lower(),
            "duration": int(data.get("duration", DEFAULT_CAPTURE_SECONDS) or 0),
            **schedule,
        }
        self.settings_store.save(payload)
        with self._lock:
            self._state.update({
                "enabled": schedule["schedule_enabled"],
                "unit": schedule["schedule_unit"],
                "every": schedule["schedule_every"],
                "hour": schedule["schedule_hour"],
                "minute": schedule["schedule_minute"],
                "next_run_at": self._compute_next_run(schedule),
                "last_error": None,
                "last_message": "定时任务已启用" if schedule["schedule_enabled"] else "定时任务未启用",
            })
        if schedule["schedule_enabled"]:
            self.logger.info(f"定时嗅探任务已保存：{self._describe(self.status())}")
        else:
            self.logger.info("定时嗅探任务已停用")
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            payload = dict(self._state)
        next_run_at = payload.get("next_run_at")
        payload["next_run_text"] = self._format_ts(next_run_at)
        payload["last_run_text"] = self._format_ts(payload.get("last_run_at"))
        return payload

    def _loop(self) -> None:
        while not self._stop_event.wait(5):
            with self._lock:
                enabled = bool(self._state.get("enabled"))
                next_run_at = self._state.get("next_run_at")
                due = enabled and isinstance(next_run_at, (int, float)) and time.time() >= float(next_run_at)
            if due:
                self._run_due()

    def _run_due(self) -> None:
        settings = self.settings_store.load()
        schedule = self._normalize(settings)
        if not schedule.get("schedule_enabled"):
            with self._lock:
                self._state["enabled"] = False
                self._state["next_run_at"] = None
                self._state["last_message"] = "定时任务未启用"
            return
        with self._lock:
            self._state["next_run_at"] = self._compute_next_run(schedule, after=time.time())
            self._state["last_run_at"] = int(time.time())
            self._state["last_error"] = None
            self._state["last_message"] = "定时任务已触发"
        try:
            self.logger.info("定时嗅探任务触发，开始自动抓包")
            self.capture_service.start(settings)
            with self._lock:
                self._state["last_message"] = "已启动一次定时嗅探"
        except Exception as exc:
            message = str(exc)
            with self._lock:
                self._state["last_error"] = message
                self._state["last_message"] = "定时嗅探启动失败"
            self.logger.warning(f"定时嗅探启动失败：{message}")

    def _normalize(self, data: dict[str, Any], strict: bool = False) -> dict[str, Any]:
        enabled = self._to_bool(data.get("schedule_enabled", False))
        unit = str(data.get("schedule_unit", "days")).strip().lower()
        if unit not in {"hours", "days"}:
            raise ValueError("定时单位只能选择小时或天")
        try:
            every = int(data.get("schedule_every", 1))
            hour = int(data.get("schedule_hour", 3))
            minute = int(data.get("schedule_minute", 0))
            duration = int(data.get("duration", DEFAULT_CAPTURE_SECONDS) or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("定时任务参数必须是有效数字") from exc
        if unit == "hours" and not 1 <= every <= 168:
            raise ValueError("按小时定时的间隔必须在 1-168 小时之间")
        if unit == "days" and not 1 <= every <= 30:
            raise ValueError("按天定时的间隔必须在 1-30 天之间")
        if not 0 <= hour <= 23 or not 0 <= minute <= 59:
            raise ValueError("定时执行时间必须位于 00:00-23:59")
        if strict and enabled:
            if duration <= 0:
                raise ValueError("启用定时任务时，嗅探时长必须大于 0 秒")
            if not str(data.get("interface", "")).strip():
                raise ValueError("启用定时任务前请先选择抓包网卡")
            if not str(data.get("http_host", "")).strip():
                raise ValueError("启用定时任务前请先填写 rtp2httpd 地址")
        return {
            "schedule_enabled": enabled,
            "schedule_unit": unit,
            "schedule_every": every,
            "schedule_hour": hour,
            "schedule_minute": minute,
        }

    def _compute_next_run(self, schedule: dict[str, Any], after: float | None = None) -> int | None:
        if not schedule.get("schedule_enabled"):
            return None
        after_ts = time.time() if after is None else float(after)
        if schedule["schedule_unit"] == "hours":
            return int(after_ts + int(schedule["schedule_every"]) * 3600)
        now = datetime.fromtimestamp(after_ts)
        target = now.replace(
            hour=int(schedule["schedule_hour"]),
            minute=int(schedule["schedule_minute"]),
            second=0,
            microsecond=0,
        )
        if target.timestamp() <= after_ts:
            target += timedelta(days=int(schedule["schedule_every"]))
        return int(target.timestamp())

    @staticmethod
    def _format_ts(value: Any) -> str:
        if not isinstance(value, (int, float)):
            return "-"
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _to_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    @staticmethod
    def _describe(status: dict[str, Any]) -> str:
        if not status.get("enabled"):
            return "未启用"
        if status.get("unit") == "hours":
            return f"每 {status.get('every')} 小时执行一次，下次 {status.get('next_run_text', '-')}"
        return (
            f"每 {status.get('every')} 天 "
            f"{int(status.get('hour', 0)):02d}:{int(status.get('minute', 0)):02d} 执行，下次 {status.get('next_run_text', '-')}"
        )
