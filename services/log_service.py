#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Thread-safe in-memory + file logger for the Web UI."""
from __future__ import annotations

import threading
import time
from collections import deque
from pathlib import Path
from typing import Any


class AppLogger:
    def __init__(self, log_file: Path, memory_limit: int = 600) -> None:
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._entries: deque[dict[str, Any]] = deque(maxlen=memory_limit)
        self._seq = 0

    def append(self, message: str, level: str = "INFO") -> dict[str, Any]:
        now = time.time()
        entry = {
            "id": 0,
            "timestamp": now,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "level": level.upper(),
            "message": str(message),
        }
        with self._lock:
            self._seq += 1
            entry["id"] = self._seq
            self._entries.append(entry)
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(f"[{entry['time']}] [{entry['level']}] {entry['message']}\n")
        return entry

    def info(self, message: str) -> dict[str, Any]:
        return self.append(message, "INFO")

    def warning(self, message: str) -> dict[str, Any]:
        return self.append(message, "WARN")

    def error(self, message: str) -> dict[str, Any]:
        return self.append(message, "ERROR")

    def read(self, after_id: int = 0, limit: int = 300) -> dict[str, Any]:
        with self._lock:
            entries = [entry.copy() for entry in self._entries if entry["id"] > after_id]
            if limit > 0:
                entries = entries[-limit:]
            latest_id = self._seq
        return {"entries": entries, "latest_id": latest_id}

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "latest_id": self._seq,
                "memory_entries": len(self._entries),
                "log_file": str(self.log_file),
                "log_file_exists": self.log_file.exists(),
                "log_file_size": self.log_file.stat().st_size if self.log_file.exists() else 0,
            }

    def clear_memory(self) -> None:
        with self._lock:
            self._entries.clear()
