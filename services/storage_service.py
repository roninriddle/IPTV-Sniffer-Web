#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JSON persistence for settings and named channel drafts."""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

from config import CATEGORY_OPTIONS, DEFAULT_SETTINGS
from utils import classify_channel_name, stream_key


def _safe_load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def _atomic_dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, path)
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass


class SettingsStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def load(self) -> dict[str, Any]:
        with self._lock:
            data = _safe_load_json(self.path, {})
            merged = DEFAULT_SETTINGS.copy()
            if isinstance(data, dict):
                merged.update(data)
            return merged

    def save(self, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            current = self.load()
            current.update(data)
            _atomic_dump_json(self.path, current)
            return current


class ChannelStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def load(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            data = _safe_load_json(self.path, {})
            return data if isinstance(data, dict) else {}

    def list(self) -> list[dict[str, Any]]:
        return list(self.load().values())

    def get(self, key: str) -> dict[str, Any] | None:
        return self.load().get(key)

    def save_rows(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        with self._lock:
            data = self.load()
            saved = 0
            deleted = 0
            for row in rows:
                host = str(row.get("host", "")).strip()
                try:
                    port = int(row.get("port"))
                except (TypeError, ValueError):
                    continue
                key = str(row.get("key") or stream_key(host, port))
                name = str(row.get("name", "")).strip()
                category = str(row.get("category", "")).strip() or classify_channel_name(name)
                if category not in CATEGORY_OPTIONS:
                    category = classify_channel_name(name)
                if not name:
                    if key in data:
                        data.pop(key, None)
                        deleted += 1
                    continue
                data[key] = {
                    "key": key,
                    "host": host,
                    "port": port,
                    "name": name,
                    "category": category,
                    "packets": int(row.get("packets", 0) or 0),
                    "probe_status": str(row.get("probe_status", data.get(key, {}).get("probe_status", "not_probed"))),
                    "probe_message": str(row.get("probe_message", data.get(key, {}).get("probe_message", "未检测"))),
                    "codec_name": str(row.get("codec_name", data.get(key, {}).get("codec_name", ""))),
                    "width": row.get("width", data.get(key, {}).get("width")),
                    "height": row.get("height", data.get(key, {}).get("height")),
                    "frame_rate": str(row.get("frame_rate", data.get(key, {}).get("frame_rate", ""))),
                    "resolution_label": str(row.get("resolution_label", data.get(key, {}).get("resolution_label", "未识别"))),
                    "quality_group": str(row.get("quality_group", data.get(key, {}).get("quality_group", "未识别"))),
                    "probed_at": row.get("probed_at", data.get(key, {}).get("probed_at")),
                    "updated_at": row.get("updated_at"),
                }
                saved += 1
            _atomic_dump_json(self.path, data)
            return {"saved": saved, "deleted": deleted, "total": len(data)}
