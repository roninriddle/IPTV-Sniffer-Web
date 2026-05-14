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
from utils import classify_channel_name, stream_key, valid_ip_or_host


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
                    "probe_message": str(row.get("probe_message", data.get(key, {}).get("probe_message", "未识别"))),
                    "codec_name": str(row.get("codec_name", data.get(key, {}).get("codec_name", ""))),
                    "width": row.get("width", data.get(key, {}).get("width")),
                    "height": row.get("height", data.get(key, {}).get("height")),
                    "frame_rate": str(row.get("frame_rate", data.get(key, {}).get("frame_rate", ""))),
                    "resolution_label": str(row.get("resolution_label", data.get(key, {}).get("resolution_label", "未识别"))),
                    "quality_group": str(row.get("quality_group", data.get(key, {}).get("quality_group", "未识别"))),
                    "detected_name": str(row.get("detected_name") or data.get(key, {}).get("detected_name", "")),
                    "detected_name_source": str(row.get("detected_name_source") or data.get(key, {}).get("detected_name_source", "")),
                    "fcc_ip": str(row.get("fcc_ip") or data.get(key, {}).get("fcc_ip", "")),
                    "fcc_port": self._safe_port(row.get("fcc_port") or data.get(key, {}).get("fcc_port")),
                    "tvg_id": str(row.get("tvg_id") or data.get(key, {}).get("tvg_id", "")),
                    "tvg_name": str(row.get("tvg_name") or data.get(key, {}).get("tvg_name", "")),
                    "tvg_logo": str(row.get("tvg_logo") or data.get(key, {}).get("tvg_logo", "")),
                    "epg_source": str(row.get("epg_source") or data.get(key, {}).get("epg_source", "")),
                    "auto_name": str(row.get("auto_name") or data.get(key, {}).get("auto_name", "")),
                    "auto_name_source": str(row.get("auto_name_source") or data.get(key, {}).get("auto_name_source", "")),
                    "probed_at": row.get("probed_at", data.get(key, {}).get("probed_at")),
                    "epg_matched_at": row.get("epg_matched_at", data.get(key, {}).get("epg_matched_at")),
                    "updated_at": row.get("updated_at"),
                }
                saved += 1
            _atomic_dump_json(self.path, data)
            return {"saved": saved, "deleted": deleted, "total": len(data)}

    @staticmethod
    def _safe_port(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            port = int(value)
        except (TypeError, ValueError):
            return None
        return port if 1 <= port <= 65535 else None


class FccStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def load(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            data = _safe_load_json(self.path, {})
            return data if isinstance(data, dict) else {}

    def get(self, key: str) -> dict[str, Any] | None:
        return self.load().get(key)

    def save_record(self, record: dict[str, Any]) -> bool:
        key = str(record.get("key", "")).strip()
        fcc_ip = str(record.get("fcc_ip", "")).strip()
        try:
            fcc_port = int(record.get("fcc_port"))
        except (TypeError, ValueError):
            return False
        if not key or not valid_ip_or_host(fcc_ip) or not 1 <= fcc_port <= 65535:
            return False
        with self._lock:
            data = self.load()
            current = data.get(key, {})
            payload = {
                "key": key,
                "host": str(record.get("host", current.get("host", ""))).strip(),
                "port": ChannelStore._safe_port(record.get("port", current.get("port"))),
                "fcc_ip": fcc_ip,
                "fcc_port": fcc_port,
                "source_url": str(record.get("source_url", current.get("source_url", ""))).strip(),
                "raw_field": str(record.get("raw_field", current.get("raw_field", ""))).strip(),
                "first_seen": current.get("first_seen") or record.get("discovered_at"),
                "last_seen": record.get("discovered_at"),
            }
            data[key] = payload
            _atomic_dump_json(self.path, data)
            return True


class DiscoveryStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def load(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            data = _safe_load_json(self.path, {})
            return data if isinstance(data, dict) else {}

    def get(self, key: str) -> dict[str, Any] | None:
        return self.load().get(key)

    def save_record(self, record: dict[str, Any]) -> bool:
        key = str(record.get("key", "")).strip()
        name = str(record.get("name", "")).strip()
        if not key or not name:
            return False
        with self._lock:
            data = self.load()
            current = data.get(key, {})
            payload = {
                "key": key,
                "host": str(record.get("host", current.get("host", ""))).strip(),
                "port": ChannelStore._safe_port(record.get("port", current.get("port"))),
                "name": name,
                "channel_id": str(record.get("channel_id", current.get("channel_id", ""))).strip(),
                "source": str(record.get("source", current.get("source", "stb_payload"))).strip(),
                "raw_field": str(record.get("raw_field", current.get("raw_field", ""))).strip(),
                "source_url": str(record.get("source_url", current.get("source_url", ""))).strip(),
                "first_seen": current.get("first_seen") or record.get("discovered_at"),
                "last_seen": record.get("discovered_at"),
            }
            data[key] = payload
            _atomic_dump_json(self.path, data)
            return True


class StbTokenStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def load(self) -> dict[str, Any]:
        with self._lock:
            data = _safe_load_json(self.path, {"latest": None, "history": []})
            if not isinstance(data, dict):
                return {"latest": None, "history": []}
            history = data.get("history")
            if not isinstance(history, list):
                history = []
            return {"latest": data.get("latest"), "history": history[-100:]}

    def save_token(self, record: dict[str, Any]) -> bool:
        token = str(record.get("token", "")).strip()
        if not token:
            return False
        with self._lock:
            data = self.load()
            latest = data.get("latest") or {}
            if latest.get("token") == token and latest.get("dip") == record.get("dip"):
                return False
            payload = {
                "token": token,
                "sip": str(record.get("sip", "")).strip(),
                "sport": ChannelStore._safe_port(record.get("sport")),
                "dip": str(record.get("dip", "")).strip(),
                "dport": ChannelStore._safe_port(record.get("dport")),
                "path": str(record.get("path", "")).strip(),
                "captured_at": record.get("captured_at"),
            }
            history = list(data.get("history") or [])
            history.append(payload)
            data = {"latest": payload, "history": history[-100:]}
            _atomic_dump_json(self.path, data)
            return True


class CustomSourcesStore:
    """Persists user-added EPG and logo sources plus hidden built-in IDs."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def _load_raw(self) -> dict[str, Any]:
        raw = _safe_load_json(self.path, {})
        return raw if isinstance(raw, dict) else {}

    def load(self) -> dict[str, Any]:
        with self._lock:
            raw = self._load_raw()
            return {
                "epg": list(raw.get("epg") or []),
                "logo": list(raw.get("logo") or []),
                "deleted_builtin": {
                    "epg": list((raw.get("deleted_builtin") or {}).get("epg") or []),
                    "logo": list((raw.get("deleted_builtin") or {}).get("logo") or []),
                },
            }

    def add(self, source_type: str, name: str, url: str) -> dict[str, Any]:
        if source_type not in ("epg", "logo"):
            raise ValueError("来源类型必须是 epg 或 logo")
        name = str(name).strip()
        url = str(url).strip()
        if not name or not url:
            raise ValueError("名称和地址不能为空")
        if not url.startswith(("http://", "https://")):
            raise ValueError("地址必须以 http:// 或 https:// 开头")
        with self._lock:
            raw = self._load_raw()
            existing_urls = {s["url"] for s in (raw.get(source_type) or [])}
            if url in existing_urls:
                raise ValueError("该地址已存在")
            import uuid
            entry = {"id": str(uuid.uuid4())[:8], "name": name, "url": url}
            raw.setdefault(source_type, []).append(entry)
            _atomic_dump_json(self.path, raw)
            return entry

    def delete(self, source_type: str, source_id: str) -> bool:
        if source_type not in ("epg", "logo"):
            return False
        with self._lock:
            raw = self._load_raw()
            lst = list(raw.get(source_type) or [])
            filtered = [s for s in lst if s.get("id") != source_id]
            if len(filtered) == len(lst):
                return False
            raw[source_type] = filtered
            _atomic_dump_json(self.path, raw)
            return True

    def delete_builtin(self, source_type: str, source_id: str) -> bool:
        if source_type not in ("epg", "logo"):
            return False
        with self._lock:
            raw = self._load_raw()
            db = raw.setdefault("deleted_builtin", {})
            lst = list(db.get(source_type) or [])
            if source_id not in lst:
                lst.append(source_id)
                db[source_type] = lst
                _atomic_dump_json(self.path, raw)
            return True

    def restore_builtin(self, source_type: str, source_id: str) -> bool:
        if source_type not in ("epg", "logo"):
            return False
        with self._lock:
            raw = self._load_raw()
            db = raw.get("deleted_builtin") or {}
            lst = list(db.get(source_type) or [])
            if source_id not in lst:
                return False
            lst.remove(source_id)
            raw.setdefault("deleted_builtin", {})[source_type] = lst
            _atomic_dump_json(self.path, raw)
            return True
