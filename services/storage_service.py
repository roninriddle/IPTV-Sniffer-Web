#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JSON persistence for settings and named channel drafts."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
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
                    "fec_port": self._safe_port(row.get("fec_port") or data.get(key, {}).get("fec_port")),
                    "tvg_id": str(row.get("tvg_id") or data.get(key, {}).get("tvg_id", "")),
                    "tvg_name": str(row.get("tvg_name") or data.get(key, {}).get("tvg_name", "")),
                    "tvg_logo": str(row.get("tvg_logo") or data.get(key, {}).get("tvg_logo", "")),
                    "epg_source": str(row.get("epg_source") or data.get(key, {}).get("epg_source", "")),
                    "auto_name": str(row.get("auto_name") or data.get(key, {}).get("auto_name", "")),
                    "auto_name_source": str(row.get("auto_name_source") or data.get(key, {}).get("auto_name_source", "")),
                    "probed_at": row.get("probed_at", data.get(key, {}).get("probed_at")),
                    "epg_matched_at": row.get("epg_matched_at", data.get(key, {}).get("epg_matched_at")),
                    "updated_at": row.get("updated_at"),
                    "is_primary": bool(row.get("is_primary", data.get(key, {}).get("is_primary", False))),
                    "export_health_status": str(row.get("export_health_status", data.get(key, {}).get("export_health_status", ""))),
                    "export_health_http_code": self._safe_nonnegative_int(row.get("export_health_http_code", data.get(key, {}).get("export_health_http_code", 0))) or None,
                    "export_health_bytes": self._safe_nonnegative_int(row.get("export_health_bytes", data.get(key, {}).get("export_health_bytes", 0))),
                    "export_health_speed": self._safe_nonnegative_int(row.get("export_health_speed", data.get(key, {}).get("export_health_speed", 0))),
                    "export_health_elapsed_ms": self._safe_nonnegative_int(row.get("export_health_elapsed_ms", data.get(key, {}).get("export_health_elapsed_ms", 0))),
                    "export_health_checked_at": row.get("export_health_checked_at", data.get(key, {}).get("export_health_checked_at")),
                    "export_health_message": str(row.get("export_health_message", data.get(key, {}).get("export_health_message", ""))),
                }
                saved += 1
            _atomic_dump_json(self.path, data)
            return {"saved": saved, "deleted": deleted, "total": len(data)}

    def patch_group_primary(self, group_key: str, primary_key: str) -> int:
        """Set is_primary=True on primary_key and False on all others in the same group.

        Returns 0 if primary_key does not exist in group_key (safe no-op).
        """
        from utils import channel_group_key
        with self._lock:
            data = self.load()
            # Verify primary_key actually belongs to this group
            target = data.get(primary_key)
            if not target or channel_group_key(target) != group_key:
                return 0
            updated = 0
            for k, ch in data.items():
                if channel_group_key(ch) == group_key:
                    ch["is_primary"] = (k == primary_key)
                    updated += 1
            if updated:
                _atomic_dump_json(self.path, data)
            return updated

    def delete_keys(self, keys: list[str]) -> int:
        with self._lock:
            data = self.load()
            deleted = 0
            for key in keys:
                if str(key) in data:
                    data.pop(str(key))
                    deleted += 1
            if deleted:
                _atomic_dump_json(self.path, data)
            return deleted

    @staticmethod
    def _safe_port(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            port = int(value)
        except (TypeError, ValueError):
            return None
        return port if 1 <= port <= 65535 else None

    @staticmethod
    def _safe_nonnegative_int(value: Any) -> int:
        try:
            number = int(value or 0)
        except (TypeError, ValueError):
            return 0
        return max(0, number)


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

    def bulk_save(self, records: list[dict[str, Any]]) -> int:
        """Write multiple FCC records in a single lock acquisition. Returns saved count."""
        saved = 0
        now = time.time()
        with self._lock:
            data = self.load()
            for record in records:
                key = str(record.get("key", "")).strip()
                fcc_ip = str(record.get("fcc_ip", "")).strip()
                try:
                    fcc_port = int(record.get("fcc_port"))
                except (TypeError, ValueError):
                    continue
                if not key or not valid_ip_or_host(fcc_ip) or not 1 <= fcc_port <= 65535:
                    continue
                current = data.get(key, {})
                data[key] = {
                    "key": key,
                    "host": str(record.get("host", current.get("host", ""))).strip(),
                    "port": ChannelStore._safe_port(record.get("port", current.get("port"))),
                    "fcc_ip": fcc_ip,
                    "fcc_port": fcc_port,
                    "source_url": str(record.get("source_url", current.get("source_url", ""))).strip(),
                    "raw_field": str(record.get("raw_field", current.get("raw_field", ""))).strip(),
                    "first_seen": current.get("first_seen") or now,
                    "last_seen": now,
                }
                saved += 1
            if saved:
                _atomic_dump_json(self.path, data)
        return saved


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


class ChannelSnapshotStore:
    """Persists named snapshots of the channel list."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def list_meta(self) -> list[dict[str, Any]]:
        with self._lock:
            data = _safe_load_json(self.path, {})
            if not isinstance(data, dict):
                return []
            return sorted(
                [{"id": k, "name": v.get("name", ""), "created_at": v.get("created_at", 0), "count": v.get("count", 0)}
                 for k, v in data.items() if isinstance(v, dict)],
                key=lambda x: x["created_at"],
                reverse=True,
            )

    def save(self, name: str, channels: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            data = _safe_load_json(self.path, {})
            if not isinstance(data, dict):
                data = {}
            snap_id = f"snap_{int(time.time() * 1000)}"
            entry = {
                "id": snap_id,
                "name": name,
                "created_at": time.time(),
                "count": len(channels),
                "channels": channels,
            }
            data[snap_id] = entry
            _atomic_dump_json(self.path, data)
            return {"id": snap_id, "name": name, "created_at": entry["created_at"], "count": entry["count"]}

    def get(self, snap_id: str) -> dict[str, Any] | None:
        with self._lock:
            data = _safe_load_json(self.path, {})
            if not isinstance(data, dict):
                return None
            return data.get(snap_id)

    def delete(self, snap_id: str) -> bool:
        with self._lock:
            data = _safe_load_json(self.path, {})
            if not isinstance(data, dict) or snap_id not in data:
                return False
            data.pop(snap_id)
            _atomic_dump_json(self.path, data)
            return True


class OperatorChannelStore:
    """Persists operator-provided channel list (ip:port -> channel info)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._cache: dict[str, dict[str, Any]] | None = None

    def load(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            if self._cache is None:
                data = _safe_load_json(self.path, {})
                self._cache = data if isinstance(data, dict) else {}
            return dict(self._cache)

    def get(self, key: str) -> dict[str, Any] | None:
        return self.load().get(key)

    def import_channels(self, channels: list[dict[str, Any]]) -> int:
        """Bulk-import a list of channel dicts. Returns count of imported entries."""
        saved = 0
        with self._lock:
            data: dict[str, dict[str, Any]] = {}
            for ch in channels:
                ip = str(ch.get("ip", "")).strip()
                port = ch.get("port")
                name = str(ch.get("name", "")).strip()
                if not ip or not port or not name:
                    continue
                try:
                    port_int = int(port)
                except (TypeError, ValueError):
                    continue
                key = f"{ip}:{port_int}"
                data[key] = {
                    "key": key,
                    "host": ip,
                    "port": port_int,
                    "name": name,
                    "channel_num": ch.get("num"),
                    "is_hd": ch.get("is_hd", False),
                    "time_shift": ch.get("time_shift", False),
                    "fcc_ip": str(ch.get("fcc_ip", "")).strip(),
                    "fcc_port": ch.get("fcc_port"),
                    "fec_port": ch.get("fec_port"),
                    "channel_id": str(ch.get("channel_id", "")).strip(),
                    "source": "operator_channel_list",
                }
                saved += 1
            self._cache = data
            _atomic_dump_json(self.path, data)
        return saved

    def invalidate(self) -> None:
        with self._lock:
            self._cache = None

    def clear(self) -> None:
        with self._lock:
            self._cache = {}
            _atomic_dump_json(self.path, {})
