#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPTV Sniffer Web application entrypoint."""
from __future__ import annotations

import gzip
import os
import zlib
import json
import re
import shutil
import subprocess
import time
import threading
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Flask, Response, jsonify, render_template, request, send_file, send_from_directory
from waitress import serve

from config import (
    ALLOWED_DOWNLOADS,
    APP_DESCRIPTION,
    CATEGORY_ORDER,
    APP_NAME,
    APP_VERSION,
    GITHUB_REPO,
    IPTV_AUTH_BACKUP_FILE,
    VERSION_CHECK_INTERVAL,
    CHANNELS_FILE,
    DATA_DIR,
    DISCOVERY_FILE,
    EPG_CACHE_FILE,
    EXPORT_HEALTH_MAX_CANDIDATES_PER_GROUP,
    EXPORT_HEALTH_MAX_GROUPS,
    EXPORT_HEALTH_SAMPLE_BYTES,
    EXPORT_HEALTH_TIMEOUT_SECONDS,
    FCC_FILE,
    LOG_FILE,
    LOG_MEMORY_LIMIT,
    OUTPUT_DIR,
    SETTINGS_FILE,
    STB_TOKEN_FILE,
    DEFAULT_RTP2HTTPD_CONFIG_PATH,
    OPERATOR_CHANNELS_FILE,
    SNAPSHOTS_FILE,
    WAITRESS_THREADS,
    WEB_HOST,
    WEB_PORT,
)
from services.capture_service import CaptureService
from services.epg_service import EpgService, normalize_channel_name
from services.export_service import ExportService
from services.iptv_auth_service import IptvAuthService
from services.log_service import AppLogger
from services.hls_service import HlsService
from services.stb_discovery_service import StbDiscoveryService
from services.storage_service import ChannelSnapshotStore, ChannelStore, DiscoveryStore, FccStore, OperatorChannelStore, SettingsStore, StbTokenStore
from utils import channel_group_key, channel_primary_score, channel_variant_key, classify_channel_name, natural_key, normalize_channel_name_for_group, valid_ip_or_host, valid_ipv4_multicast

app = Flask(__name__)
logger = AppLogger(LOG_FILE, LOG_MEMORY_LIMIT)
settings_store = SettingsStore(SETTINGS_FILE)
channel_store = ChannelStore(CHANNELS_FILE)
fcc_store = FccStore(FCC_FILE)
operator_channel_store = OperatorChannelStore(OPERATOR_CHANNELS_FILE)
snapshot_store = ChannelSnapshotStore(SNAPSHOTS_FILE)
stb_discovery_service = StbDiscoveryService(logger)
token_store = StbTokenStore(STB_TOKEN_FILE)
discovery_store = DiscoveryStore(DISCOVERY_FILE)
capture_service = CaptureService(logger, fcc_store, token_store, discovery_store)
export_service = ExportService(OUTPUT_DIR)
hls_service = HlsService(logger)
epg_service = EpgService(logger, EPG_CACHE_FILE)
iptv_auth_service = IptvAuthService(IPTV_AUTH_BACKUP_FILE, DATA_DIR, logger)
STARTED_AT = time.time()
_snapshot_cache: dict[str, tuple[float, bytes]] = {}
_snapshot_cache_ttl = 30
_version_check_lock = threading.RLock()
_version_check: dict[str, Any] = {
    "latest_version": None,
    "update_available": False,
    "checked_at": None,
    "error": None,
    "release_url": "",
}


def _version_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in str(v).strip().lstrip("v").split("."))
    except (ValueError, AttributeError):
        return (0,)


def _do_version_check() -> None:
    try:
        req = Request(
            f"https://api.github.com/repos/{GITHUB_REPO}/tags",
            headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}", "Accept": "application/vnd.github+json"},
        )
        with urlopen(req, timeout=10) as resp:
            tags = json.loads(resp.read())
        if not tags:
            return
        tag = str(tags[0].get("name", "")).strip()
        release_url = f"https://github.com/{GITHUB_REPO}/releases/tag/{tag}"
        clean = tag.lstrip("v")
        update_available = bool(clean and _version_tuple(clean) > _version_tuple(APP_VERSION))
        with _version_check_lock:
            _version_check.update({
                "latest_version": clean or None,
                "update_available": update_available,
                "checked_at": int(time.time()),
                "error": None,
                "release_url": release_url,
            })
        if update_available:
            logger.info(f"发现新版本 v{clean}（当前 v{APP_VERSION}），标签地址：{release_url}")
    except Exception as exc:
        with _version_check_lock:
            _version_check.update({"checked_at": int(time.time()), "error": str(exc)})


def _start_version_check_loop() -> None:
    def worker() -> None:
        while True:
            _do_version_check()
            time.sleep(VERSION_CHECK_INTERVAL)
    threading.Thread(target=worker, daemon=True).start()
M3U_ATTR_RE = re.compile(r'([\w-]+)="([^"]*)"')


def api_success(data: Any | None = None, **extra: Any):
    payload = {"success": True, "timestamp": int(time.time()), "data": data if data is not None else {}}
    payload.update(extra)
    return jsonify(payload)


def api_error(message: str, status_code: int = 400, **extra: Any):
    payload = {"success": False, "timestamp": int(time.time()), "error": str(message)}
    payload.update(extra)
    return jsonify(payload), status_code




def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _has_cjk(value: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", value or ""))


def _is_generic_cctv4_name(name: str) -> bool:
    normalized = normalize_channel_name_for_group(name).replace("频道", "")
    return normalized in {"CCTV4", "CCTV4中文国际", "CCTV4国际"}


def _prefer_auto_display_name(current_name: str, auto_name: str) -> bool:
    auto_variant = channel_variant_key({"name": auto_name})
    if not auto_variant:
        return False
    current_variant = channel_variant_key({"name": current_name})
    if current_variant == auto_variant:
        return _has_cjk(auto_name) and not _has_cjk(current_name)
    return _is_generic_cctv4_name(current_name)


def _should_keep_auto_name_over_epg(auto_name: str, epg_name: str) -> bool:
    auto_variant = channel_variant_key({"name": auto_name})
    if not auto_variant:
        return False
    epg_variant = channel_variant_key({"name": epg_name})
    if epg_variant != auto_variant:
        return True
    return _has_cjk(auto_name) and not _has_cjk(epg_name)


def fill_channel_name_from_metadata(item: dict[str, Any], allow_epg_name: bool = True) -> dict[str, Any]:
    current_name = str(item.get("name", "")).strip()
    detected_name = str(item.get("detected_name", "")).strip()
    epg_name = str(item.get("tvg_name", "")).strip()
    auto_name = str(item.get("auto_name", "")).strip()
    if detected_name and not auto_name:
        item["auto_name"] = detected_name
        item["auto_name_source"] = str(item.get("detected_name_source") or "ffprobe_service_name")
        auto_name = detected_name
    if detected_name and not current_name:
        item["name"] = detected_name
        current_name = detected_name
    if current_name and auto_name and _prefer_auto_display_name(current_name, auto_name):
        item["name"] = auto_name
        item["category"] = classify_channel_name(auto_name)
        current_name = auto_name
    current_matches_epg = (
        bool(current_name)
        and bool(epg_name)
        and normalize_channel_name(current_name) == normalize_channel_name(epg_name)
    )
    keep_auto_name = auto_name and _should_keep_auto_name_over_epg(auto_name, epg_name)
    if allow_epg_name and epg_name and not keep_auto_name and (not current_name or current_name == auto_name or current_matches_epg):
        if current_name and not auto_name:
            item["auto_name"] = current_name
            item["auto_name_source"] = str(item.get("auto_name_source") or "auto")
        item["name"] = epg_name
        item["category"] = classify_channel_name(epg_name)
        current_name = epg_name
    if not current_name and auto_name:
        item["name"] = auto_name
    return item


def _prepare_variant_epg_rematch(item: dict[str, Any]) -> None:
    variant = channel_variant_key(item)
    if not variant:
        return
    tvg_variant = channel_variant_key({"name": item.get("tvg_name", "")})
    if tvg_variant != variant:
        item["tvg_id"] = ""
        item["tvg_name"] = ""


def can_replace_with_epg_name(stored: dict[str, Any], item: dict[str, Any] | None = None) -> bool:
    item = item or stored
    saved_name = str(stored.get("name", "")).strip()
    auto_names = {
        str(stored.get("auto_name", "")).strip(),
        str(item.get("auto_name", "")).strip(),
        str(item.get("detected_name", "")).strip(),
    }
    auto_names.discard("")
    epg_name = str(item.get("tvg_name", "")).strip()
    saved_matches_epg = (
        bool(saved_name)
        and bool(epg_name)
        and normalize_channel_name(saved_name) == normalize_channel_name(epg_name)
    )
    auto_variant = channel_variant_key({
        "name": saved_name,
        "auto_name": str(item.get("auto_name", "") or stored.get("auto_name", "")),
        "detected_name": str(item.get("detected_name", "") or stored.get("detected_name", "")),
    })
    epg_variant = channel_variant_key({"name": epg_name})
    if auto_variant and auto_variant != epg_variant:
        return False
    return not saved_name or saved_name in auto_names or saved_matches_epg


def display_channel_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [fill_channel_name_from_metadata(dict(row), allow_epg_name=False) for row in rows]


def enrich_channel_rows(rows: list[dict[str, Any]], settings: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    settings = settings or settings_store.load()
    discovered = discovery_store.load()
    operator_channels = operator_channel_store.load()
    enriched: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        key = str(item.get("key") or f"{item.get('host', '')}:{item.get('port', '')}")
        # Operator channel list — most accurate source, takes priority when no manual name set
        op_ch = operator_channels.get(key)
        if op_ch and op_ch.get("name"):
            op_name = str(op_ch["name"]).strip()
            if not str(item.get("name", "")).strip():
                item["name"] = op_name
            if not str(item.get("auto_name", "")).strip():
                item["auto_name"] = op_name
                item["auto_name_source"] = "operator_channel_list"
            if op_ch.get("fcc_ip") and not str(item.get("fcc_ip", "")).strip():
                item["fcc_ip"] = op_ch["fcc_ip"]
            if op_ch.get("fcc_port") and not item.get("fcc_port"):
                item["fcc_port"] = op_ch["fcc_port"]
            if op_ch.get("fec_port") and not item.get("fec_port"):
                item["fec_port"] = op_ch["fec_port"]
        discovery = discovered.get(key, {})
        if not str(item.get("name", "")).strip() and discovery.get("name"):
            item["name"] = str(discovery.get("name", "")).strip()
        if discovery.get("name"):
            if not str(item.get("auto_name", "")).strip():
                item["auto_name"] = str(discovery.get("name", "")).strip()
            if not str(item.get("auto_name_source", "")).strip():
                item["auto_name_source"] = str(discovery.get("source", "stb_payload")).strip()
        fill_channel_name_from_metadata(item, allow_epg_name=False)
        _auto_cat = classify_channel_name(str(item.get("name", "")))
        item["category"] = _auto_cat if _auto_cat != "其它频道" else (str(item.get("category", "")).strip() or "其它频道")
        # Pull is_hd from operator channel table if missing. The old quality_group
        # field is kept only for compatibility with existing data.
        if op_ch and "is_hd" in op_ch and "is_hd" not in item:
            item["is_hd"] = op_ch["is_hd"]
        if settings.get("use_epg", True) and settings.get("auto_epg", True):
            _prepare_variant_epg_rematch(item)
            epg_service.enrich_item(item, str(settings.get("epg_url", "")), only_missing=True)
            fill_channel_name_from_metadata(item, allow_epg_name=can_replace_with_epg_name(row, item))
        enriched.append(item)
    return enriched


def _iptv_local_ip(settings: dict[str, Any]) -> str:
    """Return the primary IPv4 of the configured IPTV interface for multicast localaddr binding."""
    iface = str(settings.get("interface") or "").strip()
    if not iface:
        return ""
    try:
        out = subprocess.run(
            ["ip", "-j", "-4", "addr", "show", "dev", iface],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3, check=False,
        ).stdout
        addrs = json.loads(out) if out.strip() else []
        for entry in (addrs or []):
            for ai in (entry.get("addr_info") or []):
                ip = str(ai.get("local", "")).strip()
                if ip:
                    return ip
    except Exception:
        pass
    return ""


def _row_with_operator_stream_params(row: dict[str, Any], operator_channels: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of row with FCC/FEC filled from the operator table when absent."""
    item = dict(row)
    key = str(item.get("key") or f"{item.get('host', '')}:{item.get('port', '')}").strip()
    op = operator_channels.get(key) or {}
    for field, op_field in (
        ("fcc_ip", "fcc_ip"),
        ("fcc_port", "fcc_port"),
        ("fec_port", "fec_port"),
    ):
        if item.get(field) in (None, "", 0):
            value = op.get(op_field)
            if value not in (None, "", 0):
                item[field] = value
    return item


def _export_health_check_one(
    row: dict[str, Any],
    settings: dict[str, Any],
    operator_channels: dict[str, Any],
) -> dict[str, Any]:
    checked_at = int(time.time())
    key = str(row.get("key") or f"{row.get('host', '')}:{row.get('port', '')}").strip()
    host = str(row.get("host", "")).strip()
    port = _safe_int(row.get("port"))
    if not valid_ipv4_multicast(host) or not 1 <= port <= 65535:
        return {
            "export_health_status": "skipped",
            "export_health_http_code": None,
            "export_health_bytes": 0,
            "export_health_speed": 0,
            "export_health_elapsed_ms": 0,
            "export_health_checked_at": checked_at,
            "export_health_message": "非有效 IPv4 组播源，跳过",
        }
    http_host = str(settings.get("http_host", "")).strip()
    if not http_host:
        return {
            "export_health_status": "skipped",
            "export_health_http_code": None,
            "export_health_bytes": 0,
            "export_health_speed": 0,
            "export_health_elapsed_ms": 0,
            "export_health_checked_at": checked_at,
            "export_health_message": "未配置 rtp2httpd 地址，跳过",
        }
    try:
        http_port = int(settings.get("http_port", 5140) or 5140)
    except (TypeError, ValueError):
        http_port = 5140
    path_mode = str(settings.get("path_mode", "rtp")).strip().lower()
    if path_mode not in {"rtp", "udp"}:
        path_mode = "rtp"
    item = _row_with_operator_stream_params(row, operator_channels)
    url = ExportService.make_http_url(
        http_host,
        http_port,
        path_mode,
        host,
        port,
        str(item.get("fcc_ip") or "").strip(),
        _safe_int(item.get("fcc_port")),
        _safe_int(item.get("fec_port")),
        str(settings.get("fcc_type", "") or "").strip(),
    )
    timeout = max(0.5, float(settings.get("export_health_timeout_seconds", EXPORT_HEALTH_TIMEOUT_SECONDS) or EXPORT_HEALTH_TIMEOUT_SECONDS))
    sample_bytes = max(188, int(settings.get("export_health_sample_bytes", EXPORT_HEALTH_SAMPLE_BYTES) or EXPORT_HEALTH_SAMPLE_BYTES))
    started = time.time()
    try:
        req = Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION} export-health"})
        with urlopen(req, timeout=timeout) as resp:
            code = int(resp.getcode() or 0)
            chunk = resp.read(sample_bytes)
        elapsed_ms = int((time.time() - started) * 1000)
        size = len(chunk or b"")
        speed = int(size / max(0.001, elapsed_ms / 1000))
        ok = 200 <= code < 400 and size > 0
        return {
            "export_health_status": "ok" if ok else "failed",
            "export_health_http_code": code,
            "export_health_bytes": size,
            "export_health_speed": speed,
            "export_health_elapsed_ms": elapsed_ms,
            "export_health_checked_at": checked_at,
            "export_health_message": f"HTTP {code}，读取 {size} 字节" if ok else f"HTTP {code}，未读取到媒体数据",
        }
    except HTTPError as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        return {
            "export_health_status": "failed",
            "export_health_http_code": int(exc.code or 0),
            "export_health_bytes": 0,
            "export_health_speed": 0,
            "export_health_elapsed_ms": elapsed_ms,
            "export_health_checked_at": checked_at,
            "export_health_message": f"HTTP {exc.code}",
        }
    except TimeoutError:
        elapsed_ms = int((time.time() - started) * 1000)
        return {
            "export_health_status": "timeout",
            "export_health_http_code": None,
            "export_health_bytes": 0,
            "export_health_speed": 0,
            "export_health_elapsed_ms": elapsed_ms,
            "export_health_checked_at": checked_at,
            "export_health_message": f"{timeout:.1f} 秒内未读到媒体数据",
        }
    except URLError as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        reason = str(getattr(exc, "reason", exc))
        status = "timeout" if "timed out" in reason.lower() else "error"
        return {
            "export_health_status": status,
            "export_health_http_code": None,
            "export_health_bytes": 0,
            "export_health_speed": 0,
            "export_health_elapsed_ms": elapsed_ms,
            "export_health_checked_at": checked_at,
            "export_health_message": reason,
        }
    except Exception as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        return {
            "export_health_status": "error",
            "export_health_http_code": None,
            "export_health_bytes": 0,
            "export_health_speed": 0,
            "export_health_elapsed_ms": elapsed_ms,
            "export_health_checked_at": checked_at,
            "export_health_message": str(exc),
        }


def apply_pre_export_health_check(
    rows: list[dict[str, Any]],
    settings: dict[str, Any],
    operator_channels: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    summary = {
        "enabled": bool(settings.get("pre_export_health_check", True)),
        "groups_checked": 0,
        "checked": 0,
        "ok": 0,
        "failed": 0,
        "timeout": 0,
        "error": 0,
        "skipped": 0,
        "limit_reached": False,
        "message": "",
    }
    if not summary["enabled"]:
        summary["message"] = "已关闭导出前线路健康检查"
        return rows, summary
    if not str(settings.get("http_host", "")).strip():
        summary["message"] = "未配置 rtp2httpd 地址，跳过导出前线路健康检查"
        return rows, summary

    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict) or not str(row.get("name", "")).strip():
            continue
        groups.setdefault(channel_group_key(row), []).append(row)

    multi_groups = [members for members in groups.values() if len(members) > 1]
    max_groups = max(0, int(settings.get("export_health_max_groups", EXPORT_HEALTH_MAX_GROUPS) or EXPORT_HEALTH_MAX_GROUPS))
    max_candidates = max(1, int(settings.get("export_health_max_candidates_per_group", EXPORT_HEALTH_MAX_CANDIDATES_PER_GROUP) or EXPORT_HEALTH_MAX_CANDIDATES_PER_GROUP))
    if max_groups and len(multi_groups) > max_groups:
        summary["limit_reached"] = True
        multi_groups = multi_groups[:max_groups]

    for members in multi_groups:
        summary["groups_checked"] += 1
        ordered = sorted(members, key=channel_primary_score, reverse=True)[:max_candidates]
        for row in ordered:
            health = _export_health_check_one(row, settings, operator_channels)
            row.update(health)
            status = str(health.get("export_health_status") or "error")
            if status not in {"ok", "failed", "timeout", "error", "skipped"}:
                status = "error"
            summary[status] += 1
            summary["checked"] += 1
            logger.info(
                "导出前线路检查："
                f"{row.get('name', '')} {row.get('key', '')} → {status}，{health.get('export_health_message', '')}"
            )
    if summary["checked"]:
        summary["message"] = (
            f"已检查 {summary['groups_checked']} 个多线路频道组、{summary['checked']} 条源，"
            f"可用 {summary['ok']} 条，失败 {summary['failed']} 条，超时 {summary['timeout']} 条"
        )
    else:
        summary["message"] = "没有需要比较的多线路频道组"
    return rows, summary


def fetch_text_resource(url: str, timeout: int = 30) -> str:
    source = str(url or "").strip()
    if not source:
        raise ValueError("M3U 地址不能为空")
    req = Request(source, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
    with urlopen(req, timeout=timeout) as response:
        data = response.read()
    if source.lower().endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8-sig", errors="ignore")


def parse_m3u_channels(text: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.upper().startswith("#EXTINF"):
            parts = line.split(",", 1)
            extinf = parts[0]
            title = parts[1] if len(parts) > 1 else ""
            duration = "-1"
            if ":" in extinf:
                duration_part = extinf.split(":", 1)[1].strip()
                duration = (duration_part.split(" ", 1)[0] or "-1").strip()
            attrs = dict(M3U_ATTR_RE.findall(extinf))
            current = {
                "duration": duration,
                "attrs": attrs,
                "title": title.strip() or str(attrs.get("tvg-name", "")).strip(),
                "url": "",
            }
        elif current and not line.startswith("#"):
            current["url"] = line
            items.append(current)
            current = None
    return items


def safe_m3u_attr(value: Any) -> str:
    return str(value or "").replace('"', "'").replace("\r", " ").replace("\n", " ").strip()


def write_m3u_channels(items: list[dict[str, Any]], epg_url: str) -> str:
    lines = [f'#EXTM3U x-tvg-url="{safe_m3u_attr(epg_url)}"']
    ordered_attrs = ["tvg-id", "tvg-name", "tvg-logo", "group-title"]
    for item in items:
        attrs = {str(key): safe_m3u_attr(value) for key, value in dict(item.get("attrs") or {}).items() if safe_m3u_attr(value)}
        attr_keys = ordered_attrs + sorted(key for key in attrs if key not in ordered_attrs)
        attr_text = " ".join(f'{key}="{attrs[key]}"' for key in attr_keys if attrs.get(key))
        title = safe_m3u_attr(item.get("title") or attrs.get("tvg-name") or attrs.get("tvg-id") or "未命名频道")
        duration = safe_m3u_attr(item.get("duration") or "-1")
        prefix = f"#EXTINF:{duration}"
        if attr_text:
            prefix = f"{prefix} {attr_text}"
        lines.append(f"{prefix},{title}")
        lines.append(str(item.get("url", "")).strip())
    return "\n".join(lines) + "\n"


@app.get("/")
def index():
    return render_template(
        "index.html",
        app_name=APP_NAME,
        app_version=APP_VERSION,
        app_description=APP_DESCRIPTION,
    )


@app.get("/api/version")
def api_version():
    with _version_check_lock:
        vc = dict(_version_check)
    return api_success({"name": APP_NAME, "version": APP_VERSION, "description": APP_DESCRIPTION, **vc})


@app.get("/api/health")
def api_health():
    capture_runtime = capture_service.runtime_check()
    all_ok = bool(capture_runtime.get("ok"))
    status_code = 200 if all_ok else 503
    payload = {
        "status": "ok" if all_ok else "degraded",
        "version": APP_VERSION,
        "uptime_seconds": int(time.time() - STARTED_AT),
        "runtime": capture_runtime,
    }
    response = api_success(payload)
    response.status_code = status_code
    return response


@app.get("/api/metrics")
def api_metrics():
    data = {
        "version": APP_VERSION,
        "uptime_seconds": int(time.time() - STARTED_AT),
        "capture": capture_service.metrics(),
        "logs": logger.stats(),
        "saved_channels": len(channel_store.load()),
        "discovered_channels": len(discovery_store.load()),
        "fcc_records": len(fcc_store.load()),
        "epg": epg_service.status(summary=True),
        "stb_tokens": len(token_store.load().get("history") or []),
        "output_files": {
            name: (OUTPUT_DIR / name).exists()
            for name in sorted(ALLOWED_DOWNLOADS)
        },
    }
    return api_success(data)


@app.get("/api/interfaces")
def api_interfaces():
    try:
        return api_success({"interfaces": capture_service.list_interfaces()})
    except Exception as exc:
        return api_error(str(exc), 500)

@app.get("/api/settings")
def api_settings_get():
    return api_success(settings_store.load())


@app.post("/api/settings")
def api_settings_save():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    if "fcc_type" in data and str(data.get("fcc_type") or "").strip() not in {"", "telecom", "huawei"}:
        data["fcc_type"] = ""
    saved = settings_store.save(data)
    epg_url = str(saved.get("epg_url", "")).strip()
    logo_url = str(saved.get("logo_url", "")).strip()
    if saved.get("use_epg", True) and saved.get("auto_epg", True) and epg_url:
        epg_status = epg_service.status(summary=True)
        if (
            not epg_status.get("refreshing")
            and (
                epg_status.get("url") != epg_url
                or epg_status.get("logo_url") != logo_url
                or int(epg_status.get("channels") or 0) == 0
            )
        ):
            epg_service.refresh_async(epg_url, logo_url if saved.get("use_logo", True) else "")
    logger.info("已保存网页默认设置")
    return api_success(saved)


@app.get("/api/status")
def api_status():
    return api_error("UDP 流发现功能已移除，请使用运营商频道发现导入频道", 410)


@app.post("/api/capture/start")
def api_capture_start():
    return api_error("UDP 流发现功能已移除，请使用运营商频道发现导入频道", 410)


@app.post("/api/capture/stop")
def api_capture_stop():
    return api_error("UDP 流发现功能已移除，请使用运营商频道发现导入频道", 410)


@app.post("/api/capture/reset")
def api_capture_reset():
    return api_error("UDP 流发现功能已移除，请使用运营商频道发现导入频道", 410)


@app.get("/api/streams")
def api_streams():
    return api_error("UDP 流发现功能已移除，请使用运营商频道发现导入频道", 410)


@app.get("/api/channels")
def api_channels():
    return api_success({"channels": display_channel_rows(channel_store.list())})


@app.get("/api/fcc")
def api_fcc():
    return api_success({"records": list(fcc_store.load().values()), "file": str(FCC_FILE)})


@app.get("/api/stb-token")
def api_stb_token():
    data = token_store.load()
    return api_success({"latest": data.get("latest"), "count": len(data.get("history") or []), "file": str(STB_TOKEN_FILE)})


@app.get("/api/discovery")
def api_discovery():
    return api_success({"records": list(discovery_store.load().values()), "file": str(DISCOVERY_FILE)})


@app.get("/api/epg/status")
def api_epg_status():
    status = epg_service.status()
    status["source_stats"] = epg_service.source_stats()
    return api_success(status)


@app.post("/api/epg/refresh")
def api_epg_refresh():
    settings = settings_store.load()
    try:
        epg_url = str(settings.get("epg_url", "")).strip()
        logo_url = str(settings.get("logo_url", "")).strip() if settings.get("use_logo", True) else ""
        if not epg_url:
            return api_error("EPG 地址不能为空，请先在频道线路中配置 EPG 来源")
        status = epg_service.refresh_async(epg_url, logo_url)
        logger.info(f"已启动 EPG 刷新：{epg_url}")
        return api_success(status)
    except ValueError as exc:
        return api_error(str(exc), 400)
    except Exception as exc:
        logger.error(f"启动 EPG 刷新失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/epg/rematch")
def api_epg_rematch():
    """Force re-enrich ALL channel records with EPG, overwriting any previous match."""
    settings = settings_store.load()
    if not settings.get("use_epg", True):
        return api_error("EPG 已关闭，请先在频道线路中开启 EPG。")
    epg_url = str(settings.get("epg_url", "")).strip()
    try:
        channels = channel_store.load()
        rows = []
        updated = 0
        for ch in channels.values():
            item = dict(ch)
            epg_service.enrich_item(item, epg_url, only_missing=False)
            rows.append(item)
            if item.get("tvg_id") != ch.get("tvg_id"):
                updated += 1
        channel_store.save_rows(rows)
        logger.info(f"EPG 重新匹配完成：共处理 {len(rows)} 个频道，更新 {updated} 个")
        return api_success({"total": len(rows), "updated": updated})
    except Exception as exc:
        logger.error(f"EPG 重新匹配失败：{exc}")
        return api_error(str(exc))


@app.get("/api/operator_channels")
def api_operator_channels_get():
    channels = operator_channel_store.load()
    items = sorted(channels.values(), key=lambda x: x.get("channel_num") or 9999)
    return api_success({"channels": items, "count": len(items)})


def _do_operator_import(channels: list[dict]) -> dict:
    """Import operator channels: store lookup table, bulk-write FCC, bulk-save channel records with EPG."""
    count = operator_channel_store.import_channels(channels)

    # Bulk-write FCC records (single file write)
    fcc_records = [
        {"key": f"{ch['ip']}:{ch['port']}", "host": ch["ip"], "port": ch["port"],
         "fcc_ip": ch["fcc_ip"], "fcc_port": ch["fcc_port"]}
        for ch in channels
        if ch.get("fcc_ip") and ch.get("fcc_port") and ch.get("ip") and ch.get("port")
    ]
    fcc_saved = fcc_store.bulk_save(fcc_records)

    # Bulk-save channel records so EPG enrichment runs immediately
    settings = settings_store.load()
    # Pre-load stored channels so operator imports keep existing runtime metadata.
    existing = channel_store.load()
    rows = []
    for ch in channels:
        if not (ch.get("ip") and ch.get("port") and ch.get("name")):
            continue
        key = f"{ch['ip']}:{ch['port']}"
        stored = existing.get(key, {})
        rows.append({
            "key": key,
            "host": ch["ip"],
            "port": ch["port"],
            "name": ch.get("name", ""),
            "category": classify_channel_name(ch.get("name", "")),
            "packets": stored.get("packets", 0),
            "fcc_ip": ch.get("fcc_ip", ""),
            "fcc_port": ch.get("fcc_port"),
            "fec_port": ch.get("fec_port"),
            "is_hd": ch.get("is_hd", False),
            "probe_status": stored.get("probe_status", "not_probed"),
            "width": stored.get("width"),
            "height": stored.get("height"),
            "quality_group": stored.get("quality_group", ""),
        })
    enriched = enrich_channel_rows(rows, settings)
    # Save rows: preserve user-modified names but always update tech params (FCC/FEC/probe).
    to_save = []
    for row in enriched:
        key = str(row.get("key", ""))
        stored = existing.get(key)
        if stored and str(stored.get("name", "")).strip():
            op_name = str(row.get("auto_name", "")).strip()
            stored_name = str(stored.get("name", "")).strip()
            if stored_name and stored_name != op_name:
                # User renamed this channel — keep their name but refresh tech fields.
                merged = dict(stored)
                for tech_field in ("fcc_ip", "fcc_port", "fec_port", "is_hd", "time_shift"):
                    if row.get(tech_field) is not None and row.get(tech_field) != "":
                        merged[tech_field] = row[tech_field]
                to_save.append(merged)
                continue
        to_save.append(row)
    ch_result = channel_store.save_rows(to_save) if to_save else {"saved": 0, "deleted": 0, "total": 0}

    return {
        "imported": count,
        "fcc_saved": fcc_saved,
        "channels_saved": ch_result.get("saved", 0),
    }


@app.post("/api/operator_channels/import")
def api_operator_channels_import():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    channels = data.get("channels")
    if not isinstance(channels, list):
        return api_error("channels 必须是数组")
    try:
        result = _do_operator_import(channels)
        logger.info(f"运营商频道表导入完成：{result['imported']} 个频道，FCC {result['fcc_saved']} 条，频道记录 {result['channels_saved']} 条（含 EPG 匹配）")
        return api_success(result)
    except Exception as exc:
        logger.error(f"运营商频道表导入失败：{exc}")
        return api_error(str(exc), 500)


@app.delete("/api/operator_channels")
def api_operator_channels_clear():
    operator_channel_store.clear()
    logger.info("运营商频道表已清空")
    return api_success({"cleared": True})


_BACKUP_VERSION = 1
_BACKUP_FILES: list[tuple[str, Path]] = [
    ("settings", SETTINGS_FILE),
    ("channels", CHANNELS_FILE),
    ("operator_channels", OPERATOR_CHANNELS_FILE),
    ("discovered_channels", DISCOVERY_FILE),
    ("fcc", FCC_FILE),
    ("stb_token", STB_TOKEN_FILE),
    ("iptv_auth_backups", IPTV_AUTH_BACKUP_FILE),
    ("channel_snapshots", SNAPSHOTS_FILE),
]


@app.get("/api/backup/export")
def api_backup_export():
    payload: dict[str, Any] = {"_version": _BACKUP_VERSION, "_exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    for key, path in _BACKUP_FILES:
        try:
            payload[key] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
        except Exception:
            payload[key] = None
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": 'attachment; filename="iptv-sniffer-backup.json"'},
    )


@app.post("/api/backup/import")
def api_backup_import():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("格式错误：需要 JSON 对象")
    restored: list[str] = []
    skipped: list[str] = []
    for key, path in _BACKUP_FILES:
        value = data.get(key)
        if value is None:
            skipped.append(key)
            continue
        try:
            path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
            restored.append(key)
        except Exception as exc:
            logger.warning(f"backup import: failed to write {key}: {exc}")
            skipped.append(key)
    if "operator_channels" in restored:
        operator_channel_store.invalidate()
    logger.info(f"备份导入完成：已恢复 {len(restored)} 项，跳过 {len(skipped)} 项")
    return api_success({"restored": restored, "skipped": skipped})


@app.get("/api/channels/snapshots")
def api_snapshots_list():
    return api_success({"snapshots": snapshot_store.list_meta()})


@app.post("/api/channels/snapshot")
def api_snapshot_save():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    channels = channel_store.load()
    if not channels:
        return api_error("频道列表为空，无法保存快照")
    if not name:
        import datetime
        name = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    meta = snapshot_store.save(name, channels)
    logger.info(f"已保存频道列表快照「{name}」，共 {meta['count']} 个频道")
    return api_success(meta)


@app.post("/api/channels/snapshots/<snap_id>/restore")
def api_snapshot_restore(snap_id: str):
    snap = snapshot_store.get(snap_id)
    if not snap:
        return api_error("快照不存在")
    channels = snap.get("channels") or {}
    rows = list(channels.values()) if isinstance(channels, dict) else []
    result = channel_store.save_rows(rows)
    logger.info(f"已从快照「{snap.get('name')}」恢复 {result['saved']} 个频道")
    return api_success({"restored": result["saved"], "name": snap.get("name")})


@app.delete("/api/channels/snapshots/<snap_id>")
def api_snapshot_delete(snap_id: str):
    if snapshot_store.delete(snap_id):
        logger.info(f"已删除频道列表快照 {snap_id}")
        return api_success({"deleted": True})
    return api_error("快照不存在")


@app.post("/api/logo/refresh")
def api_logo_refresh():
    data = request.get_json(silent=True) or {}
    logo_url = str(data.get("logo_url", "")).strip()
    if not logo_url:
        return api_error("logo_url 不能为空")
    try:
        count = epg_service.refresh_logo(logo_url)
        return api_success({"logos": count, "url": logo_url})
    except Exception as exc:
        return api_error(str(exc), 500)


@app.get("/api/stb_discovery/status")
def api_stb_discovery_status():
    return api_success(stb_discovery_service.status())


@app.post("/api/stb_discovery/start")
def api_stb_discovery_start():
    data = request.get_json(silent=True) or {}
    stb_ip = str(data.get("stb_ip", "")).strip()
    interface = str(data.get("interface", "any")).strip() or "any"
    if not stb_ip:
        return api_error("请填写机顶盒 IP 地址")
    if not valid_ip_or_host(stb_ip):
        return api_error("IP 地址格式不正确")
    rt = stb_discovery_service.runtime_check()
    if not rt["ok"]:
        return api_error("；".join(rt["errors"]), 500)
    try:
        stb_discovery_service.start(stb_ip, interface)
        return api_success(stb_discovery_service.status())
    except RuntimeError as exc:
        return api_error(str(exc))
    except Exception as exc:
        logger.error(f"启动 STB 捕获失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/stb_discovery/stop")
def api_stb_discovery_stop():
    try:
        state = stb_discovery_service.stop()
        return api_success(state)
    except Exception as exc:
        logger.error(f"停止 STB 捕获失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/stb_discovery/reset")
def api_stb_discovery_reset():
    stb_discovery_service.reset()
    return api_success(stb_discovery_service.status())


@app.post("/api/stb_discovery/import")
def api_stb_discovery_import():
    """Import channels discovered from the last STB boot capture."""
    state = stb_discovery_service.status()
    channels = state.get("channels") or []
    if not channels:
        return api_error("没有可导入的频道，请先完成 STB 开机捕获")
    try:
        result = _do_operator_import(channels)
        logger.info(f"已从 STB 开机捕获导入 {result['imported']} 个频道，FCC {result['fcc_saved']} 条，频道记录 {result['channels_saved']} 条（含 EPG 匹配）")
        return api_success(result)
    except Exception as exc:
        logger.error(f"导入 STB 捕获频道失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/channels/save")
def api_channels_save():
    data = request.get_json(silent=True) or {}
    rows = data.get("channels", []) if isinstance(data, dict) else []
    if not isinstance(rows, list):
        return api_error("channels 必须是数组")
    rows = enrich_channel_rows(rows)
    result = channel_store.save_rows(rows)
    logger.info(f"已导入频道列表：新增或更新 {result['saved']} 条，删除 {result['deleted']} 条")
    return api_success(result)


@app.post("/api/channels/delete")
def api_channels_delete():
    data = request.get_json(silent=True) or {}
    keys = data.get("keys", []) if isinstance(data, dict) else []
    if not isinstance(keys, list):
        return api_error("keys 必须是数组")
    deleted = channel_store.delete_keys([str(k) for k in keys if k])
    logger.info(f"已从频道列表删除 {deleted} 个频道")
    return api_success({"deleted": deleted})


@app.post("/api/probe")
def api_probe_one():
    return api_error("流信息探测功能已移除，请使用播放诊断和导出前线路检查判断源可用性", 410)


@app.post("/api/probe/batch")
def api_probe_batch():
    return api_error("批量流信息探测功能已移除，请使用播放诊断和导出前线路检查判断源可用性", 410)


@app.post("/api/export")
def api_export():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    rows = data.get("channels")
    if rows is None:
        rows = channel_store.list()
    if not isinstance(rows, list):
        return api_error("channels 必须是数组")
    settings = {**settings_store.load(), **{k: v for k, v in data.items() if k != "channels"}}
    if not settings.get("use_epg", True):
        settings["epg_url"] = ""
    if not settings.get("use_logo", True):
        settings["logo_url"] = ""
    try:
        rows = enrich_channel_rows(rows, settings)
        operator_channels = operator_channel_store.load()
        rows, health_summary = apply_pre_export_health_check(rows, settings, operator_channels)
        result = export_service.export(rows, settings, operator_channels=operator_channels)
        result["health_check"] = health_summary
        channel_store.save_rows(rows)
        logger.info(
            "导出完成：共生成 "
            f"{result['count']} 个频道，文件为 channels-direct.m3u / "
            "channels-rtp2httpd-source.m3u / channels.json / channels.txt / channels.csv"
        )
        if health_summary.get("checked"):
            logger.info(f"导出前线路健康检查完成：{health_summary.get('message')}")
        return api_success(result)
    except ValueError as exc:
        return api_error(str(exc), 400)
    except Exception as exc:
        logger.error(f"导出失败：{exc}")
        return api_error(str(exc), 500)


@app.get("/api/download/<path:filename>")
def api_download(filename: str):
    if filename not in ALLOWED_DOWNLOADS:
        return api_error("不允许下载该文件", 404)
    target = OUTPUT_DIR / filename
    if not target.exists():
        return api_error("文件尚未生成", 404)
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)




@app.get("/hls/<hls_key>/stream.m3u8")
def hls_playlist(hls_key: str):
    parsed = HlsService.parse_key(hls_key)
    if not parsed:
        return api_error("无效的 HLS 流 key", 400)
    host, port = parsed
    if not valid_ipv4_multicast(host):
        return api_error("仅支持 IPv4 组播地址", 400)
    settings = settings_store.load()
    path_mode = str(settings.get("path_mode", "rtp"))
    localaddr = _iptv_local_ip(settings)
    _, hls_dir = hls_service.ensure(host, port, path_mode, localaddr)
    m3u8 = hls_dir / "stream.m3u8"
    deadline = time.time() + 10
    while time.time() < deadline:
        if m3u8.exists() and m3u8.stat().st_size > 0:
            break
        time.sleep(0.25)
    if not m3u8.exists() or m3u8.stat().st_size == 0:
        return api_error("HLS 流启动超时，请检查组播路由和 rtp2httpd 上游接口", 504)
    hls_service.touch(hls_key)
    content = HlsService.read_playlist(m3u8)
    resp = Response(content, mimetype="application/vnd.apple.mpegurl")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Cache-Control"] = "no-cache, no-store"
    return resp


@app.get("/hls/<hls_key>/<segment>")
def hls_segment(hls_key: str, segment: str):
    parsed = HlsService.parse_key(hls_key)
    if not parsed or not segment.endswith(".ts") or "/" in segment or ".." in segment:
        return ("", 404)
    host, port = parsed
    settings = settings_store.load()
    path_mode = str(settings.get("path_mode", "rtp"))
    localaddr = _iptv_local_ip(settings)
    _, hls_dir = hls_service.ensure(host, port, path_mode, localaddr)
    seg_path = hls_dir / segment
    if not seg_path.is_file():
        return ("", 404)
    hls_service.touch(hls_key)
    resp = send_file(seg_path, mimetype="video/mp2t")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.get("/api/hls/status")
def api_hls_status():
    return api_success({"streams": hls_service.status()})


@app.get("/api/hls/m3u")
def api_hls_m3u():
    settings = settings_store.load()
    epg_url = str(settings.get("epg_url", "") or "").strip() if settings.get("use_epg", True) else ""
    base_url = request.url_root.rstrip("/")
    channels = channel_store.load()
    if not channels:
        return api_error("尚无频道数据，请先完成运营商频道发现并导入。")
    try:
        content = export_service.hls_m3u(channels, base_url, epg_url)
        resp = Response(
            content,
            mimetype="audio/x-mpegurl",
            headers={"Content-Disposition": 'attachment; filename="channels-fnos-hls.m3u"'},
        )
        return resp
    except Exception as exc:
        return api_error(str(exc))


@app.get("/api/snapshot/<host>/<int:port>")
def api_snapshot(host: str, port: int):
    if not valid_ipv4_multicast(host):
        return api_error("预览地址必须是 IPv4 组播地址", 400)
    if not 1 <= port <= 65535:
        return api_error("预览端口必须位于 1-65535", 400)
    if shutil.which("ffmpeg") is None:
        return api_error("缺少 ffmpeg 命令", 503)
    key = f"{host}:{port}"
    now = time.time()
    cached = _snapshot_cache.get(key)
    if cached and now - cached[0] < _snapshot_cache_ttl:
        return Response(cached[1], mimetype="image/jpeg", headers={"Cache-Control": f"max-age={_snapshot_cache_ttl}"})
    path_mode = str(settings_store.load().get("path_mode", "rtp")).strip().lower()
    scheme = "rtp" if path_mode == "rtp" else "udp"
    source = f"{scheme}://{host}:{port}?timeout=12000000"
    cmd = [
        "ffmpeg", "-y",
        "-analyzeduration", "8000000",
        "-probesize", "12000000",
        "-i", source,
        "-frames:v", "1",
        "-f", "image2",
        "-vcodec", "mjpeg",
        "-q:v", "4",
        "pipe:1",
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=22)
    except subprocess.TimeoutExpired:
        return api_error("截图超时", 504)
    except OSError as exc:
        return api_error(f"ffmpeg 执行失败：{exc}", 500)
    if proc.returncode != 0 or not proc.stdout:
        stderr_tail = (proc.stderr or b"").decode(errors="replace").strip().splitlines()
        msg = stderr_tail[-1] if stderr_tail else "ffmpeg 无输出"
        logger.warning(f"截图失败：{key}，{msg}")
        return api_error(f"无法从流中截图：{msg}", 502)
    _snapshot_cache[key] = (now, proc.stdout)
    return Response(proc.stdout, mimetype="image/jpeg", headers={"Cache-Control": f"max-age={_snapshot_cache_ttl}"})


@app.get("/api/logs")
def api_logs():
    try:
        after_id = int(request.args.get("after_id", "0"))
        limit = int(request.args.get("limit", "300"))
    except ValueError:
        return api_error("日志查询参数不正确")
    limit = max(1, min(limit, 600))
    return api_success(logger.read(after_id=after_id, limit=limit))


@app.post("/api/logs/clear-memory")
def api_logs_clear_memory():
    logger.clear_memory()
    logger.info("实时日志面板缓存已清空；磁盘日志文件保留")
    return api_success({"cleared": True})


@app.get("/api/logs/download")
def api_logs_download():
    if not LOG_FILE.exists():
        LOG_FILE.write_text("", encoding="utf-8")
    return send_file(LOG_FILE, as_attachment=True, download_name="iptv-sniffer-web.log")


@app.get("/api/channels/groups")
def api_channels_groups():
    """Return channels grouped by tvg_id / normalized name with primary source per group."""
    channels = display_channel_rows(list(channel_store.load().values()))
    groups_dict: dict[str, list[dict]] = {}
    for ch in channels:
        gk = channel_group_key(ch)
        groups_dict.setdefault(gk, []).append(ch)

    result: list[dict] = []
    for gk, members in groups_dict.items():
        manual = next((m for m in members if m.get("is_primary")), None)
        if manual:
            rest = sorted(
                [m for m in members if m.get("key") != manual.get("key")],
                key=channel_primary_score, reverse=True,
            )
            primary, alternates = manual, rest
        else:
            scored = sorted(members, key=channel_primary_score, reverse=True)
            primary, alternates = scored[0], scored[1:]
        result.append({
            "group_key": gk,
            "name": primary.get("name", ""),
            "category": primary.get("category", "其它频道"),
            "primary": primary,
            "alternates": alternates,
            "count": len(members),
        })
    result.sort(key=lambda g: (
        CATEGORY_ORDER.get(g["category"], 99),
        natural_key(g["name"]),
    ))
    return api_success({"groups": result, "total": len(result)})


@app.post("/api/channels/set-primary")
def api_channels_set_primary():
    data = request.get_json(silent=True) or {}
    group_key = str(data.get("group_key", "")).strip()
    channel_key = str(data.get("channel_key", "")).strip()
    if not group_key or not channel_key:
        return api_error("group_key 和 channel_key 不能为空")
    updated = channel_store.patch_group_primary(group_key, channel_key)
    if not updated:
        return api_error("未找到该频道组")
    return api_success({"updated": updated, "primary": channel_key})


@app.get("/api/stb-summary")
def api_stb_summary():
    """Compact summary of STB auth/channel state for the top status bar."""
    auth = stb_discovery_service.status().get("auth_info") or {}
    if auth.get("mac") or auth.get("assigned_ip"):
        token_store.save_auth_info(auth)
    else:
        auth = token_store.load_auth_info()
    token_data = token_store.load()
    has_token = bool((token_data.get("history") or []))
    fcc_count = len(fcc_store.load())
    ch_count = len(channel_store.load())
    return api_success({
        "mac": auth.get("mac", ""),
        "hostname": auth.get("hostname", ""),
        "assigned_ip": auth.get("assigned_ip", ""),
        "gateway": auth.get("gateway", ""),
        "vendor_class": auth.get("vendor_class", ""),
        "has_token": has_token,
        "fcc_count": fcc_count,
        "channel_count": ch_count,
    })


def _latest_stb_auth_info() -> dict[str, Any]:
    return stb_discovery_service.status().get("auth_info") or {}


@app.get("/api/iptv-auth/status")
def api_iptv_auth_status():
    iface = str(request.args.get("interface") or settings_store.load().get("interface") or "").strip()
    if not iface:
        return api_error("请先选择 IPTV 上游接口")
    try:
        return api_success(iptv_auth_service.status(iface, _latest_stb_auth_info()))
    except Exception as exc:
        return api_error(str(exc))


@app.post("/api/iptv-auth/apply")
def api_iptv_auth_apply():
    data = request.get_json(silent=True) or {}
    try:
        return api_success(iptv_auth_service.apply(data, _latest_stb_auth_info()))
    except Exception as exc:
        logger.error(f"实验性 IPTV 认证执行失败：{exc}")
        return api_error(str(exc))


@app.get("/api/iptv-auth/backup-export")
def api_iptv_auth_backup_export():
    iface = str(request.args.get("interface") or "").strip()
    if not iface:
        return api_error("请先选择 IPTV 上游接口")
    try:
        return api_success(iptv_auth_service.backup_export(iface))
    except Exception as exc:
        return api_error(str(exc))


@app.post("/api/iptv-auth/backup-import")
def api_iptv_auth_backup_import():
    data = request.get_json(silent=True) or {}
    try:
        return api_success(iptv_auth_service.backup_import(data))
    except Exception as exc:
        return api_error(str(exc))


@app.post("/api/iptv-auth/restore")
def api_iptv_auth_restore():
    data = request.get_json(silent=True) or {}
    try:
        return api_success(iptv_auth_service.restore(data))
    except Exception as exc:
        logger.error(f"IPTV 认证恢复失败：{exc}")
        return api_error(str(exc))


@app.get("/api/iptv-auth/egress-bpf/status")
def api_iptv_auth_egress_bpf_status():
    iface = str(request.args.get("interface") or settings_store.load().get("interface") or "").strip()
    if not iface:
        return api_error("请先选择 IPTV 上游接口")
    try:
        return api_success(iptv_auth_service.egress_bpf_status(iface))
    except Exception as exc:
        return api_error(str(exc))


@app.post("/api/iptv-auth/egress-bpf/clear")
def api_iptv_auth_egress_bpf_clear():
    data = request.get_json(silent=True) or {}
    try:
        return api_success(iptv_auth_service.clear_egress_bpf(data))
    except Exception as exc:
        logger.error(f"解除 egress BPF 失败：{exc}")
        return api_error(str(exc))


@app.get("/api/iptv-auth/egress-bpf/watch")
def api_iptv_auth_egress_bpf_watch_status():
    try:
        return api_success(iptv_auth_service.egress_bpf_watch_status())
    except Exception as exc:
        return api_error(str(exc))


@app.post("/api/iptv-auth/egress-bpf/watch")
def api_iptv_auth_egress_bpf_watch_configure():
    data = request.get_json(silent=True) or {}
    try:
        return api_success(iptv_auth_service.configure_egress_bpf_watch(data))
    except Exception as exc:
        logger.error(f"配置 egress BPF 自动修复失败：{exc}")
        return api_error(str(exc))


def _parse_rtp2httpd_config_text(text: str) -> dict[str, Any]:
    """Parse the small INI-like subset used by rtp2httpd configs."""
    section = "global"
    values: dict[str, str] = {}
    bind_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip() or "global"
            continue
        if section == "bind" and "=" not in line:
            bind_lines.append(line)
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.split("#", 1)[0].split(";", 1)[0].strip()
        if key:
            values[f"{section}.{key}"] = value
            values.setdefault(key, value)
    return {"values": values, "bind": bind_lines}


def _rtp2httpd_config_candidates(path_hint: str) -> list[Path]:
    candidates: list[str] = []
    if path_hint:
        candidates.append(path_hint)
    if DEFAULT_RTP2HTTPD_CONFIG_PATH:
        candidates.append(DEFAULT_RTP2HTTPD_CONFIG_PATH)
    candidates.extend([
        "/vol1/@appconf/rtp2httpd/rtp2httpd.conf",
        "/host/vol1/@appconf/rtp2httpd/rtp2httpd.conf",
        "/etc/rtp2httpd/rtp2httpd.conf",
        "/host/etc/rtp2httpd/rtp2httpd.conf",
        "/config/rtp2httpd.conf",
    ])
    seen: set[str] = set()
    result: list[Path] = []
    for item in candidates:
        if not item:
            continue
        expanded = os.path.expanduser(str(item))
        if expanded in seen:
            continue
        seen.add(expanded)
        result.append(Path(expanded))
    return result


def _load_rtp2httpd_config(path_hint: str) -> dict[str, Any]:
    checked: list[str] = []
    for path in _rtp2httpd_config_candidates(path_hint):
        checked.append(str(path))
        try:
            if not path.exists() or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")[:128_000]
            parsed = _parse_rtp2httpd_config_text(text)
            values = parsed["values"]
            return {
                "ok": True,
                "path": str(path),
                "checked": checked,
                "upstream_interface": values.get("upstream-interface", ""),
                "upstream_interface_multicast": values.get("upstream-interface-multicast", ""),
                "upstream_interface_fcc": values.get("upstream-interface-fcc", ""),
                "external_m3u": values.get("external-m3u", ""),
                "status_page_path": values.get("status-page-path", "/status"),
                "player_page_path": values.get("player-page-path", "/player"),
                "bind": parsed["bind"],
            }
        except Exception as exc:
            return {"ok": False, "path": str(path), "checked": checked, "error": str(exc)}
    return {"ok": None, "path": path_hint, "checked": checked, "error": "未找到可读取的 rtp2httpd 配置文件"}


def _diagnose_sections(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = ["rtp2httpd", "network", "auth", "fcc", "multicast", "playlist"]
    names = {
        "rtp2httpd": "rtp2httpd 服务",
        "network": "网络接口",
        "auth": "接入认证",
        "fcc": "FCC / FEC",
        "multicast": "组播链路",
        "playlist": "频道资产 / M3U",
    }
    buckets: dict[str, list[dict[str, Any]]] = {}
    for check in checks:
        buckets.setdefault(str(check.get("layer") or "playlist"), []).append(check)
    return [
        {"id": key, "title": names.get(key, key), "checks": buckets[key]}
        for key in order
        if key in buckets
    ]


@app.post("/api/diagnose")
def api_diagnose():
    """Playback chain diagnostic: rtp2httpd reachability + FCC + config review."""
    data = request.get_json(silent=True) or {}
    settings = settings_store.load()
    http_host = str(data.get("http_host") or settings.get("http_host", "")).strip()
    http_port = int(data.get("http_port") or settings.get("http_port") or 5140)
    channel_addr = str(data.get("channel", "")).strip()  # "ip:port"
    config_path = str(data.get("config_path") or settings.get("rtp2httpd_config_path", "")).strip()
    iface = str(settings.get("interface", "")).strip()

    checks: list[dict] = []
    conclusions: list[str] = []

    def add_check(layer: str, item: str, ok: bool | None, detail: str) -> None:
        checks.append({"layer": layer, "item": item, "ok": ok, "detail": detail})

    # --- Check 1: rtp2httpd reachability ---
    rtp2httpd_ok = False
    if http_host:
        url = f"http://{http_host}:{http_port}/"
        cfg = _load_rtp2httpd_config(config_path)
        try:
            req = Request(url)
            req.add_header("User-Agent", "IPTV-Sniffer-Web-Diag/1.0")
            with urlopen(req, timeout=5) as resp:
                code = resp.getcode()
                rtp2httpd_ok = code < 500
            add_check("rtp2httpd", "rtp2httpd 可访问", True, f"{url} → HTTP {code}")
        except Exception as exc:
            err = str(exc)
            add_check("rtp2httpd", "rtp2httpd 可访问", False, f"{url} → {err}")
            conclusions.append("rtp2httpd 不可访问：请确认地址/端口正确且服务已运行。")

        status_path = cfg.get("status_page_path") if cfg.get("ok") is True else "/status"
        if not str(status_path or "").startswith("/"):
            status_path = "/" + str(status_path)
        status_url = f"http://{http_host}:{http_port}{status_path or '/status'}"
        try:
            req = Request(status_url)
            req.add_header("User-Agent", "IPTV-Sniffer-Web-Diag/1.0")
            with urlopen(req, timeout=5) as resp:
                code = resp.getcode()
                body = resp.read(4096).decode("utf-8", errors="replace")
            marker = "rtp2httpd" if "rtp2httpd" in body.lower() else "HTTP 状态页"
            add_check("rtp2httpd", "rtp2httpd 状态页", code < 500, f"{status_url} → HTTP {code}（{marker}）")
        except Exception as exc:
            add_check("rtp2httpd", "rtp2httpd 状态页", None, f"{status_url} → {exc}")
            conclusions.append("无法读取 rtp2httpd /status：如果服务可播放但状态页不可访问，请检查 status-page-path 或反向代理。")

        if cfg.get("ok") is True:
            upstream = cfg.get("upstream_interface_multicast") or cfg.get("upstream_interface") or "系统路由表"
            fcc_iface = cfg.get("upstream_interface_fcc") or cfg.get("upstream_interface") or "系统路由表"
            detail = (
                f"配置={cfg.get('path')}；组播接口={upstream}；FCC接口={fcc_iface}；"
                f"external-m3u={cfg.get('external_m3u') or '未配置'}"
            )
            add_check("rtp2httpd", "rtp2httpd 配置文件", True, detail)
            if cfg.get("upstream_interface") and iface and cfg.get("upstream_interface") == iface:
                add_check("network", "上游接口与抓包接口一致", True, f"rtp2httpd upstream-interface={cfg.get('upstream_interface')}，抓包接口={iface}")
            elif cfg.get("upstream_interface") and iface:
                add_check("network", "上游接口与抓包接口一致", None, f"rtp2httpd upstream-interface={cfg.get('upstream_interface')}，抓包接口={iface}；如前者不是 IPTV 上游口会无法主动播放")
        elif cfg.get("ok") is False:
            add_check("rtp2httpd", "rtp2httpd 配置文件", False, f"{cfg.get('path')} → {cfg.get('error')}")
        else:
            checked = "、".join(cfg.get("checked") or []) or "未配置路径"
            add_check("rtp2httpd", "rtp2httpd 配置文件", None, f"{cfg.get('error')}；已检查：{checked}")
            conclusions.append("如需诊断 upstream-interface，请把 rtp2httpd.conf 挂载进容器并设置 RTP2HTTPD_CONFIG_PATH 或在诊断页填写路径。")
    else:
        add_check("rtp2httpd", "rtp2httpd 可访问", None, "未配置 rtp2httpd 地址，跳过检测。")
        conclusions.append("未配置 rtp2httpd 地址，直连 M3U 使用 rtp:// 源地址。")

    # --- Check 2: Interface configured ---
    add_check("network", "抓包接口已配置", bool(iface), f"interface = {iface or '（未设置）'}")
    if not iface:
                conclusions.append("未设置抓包接口，诊断将使用默认接口 any。")

    # --- Check 3: Auth info captured ---
    auth = stb_discovery_service.status().get("auth_info") or {}
    has_mac = bool(auth.get("mac"))
    has_ip = bool(auth.get("assigned_ip"))
    option60 = auth.get("vendor_class") or auth.get("option60") or ""
    add_check(
        "auth",
        "DHCP 认证信息已捕获",
        has_mac or has_ip,
        f"MAC={auth.get('mac','—')}  IP={auth.get('assigned_ip','—')}  网关={auth.get('gateway','—')}  Option60={option60 or '—'}",
    )
    if not (has_mac or has_ip):
        conclusions.append("未捕获到 DHCP 认证信息，如需 Option60 认证，请重启机顶盒并再次捕获。")

    # --- Check 4: UserToken captured ---
    token_data = token_store.load()
    has_token = bool(token_data.get("history"))
    add_check("auth", "UserToken 已捕获", has_token, f"历史记录 {len(token_data.get('history') or [])} 条")
    if not has_token:
        conclusions.append("未捕获到 UserToken，channelAcquire 鉴权播放列表不可用。")

    # --- Check 5: FCC records ---
    fcc_count = len(fcc_store.load())
    add_check("fcc", "FCC 记录", fcc_count > 0, f"已记录 {fcc_count} 条 FCC 服务器地址")
    if fcc_count == 0:
        conclusions.append("没有 FCC 记录，快速换台功能不可用（不影响正常播放）。")

    # --- Check 6: FCC TCP reachability (if channel provided) ---
    # Note: this tests TCP connect only; actual FCC uses a proprietary protocol.
    # A TCP connect success means the port is open but does not guarantee FCC
    # will work correctly in rtp2httpd context.
    if channel_addr:
        import socket as _socket
        key = channel_addr
        fcc_records = fcc_store.load()
        fcc_rec = fcc_records.get(key) or {}
        fcc_ip = str(fcc_rec.get("fcc_ip", "")).strip()
        fcc_port = fcc_rec.get("fcc_port")
        if fcc_ip and fcc_port:
            try:
                with _socket.create_connection((fcc_ip, int(fcc_port)), timeout=3):
                    pass
                add_check("fcc", f"FCC 服务器端口可达 ({channel_addr})", True, f"TCP connect {fcc_ip}:{fcc_port} → 成功（注：仅验证端口可达，非 FCC 协议握手）")
            except Exception as exc:
                add_check("fcc", f"FCC 服务器端口可达 ({channel_addr})", False, f"TCP connect {fcc_ip}:{fcc_port} → {exc}")
                conclusions.append(f"FCC 服务器 {fcc_ip}:{fcc_port} 端口不可达，rtp2httpd FCC 快速换台将超时。")
        else:
            add_check("fcc", f"FCC 记录查询 ({channel_addr})", None, "此频道无 FCC 记录（不影响正常播放，仅影响快速换台）")

    # --- Check 6b: Live multicast link (IGMP join + 239.x UDP / mirror-port) ---
    # Only when a concrete multicast channel is given and we have tcpdump权限.
    if channel_addr and ":" in channel_addr:
        mc_host, _, mc_port_raw = channel_addr.partition(":")
        try:
            mc_port = int(mc_port_raw)
        except ValueError:
            mc_port = 0
        if valid_ipv4_multicast(mc_host) and mc_port:
            runtime_ok = capture_service.runtime_check().get("ok")
            if not runtime_ok:
                add_check("multicast", f"组播链路检测 ({channel_addr})", None, "缺少 tcpdump/抓包权限，跳过 IGMP/UDP 链路检测（需 NET_ADMIN, NET_RAW）")
                conclusions.append("无法进行 IGMP/组播回流检测：宿主机需安装 tcpdump 并授予 NET_ADMIN、NET_RAW 权限。")
            else:
                link = capture_service.diagnose_multicast(mc_host, mc_port, iface)
                igmp_detail = "已发出 IGMP 加入请求" if link.get("igmp_sent") else "未确认 IGMP 加入"
                add_check(
                    "multicast",
                    f"IGMP 组播加入 ({channel_addr})",
                    bool(link.get("igmp_sent")),
                    f"接口 {link.get('interface')}（{link.get('interface_ip') or '自动'}）→ {igmp_detail}",
                )
                verdict_code = link.get("verdict")
                udp_detail = (f"主动加入后收到 UDP 包：socket={link.get('socket_active_packets')} "
                              f"/ 线缆={link.get('wire_active_packets')}；"
                              f"未加入时线缆收到={link.get('wire_passive_packets')}")
                if verdict_code == "ok":
                    add_check("multicast", f"收到 239.x UDP 组播流 ({channel_addr})", True, udp_detail)
                elif verdict_code == "mirror":
                    add_check("multicast", f"收到 239.x UDP 组播流 ({channel_addr})", False, udp_detail + " → 疑似镜像口（SPAN）")
                    conclusions.append("疑似镜像/SPAN 抓包口：未加入组播即可收到流量，但主动 IGMP 加入收不到。"
                                       "镜像口只能被动看到流量，播放器无法主动播放；请改用真实的 IPTV 接入口。")
                else:
                    add_check("multicast", f"收到 239.x UDP 组播流 ({channel_addr})", False, udp_detail)
                    conclusions.append("未收到该组播流：可能不在 IPTV 组播 VLAN、抓包接口选择错误，或该频道已停播。")
                for err in link.get("errors", []):
                    conclusions.append(f"组播链路检测：{err}")

    # --- Check 7: Channel list populated ---
    ch_count = len(channel_store.load())
    add_check("playlist", "频道列表已导入", ch_count > 0, f"已保存 {ch_count} 个频道")
    if ch_count == 0:
        conclusions.append("频道列表为空，请先运行运营商频道发现并导入。")

    # --- Verdict ---
    failed = [c for c in checks if c["ok"] is False]
    if not failed and rtp2httpd_ok:
        verdict = "✓ 播放链路基本正常，可尝试播放。"
    elif not http_host:
        verdict = "直连 rtp:// 模式，无需 rtp2httpd。如需代理播放请配置 rtp2httpd 地址。"
    elif failed:
        verdict = f"⚠ 发现 {len(failed)} 项问题，详见诊断项和结论。"
    else:
        verdict = "诊断完成。"

    return api_success({
        "verdict": verdict,
        "checks": checks,
        "sections": _diagnose_sections(checks),
        "conclusions": conclusions,
    })


def _startup_epg_refresh() -> None:
    try:
        settings = settings_store.load()
        if not settings.get("use_epg", True):
            return
        epg_url = str(settings.get("epg_url", "")).strip()
        logo_url = str(settings.get("logo_url", "")).strip() if settings.get("use_logo", True) else ""
        if epg_url:
            epg_service.refresh(epg_url)
        if logo_url:
            epg_service.refresh_logo(logo_url)
        logger.info(f"启动 EPG 自动刷新完成：{epg_url}")
    except Exception as exc:
        logger.warning(f"启动 EPG 自动刷新失败：{exc}")


def boot() -> None:
    logger.info(f"应用启动：{APP_NAME} v{APP_VERSION}")
    capture_service.validate_runtime()
    epg_service.start_auto_refresh(settings_store)
    iptv_auth_service.start_egress_bpf_watchdog()
    threading.Thread(target=_startup_epg_refresh, daemon=True).start()
    _start_version_check_loop()
    logger.info(f"数据目录：{DATA_DIR}")
    logger.info(f"输出目录：{OUTPUT_DIR}")
    serve(app, host=WEB_HOST, port=WEB_PORT, threads=WAITRESS_THREADS)


if __name__ == "__main__":
    boot()
