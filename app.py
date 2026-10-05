#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPTV Sniffer Web application entrypoint."""
from __future__ import annotations

import gzip
import hashlib
import io
import os
import zlib
import json
import re
import select
import shutil
import subprocess
import tempfile
import time
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

from flask import Flask, Response, jsonify, redirect, render_template, request, send_file, send_from_directory
from waitress import serve

from config import (
    ALLOWED_DOWNLOADS,
    APP_DESCRIPTION,
    CATEGORY_OPTIONS,
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
    SUBSCRIPTION_FILE,
    DEFAULT_RTP2HTTPD_CONFIG_PATH,
    EPG_KEY_FILE,
    OPERATOR_CHANNELS_FILE,
    SNAPSHOTS_FILE,
    WAITRESS_THREADS,
    WEB_HOST,
    WEB_PORT,
)
from services.capture_service import CaptureService
from services.epg_refresh_service import refresh_backtv_urls
from services.epg_service import EpgService, normalize_channel_name
from services.export_service import ExportService
from services.iptv_auth_service import IptvAuthService
from services.log_service import AppLogger
from services.hls_service import HlsService
from services.media_task_service import MediaTaskManager, MediaCapacityError
from services.snapshot_service import SnapshotService
from services.diagnostic_service import playback_evidence, diagnostic_verdict
from services import subscription_service
from services.catchup_scheduler import CatchupScheduler
from services.io_limits import validate_http_url, HttpOnlyRedirects, read_bounded, gunzip_bounded, MAX_HTTP_BYTES
from urllib.request import build_opener
from services.media_task_service import ProcessTail
from utils import with_playseek, valid_playseek
from services.backup_service import RestoreTransaction, STORAGE_LOCK, validate_modules, restore_modules
from services.rtsp_catchup_service import CombinedRtspUdpSession, RtspCatchupError
from services.stb_discovery_service import StbDiscoveryService
from services.storage_service import ChannelSnapshotStore, ChannelStore, DiscoveryStore, FccStore, LocalSecretStore, OperatorChannelStore, SettingsStore, StbTokenStore, SubscriptionStore
from utils import channel_group_key, channel_primary_score, channel_variant_key, classify_channel_name, natural_key, normalize_channel_name_for_group, redact_sensitive_text, valid_ip_or_host, valid_ipv4_multicast

app = Flask(__name__)
logger = AppLogger(LOG_FILE, LOG_MEMORY_LIMIT)
settings_store = SettingsStore(SETTINGS_FILE)
epg_key_store = LocalSecretStore(EPG_KEY_FILE)
channel_store = ChannelStore(CHANNELS_FILE)
fcc_store = FccStore(FCC_FILE)
operator_channel_store = OperatorChannelStore(OPERATOR_CHANNELS_FILE)
snapshot_store = ChannelSnapshotStore(SNAPSHOTS_FILE)
subscription_store = SubscriptionStore(SUBSCRIPTION_FILE)
token_store = StbTokenStore(STB_TOKEN_FILE)
stb_discovery_service = StbDiscoveryService(logger, token_store)
discovery_store = DiscoveryStore(DISCOVERY_FILE)
capture_service = CaptureService(logger, fcc_store, token_store, discovery_store)
export_service = ExportService(OUTPUT_DIR)
media_tasks = MediaTaskManager(limit=max(1, min(4, WAITRESS_THREADS - 2)))
hls_service = HlsService(logger, media_tasks)
snapshot_service = SnapshotService(media_tasks)
epg_service = EpgService(logger, EPG_CACHE_FILE)
iptv_auth_service = IptvAuthService(IPTV_AUTH_BACKUP_FILE, DATA_DIR, logger)


def _with_local_epg_key(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    """Inject the locally stored EPG key for an internal refresh only."""
    merged = dict(settings if settings is not None else settings_store.load())
    key = epg_key_store.get_epg_key()
    if key:
        merged["epg_des3_key"] = key
    return merged


_CREDENTIAL_BACKUP_KEY = "credentials"
_CREDENTIAL_SETTING_KEYS = ("iptv_password", "epg_des3_key", "epg_des3_key_configured")


def _public_settings(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return settings for the locally authorized management page.

    The DES/DES3 key remains in its owner-only file at rest, but is included in
    this response because the owner explicitly chose to view and edit it here.
    JSON backups handle credentials through their separate opt-in module.
    """
    public = dict(settings if settings is not None else settings_store.load())
    if not str(public.get("timeshift_host") or "").strip():
        for channel in operator_channel_store.load().values():
            backtv_url = str(channel.get("backtv_url") or "").strip()
            if not backtv_url:
                continue
            host = urlsplit(backtv_url).netloc.strip()
            if host:
                public["timeshift_host"] = host
                public["timeshift_host_inferred"] = True
                break
    public["epg_des3_key"] = epg_key_store.get_epg_key()
    public["epg_des3_key_configured"] = bool(public["epg_des3_key"])
    return public


def _backup_settings() -> dict[str, Any]:
    """Export non-secret settings; credentials require explicit opt-in."""
    settings = _public_settings()
    for key in _CREDENTIAL_SETTING_KEYS:
        settings.pop(key, None)
    return settings


def _backup_credentials() -> dict[str, str]:
    """Build the explicit sensitive portion of a portable backup."""
    settings = settings_store.load()
    return {
        "iptv_password": str(settings.get("iptv_password") or ""),
        "epg_des3_key": epg_key_store.get_epg_key(),
    }


def _migrate_legacy_epg_key() -> None:
    """Move an old key out of settings.json without ever returning it by API."""
    settings = settings_store.load()
    legacy_key = str(settings.get("epg_des3_key") or "").strip()
    if legacy_key and not epg_key_store.has_epg_key():
        epg_key_store.set_epg_key(legacy_key)
    if legacy_key:
        settings_store.save({"epg_des3_key": ""})


_migrate_legacy_epg_key()
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
_catchup_refresh_lock = threading.RLock()
_catchup_auto_state: dict[str, Any] = {
    "running": False,
    "last_run_at": None,
    "last_success_at": None,
    "next_run_at": None,
    "last_error": "",
    "last_result": None,
    "token_expires_at": None,
    "token_expiry_note": "尚未刷新",
}
_catchup_auto_thread_started = False
catchup_scheduler = CatchupScheduler(_catchup_auto_state, _catchup_refresh_lock, DATA_DIR / "catchup_schedule.json")
_CATCHUP_FFMPEG_START_TIMEOUT_SECONDS = 15
_CATCHUP_FFMPEG_READ_TIMEOUT_MICROSECONDS = 15_000_000
_STABLE_CHANNEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")


def _stop_catchup_ffmpeg(proc: subprocess.Popen[Any]) -> str:
    """Stop a catchup FFmpeg process and return a redacted stderr excerpt."""
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    except Exception:
        pass
    try:
        tail = getattr(proc, "_iptv_stderr", None)
        content = tail.text() if tail else proc.stderr.read().decode(errors="replace")
        return redact_sensitive_text(content.strip(), 400)
    except Exception:
        return ""
    finally:
        for pipe in (proc.stdout, proc.stderr):
            if pipe:
                pipe.close()


def _wait_for_catchup_first_chunk(
    proc: subprocess.Popen[Any], timeout_seconds: float = _CATCHUP_FFMPEG_START_TIMEOUT_SECONDS,
) -> tuple[bytes, str]:
    """Return the first MPEG-TS chunk, or a reason before HTTP streaming starts."""
    deadline = time.monotonic() + timeout_seconds
    stdout = proc.stdout
    if stdout is None:
        return b"", "FFmpeg 未创建输出管道"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return b"", "FFmpeg 在输出首帧前退出"
        remaining = max(0.01, deadline - time.monotonic())
        ready, _, _ = select.select([stdout], [], [], remaining)
        if not ready:
            break
        chunk = os.read(stdout.fileno(), 65536)
        if chunk:
            return chunk, ""
        if proc.poll() is not None:
            return b"", "FFmpeg 在输出首帧前退出"
    return b"", f"回看上游在 {int(timeout_seconds)} 秒内未返回数据"


def _catchup_rtsp_candidates(backtv_url: str, playseek: str) -> list[tuple[str, str]]:
    """Build safe RTSP playback candidates without exposing the saved URL."""
    backtv = str(backtv_url or "").strip()
    if not backtv:
        return []
    candidates = [("captured", with_playseek(backtv, playseek))]
    # Some Huawei/CU channel tables include stale query parameters after the
    # ``.smil`` resource.  The compatible player flow starts from the bare
    # resource and sends only the requested playback window.
    smil_match = re.match(r"^(.+?\.smil)(?:[?#].*)?$", backtv, re.IGNORECASE)
    if smil_match:
        candidates.insert(0, ("canonical_smil", f"{smil_match.group(1)}?playseek={playseek}"))
    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    for mode, url in candidates:
        if url not in seen:
            unique.append((mode, url))
            seen.add(url)
    return unique


def _catchup_failure_category(stderr_text: str, start_error: str) -> str:
    """Return a user-safe diagnostic category; never return FFmpeg text."""
    text = f"{stderr_text}\n{start_error}".lower()
    rules = (
        ("rtsp_unauthorized", ("401", "unauthorized")),
        ("rtsp_forbidden", ("403", "forbidden")),
        ("rtsp_not_found", ("404", "not found")),
        ("rtsp_connection_refused", ("connection refused",)),
        ("rtsp_timeout", ("timed out", "connection timeout", "timeout")),
        ("rtsp_transport_unsupported", ("461", "unsupported transport")),
        ("rtsp_method_rejected", ("405", "455", "method not allowed", "method not valid")),
        ("rtsp_protocol_incompatible", ("method", "protocol not found", "option not found")),
        ("rtsp_invalid_media", ("invalid data", "could not find codec")),
    )
    for category, markers in rules:
        if any(marker in text for marker in markers):
            return category
    return "rtsp_no_media"


def _version_tuple(v: str) -> tuple[int, ...]:
    # Project tags use x.y.z and x.y.z-test; stable follows its test build.
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(-test)?", str(v).strip())
    if not match:
        return (0,)
    return tuple(int(match.group(i)) for i in (1, 2, 3)) + (int(match.group(4) is None),)


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


def enrich_channel_rows(rows: list[dict[str, Any]], settings: dict[str, Any] | None = None, operator_channels=None) -> list[dict[str, Any]]:
    settings = settings or settings_store.load()
    discovered = discovery_store.load()
    operator_channels = operator_channel_store.load() if operator_channels is None else operator_channels
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
        op_category = str((op_ch or {}).get("category") or "").strip()
        row_category = str(item.get("category", "")).strip()
        _auto_cat = classify_channel_name(str(item.get("name", "")))
        item["category"] = op_category or row_category or _auto_cat or "其它频道"
        if op_ch and op_ch.get("operator_group") and not str(item.get("operator_group", "")).strip():
            item["operator_group"] = str(op_ch.get("operator_group", "")).strip()
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
    iface = str(settings.get("media_interface") or settings.get("interface") or "").strip()
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
        str(settings.get("rtp2httpd_path_prefix", "") or "").strip(),
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

    summary["groups_checked"] = len(multi_groups)
    candidates: list[dict[str, Any]] = []
    for members in multi_groups:
        ordered = sorted(members, key=channel_primary_score, reverse=True)[:max_candidates]
        candidates.extend(ordered)

    if candidates:
        max_workers = min(len(candidates), 16)
        check_results: list[tuple[dict[str, Any], dict[str, Any]]] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_row = {
                executor.submit(_export_health_check_one, row, settings, operator_channels): row
                for row in candidates
            }
            for future in as_completed(future_to_row):
                check_results.append((future_to_row[future], future.result()))
        for row, health in check_results:
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
    validate_http_url(source)
    req = Request(source, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
    with build_opener(HttpOnlyRedirects()).open(req, timeout=timeout) as response:
        validate_http_url(response.geturl())
        data = read_bounded(response, MAX_HTTP_BYTES)
    if source.lower().endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gunzip_bounded(data)
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


def _safe_import_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _parse_playlist_stream_url(url: str) -> tuple[str, int, dict[str, list[str]]] | None:
    """Extract a multicast source from this app's exported M3U URL formats."""
    parsed = urlsplit(str(url or "").strip())
    host = parsed.hostname or ""
    try:
        port = _safe_import_port(parsed.port)
    except ValueError:
        port = None
    if parsed.scheme.lower() in {"rtp", "udp", "igmp"} and host and port:
        return host, port, parse_qs(parsed.query)

    # Player playlists use rtp2httpd URLs such as
    # http://host:5140/rtp/239.1.1.1:8001?fcc=10.0.0.1:8027&fec=8000.
    path_parts = [part for part in parsed.path.split("/") if part]
    if parsed.scheme.lower() in {"http", "https"} and len(path_parts) >= 2 and path_parts[-2].lower() in {"rtp", "udp", "igmp"}:
        stream_host, separator, stream_port = path_parts[-1].rpartition(":")
        resolved_port = _safe_import_port(stream_port) if separator else None
        if stream_host and resolved_port:
            return stream_host, resolved_port, parse_qs(parsed.query)
    return None


def _playlist_item_to_channel_row(item: dict[str, Any]) -> dict[str, Any] | None:
    parsed = _parse_playlist_stream_url(str(item.get("url") or ""))
    if not parsed:
        return None
    host, port, query = parsed
    if not valid_ipv4_multicast(host):
        return None
    attrs = item.get("attrs") if isinstance(item.get("attrs"), dict) else {}
    name = str(item.get("title") or attrs.get("tvg-name") or attrs.get("tvg-id") or "").strip()
    if not name:
        return None
    fcc = str((query.get("fcc") or [""])[0]).strip()
    fcc_host, separator, fcc_port_text = fcc.rpartition(":")
    fcc_port = _safe_import_port(fcc_port_text) if separator else None
    fec_port = _safe_import_port((query.get("fec") or [None])[0])
    return {
        "key": f"{host}:{port}",
        "host": host,
        "port": port,
        "name": name,
        "category": str(attrs.get("group-title") or classify_channel_name(name)).strip(),
        "tvg_id": str(attrs.get("tvg-id") or "").strip(),
        "tvg_name": str(attrs.get("tvg-name") or "").strip(),
        "tvg_logo": str(attrs.get("tvg-logo") or "").strip(),
        "fcc_ip": fcc_host.strip() if fcc_port else "",
        "fcc_port": fcc_port,
        "fec_port": fec_port,
    }


def parse_exported_m3u_channels(text: str) -> tuple[list[dict[str, Any]], int]:
    """Parse channels exported by this application, retaining usable M3U metadata."""
    items = parse_m3u_channels(text)
    rows = [row for item in items if (row := _playlist_item_to_channel_row(item))]
    return rows, len(items) - len(rows)


def parse_exported_channels_json(data: Any) -> tuple[list[dict[str, Any]], int]:
    """Parse the channels.json format written by ExportService."""
    if isinstance(data, dict) and data.get("_format") == "iptv-sniffer-channels":
        if data.get("schema_version") != 2 or not isinstance(data.get("items"), list):
            raise ValueError("不支持的频道导出格式版本")
        rows, skipped = [], 0
        for item in data["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"].strip():
                skipped += 1
                continue
            parsed, ignored = parse_exported_channels_json({item["name"]: item})
            rows.extend(parsed)
            skipped += ignored
        return rows, skipped
    if isinstance(data, list):
        rows = [dict(item) for item in data if isinstance(item, dict)]
        return rows, len(data) - len(rows)
    if not isinstance(data, dict):
        raise ValueError("频道列表 JSON 必须是对象或数组")
    rows: list[dict[str, Any]] = []
    skipped = 0
    for name, item in data.items():
        if not isinstance(item, dict):
            skipped += 1
            continue
        live = item.get("live") if isinstance(item.get("live"), dict) else {}
        source = live.get("local-multicast") if isinstance(live.get("local-multicast"), dict) else {}
        parsed = _parse_playlist_stream_url(str(source.get("addr") or ""))
        if not parsed:
            skipped += 1
            continue
        host, port, query = parsed
        if not valid_ipv4_multicast(host):
            skipped += 1
            continue
        sniffer = item.get("sniffer") if isinstance(item.get("sniffer"), dict) else {}
        fcc = str(sniffer.get("fcc") or (query.get("fcc") or [""])[0]).strip()
        fcc_host, separator, fcc_port_text = fcc.rpartition(":")
        fcc_port = _safe_import_port(fcc_port_text) if separator else None
        rows.append({
            "key": f"{host}:{port}",
            "stable_id": _valid_stable_channel_id(sniffer.get("stable_id")),
            "provenance": sniffer.get("provenance") if isinstance(sniffer.get("provenance"), dict) else {},
            "host": host,
            "port": port,
            "name": str(name or item.get("tvg_name") or item.get("tvg_id") or "").strip(),
            "category": str(item.get("group_title") or classify_channel_name(str(name))).strip(),
            "tvg_id": str(item.get("tvg_id") or "").strip(),
            "tvg_name": str(item.get("tvg_name") or "").strip(),
            "tvg_logo": str(item.get("tvg_logo") or "").strip(),
            "epg_source": str(item.get("epg_source") or "").strip(),
            "is_hd": bool(item.get("is_hd", False)),
            "packets": sniffer.get("packets", 0),
            "codec_name": str(sniffer.get("codec") or ""),
            "width": sniffer.get("width"),
            "height": sniffer.get("height"),
            "fcc_ip": fcc_host.strip() if fcc_port else "",
            "fcc_port": fcc_port,
            "fec_port": _safe_import_port(sniffer.get("fec") or (query.get("fec") or [None])[0]),
        })
    return rows, skipped


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
    response = api_success(_public_settings())
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.post("/api/settings")
def api_settings_save():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    try:
        data = SettingsStore.validate_update(data)
        if "rtp2httpd_path_prefix" in data:
            data["rtp2httpd_path_prefix"] = ExportService.normalize_path_prefix(data["rtp2httpd_path_prefix"])
    except ValueError as exc:
        return api_error(str(exc), 400)
    epg_key = str(data.pop("epg_des3_key", "") or "").strip()
    clear_epg_key = bool(data.pop("clear_epg_des3_key", False))
    data.pop("epg_des3_key_configured", None)
    if epg_key:
        epg_key_store.set_epg_key(epg_key)
    elif clear_epg_key:
        epg_key_store.clear_epg_key()
    saved = settings_store.save(data)
    epg_url = str(saved.get("epg_url", "")).strip()
    logo_url = str(saved.get("logo_url", "")).strip()
    epg_service.select_primary(epg_url, logo_url)
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
    response = api_success(_public_settings(saved))
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


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


def _valid_stable_channel_id(value):
    return subscription_service._valid_stable_channel_id(value)


def _stable_channel_id(row, operator=None):
    return subscription_service._stable_channel_id(row, operator)


def _stable_channel_catalog():
    return subscription_service._stable_channel_catalog(channel_store.load(), operator_channel_store.load(), fill_channel_name_from_metadata)


def _default_subscription_ids(catalog: dict[str, dict[str, Any]]) -> list[str]:
    """Choose the existing best-source view when migrating pre-1.3 installs."""
    records = list(catalog.values())
    normalized = export_service._normalize_channels([item["row"] for item in records])
    selected_keys = {channel.key for channel in export_service._select_best_channels(normalized)}
    return [
        stable_id for stable_id, item in catalog.items()
        if str(item["row"].get("key") or "") in selected_keys
    ]


def _subscription_candidate_ids(catalog: dict[str, dict[str, Any]]) -> list[str]:
    """Return persisted candidates, migrating older installations once."""
    saved = subscription_store.load()
    if not saved["initialized"]:
        saved = subscription_store.save(_default_subscription_ids(catalog))
    available = set(catalog)
    return [stable_id for stable_id in saved["candidate_ids"] if stable_id in available]


def _subscription_entry(stable_id: str, item: dict[str, Any]) -> dict[str, Any]:
    row = item["row"]
    operator = item["operator"]
    return {
        "stable_id": stable_id,
        "name": str(row.get("name") or ""),
        "category": str(row.get("category") or "其它频道"),
        "is_hd": bool(row.get("is_hd")),
        "has_catchup": bool(str(operator.get("backtv_url") or "").strip()),
        "has_fcc": bool(str(row.get("fcc_ip") or "").strip() and row.get("fcc_port")),
        "source_count": 1,
    }


def _operator_time_shift_minutes(operator):
    return subscription_service._operator_time_shift_minutes(operator)


def _subscription_m3u(hls_compat=False):
    catalog = _stable_channel_catalog()
    return subscription_service._subscription_m3u(settings_store.load(), catalog,
        _subscription_candidate_ids(catalog), request.url_root.rstrip("/"), hls_compat)


def _subscription_response(hls_compat: bool = False) -> Response:
    response = Response(_subscription_m3u(hls_compat), mimetype="audio/x-mpegurl")
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.get("/playlist.m3u")
def playlist_best_subscription():
    return _subscription_response()


@app.get("/playlist-all.m3u")
def playlist_all_subscription():
    # Compatibility alias.  A durable channel ID always resolves to its one
    # current source, so this intentionally has the same content as the main
    # subscription instead of implying non-existent source variants.
    return _subscription_response()


@app.get("/playlist-hls.m3u")
def playlist_hls_subscription():
    return _subscription_response(hls_compat=True)


def _rtp2httpd_source_rows() -> list[dict[str, Any]]:
    catalog = _stable_channel_catalog()
    candidate_ids = _subscription_candidate_ids(catalog)
    selected_groups = {
        channel_group_key(catalog[stable_id]["row"])
        for stable_id in candidate_ids
    }
    if not selected_groups:
        return []
    operator_channels = operator_channel_store.load()
    # The catalog supplies current operator endpoints, including mappings
    # rebuilt by EPG refresh. Historical c-* records are not alternate lines.
    rows = {str(item["row"]["key"]): item["row"] for item in catalog.values()}
    for row in display_channel_rows(channel_store.list()):
        key = str(row.get("key") or "")
        if operator_channels and str(row.get("stable_id") or "").startswith("c-") and key not in operator_channels:
            continue
        rows.setdefault(key, row)
    return [_row_with_operator_stream_params(row, operator_channels)
            for row in rows.values() if channel_group_key(row) in selected_groups]


def _rtp2httpd_subscription_response(*, best_only: bool) -> Response:
    content, count = export_service.source_subscription_m3u(
        _rtp2httpd_source_rows(),
        settings_store.load(),
        best_only=best_only,
    )
    response = Response(content, mimetype="audio/x-mpegurl")
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["X-Playlist-Records"] = str(count)
    return response


@app.get("/playlist-rtp2httpd.m3u")
def playlist_rtp2httpd_best():
    """One best original RTP source per logical channel."""
    return _rtp2httpd_subscription_response(best_only=True)


@app.get("/playlist-rtp2httpd-all.m3u")
def playlist_rtp2httpd_all():
    """Every current original RTP source, including alternate lines."""
    return _rtp2httpd_subscription_response(best_only=False)


@app.get("/epg.xml")
def epg_subscription():
    settings = settings_store.load()
    source = str(settings.get("epg_url") or "").strip() if settings.get("use_epg", True) else ""
    if not source:
        return api_error("未配置 EPG 订阅源", 404)
    response = redirect(source, code=307)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.get("/live/<stable_id>")
def stable_live(stable_id: str):
    entry = _stable_channel_catalog().get(_valid_stable_channel_id(stable_id))
    if not entry:
        return api_error("频道不存在或已移除", 404)
    row = entry["row"]
    settings = settings_store.load()
    if str(request.args.get("format") or "").strip().lower() == "hls":
        target = f"{request.url_root.rstrip('/')}/hls/{row['host']}_{row['port']}/stream.m3u8"
    else:
        http_host = str(settings.get("http_host") or "").strip()
        if not http_host:
            return api_error("未配置 rtp2httpd 地址", 503)
        target = ExportService.make_http_url(
            http_host,
            int(settings.get("http_port") or 5140),
            str(settings.get("path_mode") or "rtp"),
            str(row["host"]),
            int(row["port"]),
            str(row.get("fcc_ip") or ""),
            row.get("fcc_port"),
            row.get("fec_port"),
            str(settings.get("fcc_type") or ""),
            str(settings.get("rtp2httpd_path_prefix") or ""),
        )
    response = redirect(target, code=307)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.get("/catchup/<stable_id>")
def stable_catchup(stable_id: str):
    entry = _stable_channel_catalog().get(_valid_stable_channel_id(stable_id))
    if not entry:
        return api_error("频道不存在或已移除", 404)
    row = entry["row"]
    # Reuse the proven RTSP compatibility path; only the public lookup key is
    # stable.  The current multicast key remains an internal implementation detail.
    return hls_catchup(f"{row['host']}_{row['port']}")


@app.get("/api/subscription")
def api_subscription():
    catalog = _stable_channel_catalog()
    candidate_ids = _subscription_candidate_ids(catalog)
    candidates = [_subscription_entry(stable_id, catalog[stable_id]) for stable_id in candidate_ids]
    source_rows = _rtp2httpd_source_rows()
    normalized_sources = export_service._normalize_channels(source_rows)
    best_source_count = len(export_service._select_best_channels(normalized_sources))
    return api_success({
        "candidates": candidates,
        "candidate_ids": candidate_ids,
        "total_candidates": len(candidates),
        "available_candidates": len(candidates),
        "catchup_candidates": sum(1 for item in candidates if item["has_catchup"]),
        "fcc_candidates": sum(1 for item in candidates if item["has_fcc"]),
        "rtp2httpd_best_count": best_source_count,
        "rtp2httpd_all_count": len(normalized_sources),
        "urls": {
            "best": "/playlist.m3u",
            "all": "/playlist-all.m3u",
            "hls": "/playlist-hls.m3u",
            "rtp2httpd": "/playlist-rtp2httpd.m3u",
            "rtp2httpd_all": "/playlist-rtp2httpd-all.m3u",
            "epg": "/epg.xml",
        },
    })


@app.post("/api/subscription/candidates")
def api_subscription_candidates():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    action = str(data.get("action") or "").strip()
    requested = data.get("stable_ids") or []
    if action not in {"add", "remove", "replace", "reset_to_best"}:
        return api_error("action 必须为 add、remove、replace 或 reset_to_best")
    if not isinstance(requested, list):
        return api_error("stable_ids 必须是数组")
    catalog = _stable_channel_catalog()
    current = _subscription_candidate_ids(catalog)
    valid_requested = [str(item).strip() for item in requested if str(item).strip() in catalog]
    if action == "reset_to_best":
        updated = _default_subscription_ids(catalog)
    elif action == "replace":
        updated = valid_requested
    elif action == "add":
        updated = current + [item for item in valid_requested if item not in current]
    else:
        remove = set(valid_requested)
        updated = [item for item in current if item not in remove]
    subscription_store.save(updated)
    logger.info(f"订阅候选清单已更新：{action}，当前 {len(updated)} 个频道")
    return api_subscription()


@app.get("/api/channels")
def api_channels():
    rows = display_channel_rows(channel_store.list())
    catalog = _stable_channel_catalog()
    candidate_ids = set(_subscription_candidate_ids(catalog))
    stable_by_key = {str(item["row"].get("key") or ""): stable_id for stable_id, item in catalog.items()}
    for row in rows:
        stable_id = stable_by_key.get(str(row.get("key") or "")) or _stable_channel_id(row)
        row["stable_id"] = stable_id
        row["subscription_candidate"] = stable_by_key.get(str(row.get("key") or "")) in candidate_ids
        row["source_state"] = "current" if str(row.get("key") or "") in stable_by_key else "historical"
        operator = catalog.get(stable_id, {}).get("operator", {})
        row["has_catchup"] = bool(operator.get("backtv_url"))
        row["has_timeshift"] = bool(operator.get("time_shift") or _operator_time_shift_minutes(operator))
        row["has_fcc"] = bool(str(row.get("fcc_ip") or "").strip() and row.get("fcc_port"))
    seen = {cat: None for cat in CATEGORY_OPTIONS}
    for row in rows:
        cat = str(row.get("category") or "").strip()
        if cat:
            seen.setdefault(cat, None)
    categories = sorted(seen.keys(), key=lambda cat: (CATEGORY_ORDER.get(cat, 99), natural_key(cat)))
    return api_success({"channels": rows, "categories": categories})


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
            original = ch.get("original_metadata")
            if not isinstance(original, dict):
                original = ChannelStore._metadata_fields(ch)
            item = dict(ch)
            item.update(ChannelStore._metadata_fields(original))
            epg_service.enrich_item(item, epg_url, only_missing=False)
            item["original_metadata"] = ChannelStore._metadata_fields(item)
            edited = ch.get("edited_metadata")
            if isinstance(edited, dict):
                item.update(ChannelStore._metadata_fields(edited))
                item["edited_metadata"] = ChannelStore._metadata_fields(edited)
            rows.append(item)
            if item["original_metadata"].get("tvg_id") != original.get("tvg_id"):
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
    with STORAGE_LOCK:
        tx = RestoreTransaction(DATA_DIR)
        try:
            stores = []
            for store in (operator_channel_store, fcc_store, channel_store):
                shadow = type(store)(tx.directory / store.path.name)
                shadow.path.write_text(json.dumps(store.load(), ensure_ascii=False))
                stores.append(shadow)
            result = _build_operator_import(channels, *stores)
            for target, staged in zip((operator_channel_store, fcc_store, channel_store), stores):
                tx.stage_json(target.path, staged.load())
            tx.commit()
            operator_channel_store.invalidate()
            return result
        finally:
            if not (tx.directory / "journal.json").exists():
                tx.abort()


def _build_operator_import(channels, operator_channel_store, fcc_store, channel_store) -> dict:
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
            "stable_id": f"c-{str(ch.get('channel_id') or '').strip()}" if str(ch.get("channel_id") or "").strip() else "",
            "provenance": ch.get("provenance") or {},
            "host": ch["ip"],
            "port": ch["port"],
            "name": ch.get("name", ""),
            "category": str(ch.get("category") or "").strip() or classify_channel_name(ch.get("name", "")),
            "packets": stored.get("packets", 0),
            "fcc_ip": ch.get("fcc_ip", ""),
            "fcc_port": ch.get("fcc_port"),
            "fec_port": ch.get("fec_port"),
            "is_hd": ch.get("is_hd", False),
            "time_shift": ch.get("time_shift", False),
            "operator_group": str(ch.get("operator_group", "")).strip(),
            "probe_status": stored.get("probe_status", "not_probed"),
            "width": stored.get("width"),
            "height": stored.get("height"),
            "quality_group": stored.get("quality_group", ""),
        })
    enriched = enrich_channel_rows(rows, settings, operator_channels=operator_channel_store.load())
    # Refresh automatic values, but keep explicit user edits available and active.
    to_save = []
    for row in enriched:
        key = str(row.get("key", ""))
        stored = existing.get(key)
        original = ChannelStore._metadata_fields(row)
        row["original_metadata"] = original
        if stored:
            edited = stored.get("edited_metadata")
            if isinstance(edited, dict):
                edited = ChannelStore._metadata_fields(edited)
                row.update(edited)
                row["edited_metadata"] = edited
            else:
                # Compatibility with old records where a changed name implied a manual edit.
                old_name = str(stored.get("name") or "").strip()
                auto_name = str(row.get("auto_name") or "").strip()
                if old_name and auto_name and old_name != auto_name:
                    edited = dict(original)
                    edited["name"] = old_name
                    row.update(edited)
                    row["edited_metadata"] = edited
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


_BACKUP_VERSION = 2
_DISASTER_BACKUP_VERSION = 1
_DISASTER_MAX_FILES = 10_000
_DISASTER_MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
_DISASTER_PCAP_RE = re.compile(r"^pcaps/(stb-boot-[A-Za-z0-9._-]+\.pcap)$")
_DISASTER_MANIFEST_RE = re.compile(r"^metadata/(stb-boot-[A-Za-z0-9._-]+)\.manifest\.json$")
_BACKUP_FILES: list[tuple[str, Path]] = [
    ("settings", SETTINGS_FILE),
    ("channels", CHANNELS_FILE),
    ("operator_channels", OPERATOR_CHANNELS_FILE),
    ("discovered_channels", DISCOVERY_FILE),
    ("fcc", FCC_FILE),
    ("stb_token", STB_TOKEN_FILE),
    ("iptv_auth_backups", IPTV_AUTH_BACKUP_FILE),
    ("channel_snapshots", SNAPSHOTS_FILE),
    ("subscription_candidates", SUBSCRIPTION_FILE),
]


def serialized_storage(function):
    from functools import wraps
    @wraps(function)
    def wrapped(*args, **kwargs):
        with STORAGE_LOCK:
            return function(*args, **kwargs)
    return wrapped


@serialized_storage
def _global_backup_payload(selected: list[str] | None = None) -> dict[str, Any]:
    selected_keys = set(selected if selected is not None else [key for key, _ in _BACKUP_FILES])
    payload: dict[str, Any] = {
        "schema_version": _BACKUP_VERSION,
        "_version": _BACKUP_VERSION,
        "_app_version": APP_VERSION,
        "_exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    for key, path in _BACKUP_FILES:
        if key not in selected_keys:
            continue
        if key == "settings":
            payload[key] = _backup_settings()
            continue
        try:
            payload[key] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
        except Exception:
            payload[key] = None
    if _CREDENTIAL_BACKUP_KEY in selected_keys:
        payload[_CREDENTIAL_BACKUP_KEY] = _backup_credentials()
    validate_modules(payload, [key for key, _ in _BACKUP_FILES])
    return payload


def _global_backup_response(selected: list[str] | None = None) -> Response:
    payload = _global_backup_payload(selected)
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        body,
        mimetype="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="iptv-sniffer-backup.json"',
            "Cache-Control": "no-store, max-age=0",
        },
    )


def _normalize_global_backup_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize legacy per-interface auth exports into the global backup schema."""
    payload = data.get("backup") if isinstance(data.get("backup"), dict) else data
    if not isinstance(payload, dict):
        raise ValueError("格式错误：备份内容必须是 JSON 对象")
    if payload.get("_format") == "iptv-sniffer-channels":
        raise ValueError("这是频道列表，请使用频道导入")
    legacy_iface = str(payload.get("interface") or "").strip()
    legacy_initial = payload.get("initial")
    if legacy_iface and isinstance(legacy_initial, dict) and "iptv_auth_backups" not in payload:
        return {
            "schema_version": 1,
            "_version": 1,
            "_app_version": str(payload.get("_app_version") or ""),
            "_exported_at": str(payload.get("_exported_at") or ""),
            "iptv_auth_backups": {
                "interfaces": {legacy_iface: {"initial": legacy_initial, "history": []}},
            },
        }
    normalized = dict(payload)
    normalized["schema_version"] = normalized.get("schema_version", normalized.get("_version", 1))
    settings = normalized.get("settings")
    # Older backups placed the IPTV password in settings.  Split it into the
    # new explicit module so restore still gives the owner a choice.
    if isinstance(settings, dict):
        settings = dict(settings)
        existing_credentials = normalized.get(_CREDENTIAL_BACKUP_KEY)
        credentials = dict(existing_credentials) if isinstance(existing_credentials, dict) else {}
        legacy_credentials_migrated = False
        for key in ("iptv_password", "epg_des3_key"):
            if key in settings and key not in credentials:
                credentials[key] = settings.pop(key)
                legacy_credentials_migrated = True
        settings.pop("epg_des3_key_configured", None)
        normalized["settings"] = settings
        if credentials:
            normalized[_CREDENTIAL_BACKUP_KEY] = credentials
        if legacy_credentials_migrated:
            normalized["_legacy_credentials_migrated"] = True
    if "settings" in normalized and normalized["settings"] is not None:
        SettingsStore.validate_update(normalized["settings"])
        prefix = normalized["settings"].get("rtp2httpd_path_prefix", "")
        ExportService.normalize_path_prefix(prefix)
    validate_modules(normalized, [key for key, _ in _BACKUP_FILES])
    return normalized


def _auth_backup_conflicts(payload: dict[str, Any]) -> list[str]:
    incoming = payload.get("iptv_auth_backups")
    incoming_interfaces = incoming.get("interfaces") if isinstance(incoming, dict) else {}
    existing_interfaces = iptv_auth_service._backup_data().get("interfaces", {})
    if not isinstance(incoming_interfaces, dict) or not isinstance(existing_interfaces, dict):
        return []
    return sorted(
        iface for iface, entry in incoming_interfaces.items()
        if isinstance(entry, dict) and entry.get("initial")
        and isinstance(existing_interfaces.get(str(iface)), dict)
        and existing_interfaces[str(iface)].get("initial")
    )


@serialized_storage
def _restore_global_backup_payload(
    payload: dict[str, Any],
    selected_keys: list[str],
    *,
    overwrite_auth_backups: bool = False,
    transaction=None,
) -> dict[str, Any]:
    """Restore validated backup modules without ever echoing credential values."""
    auth_conflicts = _auth_backup_conflicts(payload)
    if "iptv_auth_backups" in selected_keys and auth_conflicts and not overwrite_auth_backups:
        raise FileExistsError(
            f"认证备份与本机接口快照冲突：{', '.join(auth_conflicts)}。请明确确认覆盖后再恢复。"
        )
    restored, skipped = restore_modules(
        payload, selected_keys, files=_BACKUP_FILES, root=DATA_DIR,
        settings_store=settings_store, epg_key_store=epg_key_store,
        credential_keys=_CREDENTIAL_SETTING_KEYS, validate_settings=SettingsStore.validate_update,
        transaction=transaction,
    )
    if "operator_channels" in restored:
        operator_channel_store.invalidate()
    restore_warnings: list[str] = []
    restored_set = set(restored)
    if ("settings" in restored_set) != ("operator_channels" in restored_set):
        restore_warnings.append("仅恢复了部分回看数据；完整恢复需要同时选择“应用与导出设置”和“运营商频道表”。")
    catchup_refresh_required = "operator_channels" in restored_set
    if catchup_refresh_required:
        restore_warnings.append("运营商频道表中的回看 Token 可能已过期，请在恢复后执行一次回看刷新。")
    return {
        "restored": restored,
        "skipped": skipped,
        "selected": selected_keys,
        "warnings": restore_warnings,
        "catchup_refresh_required": catchup_refresh_required,
    }


def _sha256_stream(stream: Any) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _zip_write_bytes(zf: zipfile.ZipFile, name: str, content: bytes, checksums: dict[str, str]) -> None:
    zf.writestr(name, content)
    checksums[name] = hashlib.sha256(content).hexdigest()


def _zip_write_file(zf: zipfile.ZipFile, name: str, path: Path, checksums: dict[str, str]) -> None:
    digest = hashlib.sha256()
    with path.open("rb") as source, zf.open(name, "w", force_zip64=True) as target:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            target.write(chunk)
    checksums[name] = digest.hexdigest()


def _deployment_recovery_manifest() -> dict[str, Any]:
    settings = settings_store.load()
    interface = str(settings.get("interface") or "").strip()
    snapshot: dict[str, Any] | None = None
    if interface:
        try:
            snapshot = iptv_auth_service.snapshot(interface)
        except Exception:
            snapshot = None
    return {
        "schema_version": 1,
        "app_version": APP_VERSION,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "container": {
            "network_mode": "host",
            "required_capabilities": ["NET_ADMIN", "NET_RAW"],
            "web_port_at_export": WEB_PORT,
            "data_dir": "/app/data",
            "output_dir": "/app/output",
        },
        "iptv_network": {
            "interface": interface,
            "network_manager_unmanaged_required": bool(interface),
            "route_requirements": ["10.0.0.0/8", "224.0.0.0/4"],
            "snapshot": snapshot,
        },
        "restore_notes": [
            "Install the same or a compatible IPTV Sniffer Web image before import.",
            "Import restores application state, plaintext credentials, raw PCAPs and protocol manifests.",
            "Host network mode, capabilities, interface management and routes remain host-level responsibilities.",
            "Refresh catchup once after restore because server-side sessions and tokens may expire.",
        ],
    }


def _disaster_readme() -> bytes:
    return (
        "IPTV Sniffer Web complete disaster-recovery package\n\n"
        "HIGHLY SENSITIVE: backup.json contains plaintext IPTV password/key material, and raw PCAPs may "
        "contain authentication traffic. Store this ZIP only in a trusted private location.\n\n"
        "Restore order:\n"
        "1. Install the same or a compatible application image.\n"
        "2. Use host networking and grant NET_ADMIN + NET_RAW.\n"
        "3. Keep the dedicated IPTV interface unmanaged by NetworkManager and restore required routes.\n"
        "4. Import this ZIP from the management page.\n"
        "5. Apply normal IPTV authentication and refresh catchup once.\n\n"
        "The ZIP intentionally excludes application logs, HLS temporary files, EPG cache, generated output, "
        "runtime DHCP processes, Cookie/JSESSIONID state and the Docker image itself.\n"
    ).encode("utf-8")


def _disaster_archive_targets(zf: zipfile.ZipFile) -> dict[str, Path]:
    targets: dict[str, Path] = {}
    pcap_bases: set[str] = set()
    for info in zf.infolist():
        pcap_match = _DISASTER_PCAP_RE.fullmatch(info.filename)
        if pcap_match:
            if not stb_discovery_service.archive_dir:
                raise ValueError("未配置 STB 抓包归档目录")
            filename = pcap_match.group(1)
            pcap_bases.add(Path(filename).stem)
            targets[info.filename] = Path(stb_discovery_service.archive_dir) / filename
            continue
        manifest_match = _DISASTER_MANIFEST_RE.fullmatch(info.filename)
        if manifest_match:
            if not stb_discovery_service.archive_dir:
                raise ValueError("未配置 STB 抓包归档目录")
            stem = manifest_match.group(1)
            targets[info.filename] = Path(stb_discovery_service.archive_dir) / f"{stem}.artifacts" / "manifest.json"
    manifest_bases = {
        match.group(1)
        for info in zf.infolist()
        if (match := _DISASTER_MANIFEST_RE.fullmatch(info.filename))
    }
    if not manifest_bases.issubset(pcap_bases):
        raise ValueError("灾备包中存在没有对应 PCAP 的协议清单")
    return targets


def _check_disaster_limits(infos: list[zipfile.ZipInfo]) -> None:
    if not infos or len(infos) > _DISASTER_MAX_FILES:
        raise ValueError(f"灾备包文件数量超过限制（最多 {_DISASTER_MAX_FILES} 项），请减少归档后重试")
    if sum(info.file_size for info in infos) > _DISASTER_MAX_UNCOMPRESSED_BYTES:
        raise ValueError("灾备包解压后超过 2 GiB 安全限制，请减少归档后重试")


def _validate_disaster_zip(zf: zipfile.ZipFile) -> tuple[dict[str, Any], dict[str, Path], dict[str, str]]:
    infos = zf.infolist()
    _check_disaster_limits(infos)
    if len({info.filename for info in infos}) != len(infos):
        raise ValueError("灾备包中存在重名文件")
    if any(info.is_dir() for info in infos):
        raise ValueError("灾备包不应包含独立目录项")
    required = {"backup.json", "deployment.json", "README.txt", "CHECKSUMS.sha256"}
    names = {info.filename for info in infos}
    if not required.issubset(names):
        raise ValueError("不是完整的 IPTV Sniffer Web 灾备包")
    allowed = required | {
        name for name in names
        if _DISASTER_PCAP_RE.fullmatch(name) or _DISASTER_MANIFEST_RE.fullmatch(name)
    }
    unsupported = sorted(names - allowed)
    if unsupported:
        raise ValueError(f"灾备包包含不支持的路径：{unsupported[0]}")
    checksum_text = zf.read("CHECKSUMS.sha256").decode("utf-8")
    checksums: dict[str, str] = {}
    for line in checksum_text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match.group(2) in checksums:
            raise ValueError("灾备包校验清单格式错误")
        checksums[match.group(2)] = match.group(1)
    expected_names = names - {"CHECKSUMS.sha256"}
    if set(checksums) != expected_names:
        raise ValueError("灾备包校验清单与文件内容不匹配")
    for name, expected in checksums.items():
        with zf.open(name) as stream:
            actual = _sha256_stream(stream)
        if actual != expected:
            raise ValueError(f"灾备包校验失败：{name}")
    try:
        package_backup = json.loads(zf.read("backup.json"))
    except Exception as exc:
        raise ValueError("灾备包中的 backup.json 无法读取") from exc
    payload = _normalize_global_backup_payload(package_backup)
    targets = _disaster_archive_targets(zf)
    available_modules = [key for key, _ in _BACKUP_FILES if payload.get(key) is not None]
    if payload.get(_CREDENTIAL_BACKUP_KEY) is not None:
        available_modules.append(_CREDENTIAL_BACKUP_KEY)
    if not available_modules and not targets:
        raise ValueError("备份 ZIP 中没有可恢复的模块或 PCAP")
    return payload, targets, checksums


def _write_zip_member_private(zf: zipfile.ZipFile, member: str, target: Path) -> None:
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    temp_path = target.with_name(f".{target.name}.{time.time_ns()}.tmp")
    try:
        with zf.open(member) as source, temp_path.open("wb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, target)
        os.chmod(target, 0o600)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _stream_private_temp_file(path: Path):
    """Stream a sensitive temporary export and remove it even under Waitress."""
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk
    finally:
        path.unlink(missing_ok=True)


@app.get("/api/backup/export")
def api_backup_export():
    return _global_backup_response()


@app.post("/api/backup/export")
def api_backup_export_selected():
    data = request.get_json(silent=True) or {}
    modules = data.get("modules") if isinstance(data, dict) else None
    known = {key for key, _ in _BACKUP_FILES} | {_CREDENTIAL_BACKUP_KEY}
    if not isinstance(modules, list):
        return api_error("modules 必须是数组", 400)
    selected = [str(key) for key in modules if str(key) in known]
    if not selected:
        return api_error("请至少选择一个要备份的模块", 400)
    return _global_backup_response(selected)


@app.post("/api/backup/inspect")
def api_backup_inspect():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("格式错误：需要 JSON 对象")
    try:
        payload = _normalize_global_backup_payload(data)
    except ValueError as exc:
        return api_error(str(exc))
    available = [key for key, _ in _BACKUP_FILES if payload.get(key) is not None]
    if payload.get(_CREDENTIAL_BACKUP_KEY) is not None:
        available.append(_CREDENTIAL_BACKUP_KEY)
    if not available:
        return api_error("不是可恢复的全局备份文件")
    response = api_success({
        "backup": payload,
        "available": available,
        "auth_conflicts": _auth_backup_conflicts(payload),
    })
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.post("/api/backup/import")
def api_backup_import():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("格式错误：需要 JSON 对象")
    try:
        payload = _normalize_global_backup_payload(data)
    except ValueError as exc:
        return api_error(str(exc))
    selected = data.get("modules") if isinstance(data.get("modules"), list) else None
    known = {key for key, _ in _BACKUP_FILES} | {_CREDENTIAL_BACKUP_KEY}
    if selected is None:
        selected_keys = [key for key, _ in _BACKUP_FILES]
    else:
        selected_keys = [str(key) for key in selected if str(key) in known]
        if not selected_keys:
            return api_error("请至少选择一个要恢复的模块", 400)
    auth_conflicts = _auth_backup_conflicts(payload)
    if "iptv_auth_backups" in selected_keys and auth_conflicts and not bool(data.get("overwrite_auth_backups", False)):
        return api_error(f"认证备份与本机接口快照冲突：{', '.join(auth_conflicts)}。请明确确认覆盖后再恢复。", 409)
    result = _restore_global_backup_payload(
        payload,
        selected_keys,
        overwrite_auth_backups=bool(data.get("overwrite_auth_backups", False)),
    )
    logger.info(f"全局备份导入完成：已恢复 {len(result['restored'])} 项，跳过 {len(result['skipped'])} 项")
    return api_success(result)


@app.post("/api/backup/disaster-export")
def api_disaster_backup_export():
    json_data = request.get_json(silent=True)
    data = json_data if isinstance(json_data, dict) else request.form.to_dict()
    confirmed = data.get("confirmed") is True if isinstance(json_data, dict) else str(data.get("confirmed") or "").strip().lower() in {"1", "true", "yes"}
    if not confirmed:
        return api_error("请在页面完成两次确认后再导出", 400)
    raw_modules = data.get("modules") if isinstance(json_data, dict) else request.form.getlist("modules")
    known_modules = {key for key, _ in _BACKUP_FILES} | {_CREDENTIAL_BACKUP_KEY, "pcap_archives"}
    if not isinstance(raw_modules, list):
        return api_error("modules 必须是数组", 400)
    selected_modules = [str(key) for key in raw_modules if str(key) in known_modules]
    if not selected_modules:
        return api_error("请至少选择一个要备份的模块", 400)
    include_pcaps = "pcap_archives" in selected_modules
    backup_modules = [key for key in selected_modules if key != "pcap_archives"]
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".iptv-disaster-", suffix=".zip", dir=str(DATA_DIR))
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        backup = _global_backup_payload(backup_modules)
        backup["_disaster_package_version"] = _DISASTER_BACKUP_VERSION
        backup["_selected_modules"] = selected_modules
        backup_bytes = json.dumps(backup, ensure_ascii=False, indent=2).encode("utf-8")
        deployment_bytes = json.dumps(
            _deployment_recovery_manifest(), ensure_ascii=False, indent=2,
        ).encode("utf-8")
        checksums: dict[str, str] = {}
        archive_files = []
        archive_dir = stb_discovery_service.archive_dir
        if include_pcaps and archive_dir:
            for path in sorted(Path(archive_dir).glob("stb-boot-*.pcap")):
                if path.is_file():
                    archive_files.append((f"pcaps/{path.name}", path))
                    manifest = Path(archive_dir) / f"{path.stem}.artifacts" / "manifest.json"
                    if manifest.is_file():
                        archive_files.append((f"metadata/{path.stem}.manifest.json", manifest))
        # Use the same limits before doing expensive compression and after writing.
        sizes = [("backup.json", len(backup_bytes)), ("deployment.json", len(deployment_bytes)),
                 ("README.txt", len(_disaster_readme()))] + [(n, p.stat().st_size) for n,p in archive_files]
        sizes.append(("CHECKSUMS.sha256", sum(67 + len(n.encode()) for n, _ in sizes)))
        infos = []
        for name, size in sizes:
            info = zipfile.ZipInfo(name)
            info.file_size = size
            infos.append(info)
        _check_disaster_limits(infos)
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            _zip_write_bytes(zf, "backup.json", backup_bytes, checksums)
            _zip_write_bytes(zf, "deployment.json", deployment_bytes, checksums)
            _zip_write_bytes(zf, "README.txt", _disaster_readme(), checksums)
            for name, path in archive_files:
                _zip_write_file(zf, name, path, checksums)
            checksum_body = "".join(
                f"{digest}  {name}\n" for name, digest in sorted(checksums.items())
            ).encode("utf-8")
            zf.writestr("CHECKSUMS.sha256", checksum_body)
            # Never hand out a package that this version cannot read back.
            _check_disaster_limits(zf.infolist())
        os.chmod(temp_path, 0o600)
        timestamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        size = temp_path.stat().st_size
        response = Response(
            _stream_private_temp_file(temp_path),
            mimetype="application/zip",
            direct_passthrough=True,
        )
        response.headers["Content-Disposition"] = (
            f'attachment; filename="iptv-sniffer-disaster-{timestamp}.zip"'
        )
        response.headers["Content-Length"] = str(size)
        response.headers["Cache-Control"] = "no-store, max-age=0"
        logger.warning(
            f"已导出迁移备份 ZIP：模块 {len(selected_modules)} 项，"
            f"明文凭据={'是' if _CREDENTIAL_BACKUP_KEY in selected_modules else '否'}，"
            f"原始 PCAP={'是' if include_pcaps else '否'}"
        )
        return response
    except ValueError as exc:
        temp_path.unlink(missing_ok=True)
        return api_error(str(exc), 400)
    except Exception as exc:
        temp_path.unlink(missing_ok=True)
        logger.warning(f"完整灾备包导出失败：{type(exc).__name__}")
        return api_error("完整灾备包导出失败，请检查数据目录空间与抓包文件权限", 500)


@app.post("/api/backup/disaster-import")
def api_disaster_backup_import():
    if str(request.form.get("confirmed") or "").strip().lower() not in {"1", "true", "yes"}:
        return api_error("请在页面完成两次确认后再恢复", 400)
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return api_error("请选择完整灾备 ZIP 文件", 400)
    if not str(upload.filename).lower().endswith(".zip"):
        return api_error("完整灾备文件必须是 ZIP 格式", 400)
    transaction = None
    try:
        upload.stream.seek(0)
        with zipfile.ZipFile(upload.stream, "r") as zf:
            payload, targets, checksums = _validate_disaster_zip(zf)
            archive_conflicts: list[str] = []
            archive_skipped: list[str] = []
            for member, target in targets.items():
                if not target.exists():
                    continue
                with target.open("rb") as existing:
                    existing_digest = _sha256_stream(existing)
                if existing_digest == checksums[member]:
                    archive_skipped.append(member)
                else:
                    archive_conflicts.append(member)
            if archive_conflicts:
                return api_error(
                    f"归档中已存在同名但内容不同的文件：{archive_conflicts[0]}。为避免覆盖原始抓包，已取消恢复。",
                    409,
                )
            auth_conflicts = _auth_backup_conflicts(payload)
            selected = [key for key, _ in _BACKUP_FILES if payload.get(key) is not None]
            if payload.get(_CREDENTIAL_BACKUP_KEY) is not None:
                selected.append(_CREDENTIAL_BACKUP_KEY)
            imported_archives: list[str] = []
            transaction = RestoreTransaction(DATA_DIR)
            for member, target in targets.items():
                if member in archive_skipped:
                    continue
                with zf.open(member) as content:
                    transaction.stage(target, content)
                imported_archives.append(member)
            result = _restore_global_backup_payload(
                payload, selected, overwrite_auth_backups=True, transaction=transaction,
            )
        result.update({
            "pcap_archives_restored": sum(name.startswith("pcaps/") for name in imported_archives),
            "protocol_manifests_restored": sum(name.startswith("metadata/") for name in imported_archives),
            "archive_files_skipped": len(archive_skipped),
            "auth_conflicts_overwritten": auth_conflicts,
            "network_restore_required": True,
        })
        result["warnings"].append(
            "完整灾备已恢复；宿主机网卡托管、IPTV DHCP 认证和路由仍需在新机器上按部署说明完成。"
        )
        logger.warning(
            f"完整灾备包恢复完成：模块 {len(result['restored'])} 项，"
            f"新归档 {len(imported_archives)} 个，已存在 {len(archive_skipped)} 个"
        )
        response = api_success(result)
        response.headers["Cache-Control"] = "no-store, max-age=0"
        return response
    except zipfile.BadZipFile:
        return api_error("无法读取 ZIP 文件，文件可能已损坏", 400)
    except ValueError as exc:
        return api_error(str(exc), 400)
    except Exception as exc:
        logger.warning(f"完整灾备包恢复失败：{type(exc).__name__}")
        return api_error("完整灾备包恢复失败，请检查数据目录空间与文件权限", 500)

    finally:
        if transaction and not (transaction.directory / "journal.json").exists():
            transaction.abort()


@app.post("/api/backup/clear-all")
def api_backup_clear_all():
    """Delete all locally persisted config/data files, resetting the app to a fresh state."""
    data = request.get_json(silent=True) or {}
    if data.get("confirmed") is not True:
        return api_error("请在页面完成两次确认后再清除", 400)
    cleared: list[str] = []
    for key, path in _BACKUP_FILES:
        try:
            if path.exists():
                path.unlink()
            cleared.append(key)
        except Exception as exc:
            logger.warning(f"清除配置失败：{key}: {exc}")
    epg_key_store.clear_epg_key()
    cleared.append("epg_local_key")
    operator_channel_store.invalidate()
    logger.info(f"本地配置已清除：{', '.join(cleared) or '无'}")
    return api_success({"cleared": cleared})


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
    full_capture = bool(data.get("full_capture"))
    if not stb_ip:
        return api_error("请填写机顶盒 IP 地址")
    if not valid_ip_or_host(stb_ip):
        return api_error("IP 地址格式不正确")
    rt = stb_discovery_service.runtime_check()
    if not rt["ok"]:
        return api_error("；".join(rt["errors"]), 500)
    try:
        stb_discovery_service.start(stb_ip, interface, full_capture=full_capture)
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


@app.post("/api/stb_discovery/reanalyze")
def api_stb_discovery_reanalyze():
    """Reparse the latest persisted PCAP without starting a new capture."""
    data = request.get_json(silent=True) or {}
    auth = token_store.load_auth_info()
    stb_ip = str(data.get("stb_ip") or auth.get("assigned_ip") or "").strip()
    if not stb_ip:
        return api_error("未找到机顶盒 IP，请提供 stb_ip 或先恢复机顶盒认证资料")
    if not valid_ip_or_host(stb_ip):
        return api_error("IP 地址格式不正确")
    try:
        return api_success(stb_discovery_service.reanalyze_latest_archive(stb_ip))
    except RuntimeError as exc:
        return api_error(str(exc), 400)
    except Exception as exc:
        logger.error(f"离线重解析 STB 抓包失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/stb_discovery/reset")
def api_stb_discovery_reset():
    stb_discovery_service.reset()
    return api_success(stb_discovery_service.status())


@app.get("/api/stb_discovery/pcap")
def api_stb_discovery_pcap():
    archive_name = str(request.args.get("archive") or "").strip()
    if archive_name:
        archived = stb_discovery_service.archive_path(archive_name)
        path = str(archived) if archived else ""
    else:
        path = stb_discovery_service.pcap_path()
    if not path and not archive_name:
        archived = stb_discovery_service.latest_archive_path()
        path = str(archived) if archived else ""
    if not path:
        return api_error("暂无可导出的 STB 抓包文件，请先完成一次 STB 开机捕获", 404)
    stopped_at = int(stb_discovery_service.status().get("stopped_at") or time.time())
    filename = Path(path).name or time.strftime("stb-boot-%Y%m%d-%H%M%S.pcap", time.localtime(stopped_at))
    return send_file(
        path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.tcpdump.pcap",
        max_age=0,
    )


@app.get("/api/stb_discovery/archives")
def api_stb_discovery_archives():
    return api_success({"archives": stb_discovery_service.list_archives()})


@app.delete("/api/stb_discovery/archives/<path:archive_name>")
def api_stb_discovery_archive_delete(archive_name: str):
    data = request.get_json(silent=True) or {}
    if data.get("confirmed") is not True:
        return api_error("请在页面完成两次确认后再删除", 400)
    try:
        result = stb_discovery_service.delete_archive(archive_name)
    except FileNotFoundError as exc:
        return api_error(str(exc), 404)
    logger.warning(
        f"已删除历史抓包 {result['name']}（{result['size']} 字节），"
        f"协议清单={'已删除' if result['artifacts_deleted'] else '无'}"
    )
    return api_success(result)


@app.get("/api/stb_discovery/archive-backup")
def api_stb_discovery_archive_backup():
    """Export a persisted raw PCAP as a portable local backup ZIP."""
    archive_name = str(request.args.get("archive") or "").strip()
    pcap_path = (
        stb_discovery_service.archive_path(archive_name)
        if archive_name else stb_discovery_service.latest_archive_path()
    )
    if not pcap_path:
        return api_error("暂无已归档的 STB 抓包文件", 404)
    archive_dir = pcap_path.parent
    manifest_path = archive_dir / f"{pcap_path.stem}.artifacts" / "manifest.json"
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(pcap_path, arcname=f"raw/{pcap_path.name}")
        if manifest_path.is_file():
            zf.write(manifest_path, arcname=f"metadata/{pcap_path.stem}.manifest.json")
        zf.writestr(
            "README.txt",
            "This archive contains a raw local STB PCAP. It may include IPTV authentication material. "
            "Store it privately and restore it only to a trusted local IPTV Sniffer Web deployment.\n",
        )
    bundle.seek(0)
    return send_file(
        bundle,
        as_attachment=True,
        download_name=f"{pcap_path.stem}-backup.zip",
        mimetype="application/zip",
        max_age=0,
    )


@app.post("/api/stb_discovery/import")
def api_stb_discovery_import():
    """Import channels discovered from the last STB boot capture."""
    state = stb_discovery_service.status()
    channels = state.get("channels") or []
    epg_creds = state.get("epg_creds") or {}
    if not channels and not epg_creds:
        return api_error("没有可导入的频道或认证资料，请先完成 STB 开机捕获")
    try:
        result = _do_operator_import(channels) if channels else {
            "imported": 0,
            "fcc_saved": 0,
            "channels_saved": 0,
        }
        current = settings_store.load()
        # Auto-populate timeshift_host if detected and not yet configured
        timeshift_host = str(state.get("timeshift_host") or "").strip()
        if timeshift_host and not str(current.get("timeshift_host") or "").strip():
            settings_store.save({"timeshift_host": timeshift_host})
            result["timeshift_host_detected"] = timeshift_host
            logger.info(f"自动检测到回看服务器地址：{timeshift_host}")
        # Auto-populate EPG credentials extracted from pcap (never overwrite existing values)
        epg_updates: dict[str, str] = {}
        epg_key_map = {
            "epg_user_id": "epg_user_id",
            "epg_stb_id": "epg_stb_id",
            "epg_auth_host": "epg_auth_host",
            "epg_user_agent": "epg_user_agent",
            "epg_stb_type": "epg_stb_type",
            "epg_stb_version": "epg_stb_version",
            "epg_software_version": "epg_software_version",
            "access_user_name": "epg_access_user_name",
            "epg_net_user_id": "epg_net_user_id",
            "epg_conn_type": "epg_conn_type",
            "epg_lang": "epg_lang",
        }
        for src_key, dst_key in epg_key_map.items():
            val = str(epg_creds.get(src_key) or "").strip()
            if val and not str(current.get(dst_key) or "").strip():
                epg_updates[dst_key] = val
        if epg_updates:
            settings_store.save(epg_updates)
            result["epg_creds_detected"] = epg_updates
            logger.info(
                "从抓包自动提取 EPG 认证字段："
                + "、".join(sorted(epg_updates))
            )
        portal_auth = state.get("portal_auth") or {}
        if portal_auth:
            result["portal_auth_detected"] = {
                "ctc_auth_info": bool(portal_auth.get("has_ctc_auth_info")),
                "upload_user_token": bool(portal_auth.get("has_upload_user_token")),
                "x_frame_session_id": bool(portal_auth.get("has_x_frame_session_id")),
                "portal_auth_host": str(portal_auth.get("portal_auth_host") or ""),
            }
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


@app.post("/api/channels/import-export")
def api_channels_import_export():
    """Import a previously exported M3U playlist or channels.json file."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    content = data.get("content")
    if not isinstance(content, str) or not content.strip():
        return api_error("请选择非空的频道列表文件")
    filename = str(data.get("filename") or "").strip()
    try:
        if filename.lower().endswith(".json"):
            rows, skipped = parse_exported_channels_json(json.loads(content))
            source_type = "JSON"
        else:
            rows, skipped = parse_exported_m3u_channels(content)
            source_type = "M3U"
    except json.JSONDecodeError:
        return api_error("频道列表 JSON 格式错误", 400)
    except ValueError as exc:
        return api_error(str(exc), 400)
    if not rows:
        return api_error("未找到可导入的 IPv4 组播频道；请使用本应用导出的 M3U 或 channels.json 文件", 400)
    result = channel_store.save_rows(rows)
    logger.info(f"已从导出的{source_type} 频道列表导入 {result['saved']} 条，跳过 {skipped} 条")
    return api_success({**result, "skipped": skipped, "source_type": source_type})


@app.post("/api/channels/<path:channel_key>/metadata")
def api_channels_patch_metadata(channel_key: str):
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    try:
        channel = channel_store.patch_metadata(channel_key, data)
        if not channel:
            return api_error("频道不存在", 404)
        logger.info(f"已编辑频道线路信息：{channel_key}")
        return api_success({"channel": channel})
    except ValueError as exc:
        return api_error(str(exc), 400)


@app.post("/api/channels/<path:channel_key>/metadata/restore")
def api_channels_restore_metadata(channel_key: str):
    data = request.get_json(silent=True) or {}
    source = str(data.get("source") or "").strip()
    if source not in {"original", "edited"}:
        return api_error("source 必须为 original 或 edited")
    try:
        channel = channel_store.restore_metadata(channel_key, source)
        if not channel:
            return api_error("频道不存在", 404)
        label = "原始识别" if source == "original" else "编辑"
        logger.info(f"已恢复频道线路{label}信息：{channel_key}")
        return api_success({"channel": channel})
    except ValueError as exc:
        return api_error(str(exc), 400)


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
        flask_base_url = request.url_root.rstrip("/")
        result = export_service.export_bundle(rows, settings, operator_channels=operator_channels, flask_base_url=flask_base_url)
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


@app.get("/api/download/bundles/<bundle>/<filename>")
def api_download_bundle(bundle, filename):
    if not re.fullmatch(r"[a-f0-9]{32}", bundle) or filename not in ALLOWED_DOWNLOADS:
        return api_error("不允许下载该文件", 404)
    return send_from_directory(OUTPUT_DIR / "bundles" / bundle, filename, as_attachment=True)




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
    hls_service.claim_waiter(hls_key)
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            if m3u8.exists() and m3u8.stat().st_size > 0:
                break
            time.sleep(0.25)
        if not m3u8.exists() or m3u8.stat().st_size == 0:
            hls_service.stop(hls_key)
            return api_error("HLS 流启动超时，请检查组播路由和 rtp2httpd 上游接口", 504)
    finally:
        hls_service.release_waiter(hls_key)
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
    hls_dir = hls_service.existing_directory(hls_key)
    if hls_dir is None:
        return ("", 404)
    seg_path = hls_dir / segment
    if not seg_path.is_file():
        return ("", 404)
    hls_service.touch(hls_key)
    resp = send_file(seg_path, mimetype="video/mp2t")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.get("/hls/<hls_key>/catchup")
def hls_catchup(hls_key: str):
    lease = media_tasks.acquire("catchup", hls_key)
    try:
        response = app.make_response(_hls_catchup_response(hls_key, lease))
        if response.status_code >= 400:
            lease.close()
        response.call_on_close(lease.close)
        return response
    except BaseException:
        lease.close()
        raise


def _hls_catchup_response(hls_key: str, lease):
    parsed = HlsService.parse_key(hls_key)
    if not parsed:
        return ("", 404)
    host, port = parsed
    if not valid_ipv4_multicast(host):
        return ("", 404)
    playseek = request.args.get("playseek", "").strip()
    if not valid_playseek(playseek):
        return api_error("playseek 需为有效且结束晚于开始的 UTC 时间段：YYYYMMDDHHmmss-YYYYMMDDHHmmss", 400)
    op_channels = operator_channel_store.load()
    ch_info = op_channels.get(f"{host}:{port}") or {}
    backtv = str(ch_info.get("backtv_url", "") or "").strip()
    if not backtv:
        return api_error("该频道无回看地址", 404)
    try:
        parts = urlsplit(backtv)
        if parts.scheme.lower() not in {"rtsp", "http", "https"} or not parts.hostname or any(c in backtv for c in "\r\n\x00"):
            raise ValueError()
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError()
    except ValueError:
        return api_error("回看地址仅支持有效的 RTSP／HTTP(S) 网络地址", 400)
    settings = settings_store.load()
    user_agent = str(settings.get("epg_user_agent") or "").strip()
    last_start_error = "回看上游未返回媒体数据"
    last_diagnostic = "rtsp_no_media"
    # HWCU's media server requires the STB's four MP2T transport alternatives
    # in one SETUP request plus a dynamic X-NAT_ADDRESS. FFmpeg emits separate
    # SETUP requests even for ``udp+tcp`` and receives 461. Try the compatible
    # control flow first, while retaining FFmpeg for other operator profiles.
    for url_mode, rtsp_url in _catchup_rtsp_candidates(backtv, playseek):
        if lease.cancel_requested:
            return api_error("回看任务已取消", 409)
        session = CombinedRtspUdpSession(rtsp_url, user_agent)
        lease.attach(session.close)
        try:
            first_chunk = session.open()
        except RtspCatchupError as exc:
            last_diagnostic = exc.category
            logger.warning(
                f"catchup combined-rtsp [{hls_key}] mode={url_mode} diagnostic={last_diagnostic}"
            )
            continue
        resp = Response(session.iter_payloads(first_chunk), mimetype="video/mp2t")
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    if shutil.which("ffmpeg") is None:
        return api_error("缺少 ffmpeg 命令，无法转换回看流", 503, catchup_diagnostic=last_diagnostic)
    for url_mode, rtsp_url in _catchup_rtsp_candidates(backtv, playseek):
        if lease.cancel_requested:
            return api_error("回看任务已取消", 409)
        # The captured STB SETUP advertises both UDP client ports and TCP
        # interleaving.  Offer the same combination first; forcing either
        # transport alone makes this platform return 461.  Keep FFmpeg's
        # default and single-transport modes as compatibility fallbacks.
        for transport in ("udp+tcp", "auto", "tcp", "udp"):
            if lease.cancel_requested:
                return api_error("回看任务已取消", 409)
            ffmpeg_command = [
                "ffmpeg", "-protocol_whitelist", "rtsp,rtp,udp,tcp,http,https,tls",
                "-rw_timeout", str(_CATCHUP_FFMPEG_READ_TIMEOUT_MICROSECONDS),
            ]
            # EPG authentication already uses the STB's captured User-Agent. Reuse
            # it for the subsequent RTSP request as some media servers apply the
            # same terminal-profile check to the playback connection.
            if user_agent:
                ffmpeg_command.extend(["-user_agent", user_agent])
            if transport != "auto":
                ffmpeg_command.extend(["-rtsp_transport", transport])
            ffmpeg_command.extend(["-i", rtsp_url, "-c", "copy", "-f", "mpegts", "pipe:1"])
            proc = subprocess.Popen(
                ffmpeg_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc._iptv_stderr = ProcessTail(proc.stderr)
            lease.attach(lambda proc=proc: _stop_catchup_ffmpeg(proc))
            first_chunk, start_error = _wait_for_catchup_first_chunk(proc)
            if not start_error:
                def generate():
                    try:
                        yield first_chunk
                        while True:
                            chunk = proc.stdout.read(65536)
                            if not chunk:
                                break
                            yield chunk
                    finally:
                        _stop_catchup_ffmpeg(proc)

                resp = Response(generate(), mimetype="video/mp2t")
                resp.headers["Access-Control-Allow-Origin"] = "*"
                resp.headers["Cache-Control"] = "no-cache"
                return resp

            stderr_out = _stop_catchup_ffmpeg(proc)
            last_start_error = start_error
            last_diagnostic = _catchup_failure_category(stderr_out, start_error)
            logger.warning(
                f"catchup ffmpeg [{hls_key}] mode={url_mode} transport={transport} "
                f"diagnostic={last_diagnostic}"
            )
            if last_diagnostic == "rtsp_transport_unsupported" and transport != "udp":
                continue
            break

    return api_error(last_start_error, 504, catchup_diagnostic=last_diagnostic)


def _merged_stb_auth_info() -> dict[str, Any]:
    """Overlay non-empty live capture fields on the persisted STB identity."""
    persisted = token_store.load_auth_info()
    live = stb_discovery_service.status().get("auth_info") or {}
    merged = dict(persisted) if isinstance(persisted, dict) else {}
    if isinstance(live, dict):
        merged.update({key: value for key, value in live.items() if value not in (None, "", [], {})})
    return merged


def _effective_stb_auth_info() -> dict[str, Any]:
    auth_info = _merged_stb_auth_info()
    # HWCU includes an IPTV-side address in its Authenticator.  A persisted
    # STB boot capture is valuable for the terminal identity, but its old
    # lease can no longer represent the current client.  Prefer the
    # active authenticated interface address whenever it is available.
    interface = str(settings_store.load().get("interface") or "").strip()
    if interface:
        try:
            snapshot = iptv_auth_service.snapshot(interface)
            for item in snapshot.get("ipv4") or []:
                current_ip = str(item.get("local") or "").strip()
                if current_ip.startswith("10."):
                    auth_info["assigned_ip"] = current_ip
                    break
        except Exception:
            pass
    return auth_info


def _catchup_refresh_interval_hours(settings: dict[str, Any]) -> int:
    try:
        hours = int(settings.get("catchup_auto_refresh_hours") or 12)
    except (TypeError, ValueError):
        hours = 12
    return min(max(hours, 1), 168)


def _catchup_auto_enabled(settings: dict[str, Any]) -> bool:
    return bool(settings.get("catchup_enabled")) and bool(settings.get("catchup_auto_refresh_enabled"))


def _next_catchup_run_locked(settings: dict[str, Any], now: int) -> int | None:
    catchup_scheduler.state = _catchup_auto_state
    return catchup_scheduler.next_run(settings, now)


def _catchup_refresh_status(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = settings or settings_store.load()
    interval_hours = _catchup_refresh_interval_hours(settings)
    auto_enabled = _catchup_auto_enabled(settings)
    now = int(time.time())
    with _catchup_refresh_lock:
        next_run_at = _next_catchup_run_locked(settings, now)
        state = dict(_catchup_auto_state)
    return {
        "enabled": auto_enabled,
        "interval_hours": interval_hours,
        "running": bool(state.get("running")),
        "last_run_at": state.get("last_run_at"),
        "last_success_at": state.get("last_success_at"),
        "next_run_at": next_run_at,
        "last_error": state.get("last_error") or "",
        "last_result": state.get("last_result") or None,
        "token_expires_at": state.get("token_expires_at"),
        "token_expiry_note": state.get("token_expiry_note") or "未暴露明确有效期",
    }


def _refresh_backtv_with_state(settings: dict[str, Any], source: str) -> dict[str, Any]:
    settings = _with_local_epg_key(settings)
    catchup_scheduler.state = _catchup_auto_state
    def refresh():
        interface = str(settings.get("interface") or "").strip()
        if interface and str(settings.get("epg_auth_host") or "").startswith("10."):
            snapshot = iptv_auth_service.snapshot(interface)
            if not any(str(item.get("local") or "").startswith("10.") for item in snapshot.get("ipv4") or []):
                raise ValueError(f"IPTV 接口 {interface} 尚未取得 IPTV 地址，请先在认证页执行一键认证")
        import copy
        op_channels = operator_channel_store.load()
        expected = copy.deepcopy(op_channels)
        result = refresh_backtv_urls(settings, op_channels, _effective_stb_auth_info(), logger)
        operator_channel_store.save_if_unchanged(expected, op_channels)
        return result
    return catchup_scheduler.run(settings, source, refresh, redact_sensitive_text)


def _start_catchup_auto_refresh_loop() -> None:
    catchup_scheduler.state = _catchup_auto_state
    catchup_scheduler.start(settings_store.load, _refresh_backtv_with_state, logger)


@app.post("/api/catchup/refresh")
def api_catchup_refresh():
    """Re-authenticate to EPG portal and refresh backtv_url tokens in operator_channels.json."""
    settings = _with_local_epg_key()
    # Allow caller to supply credentials directly (so user needn't save first)
    override = request.get_json(silent=True) or {}
    override_key = str(override.get("epg_des3_key") or "").strip() if isinstance(override, dict) else ""
    if override_key:
        epg_key_store.set_epg_key(override_key)
        settings["epg_des3_key"] = override_key
    for key in (
        "iptv_password",
        "epg_user_id",
        "epg_stb_id",
        "epg_des3_key",
        "epg_auth_host",
        "epg_auth_profile",
        "epg_crypto_mode",
        "epg_des_padding",
        "epg_stb_type",
        "epg_stb_version",
        "epg_software_version",
        "epg_user_agent",
        "epg_access_user_name",
        "epg_net_user_id",
        "epg_conn_type",
        "epg_lang",
    ):
        if override.get(key):
            settings[key] = override[key]
    try:
        result = _refresh_backtv_with_state(settings, source="manual")
    except (ValueError, RuntimeError) as exc:
        return api_error(redact_sensitive_text(str(exc)), 400)
    except Exception as exc:
        logger.error(f"EPG 回看地址刷新异常：{redact_sensitive_text(str(exc))}")
        return api_error("回看刷新发生内部错误，请查看服务日志", 500)
    logger.info(
        f"EPG 回看地址刷新：更新 {result['updated']} / {result['total']} 个频道，"
        f"EPG={result['epg_host']}，Profile={result.get('profile', 'auto')}"
    )
    return api_success(result)


@app.get("/api/catchup/refresh/status")
def api_catchup_refresh_status():
    return api_success(_catchup_refresh_status())


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
        op_channels = operator_channel_store.load()
        catchup_enabled = bool(settings.get("catchup_enabled", False))
        catchup_days = int(settings.get("catchup_days") or 7) if catchup_enabled else 0
        content = export_service.hls_m3u(
            channels,
            base_url,
            epg_url,
            op_channels,
            catchup_enabled=catchup_enabled,
            catchup_days=catchup_days,
        )
        resp = Response(
            content,
            mimetype="audio/x-mpegurl",
            headers={"Content-Disposition": 'attachment; filename="channels-fnos-hls.m3u"'},
        )
        return resp
    except Exception as exc:
        return api_error(str(exc))


@app.errorhandler(MediaCapacityError)
def media_capacity_error(exc):
    response = app.make_response(api_error(str(exc), 429))
    response.headers["Retry-After"] = "2"
    return response


@app.get("/api/media/tasks")
def api_media_tasks():
    return api_success(media_tasks.status())


@app.delete("/api/media/tasks/<task_id>")
def api_media_cancel(task_id):
    return api_success({"cancelled": media_tasks.cancel(task_id)})


@app.get("/api/snapshot/<host>/<int:port>")
def api_snapshot(host: str, port: int):
    if not valid_ipv4_multicast(host):
        return api_error("预览地址必须是 IPv4 组播地址", 400)
    if not 1 <= port <= 65535:
        return api_error("预览端口必须位于 1-65535", 400)
    if shutil.which("ffmpeg") is None:
        return api_error("缺少 ffmpeg 命令", 503)
    settings = settings_store.load()
    try:
        data = snapshot_service.get(host, port, str(settings.get("path_mode") or "rtp"), _iptv_local_ip(settings))
        return Response(data, mimetype="image/jpeg", headers={"Cache-Control": "max-age=30"})
    except subprocess.TimeoutExpired:
        return api_error("截图超时", 504)
    except ValueError as exc:
        return api_error(str(exc), 502)


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
    auth = _merged_stb_auth_info()
    if auth:
        token_store.save_auth_info(auth)
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
    # After a backup restore or service restart, the in-memory discovery
    # state is empty while playlist_token.json still has the captured DHCP
    # identity.  IPTV authentication must use that persisted record rather
    # than forcing another STB boot capture.
    return _merged_stb_auth_info()


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
        result = iptv_auth_service.apply(data, _latest_stb_auth_info())
        # Keep the successfully authenticated interface as the active IPTV
        # interface.  HWCU refresh then uses its current lease address rather
        # than falling back to the address in the historical STB capture.
        interface = str(result.get("interface") or "").strip()
        if interface:
            settings = settings_store.load()
            if settings.get("interface") != interface:
                settings["interface"] = interface
                settings_store.save(settings)
        return api_success(result)
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
    from services.rtp2httpd_config import parse_config
    return parse_config(text)


def _rtp2httpd_config_candidates(path_hint: str) -> list[Path]:
    candidates: list[str] = []
    if path_hint:
        candidates.append(path_hint)
    if DEFAULT_RTP2HTTPD_CONFIG_PATH:
        candidates.append(DEFAULT_RTP2HTTPD_CONFIG_PATH)
    candidates.extend([
        "/vol1/@appconf/rtp2httpd/rtp2httpd.conf",
        "/host/vol1/@appconf/rtp2httpd/rtp2httpd.conf",
        "/etc/rtp2httpd.conf",
        "/host/etc/rtp2httpd.conf",
        "/etc/rtp2httpd/rtp2httpd.conf",
        "/host/etc/rtp2httpd/rtp2httpd.conf",
        "/config/rtp2httpd.conf",
        "/etc/config/rtp2httpd",
        "/host/etc/config/rtp2httpd",
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
            with path.open("rb") as handle:
                text = read_bounded(handle, 128_000).decode("utf-8", errors="replace")
            from services.rtp2httpd_config import effective_config
            parsed = effective_config(_parse_rtp2httpd_config_text(text))
            values = parsed["values"]
            if not values and not parsed["bind"]:
                return {
                    "ok": False,
                    "path": str(path),
                    "checked": checked,
                    "error": "已读取该文件但未解析出配置项，请确认它是 rtp2httpd 的 INI 或 OpenWrt UCI 配置",
                }
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
                "app_path_prefix": values.get("app-path-prefix", ""),
                "bind": parsed["bind"],
            }
        except Exception as exc:
            return {"ok": False, "path": str(path), "checked": checked, "error": str(exc)}
    return {"ok": None, "path": path_hint, "checked": checked, "error": "未找到可读取的 rtp2httpd 配置文件"}


def _diagnose_sections(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = ["rtp2httpd", "network", "auth", "wire", "igmp", "multicast", "media", "fcc", "rtsp", "player", "playlist"]
    names = {
        "wire": "线缆观测", "igmp": "IGMP 请求与发包", "media": "应用媒体接收",
        "rtsp": "回看链路", "player": "播放器验证",
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
    lease = media_tasks.acquire("diagnose")
    cancel_event = threading.Event()
    lease.cancel_callback = cancel_event.set
    try:
        return _run_diagnose(cancel_event)
    finally:
        lease.close()


def _run_diagnose(cancel_event=None):
    """Playback chain diagnostic: rtp2httpd reachability + FCC + config review."""
    data = request.get_json(silent=True) or {}
    settings = settings_store.load()
    http_host = str(data.get("http_host") or settings.get("http_host", "")).strip()
    http_port = int(data.get("http_port") or settings.get("http_port") or 5140)
    channel_addr = str(data.get("channel", "")).strip()  # "ip:port"
    config_path = str(data.get("config_path") or settings.get("rtp2httpd_config_path", "")).strip()
    iface = str(settings.get("interface", "")).strip()

    link = {}
    fcc_reachable = None
    checks: list[dict] = []
    conclusions: list[str] = []

    def add_check(layer: str, item: str, ok: bool | None, detail: str) -> None:
        checks.append({"layer": layer, "item": item, "ok": ok, "detail": detail})

    # --- Check 1: rtp2httpd reachability ---
    rtp2httpd_ok = False
    if http_host:
        cfg = _load_rtp2httpd_config(config_path)
        path_prefix = str(data.get("path_prefix") or settings.get("rtp2httpd_path_prefix") or cfg.get("app_path_prefix") or "").strip()
        try:
            path_prefix = ExportService.normalize_path_prefix(path_prefix)
        except ValueError:
            path_prefix = ""
        url = f"http://{http_host}:{http_port}{path_prefix}/status"
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
        status_url = f"http://{http_host}:{http_port}{path_prefix}{status_path or '/status'}"
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
                add_check("network", "播放上游与抓包接口", None, f"rtp2httpd upstream-interface={cfg.get('upstream_interface')}，抓包接口={iface}")
            elif cfg.get("upstream_interface") and iface:
                add_check("network", "播放上游与抓包接口", None, f"rtp2httpd upstream-interface={cfg.get('upstream_interface')}，抓包接口={iface}；抓包口与播放上游口可以不同，应分别验证可见流量和主动接收能力")
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
                fcc_reachable = True
                add_check("fcc", f"FCC 服务器端口可达 ({channel_addr})", True, f"TCP connect {fcc_ip}:{fcc_port} → 成功（注：仅验证端口可达，非 FCC 协议握手）")
            except Exception as exc:
                fcc_reachable = False
                add_check("fcc", f"FCC 服务器端口可达 ({channel_addr})", False, f"TCP connect {fcc_ip}:{fcc_port} → {exc}")
                conclusions.append("FCC TCP 端口连接失败；未验证 UDP／专有 FCC 协议，不能据此判断快速换台是否可用。")
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
                if cancel_event and cancel_event.is_set():
                    return api_error("诊断已取消", 409)
                link = capture_service.diagnose_multicast(mc_host, mc_port, str(settings.get("media_interface") or iface), cancel_event=cancel_event, capture_interface=iface)
                igmp_detail = "已向内核请求加入组播" if link.get("join_requested") else "未完成加入组播请求"
                add_check(
                    "multicast",
                    f"IGMP 组播加入 ({channel_addr})",
                    bool(link.get("join_requested")),
                    f"接口 {link.get('interface')}（{link.get('interface_ip') or '自动'}）→ {igmp_detail}",
                )
                verdict_code = link.get("verdict")
                udp_detail = (f"主动加入后收到 UDP 包：socket={link.get('socket_active_packets')} "
                              f"/ 线缆={link.get('wire_active_packets')}；"
                              f"未加入时线缆收到={link.get('wire_passive_packets')}")
                if verdict_code == "ok":
                    add_check("multicast", f"收到 239.x UDP 组播流 ({channel_addr})", True, udp_detail)
                elif verdict_code in {"wire_only", "mirror"}:
                    add_check("multicast", f"收到 239.x UDP 组播流 ({channel_addr})", False, udp_detail + " → 疑似镜像口（SPAN）")
                    conclusions.append("线缆可见流量但应用 socket 未收到；镜像口、选路、接口或过滤规则均可能导致，请分别核查。")
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

    checks.extend(playback_evidence(link, fcc_reachable))
    verdict = diagnostic_verdict(checks)

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
    _start_catchup_auto_refresh_loop()
    _start_version_check_loop()
    logger.info(f"数据目录：{DATA_DIR}")
    logger.info(f"输出目录：{OUTPUT_DIR}")
    import signal
    def shutdown(*_args):
        iptv_auth_service.stop_egress_bpf_watchdog()
        stb_discovery_service.reset()
        epg_service.shutdown()
        catchup_scheduler.shutdown()
        hls_service.shutdown()
        media_tasks.shutdown()
        raise SystemExit(0)
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, shutdown)
    try:
        serve(app, host=WEB_HOST, port=WEB_PORT, threads=WAITRESS_THREADS)
    finally:
        iptv_auth_service.stop_egress_bpf_watchdog()
        stb_discovery_service.reset()
        epg_service.shutdown()
        catchup_scheduler.shutdown()
        hls_service.shutdown()
        media_tasks.shutdown()


if __name__ == "__main__":
    boot()
