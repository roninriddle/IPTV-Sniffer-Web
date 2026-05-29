#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPTV Sniffer Web application entrypoint."""
from __future__ import annotations

import gzip
import zlib
import json
import re
import shutil
import subprocess
import time
import threading
from pathlib import Path
from typing import Any
from urllib.error import URLError
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
    VERSION_CHECK_INTERVAL,
    CHANNELS_FILE,
    DATA_DIR,
    DISCOVERY_FILE,
    EPG_CACHE_FILE,
    EPG_SOURCES,
    FCC_FILE,
    LOGO_SOURCES,
    LOG_FILE,
    LOG_MEMORY_LIMIT,
    MIN_PACKET_COUNT,
    OUTPUT_DIR,
    SETTINGS_FILE,
    STB_TOKEN_FILE,
    CUSTOM_SOURCES_FILE,
    OPERATOR_CHANNELS_FILE,
    SNAPSHOTS_FILE,
    WAITRESS_THREADS,
    WEB_HOST,
    WEB_PORT,
)
from services.capture_service import CaptureService
from services.epg_service import EpgService, normalize_channel_name
from services.export_service import ExportService
from services.log_service import AppLogger
from services.probe_service import ProbeService
from services.schedule_service import ScheduleService
from services.stb_discovery_service import StbDiscoveryService
from services.storage_service import ChannelSnapshotStore, ChannelStore, CustomSourcesStore, DiscoveryStore, FccStore, OperatorChannelStore, SettingsStore, StbTokenStore
from utils import channel_group_key, channel_primary_score, classify_channel_name, natural_key, resolution_label_from_size, stream_filter_reason, stream_quality_group, valid_ip_or_host, valid_ipv4_multicast

app = Flask(__name__)
logger = AppLogger(LOG_FILE, LOG_MEMORY_LIMIT)
settings_store = SettingsStore(SETTINGS_FILE)
channel_store = ChannelStore(CHANNELS_FILE)
fcc_store = FccStore(FCC_FILE)
custom_sources_store = CustomSourcesStore(CUSTOM_SOURCES_FILE)
operator_channel_store = OperatorChannelStore(OPERATOR_CHANNELS_FILE)
snapshot_store = ChannelSnapshotStore(SNAPSHOTS_FILE)
stb_discovery_service = StbDiscoveryService(logger)
token_store = StbTokenStore(STB_TOKEN_FILE)
discovery_store = DiscoveryStore(DISCOVERY_FILE)
capture_service = CaptureService(logger, fcc_store, token_store, discovery_store)
export_service = ExportService(OUTPUT_DIR)
probe_service = ProbeService(logger)
epg_service = EpgService(logger, EPG_CACHE_FILE)
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
_epg_detect_lock = threading.RLock()
_epg_detect_state: dict[str, Any] = {"status": "idle", "best_url": "", "best_name": "", "best_channels": 0, "checked_at": None}


def _count_epg_channels(url: str, timeout: int = 20) -> int:
    req = Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read(4 * 1024 * 1024)
    if url.lower().endswith(".gz") or raw[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(zlib.MAX_WBITS | 16)
        try:
            raw = d.decompress(raw) + d.flush()
        except zlib.error:
            raw = b""
    return raw.count(b"<channel ")


def _do_epg_detect_best(sources: list[dict[str, Any]]) -> None:
    with _epg_detect_lock:
        _epg_detect_state["status"] = "detecting"
    results: list[tuple[int, str, str]] = []
    for src in sources:
        try:
            count = _count_epg_channels(src["url"])
            results.append((count, src["url"], src["name"]))
            logger.info(f"EPG 源检测：{src['name']} → {count} 个频道")
        except Exception as exc:
            logger.warning(f"EPG 源检测失败：{src['name']}，{exc}")
    with _epg_detect_lock:
        if results:
            best = max(results, key=lambda x: x[0])
            _epg_detect_state.update({"status": "done", "best_url": best[1], "best_name": best[2], "best_channels": best[0], "checked_at": int(time.time())})
            logger.info(f"EPG 最佳来源：{best[2]}（{best[0]} 频道）")
        else:
            _epg_detect_state.update({"status": "error", "checked_at": int(time.time())})


auto_probe_lock = threading.RLock()
auto_probe_pending: set[str] = set()
auto_probe_done: set[str] = set()
auto_enrichment_started = False
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
    current_matches_epg = (
        bool(current_name)
        and bool(epg_name)
        and normalize_channel_name(current_name) == normalize_channel_name(epg_name)
    )
    if allow_epg_name and epg_name and (not current_name or current_name == auto_name or current_matches_epg):
        if current_name and not auto_name:
            item["auto_name"] = current_name
            item["auto_name_source"] = str(item.get("auto_name_source") or "auto")
        item["name"] = epg_name
        item["category"] = classify_channel_name(epg_name)
        current_name = epg_name
    if not current_name and auto_name:
        item["name"] = auto_name
    return item


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
    return not saved_name or saved_name in auto_names or saved_matches_epg


def persist_auto_channel_if_changed(item: dict[str, Any], stored: dict[str, Any], settings: dict[str, Any]) -> None:
    if not str(item.get("name", "")).strip():
        return
    if not (item.get("auto_name") or item.get("detected_name") or item.get("tvg_name")):
        return
    keys = ("name", "category", "probe_status", "codec_name", "width", "height", "tvg_id", "tvg_name", "tvg_logo")
    changed = not stored or any(str(item.get(key, "")) != str(stored.get(key, "")) for key in keys)
    if changed:
        channel_store.save_rows(enrich_channel_rows([item], settings))


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
        # If actual dimensions are known, always recompute quality_group from them
        # (prevents stale is_hd-derived group from hiding 4K channels)
        cur_qg = str(item.get("quality_group", "")).strip()
        w, h = item.get("width"), item.get("height")
        if w and h:
            item["quality_group"] = stream_quality_group(w, h)
            item["resolution_label"] = resolution_label_from_size(w, h)
        elif (not cur_qg or cur_qg == "未识别") and "is_hd" in item:
            item["quality_group"] = "高清频道" if item["is_hd"] else "普通频道"
        # Pull is_hd from operator channel table if missing
        if op_ch and "is_hd" in op_ch and "is_hd" not in item:
            item["is_hd"] = op_ch["is_hd"]
            if not (w and h) and (not cur_qg or cur_qg == "未识别"):
                item["quality_group"] = "高清频道" if op_ch["is_hd"] else "普通频道"
        if settings.get("auto_epg", True):
            epg_service.enrich_item(item, str(settings.get("epg_url", "")), only_missing=True)
            fill_channel_name_from_metadata(item, allow_epg_name=can_replace_with_epg_name(row, item))
        enriched.append(item)
    return enriched


def maybe_auto_probe(item: dict[str, Any], settings: dict[str, Any]) -> None:
    if not settings.get("auto_probe", True):
        return
    if item.get("filter_reason") or not item.get("eligible"):
        return
    if str(item.get("probe_status", "not_probed")) in {"ok", "partial", "failed"}:
        return
    key = str(item.get("key", "")).strip()
    host = str(item.get("host", "")).strip()
    port = _safe_int(item.get("port"))
    if not key or not valid_ipv4_multicast(host) or not 1 <= port <= 65535:
        return
    with auto_probe_lock:
        if key in auto_probe_pending or key in auto_probe_done:
            return
        if len(auto_probe_pending) >= 2:
            return
        auto_probe_pending.add(key)
    path_mode = str(settings.get("path_mode", "rtp"))
    snapshot = dict(item)

    def worker() -> None:
        try:
            logger.info(f"自动识别流信息：{key}")
            result = probe_service.probe(key, host, port, path_mode)
            stored = channel_store.get(key) or {}
            detected_name = str(result.get("detected_name", "")).strip()
            snapshot_name = str(snapshot.get("name", "")).strip() or detected_name
            if snapshot_name and not str(stored.get("name", "")).strip():
                _snap_cat = classify_channel_name(snapshot_name)
                stored.update({
                    "key": key,
                    "host": host,
                    "port": port,
                    "name": snapshot_name,
                    "category": _snap_cat if _snap_cat != "其它频道" else (str(snapshot.get("category", "")) or "其它频道"),
                    "auto_name": str(snapshot.get("auto_name", "")) or detected_name,
                    "auto_name_source": str(snapshot.get("auto_name_source", "")) or str(result.get("detected_name_source", "")),
                    "packets": _safe_int(snapshot.get("packets")),
                })
            stored.update(result)
            stored = fill_channel_name_from_metadata(stored, allow_epg_name=can_replace_with_epg_name(channel_store.get(key) or {}, stored))
            if str(stored.get("name", "")).strip():
                channel_store.save_rows(enrich_channel_rows([stored], settings))
        except Exception as exc:
            logger.warning(f"自动识别流信息失败：{key}，{exc}")
        finally:
            with auto_probe_lock:
                auto_probe_pending.discard(key)
                auto_probe_done.add(key)

    threading.Thread(target=worker, daemon=True).start()


def merge_streams_with_channels() -> list[dict[str, Any]]:
    streams = capture_service.streams()
    named = channel_store.load()
    fcc_records = fcc_store.load()
    discovered = discovery_store.load()
    settings = settings_store.load()
    payload: list[dict[str, Any]] = []
    for stream in streams:
        channel = named.get(stream["key"], {})
        discovery = discovered.get(stream["key"], {})
        filter_reason = stream_filter_reason(
            str(stream.get("host", "")),
            int(stream.get("port", 0)),
            int(stream.get("packets", 0)),
            MIN_PACKET_COUNT,
        )
        if filter_reason and not str(channel.get("name") or discovery.get("name") or "").strip():
            continue
        item = dict(stream)
        item["filter_reason"] = filter_reason
        auto_name = str(channel.get("auto_name") or discovery.get("name") or "").strip()
        item["auto_name"] = auto_name
        item["auto_name_source"] = str(channel.get("auto_name_source") or discovery.get("source") or "").strip()
        item["name"] = str(channel.get("name") or auto_name or "").strip()
        item.update(probe_service.merge_probe_data(stream["key"], channel))
        if not item["auto_name"] and item.get("detected_name"):
            item["auto_name"] = str(item.get("detected_name", "")).strip()
            item["auto_name_source"] = str(item.get("detected_name_source", "ffprobe_service_name")).strip()
        fill_channel_name_from_metadata(item, allow_epg_name=False)
        item["tvg_id"] = str(channel.get("tvg_id", ""))
        item["tvg_name"] = str(channel.get("tvg_name", ""))
        item["tvg_logo"] = str(channel.get("tvg_logo", ""))
        item["epg_source"] = str(channel.get("epg_source", ""))
        item["epg_matched_at"] = channel.get("epg_matched_at")
        if settings.get("auto_epg", True):
            epg_service.enrich_item(item, str(settings.get("epg_url", "")), only_missing=True)
            fill_channel_name_from_metadata(item, allow_epg_name=can_replace_with_epg_name(channel, item))
        _auto_cat = classify_channel_name(str(item.get("name", "")))
        item["category"] = _auto_cat if _auto_cat != "其它频道" else (channel.get("category") or "其它频道")
        fcc = dict(fcc_records.get(stream["key"], {}))
        if channel.get("fcc_ip"):
            fcc.update({"fcc_ip": channel.get("fcc_ip"), "fcc_port": channel.get("fcc_port")})
        item["fcc_ip"] = str(fcc.get("fcc_ip", ""))
        item["fcc_port"] = fcc.get("fcc_port")
        item["fec_port"] = channel.get("fec_port")
        if not str(item.get("name", "")).strip() and str(item.get("probe_status", "")) == "failed":
            continue
        _fcc_type = str(settings.get("fcc_type", "") or "").strip()
        item["preview_url"] = export_service.make_http_url(
            str(settings.get("http_host", "")),
            int(settings.get("http_port", 5140)),
            str(settings.get("path_mode", "rtp")),
            str(item["host"]),
            int(item["port"]),
            item["fcc_ip"],
            item["fcc_port"],
            item["fec_port"],
            _fcc_type,
        ) if settings.get("http_host") else ""
        item["snapshot_url"] = f"/api/snapshot/{item['host']}/{item['port']}" if item.get("eligible") else ""
        item["player_url"] = (
            f"http://{settings.get('http_host')}:{int(settings.get('http_port', 5140))}/player"
            if settings.get("http_host") else ""
        )
        persist_auto_channel_if_changed(item, channel, settings)
        maybe_auto_probe(item, settings)
        payload.append(item)
    return payload


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


def refresh_all_epg_sources_task(settings: dict[str, Any]) -> dict[str, Any]:
    custom = custom_sources_store.load()
    deleted_epg = set((custom.get("deleted_builtin") or {}).get("epg") or [])
    deleted_logo = set((custom.get("deleted_builtin") or {}).get("logo") or [])
    active_epg = [s for s in EPG_SOURCES if s["id"] not in deleted_epg] + (custom.get("epg") or [])
    active_logo = [s for s in LOGO_SOURCES if s["id"] not in deleted_logo] + (custom.get("logo") or [])
    if not active_epg:
        raise ValueError("没有配置 EPG 来源")
    results = []
    errors = []
    for source in active_epg:
        url = source.get("url", "")
        name = source.get("name", url)
        try:
            status = epg_service.refresh(url)
            results.append({"name": name, "url": url, "channels": status.get("channels", 0)})
        except Exception as exc:
            errors.append({"name": name, "url": url, "error": str(exc)})
    logo_results = []
    for source in active_logo:
        url = source.get("url", "")
        name = source.get("name", url)
        try:
            count = epg_service.refresh_logo(url)
            logo_results.append({"name": name, "url": url, "logos": count})
        except Exception as exc:
            errors.append({"name": name, "url": url, "error": str(exc)})
    total = sum(r.get("channels", 0) for r in results)
    total_logos = sum(r.get("logos", 0) for r in logo_results)
    return {
        "count": len(results),
        "total_channels": total,
        "sources": results,
        "logo_sources": logo_results,
        "total_logos": total_logos,
        "errors": errors,
    }


def start_auto_enrichment_loop() -> None:
    global auto_enrichment_started
    if auto_enrichment_started:
        return
    auto_enrichment_started = True

    def worker() -> None:
        while True:
            try:
                merge_streams_with_channels()
            except Exception as exc:
                logger.warning(f"自动补全后台任务异常：{exc}")
            capturing = capture_service.status().get("state") == "running"
            time.sleep(5 if capturing else 15)

    threading.Thread(target=worker, daemon=True).start()


schedule_service = ScheduleService(logger, settings_store, refresh_all_epg_sources_task)


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
    probe_runtime = probe_service.runtime_check()
    all_ok = capture_runtime.get("ok") and probe_runtime.get("ok")
    status_code = 200 if all_ok else 503
    payload = {
        "status": "ok" if all_ok else "degraded",
        "version": APP_VERSION,
        "uptime_seconds": int(time.time() - STARTED_AT),
        "runtime": capture_runtime,
        "probe_runtime": probe_runtime,
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
        "probe_runtime": probe_service.runtime_check(),
        "logs": logger.stats(),
        "schedule": schedule_service.status(),
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


def _parse_uci_network(text: str) -> dict[str, dict[str, str]]:
    interfaces: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("config interface"):
            m = re.match(r"config interface\s+['\"]?(\w+)['\"]?", line)
            if m:
                current = m.group(1)
                interfaces[current] = {}
        elif line.startswith("option ") and current is not None:
            m = re.match(r"option\s+(\w+)\s+['\"]?(.*?)['\"]?\s*$", line)
            if m:
                interfaces[current][m.group(1)] = m.group(2)
    return interfaces


def _analyze_uci_interfaces(ifaces: dict[str, dict[str, str]]) -> dict[str, Any]:
    def _dev(d: dict) -> str:
        return str(d.get("device") or d.get("ifname") or "").strip()

    lan_dev = _dev(ifaces.get("lan", {}))
    wan_dev = _dev(ifaces.get("wan", {}))
    sniff_cfg = ifaces.get("iptv_sniff", {})
    sniff_dev = _dev(sniff_cfg)
    sniff_proto = str(sniff_cfg.get("proto", "")).strip()
    iptv_configured = bool(sniff_dev == "eth0" and sniff_proto == "none")
    wan_occupies_eth0 = wan_dev == "eth0" and not iptv_configured
    is_r4s = lan_dev == "eth1" and (wan_dev == "eth0" or iptv_configured)
    if iptv_configured:
        status = "configured"
        message = "检测到 iptv_sniff 接口（eth0，proto=none），已满足被动抓包要求。"
    elif wan_occupies_eth0:
        status = "needs_setup"
        message = "LAN 管理口：eth1，WAN 当前占用 eth0，需释放 eth0 并创建 iptv_sniff 抓包接口。"
    elif lan_dev:
        status = "unknown"
        message = f"LAN 管理口：{lan_dev}，WAN：{wan_dev or '未知'}。无法自动判断是否适合抓包，请手动确认。"
    else:
        status = "unknown"
        message = "未能识别标准 LAN/WAN 接口定义，请手动确认配置。"
    return {
        "lan_device": lan_dev,
        "wan_device": wan_dev,
        "iptv_sniff_device": sniff_dev,
        "iptv_configured": iptv_configured,
        "wan_occupies_eth0": wan_occupies_eth0,
        "is_r4s": is_r4s,
        "status": status,
        "message": message,
        "recommended_capture_iface": "eth0" if (is_r4s or iptv_configured) else "",
        "all_interfaces": list(ifaces.keys()),
    }


@app.get("/api/openwrt/network-analysis")
def api_openwrt_network_analysis():
    host_cfg = Path("/host/etc/config/network")
    if not host_cfg.exists():
        return api_success({
            "available": False,
            "reason": "未检测到 /host/etc/config/network（容器未挂载宿主机网络配置，或不是 OpenWrt 宿主机）",
        })
    try:
        text = host_cfg.read_text(encoding="utf-8", errors="replace")
        ifaces = _parse_uci_network(text)
        result = _analyze_uci_interfaces(ifaces)
        result["available"] = True
        return api_success(result)
    except Exception as exc:
        logger.warning(f"解析 OpenWrt 网络配置失败：{exc}")
        return api_error(str(exc), 500)


@app.get("/api/openwrt/generate-script")
def api_openwrt_generate_script():
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup_path = f"/etc/config/network.backup-iptv-sniffer-{ts}"
    script = f"""#!/bin/sh
# IPTV Sniffer Web — R4S 被动抓包配置脚本
# 生成时间：{ts}
# 说明：将 eth0 从 WAN 释放，改为 IPTV 被动抓包接口（proto=none）
# 被动抓包不需要 IP、不配置防火墙、不配置 VLAN、不做路由转发。

set -e

# 1. 备份当前配置
cp /etc/config/network {backup_path}
echo "已备份：{backup_path}"

# 2. 删除 WAN 对 eth0 的占用
uci -q delete network.wan  || true
uci -q delete network.wan6 || true

# 3. 创建 IPTV 被动抓包接口
uci -q delete network.iptv_sniff || true
uci set network.iptv_sniff='interface'
uci set network.iptv_sniff.proto='none'
uci set network.iptv_sniff.device='eth0'

# 4. 提交并重启网络
uci commit network
/etc/init.d/network restart

echo ""
echo "完成！eth0 现在是 IPTV 被动抓包接口。"
echo "回滚命令："
echo "  cp {backup_path} /etc/config/network && /etc/init.d/network restart"
"""
    rollback = f"cp {backup_path} /etc/config/network && /etc/init.d/network restart"
    return api_success({"script": script, "rollback": rollback, "timestamp": ts})


@app.get("/api/settings")
def api_settings_get():
    return api_success(settings_store.load())


@app.post("/api/settings")
def api_settings_save():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    saved = settings_store.save(data)
    epg_url = str(saved.get("epg_url", "")).strip()
    logo_url = str(saved.get("logo_url", "")).strip()
    epg_status = epg_service.status(summary=True)
    if (
        saved.get("auto_epg", True)
        and epg_url
        and not epg_status.get("refreshing")
        and (
            epg_status.get("url") != epg_url
            or epg_status.get("logo_url") != logo_url
            or int(epg_status.get("channels") or 0) == 0
        )
    ):
        epg_service.refresh_async(epg_url, logo_url)
        _start_extra_epg_refresh(skip_url=epg_url)
    logger.info("已保存网页默认设置")
    return api_success(saved)


@app.get("/api/schedule")
def api_schedule_get():
    return api_success(schedule_service.status())


@app.post("/api/schedule")
def api_schedule_save():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    try:
        return api_success(schedule_service.configure(data))
    except ValueError as exc:
        return api_error(str(exc), 400)
    except Exception as exc:
        logger.error(f"保存定时任务失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/schedule/run-now")
def api_schedule_run_now():
    try:
        return api_success(schedule_service.run_now())
    except ValueError as exc:
        return api_error(str(exc), 400)
    except RuntimeError as exc:
        return api_error(str(exc), 409)
    except Exception as exc:
        logger.error(f"立即更新 EPG 清单失败：{exc}")
        return api_error(str(exc), 500)


@app.get("/api/status")
def api_status():
    return api_success(capture_service.status())


@app.post("/api/capture/start")
def api_capture_start():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    try:
        settings_store.save(data)
        with auto_probe_lock:
            auto_probe_pending.clear()
            auto_probe_done.clear()
        status = capture_service.start(data)
        return api_success(status)
    except ValueError as exc:
        return api_error(str(exc), 400)
    except RuntimeError as exc:
        return api_error(str(exc), 409)
    except Exception as exc:
        logger.error(f"启动抓包失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/capture/stop")
def api_capture_stop():
    try:
        return api_success(capture_service.stop())
    except Exception as exc:
        logger.error(f"停止抓包失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/capture/reset")
def api_capture_reset():
    try:
        with auto_probe_lock:
            auto_probe_pending.clear()
            auto_probe_done.clear()
        return api_success(capture_service.reset())
    except RuntimeError as exc:
        return api_error(str(exc), 409)
    except Exception as exc:
        logger.error(f"重置抓包状态失败：{exc}")
        return api_error(str(exc), 500)


@app.get("/api/streams")
def api_streams():
    return api_success({"streams": merge_streams_with_channels()})


@app.get("/api/channels")
def api_channels():
    return api_success({"channels": channel_store.list()})


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


@app.get("/api/epg/sources")
def api_epg_sources():
    custom = custom_sources_store.load()
    deleted = custom.get("deleted_builtin", {})
    deleted_epg = set(deleted.get("epg") or [])
    deleted_logo = set(deleted.get("logo") or [])
    epg_sources = [{**s, "builtin": True} for s in EPG_SOURCES if s["id"] not in deleted_epg] + custom.get("epg", [])
    logo_sources = [{**s, "builtin": True} for s in LOGO_SOURCES if s["id"] not in deleted_logo] + custom.get("logo", [])
    all_epg = [{**s, "builtin": True, "deleted": s["id"] in deleted_epg} for s in EPG_SOURCES] + custom.get("epg", [])
    all_logo = [{**s, "builtin": True, "deleted": s["id"] in deleted_logo} for s in LOGO_SOURCES] + custom.get("logo", [])
    return api_success({"epg_sources": epg_sources, "logo_sources": logo_sources, "all_epg_sources": all_epg, "all_logo_sources": all_logo})


@app.get("/api/sources/custom")
def api_sources_custom_get():
    return api_success(custom_sources_store.load())


@app.post("/api/sources/custom")
def api_sources_custom_add():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    try:
        entry = custom_sources_store.add(str(data.get("type", "")), str(data.get("name", "")), str(data.get("url", "")))
        return api_success(entry)
    except ValueError as exc:
        return api_error(str(exc), 400)


@app.delete("/api/sources/custom/<source_type>/<source_id>")
def api_sources_custom_delete(source_type: str, source_id: str):
    if custom_sources_store.delete(source_type, source_id):
        return api_success()
    return api_error("未找到该来源", 404)


@app.delete("/api/sources/builtin/<source_type>/<source_id>")
def api_sources_builtin_delete(source_type: str, source_id: str):
    if custom_sources_store.delete_builtin(source_type, source_id):
        return api_success()
    return api_error("来源类型不正确", 400)


@app.post("/api/sources/builtin/<source_type>/<source_id>/restore")
def api_sources_builtin_restore(source_type: str, source_id: str):
    if custom_sources_store.restore_builtin(source_type, source_id):
        return api_success()
    return api_error("未找到该内置来源记录", 404)


@app.post("/api/epg/detect-best")
def api_epg_detect_best():
    with _epg_detect_lock:
        current = dict(_epg_detect_state)
    if current["status"] == "detecting":
        return api_success(current)
    custom = custom_sources_store.load()
    deleted_epg = set((custom.get("deleted_builtin") or {}).get("epg") or [])
    active_builtin = [s for s in EPG_SOURCES if s["id"] not in deleted_epg]
    all_sources = active_builtin + custom.get("epg", [])
    threading.Thread(target=_do_epg_detect_best, args=(all_sources,), daemon=True).start()
    with _epg_detect_lock:
        _epg_detect_state["status"] = "detecting"
    return api_success({"status": "detecting"})


@app.get("/api/epg/detect-best")
def api_epg_detect_best_status():
    with _epg_detect_lock:
        return api_success(dict(_epg_detect_state))


def _all_epg_urls() -> list[str]:
    """Return all configured EPG URLs: built-in + custom."""
    custom = custom_sources_store.load()
    urls = [s["url"] for s in EPG_SOURCES]
    urls += [s["url"] for s in (custom.get("epg") or []) if s.get("url")]
    seen: set[str] = set()
    result = []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            result.append(u)
    return result


def _start_extra_epg_refresh(skip_url: str = "") -> None:
    """Fetch all EPG sources other than skip_url into the merged index, in background."""
    extra = [u for u in _all_epg_urls() if u != skip_url]
    if not extra:
        return

    def worker() -> None:
        for u in extra:
            try:
                epg_service.refresh(u)
            except Exception as exc:
                logger.warning(f"附加 EPG 来源刷新失败：{u}，{exc}")

    threading.Thread(target=worker, daemon=True).start()


@app.post("/api/epg/refresh")
def api_epg_refresh():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    settings = settings_store.load()
    url = str(data.get("epg_url") or settings.get("epg_url", "")).strip()
    logo_url = str(data.get("logo_url") or settings.get("logo_url", "")).strip()
    if not url:
        return api_error("EPG 地址不能为空")
    settings_store.save({
        "epg_url": url,
        "logo_url": logo_url,
        "auto_epg": bool(data.get("auto_epg", settings.get("auto_epg", True))),
    })
    try:
        status = epg_service.refresh_async(url, logo_url)
        logger.info(f"已启动 EPG 刷新：{url}")
        # Also refresh all other configured EPG sources in background so match() covers all
        _start_extra_epg_refresh(skip_url=url)
        return api_success(status)
    except ValueError as exc:
        return api_error(str(exc), 400)
    except Exception as exc:
        logger.error(f"启动 EPG 刷新失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/epg/refresh-all")
def api_epg_refresh_all():
    try:
        result = refresh_all_epg_sources_task(settings_store.load())
        logger.info(f"已触发全量 EPG 来源刷新：{result.get('count', 0)} 个来源")
        return api_success(result)
    except Exception as exc:
        logger.error(f"全量 EPG 刷新失败：{exc}")
        return api_error(str(exc), 500)


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
    rows = [
        {
            "key": f"{ch['ip']}:{ch['port']}",
            "host": ch["ip"],
            "port": ch["port"],
            "name": ch.get("name", ""),
            "category": classify_channel_name(ch.get("name", "")),
            "packets": 0,
            "fcc_ip": ch.get("fcc_ip", ""),
            "fcc_port": ch.get("fcc_port"),
            "fec_port": ch.get("fec_port"),
            "is_hd": ch.get("is_hd", False),
        }
        for ch in channels
        if ch.get("ip") and ch.get("port") and ch.get("name")
    ]
    enriched = enrich_channel_rows(rows, settings)
    # Only save rows that don't already have a user-modified name
    existing = channel_store.load()
    to_save = []
    for row in enriched:
        key = str(row.get("key", ""))
        stored = existing.get(key)
        # Skip if user has manually set a name different from the operator name
        if stored and str(stored.get("name", "")).strip():
            op_name = str(row.get("auto_name", "")).strip()
            stored_name = str(stored.get("name", "")).strip()
            if stored_name and stored_name != op_name:
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
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    key = str(data.get("key", "")).strip()
    host = str(data.get("host", "")).strip()
    try:
        port = int(data.get("port"))
    except (TypeError, ValueError):
        return api_error("端口格式不正确")
    settings = settings_store.load()
    path_mode = str(data.get("path_mode") or settings.get("path_mode", "rtp"))
    try:
        result = probe_service.probe(key or f"{host}:{port}", host, port, path_mode)
        stored = channel_store.get(result["key"]) or {
            "key": result["key"],
            "host": host,
            "port": port,
            "name": str(data.get("name", "")).strip(),
            "category": str(data.get("category", "其它频道")).strip() or "其它频道",
        }
        stored.update(result)
        # 仅当已有频道名称时持久化到草稿；未命名的流保留在内存缓存中。
        if str(stored.get("name", "")).strip():
            channel_store.save_rows(enrich_channel_rows([stored], settings))
        return api_success(result)
    except ValueError as exc:
        return api_error(str(exc), 400)
    except RuntimeError as exc:
        return api_error(str(exc), 409)
    except Exception as exc:
        logger.error(f"流信息自动识别失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/probe/batch")
def api_probe_batch():
    data = request.get_json(silent=True) or {}
    rows = data.get("channels", []) if isinstance(data, dict) else []
    if not isinstance(rows, list):
        return api_error("channels 必须是数组")
    settings = settings_store.load()
    path_mode = str(data.get("path_mode") or settings.get("path_mode", "rtp")) if isinstance(data, dict) else str(settings.get("path_mode", "rtp"))
    results: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = str(row.get("key", "")).strip()
        host = str(row.get("host", "")).strip()
        try:
            port = int(row.get("port"))
        except (TypeError, ValueError):
            continue
        try:
            result = probe_service.probe(key or f"{host}:{port}", host, port, path_mode)
        except Exception as exc:
            result = {
                "key": key or f"{host}:{port}",
                "probe_status": "failed",
                "probe_message": str(exc),
                "codec_name": "",
                "width": None,
                "height": None,
                "frame_rate": "",
                "resolution_label": "未识别",
                "quality_group": "未识别",
                "probed_at": int(time.time()),
            }
            logger.warning(f"批量自动识别跳过失败项：{result['key']}，{exc}")
        results.append(result)
        row.update(result)
    rows = enrich_channel_rows(rows, settings)
    named_rows = [row for row in rows if isinstance(row, dict) and str(row.get("name", "")).strip()]
    if named_rows:
        channel_store.save_rows(named_rows)
    return api_success({"results": results, "count": len(results)})


@app.post("/api/export")
def api_export():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return api_error("请求体格式不正确")
    rows = data.get("channels")
    if rows is None:
        rows = merge_streams_with_channels()
    if not isinstance(rows, list):
        return api_error("channels 必须是数组")
    settings = {**settings_store.load(), **{k: v for k, v in data.items() if k != "channels"}}
    try:
        rows = enrich_channel_rows(rows, settings)
        operator_channels = operator_channel_store.load()
        result = export_service.export(rows, settings, operator_channels=operator_channels)
        channel_store.save_rows(rows)
        logger.info(
            "导出完成：共生成 "
            f"{result['count']} 个频道，文件为 channels-direct.m3u / "
            "channels-rtp2httpd-source.m3u / channels.json / channels.txt / channels.csv"
        )
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
    channels = list(channel_store.load().values())
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


@app.post("/api/diagnose")
def api_diagnose():
    """Playback chain diagnostic: rtp2httpd reachability + FCC + config review."""
    data = request.get_json(silent=True) or {}
    settings = settings_store.load()
    http_host = str(data.get("http_host") or settings.get("http_host", "")).strip()
    http_port = int(data.get("http_port") or settings.get("http_port") or 5140)
    channel_addr = str(data.get("channel", "")).strip()  # "ip:port"

    checks: list[dict] = []
    conclusions: list[str] = []

    # --- Check 1: rtp2httpd reachability ---
    rtp2httpd_ok = False
    if http_host:
        url = f"http://{http_host}:{http_port}/"
        try:
            req = Request(url)
            req.add_header("User-Agent", "IPTV-Sniffer-Web-Diag/1.0")
            with urlopen(req, timeout=5) as resp:
                code = resp.getcode()
                rtp2httpd_ok = code < 500
            checks.append({"item": "rtp2httpd 可访问", "ok": True,
                           "detail": f"{url} → HTTP {code}"})
        except Exception as exc:
            err = str(exc)
            checks.append({"item": "rtp2httpd 可访问", "ok": False,
                           "detail": f"{url} → {err}"})
            conclusions.append("rtp2httpd 不可访问：请确认地址/端口正确且服务已运行。")
    else:
        checks.append({"item": "rtp2httpd 可访问", "ok": None,
                       "detail": "未配置 rtp2httpd 地址，跳过检测。"})
        conclusions.append("未配置 rtp2httpd 地址，直连 M3U 使用 rtp:// 源地址。")

    # --- Check 2: Interface configured ---
    iface = str(settings.get("interface", "")).strip()
    checks.append({"item": "抓包接口已配置", "ok": bool(iface),
                   "detail": f"interface = {iface or '（未设置）'}"})
    if not iface:
        conclusions.append("未设置抓包接口，嗅探将使用默认接口 any。")

    # --- Check 3: Auth info captured ---
    auth = stb_discovery_service.status().get("auth_info") or {}
    has_mac = bool(auth.get("mac"))
    has_ip = bool(auth.get("assigned_ip"))
    checks.append({"item": "DHCP 认证信息已捕获", "ok": has_mac or has_ip,
                   "detail": f"MAC={auth.get('mac','—')}  IP={auth.get('assigned_ip','—')}"})
    if not (has_mac or has_ip):
        conclusions.append("未捕获到 DHCP 认证信息，如需 Option60 认证，请重启机顶盒并再次捕获。")

    # --- Check 4: UserToken captured ---
    token_data = token_store.load()
    has_token = bool(token_data.get("history"))
    checks.append({"item": "UserToken 已捕获", "ok": has_token,
                   "detail": f"历史记录 {len(token_data.get('history') or [])} 条"})
    if not has_token:
        conclusions.append("未捕获到 UserToken，channelAcquire 鉴权播放列表不可用。")

    # --- Check 5: FCC records ---
    fcc_count = len(fcc_store.load())
    checks.append({"item": "FCC 记录", "ok": fcc_count > 0,
                   "detail": f"已记录 {fcc_count} 条 FCC 服务器地址"})
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
                checks.append({"item": f"FCC 服务器端口可达 ({channel_addr})", "ok": True,
                               "detail": f"TCP connect {fcc_ip}:{fcc_port} → 成功（注：仅验证端口可达，非 FCC 协议握手）"})
            except Exception as exc:
                checks.append({"item": f"FCC 服务器端口可达 ({channel_addr})", "ok": False,
                               "detail": f"TCP connect {fcc_ip}:{fcc_port} → {exc}"})
                conclusions.append(f"FCC 服务器 {fcc_ip}:{fcc_port} 端口不可达，rtp2httpd FCC 快速换台将超时。")
        else:
            checks.append({"item": f"FCC 记录查询 ({channel_addr})", "ok": None,
                           "detail": "此频道无 FCC 记录（不影响正常播放，仅影响快速换台）"})

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
                checks.append({"item": f"组播链路检测 ({channel_addr})", "ok": None,
                               "detail": "缺少 tcpdump/抓包权限，跳过 IGMP/UDP 链路检测（需 NET_ADMIN, NET_RAW）"})
                conclusions.append("无法进行 IGMP/组播回流检测：宿主机需安装 tcpdump 并授予 NET_ADMIN、NET_RAW 权限。")
            else:
                link = capture_service.diagnose_multicast(mc_host, mc_port, iface)
                igmp_detail = "已发出 IGMP 加入请求" if link.get("igmp_sent") else "未确认 IGMP 加入"
                checks.append({"item": f"IGMP 组播加入 ({channel_addr})",
                               "ok": bool(link.get("igmp_sent")),
                               "detail": f"接口 {link.get('interface')}（{link.get('interface_ip') or '自动'}）→ {igmp_detail}"})
                verdict_code = link.get("verdict")
                udp_detail = (f"主动加入后收到 UDP 包：socket={link.get('socket_active_packets')} "
                              f"/ 线缆={link.get('wire_active_packets')}；"
                              f"未加入时线缆收到={link.get('wire_passive_packets')}")
                if verdict_code == "ok":
                    checks.append({"item": f"收到 239.x UDP 组播流 ({channel_addr})", "ok": True,
                                   "detail": udp_detail})
                elif verdict_code == "mirror":
                    checks.append({"item": f"收到 239.x UDP 组播流 ({channel_addr})", "ok": False,
                                   "detail": udp_detail + " → 疑似镜像口（SPAN）"})
                    conclusions.append("疑似镜像/SPAN 抓包口：未加入组播即可收到流量，但主动 IGMP 加入收不到。"
                                       "镜像口只能被动嗅探，播放器无法主动播放；请改用真实的 IPTV 接入口。")
                else:
                    checks.append({"item": f"收到 239.x UDP 组播流 ({channel_addr})", "ok": False,
                                   "detail": udp_detail})
                    conclusions.append("未收到该组播流：可能不在 IPTV 组播 VLAN、抓包接口选择错误，或该频道已停播。")
                for err in link.get("errors", []):
                    conclusions.append(f"组播链路检测：{err}")

    # --- Check 7: Channel list populated ---
    ch_count = len(channel_store.load())
    checks.append({"item": "频道列表已导入", "ok": ch_count > 0,
                   "detail": f"已保存 {ch_count} 个频道"})
    if ch_count == 0:
        conclusions.append("频道列表为空，请先运行运营商频道发现或嗅探并导入。")

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
        "conclusions": conclusions,
    })


def _startup_epg_refresh() -> None:
    try:
        result = refresh_all_epg_sources_task(settings_store.load())
        logger.info(f"启动 EPG 自动刷新完成：{result.get('count', 0)} 个来源，{result.get('total_channels', 0)} 个频道，台标 {result.get('total_logos', 0)} 个")
    except Exception as exc:
        logger.warning(f"启动 EPG 自动刷新失败：{exc}")


def boot() -> None:
    logger.info(f"应用启动：{APP_NAME} v{APP_VERSION}")
    capture_service.validate_runtime()
    probe_service.validate_runtime()
    epg_service.start_auto_refresh(settings_store)
    schedule_service.start()
    start_auto_enrichment_loop()
    threading.Thread(target=_startup_epg_refresh, daemon=True).start()
    _start_version_check_loop()
    logger.info(f"数据目录：{DATA_DIR}")
    logger.info(f"输出目录：{OUTPUT_DIR}")
    serve(app, host=WEB_HOST, port=WEB_PORT, threads=WAITRESS_THREADS)


if __name__ == "__main__":
    boot()
