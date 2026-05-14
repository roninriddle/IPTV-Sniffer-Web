#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPTV Sniffer Web application entrypoint."""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import threading
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from flask import Flask, Response, jsonify, render_template, request, send_file, send_from_directory, stream_with_context
from waitress import serve

from config import (
    ALLOWED_DOWNLOADS,
    APP_DESCRIPTION,
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
from services.storage_service import ChannelStore, CustomSourcesStore, DiscoveryStore, FccStore, SettingsStore, StbTokenStore
from utils import classify_channel_name, stream_filter_reason, valid_ip_or_host, valid_ipv4_multicast

app = Flask(__name__)
logger = AppLogger(LOG_FILE, LOG_MEMORY_LIMIT)
settings_store = SettingsStore(SETTINGS_FILE)
channel_store = ChannelStore(CHANNELS_FILE)
fcc_store = FccStore(FCC_FILE)
custom_sources_store = CustomSourcesStore(CUSTOM_SOURCES_FILE)
token_store = StbTokenStore(STB_TOKEN_FILE)
discovery_store = DiscoveryStore(DISCOVERY_FILE)
capture_service = CaptureService(logger, fcc_store, token_store, discovery_store)
export_service = ExportService(OUTPUT_DIR)
probe_service = ProbeService(logger)
epg_service = EpgService(logger, EPG_CACHE_FILE)
STARTED_AT = time.time()
preview_failures: dict[str, str] = {}
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
            f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
            headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}", "Accept": "application/vnd.github+json"},
        )
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        tag = str(data.get("tag_name", "")).strip()
        release_url = str(data.get("html_url", "")).strip()
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
            logger.info(f"发现新版本 v{clean}（当前 v{APP_VERSION}），发布地址：{release_url}")
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

# HLS stream proxy sessions
_stream_sessions: dict[str, dict[str, Any]] = {}
_stream_sessions_lock = threading.RLock()
_STREAM_IDLE_TTL = 30


def _stream_session_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def _cleanup_stream_session(session: dict[str, Any]) -> None:
    try:
        proc = session.get("proc")
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=3)
    except Exception:
        pass
    shutil.rmtree(session.get("dir", ""), ignore_errors=True)


def _get_or_start_hls_stream(host: str, port: int) -> dict[str, Any]:
    key = _stream_session_key(host, port)
    with _stream_sessions_lock:
        session = _stream_sessions.get(key)
        if session and session["proc"].poll() is None:
            session["last_access"] = time.time()
            return session
        if session:
            _cleanup_stream_session(session)
        tmpdir = tempfile.mkdtemp(prefix="iptv_hls_")
        playlist_path = os.path.join(tmpdir, "index.m3u8")
        cmd = [
            "ffmpeg", "-y", "-loglevel", "quiet",
            "-i", f"udp://{host}:{port}?overrun_nonfatal=1&fifo_size=50000000",
            "-c", "copy",
            "-f", "hls",
            "-hls_time", "2",
            "-hls_list_size", "5",
            "-hls_flags", "delete_segments+append_list",
            "-hls_segment_filename", os.path.join(tmpdir, "seg%d.ts"),
            playlist_path,
        ]
        proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
        session = {"proc": proc, "dir": tmpdir, "playlist": playlist_path, "last_access": time.time()}
        _stream_sessions[key] = session
        return session


def _stream_cleanup_worker() -> None:
    while True:
        time.sleep(10)
        now = time.time()
        with _stream_sessions_lock:
            stale = [k for k, s in _stream_sessions.items() if now - s["last_access"] > _STREAM_IDLE_TTL or s["proc"].poll() is not None]
            for k in stale:
                _cleanup_stream_session(_stream_sessions.pop(k))


threading.Thread(target=_stream_cleanup_worker, daemon=True).start()


def _count_epg_channels(url: str, timeout: int = 20) -> int:
    req = Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read(4 * 1024 * 1024)
    if url.lower().endswith(".gz") or raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
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


def remember_preview_failure(key: str, message: str) -> None:
    preview_failures[key] = message
    cached = probe_service.get_cached(key) or {}
    if cached.get("probe_status") not in {"ok", "partial"}:
        probe_service.remember_failure(key, message)


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
    enriched: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        key = str(item.get("key") or f"{item.get('host', '')}:{item.get('port', '')}")
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
        preview_failure = preview_failures.get(stream["key"], "")
        if (
            not str(item.get("name", "")).strip()
            and (
                preview_failure
                or str(item.get("probe_status", "")) == "failed"
            )
        ):
            continue
        if preview_failure:
            item["preview_failed"] = True
            item["preview_failure"] = preview_failure
        item["preview_url"] = export_service.make_http_url(
            str(settings.get("http_host", "")),
            int(settings.get("http_port", 5140)),
            str(settings.get("path_mode", "rtp")),
            str(item["host"]),
            int(item["port"]),
            item["fcc_ip"],
            item["fcc_port"],
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


def update_scheduled_m3u_epg(settings: dict[str, Any]) -> dict[str, Any]:
    m3u_url = str(settings.get("schedule_m3u_url", "")).strip()
    epg_url = str(settings.get("epg_url", "")).strip()
    logo_url = str(settings.get("logo_url", "")).strip()
    output_name = str(settings.get("schedule_output_name", "scheduled-epg.m3u")).strip() or "scheduled-epg.m3u"
    if output_name != "scheduled-epg.m3u":
        output_name = "scheduled-epg.m3u"
    if not m3u_url:
        raise ValueError("M3U 地址不能为空")
    if not epg_url:
        raise ValueError("XMLTV EPG 地址不能为空")

    epg_status = epg_service.refresh(epg_url, logo_url)
    if epg_status.get("last_error") and int(epg_status.get("channels") or 0) == 0:
        raise RuntimeError(f"EPG 刷新失败：{epg_status.get('last_error')}")
    text = fetch_text_resource(m3u_url)
    items = parse_m3u_channels(text)
    if not items:
        raise ValueError("指定 M3U 中没有可更新的频道")

    matched = 0
    for item in items:
        attrs = dict(item.get("attrs") or {})
        name = str(attrs.get("tvg-name") or item.get("title") or "").strip()
        row = {
            "name": name,
            "tvg_id": str(attrs.get("tvg-id", "")).strip(),
            "tvg_name": str(attrs.get("tvg-name", "")).strip(),
            "tvg_logo": str(attrs.get("tvg-logo", "")).strip(),
        }
        epg_service.enrich_item(row, epg_url, only_missing=False)
        if row.get("tvg_id") or row.get("tvg_logo"):
            matched += 1
        if row.get("tvg_id"):
            attrs["tvg-id"] = row["tvg_id"]
        if row.get("tvg_name"):
            attrs["tvg-name"] = row["tvg_name"]
        if row.get("tvg_logo"):
            attrs["tvg-logo"] = row["tvg_logo"]
        if not attrs.get("group-title"):
            attrs["group-title"] = classify_channel_name(str(item.get("title") or row.get("tvg_name") or name))
        item["attrs"] = attrs

    target = OUTPUT_DIR / output_name
    target.write_text(write_m3u_channels(items, epg_url), encoding="utf-8")
    return {
        "count": len(items),
        "matched": matched,
        "file": output_name,
        "download_url": f"/api/download/{output_name}",
        "m3u_url": m3u_url,
        "epg_url": epg_url,
        "updated_at": int(time.time()),
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


schedule_service = ScheduleService(logger, settings_store, update_scheduled_m3u_epg)


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
    return api_success(epg_service.status())


@app.get("/api/epg/sources")
def api_epg_sources():
    custom = custom_sources_store.load()
    epg_sources = [{**s, "builtin": True} for s in EPG_SOURCES] + custom.get("epg", [])
    logo_sources = [{**s, "builtin": True} for s in LOGO_SOURCES] + custom.get("logo", [])
    return api_success({"epg_sources": epg_sources, "logo_sources": logo_sources})


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


@app.post("/api/epg/detect-best")
def api_epg_detect_best():
    with _epg_detect_lock:
        current = dict(_epg_detect_state)
    if current["status"] == "detecting":
        return api_success(current)
    custom = custom_sources_store.load()
    all_sources = EPG_SOURCES + custom.get("epg", [])
    threading.Thread(target=_do_epg_detect_best, args=(all_sources,), daemon=True).start()
    with _epg_detect_lock:
        _epg_detect_state["status"] = "detecting"
    return api_success({"status": "detecting"})


@app.get("/api/epg/detect-best")
def api_epg_detect_best_status():
    with _epg_detect_lock:
        return api_success(dict(_epg_detect_state))


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
        return api_success(status)
    except ValueError as exc:
        return api_error(str(exc), 400)
    except Exception as exc:
        logger.error(f"启动 EPG 刷新失败：{exc}")
        return api_error(str(exc), 500)


@app.post("/api/channels/save")
def api_channels_save():
    data = request.get_json(silent=True) or {}
    rows = data.get("channels", []) if isinstance(data, dict) else []
    if not isinstance(rows, list):
        return api_error("channels 必须是数组")
    rows = enrich_channel_rows(rows)
    result = channel_store.save_rows(rows)
    logger.info(f"已保存频道草稿：新增或更新 {result['saved']} 条，删除 {result['deleted']} 条")
    return api_success(result)



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
    settings = settings_store.load()
    try:
        rows = enrich_channel_rows(rows, settings)
        result = export_service.export(rows, settings)
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


@app.get("/api/preview/<host>/<int:port>")
def api_preview(host: str, port: int):
    settings = settings_store.load()
    http_host = str(settings.get("http_host", "")).strip()
    try:
        http_port = int(settings.get("http_port", 5140))
    except (TypeError, ValueError):
        return api_error("rtp2httpd 端口配置不正确", 400)
    path_mode = str(request.args.get("path_mode") or settings.get("path_mode", "rtp")).strip().lower()
    if not valid_ipv4_multicast(host):
        return api_error("预览地址必须是 IPv4 组播地址", 400)
    if not 1 <= port <= 65535:
        return api_error("预览端口必须位于 1-65535", 400)
    if not valid_ip_or_host(http_host):
        return api_error("rtp2httpd 地址尚未正确配置", 400)
    if path_mode not in {"rtp", "udp"}:
        return api_error("路径模式只能是 rtp 或 udp", 400)
    source_url = export_service.make_http_url(http_host, http_port, path_mode, host, port)
    try:
        upstream = urlopen(Request(source_url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"}), timeout=10)
    except (OSError, URLError) as exc:
        logger.warning(f"打开预览流失败：{source_url}，{exc}")
        remember_preview_failure(f"{host}:{port}", f"预览失败：{exc}")
        return api_error(f"无法打开预览流：{exc}", 502)

    def generate():
        with upstream:
            while True:
                chunk = upstream.read(64 * 1024)
                if not chunk:
                    break
                yield chunk

    headers = {
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
    }
    return Response(stream_with_context(generate()), headers=headers, mimetype="video/MP2T", direct_passthrough=True)


@app.get("/api/stream/<host>/<int:port>/hls/index.m3u8")
def api_stream_hls_playlist(host: str, port: int):
    if not valid_ipv4_multicast(host):
        return api_error("必须是 IPv4 组播地址", 400)
    if not 1 <= port <= 65535:
        return api_error("端口无效", 400)
    if shutil.which("ffmpeg") is None:
        return api_error("缺少 ffmpeg 命令", 503)
    session = _get_or_start_hls_stream(host, port)
    for _ in range(16):
        if os.path.exists(session["playlist"]):
            break
        time.sleep(0.5)
    if not os.path.exists(session["playlist"]):
        return api_error("流启动超时，请确认组播地址可达", 504)
    with open(session["playlist"], "r", encoding="utf-8") as fh:
        raw = fh.read()
    base = f"/api/stream/{host}/{port}/hls/"
    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(base + os.path.basename(stripped.split("?")[0]))
        else:
            lines.append(line)
    resp = Response("\n".join(lines) + "\n", mimetype="application/vnd.apple.mpegurl")
    resp.headers["Cache-Control"] = "no-cache, no-store"
    return resp


@app.get("/api/stream/<host>/<int:port>/hls/<path:filename>")
def api_stream_hls_segment(host: str, port: int, filename: str):
    key = _stream_session_key(host, port)
    with _stream_sessions_lock:
        session = _stream_sessions.get(key)
        if session:
            session["last_access"] = time.time()
    if not session:
        return ("", 404)
    seg_path = os.path.normpath(os.path.join(session["dir"], filename))
    if not seg_path.startswith(os.path.normpath(session["dir"])):
        return ("", 403)
    if not os.path.exists(seg_path):
        return ("", 404)
    return send_file(seg_path, mimetype="video/mp2t")


@app.delete("/api/stream/<host>/<int:port>/hls")
def api_stream_hls_stop(host: str, port: int):
    key = _stream_session_key(host, port)
    with _stream_sessions_lock:
        session = _stream_sessions.pop(key, None)
    if session:
        _cleanup_stream_session(session)
    return api_success({})


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
    source = f"udp://{host}:{port}?timeout=8000000"
    cmd = [
        "ffmpeg", "-y",
        "-analyzeduration", "2000000",
        "-probesize", "2000000",
        "-i", source,
        "-frames:v", "1",
        "-f", "image2",
        "-vcodec", "mjpeg",
        "pipe:1",
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
    except subprocess.TimeoutExpired:
        return api_error("截图超时", 504)
    except OSError as exc:
        return api_error(f"ffmpeg 执行失败：{exc}", 500)
    if proc.returncode != 0 or not proc.stdout:
        return api_error("无法从流中截图", 502)
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


def boot() -> None:
    logger.info(f"应用启动：{APP_NAME} v{APP_VERSION}")
    capture_service.validate_runtime()
    probe_service.validate_runtime()
    epg_service.start_auto_refresh(settings_store)
    schedule_service.start()
    start_auto_enrichment_loop()
    _start_version_check_loop()
    logger.info(f"数据目录：{DATA_DIR}")
    logger.info(f"输出目录：{OUTPUT_DIR}")
    serve(app, host=WEB_HOST, port=WEB_PORT, threads=WAITRESS_THREADS)


if __name__ == "__main__":
    boot()
