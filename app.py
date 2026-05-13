#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPTV Sniffer Web v0.6.1 application entrypoint."""
from __future__ import annotations

import time
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
    CHANNELS_FILE,
    DATA_DIR,
    FCC_FILE,
    LOG_FILE,
    LOG_MEMORY_LIMIT,
    MIN_PACKET_COUNT,
    OUTPUT_DIR,
    SETTINGS_FILE,
    STB_TOKEN_FILE,
    WAITRESS_THREADS,
    WEB_HOST,
    WEB_PORT,
)
from services.capture_service import CaptureService
from services.export_service import ExportService
from services.log_service import AppLogger
from services.probe_service import ProbeService
from services.schedule_service import ScheduleService
from services.storage_service import ChannelStore, FccStore, SettingsStore, StbTokenStore
from utils import classify_channel_name, stream_filter_reason, valid_ip_or_host, valid_ipv4_multicast

app = Flask(__name__)
logger = AppLogger(LOG_FILE, LOG_MEMORY_LIMIT)
settings_store = SettingsStore(SETTINGS_FILE)
channel_store = ChannelStore(CHANNELS_FILE)
fcc_store = FccStore(FCC_FILE)
token_store = StbTokenStore(STB_TOKEN_FILE)
capture_service = CaptureService(logger, fcc_store, token_store)
export_service = ExportService(OUTPUT_DIR)
probe_service = ProbeService(logger)
schedule_service = ScheduleService(logger, settings_store, capture_service)
STARTED_AT = time.time()
preview_failures: dict[str, str] = {}


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


def merge_streams_with_channels() -> list[dict[str, Any]]:
    streams = capture_service.streams()
    named = channel_store.load()
    fcc_records = fcc_store.load()
    settings = settings_store.load()
    payload: list[dict[str, Any]] = []
    for stream in streams:
        channel = named.get(stream["key"], {})
        filter_reason = stream_filter_reason(
            str(stream.get("host", "")),
            int(stream.get("port", 0)),
            int(stream.get("packets", 0)),
            MIN_PACKET_COUNT,
        )
        if filter_reason and not str(channel.get("name", "")).strip():
            continue
        item = dict(stream)
        item["filter_reason"] = filter_reason
        item["name"] = channel.get("name", "")
        item["category"] = channel.get("category", classify_channel_name(item["name"]))
        item.update(probe_service.merge_probe_data(stream["key"], channel))
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
        item["snapshot_url"] = (
            f"{item['preview_url']}{'&' if '?' in item['preview_url'] else '?'}snapshot=1"
            if settings.get("http_host") else ""
        )
        item["player_url"] = (
            f"http://{settings.get('http_host')}:{int(settings.get('http_port', 5140))}/player"
            if settings.get("http_host") else ""
        )
        payload.append(item)
    return payload


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
    return api_success({"name": APP_NAME, "version": APP_VERSION, "description": APP_DESCRIPTION})


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
        "fcc_records": len(fcc_store.load()),
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


@app.post("/api/channels/save")
def api_channels_save():
    data = request.get_json(silent=True) or {}
    rows = data.get("channels", []) if isinstance(data, dict) else []
    if not isinstance(rows, list):
        return api_error("channels 必须是数组")
    result = channel_store.save_rows(rows)
    logger.info(f"已保存频道草稿：新增或更新 {result['saved']} 条，删除 {result['deleted']} 条")
    return api_success(result)


@app.post("/api/channels/auto-classify")
def api_channels_auto_classify():
    rows = merge_streams_with_channels()
    for row in rows:
        row["category"] = classify_channel_name(str(row.get("name", "")))
    result = channel_store.save_rows(rows)
    logger.info("已按频道名称自动更新频道分类")
    return api_success({"store": result, "streams": merge_streams_with_channels()})


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
            channel_store.save_rows([stored])
        return api_success(result)
    except ValueError as exc:
        return api_error(str(exc), 400)
    except RuntimeError as exc:
        return api_error(str(exc), 409)
    except Exception as exc:
        logger.error(f"流信息检测失败：{exc}")
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
            logger.warning(f"批量检测跳过失败项：{result['key']}，{exc}")
        results.append(result)
        row.update(result)
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
    schedule_service.start()
    logger.info(f"数据目录：{DATA_DIR}")
    logger.info(f"输出目录：{OUTPUT_DIR}")
    serve(app, host=WEB_HOST, port=WEB_PORT, threads=WAITRESS_THREADS)


if __name__ == "__main__":
    boot()
