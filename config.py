#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Application configuration for IPTV Sniffer Web."""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "IPTV Sniffer Web"
APP_VERSION = "0.5.3"
APP_DESCRIPTION = "IPTV 组播频道抓包、整理与 rtp2httpd 播放列表生成工具"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data"))).resolve()
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", str(BASE_DIR / "output"))).resolve()
LOG_FILE = Path(os.environ.get("LOG_FILE", str(DATA_DIR / "app.log"))).resolve()
SETTINGS_FILE = DATA_DIR / "settings.json"
CHANNELS_FILE = DATA_DIR / "channels.json"

WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("WEB_PORT", "8787"))
WAITRESS_THREADS = int(os.environ.get("WAITRESS_THREADS", "6"))

DEFAULT_RTP2HTTP_HOST = os.environ.get("RTP2HTTPD_HOST", os.environ.get("RTP2HTTP_HOST", ""))
DEFAULT_RTP2HTTP_PORT = int(os.environ.get("RTP2HTTPD_PORT", os.environ.get("RTP2HTTP_PORT", "5140")))
DEFAULT_PATH_MODE = os.environ.get("PATH_MODE", "rtp")
DEFAULT_CAPTURE_SECONDS = int(os.environ.get("CAPTURE_SECONDS", "30"))
MAX_TIMED_CAPTURE_SECONDS = int(os.environ.get("MAX_TIMED_CAPTURE_SECONDS", "3600"))
MIN_PACKET_COUNT = int(os.environ.get("MIN_PACKET_COUNT", "3"))
LOG_MEMORY_LIMIT = int(os.environ.get("LOG_MEMORY_LIMIT", "600"))

PROBE_TIMEOUT_SECONDS = int(os.environ.get("PROBE_TIMEOUT_SECONDS", "10"))
PROBE_ANALYZE_DURATION_US = int(os.environ.get("PROBE_ANALYZE_DURATION_US", "8000000"))
PROBE_SIZE_BYTES = int(os.environ.get("PROBE_SIZE_BYTES", "8000000"))
PROBE_BUFFER_SIZE = int(os.environ.get("PROBE_BUFFER_SIZE", "131072"))

CAPTURE_FILTER = os.environ.get("CAPTURE_FILTER", "udp and dst net 224.0.0.0/4")
ALLOWED_DOWNLOADS = {
    "channels-direct.m3u",
    "channels-rtp2httpd-source.m3u",
    "channels.txt",
    "channels.csv",
}

CATEGORY_OPTIONS = ["央视频道", "卫视频道", "其它频道"]
CATEGORY_ORDER = {name: index for index, name in enumerate(CATEGORY_OPTIONS, start=1)}

DEFAULT_SETTINGS = {
    "interface": "",
    "http_host": DEFAULT_RTP2HTTP_HOST,
    "http_port": DEFAULT_RTP2HTTP_PORT,
    "path_mode": DEFAULT_PATH_MODE if DEFAULT_PATH_MODE in {"rtp", "udp"} else "rtp",
    "duration": DEFAULT_CAPTURE_SECONDS,
}

for directory in (DATA_DIR, OUTPUT_DIR):
    directory.mkdir(parents=True, exist_ok=True)
