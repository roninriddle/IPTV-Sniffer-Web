#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Application configuration for IPTV Sniffer Web."""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "IPTV Sniffer Web"
APP_VERSION = "1.0.1"
APP_DESCRIPTION = "IPTV 组播嗅探、频道整理与 rtp2httpd 播放列表统一工作台"
GITHUB_REPO = "roninriddle/IPTV-Sniffer-Web"
VERSION_CHECK_INTERVAL = 6 * 3600

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data"))).resolve()
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", str(BASE_DIR / "output"))).resolve()
LOG_FILE = Path(os.environ.get("LOG_FILE", str(DATA_DIR / "app.log"))).resolve()
SETTINGS_FILE = DATA_DIR / "settings.json"
CHANNELS_FILE = DATA_DIR / "channels.json"
FCC_FILE = DATA_DIR / "fcc.json"
STB_TOKEN_FILE = DATA_DIR / "playlist_token.json"
DISCOVERY_FILE = DATA_DIR / "discovered_channels.json"
EPG_CACHE_FILE = DATA_DIR / "epg_cache.json"
OPERATOR_CHANNELS_FILE = DATA_DIR / "operator_channels.json"
SNAPSHOTS_FILE = DATA_DIR / "channel_snapshots.json"
IPTV_AUTH_BACKUP_FILE = DATA_DIR / "iptv_auth_backups.json"

WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("WEB_PORT", "8787"))
WAITRESS_THREADS = int(os.environ.get("WAITRESS_THREADS", "6"))

DEFAULT_RTP2HTTP_HOST = os.environ.get("RTP2HTTPD_HOST", os.environ.get("RTP2HTTP_HOST", ""))
DEFAULT_RTP2HTTP_PORT = int(os.environ.get("RTP2HTTPD_PORT", os.environ.get("RTP2HTTP_PORT", "5140")))
DEFAULT_RTP2HTTPD_CONFIG_PATH = os.environ.get("RTP2HTTPD_CONFIG_PATH", "")
DEFAULT_PATH_MODE = os.environ.get("PATH_MODE", "rtp")
DEFAULT_CAPTURE_SECONDS = int(os.environ.get("CAPTURE_SECONDS", "30"))
DEFAULT_EPG_NAME = "suzukua/epg"
DEFAULT_EPG_URL = os.environ.get("EPG_URL", "https://epg.zsdc.eu.org/t.xml.gz")
DEFAULT_LOGO_NAME = "wanglindl/TVlogo"
DEFAULT_LOGO_URL = os.environ.get("LOGO_URL", "https://raw.githubusercontent.com/wanglindl/TVlogo/main/TVlist.m3u")
MAX_TIMED_CAPTURE_SECONDS = int(os.environ.get("MAX_TIMED_CAPTURE_SECONDS", "3600"))
MIN_PACKET_COUNT = int(os.environ.get("MIN_PACKET_COUNT", "3"))
LOG_MEMORY_LIMIT = int(os.environ.get("LOG_MEMORY_LIMIT", "600"))

PROBE_TIMEOUT_SECONDS = int(os.environ.get("PROBE_TIMEOUT_SECONDS", "10"))
PROBE_ANALYZE_DURATION_US = int(os.environ.get("PROBE_ANALYZE_DURATION_US", "8000000"))
PROBE_SIZE_BYTES = int(os.environ.get("PROBE_SIZE_BYTES", "8000000"))
PROBE_BUFFER_SIZE = int(os.environ.get("PROBE_BUFFER_SIZE", "131072"))

CAPTURE_FILTER = os.environ.get("CAPTURE_FILTER", "(udp and dst net 224.0.0.0/4) or tcp")
ALLOWED_DOWNLOADS = {
    "channels-best.m3u",
    "channels-all.m3u",
    "channels-rtp2httpd-best.m3u",
    "channels-rtp2httpd-all.m3u",
    "channels-direct.m3u",
    "channels-rtp2httpd-source.m3u",
    "channels.json",
    "channels.txt",
    "channels.csv",
}

CATEGORY_OPTIONS = ["央视频道", "卫视频道", "其它频道"]
CATEGORY_ORDER = {name: index for index, name in enumerate(CATEGORY_OPTIONS, start=1)}

DEFAULT_SETTINGS = {
    "interface": "",
    "http_host": DEFAULT_RTP2HTTP_HOST,
    "http_port": DEFAULT_RTP2HTTP_PORT,
    "rtp2httpd_config_path": DEFAULT_RTP2HTTPD_CONFIG_PATH,
    "path_mode": DEFAULT_PATH_MODE if DEFAULT_PATH_MODE in {"rtp", "udp"} else "rtp",
    "duration": DEFAULT_CAPTURE_SECONDS,
    "auto_probe": True,
    "auto_epg": True,
    "use_epg": True,
    "epg_name": DEFAULT_EPG_NAME,
    "epg_url": DEFAULT_EPG_URL,
    "use_logo": True,
    "logo_name": DEFAULT_LOGO_NAME,
    "logo_url": DEFAULT_LOGO_URL,
    "catchup_days": 7,
    "catchup_source_template": "",
    "fcc_type": "",
}

for directory in (DATA_DIR, OUTPUT_DIR):
    directory.mkdir(parents=True, exist_ok=True)
