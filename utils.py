#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared validation and sorting helpers."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

NOISE_MULTICAST_HOSTS = {
    "224.0.0.1",      # all hosts
    "224.0.0.2",      # all routers
    "224.0.0.22",     # IGMP
    "224.0.0.251",    # mDNS
    "224.0.0.252",    # LLMNR
    "239.255.255.250",  # SSDP
}
NOISE_MULTICAST_PORTS = {
    1900,  # SSDP
    3702,  # WS-Discovery
    5353,  # mDNS
    5355,  # LLMNR
}

SENSITIVE_QUERY_KEYS = {
    "accountinfo",
    "authenticator",
    "jsessionid",
    "password",
    "r2h-token",
    "token",
    "userpassword",
    "usertoken",
}
_SENSITIVE_QUERY_KEY_PATTERN = "|".join(
    re.escape(key) for key in sorted(SENSITIVE_QUERY_KEYS, key=len, reverse=True)
)
_RTSP_URL_RE = re.compile(r"(?i)rtsp://[^\s\"'<>]+")
_SENSITIVE_PARAM_RE = re.compile(
    r"(?i)([?&;\s]|^)"
    rf"({_SENSITIVE_QUERY_KEY_PATTERN})"
    r"=([^&;\s\"'<>]+)"
)


def valid_ip_or_host(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value))


def valid_ipv4_multicast(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and ip.is_multicast
    except ValueError:
        return False


def stream_static_filter_reason(host: str, port: int) -> str:
    try:
        ip = ipaddress.ip_address(host)
        port = int(port)
    except (TypeError, ValueError):
        return "地址或端口无效"
    if ip.version != 4 or not ip.is_multicast:
        return "不是 IPv4 组播地址"
    if str(ip) in NOISE_MULTICAST_HOSTS:
        return "系统服务发现组播"
    if ip in ipaddress.ip_network("224.0.0.0/24"):
        return "本地链路控制组播"
    if port in NOISE_MULTICAST_PORTS:
        return "系统服务发现端口"
    return ""


def stream_filter_reason(host: str, port: int, packets: int, min_packets: int) -> str:
    static_reason = stream_static_filter_reason(host, port)
    if static_reason:
        return static_reason
    try:
        packets = int(packets)
    except (TypeError, ValueError):
        return "包数无效"
    if packets < min_packets:
        return f"包数不足 {min_packets}"
    return ""


def is_probable_iptv_stream(host: str, port: int, packets: int, min_packets: int) -> bool:
    return not stream_filter_reason(host, port, packets, min_packets)


def natural_key(value: str) -> list[Any]:
    parts = re.split(r"(\d+)", value.casefold())
    return [int(part) if part.isdigit() else part for part in parts]


def ip_sort_key(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except Exception:
        return (999,)


def stream_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def redact_sensitive_text(value: str, limit: int | None = None) -> str:
    """Redact IPTV auth tokens before writing user-visible logs.

    回看 RTSP URL 经常把账号、token、Authenticator 等放在查询参数中。
    先替换完整 RTSP URL，再处理普通 HTTP/文本片段，避免日志截断后泄露 token。
    """
    text = str(value or "")
    text = _RTSP_URL_RE.sub("rtsp://<redacted>", text)

    def _replace(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}=<redacted>"

    text = _SENSITIVE_PARAM_RE.sub(_replace, text)
    if limit is not None and len(text) > limit:
        return text[-limit:]
    return text


def classify_channel_name(name: str) -> str:
    normalized = name.strip().upper()
    if not normalized:
        return "其它频道"
    if "CCTV" in normalized or "央视" in name or "中央" in name:
        return "央视频道"
    if "卫视" in name:
        return "卫视频道"
    return "其它频道"


def resolution_label_from_size(width: int | None, height: int | None) -> str:
    try:
        width = int(width or 0)
        height = int(height or 0)
    except (TypeError, ValueError):
        return "未识别"
    if width >= 3840 and height >= 2160:
        return "4K"
    if width >= 1920 and height >= 1080:
        return "1080p"
    if width >= 1280 and height >= 720:
        return "720p"
    if width > 0 and height > 0:
        return f"{width}x{height}"
    return "未识别"


def stream_quality_group(width: int | None, height: int | None) -> str:
    try:
        width = int(width or 0)
        height = int(height or 0)
    except (TypeError, ValueError):
        return "未识别"
    if width >= 3840 and height >= 2160:
        return "4K高清"
    if width >= 1280 and height >= 720:
        return "高清频道"
    if width > 0 and height > 0:
        return "普通频道"
    return "未识别"


# ── Channel grouping helpers ──────────────────────────────────────────────

_GROUP_SUFFIX_RE = re.compile(
    r"(4K|SUPER4K|UHD|超高清|高清|标清|HD|SD|\d{3,4}[PI])$",
    re.IGNORECASE,
)


def normalize_channel_name_for_group(name: str) -> str:
    """Strip quality suffixes and punctuation for group-key comparison."""
    n = re.sub(r"[\s\-_·•【】\[\]()（）]", "", name.upper())
    n = _GROUP_SUFFIX_RE.sub("", n)
    return n.strip()


def channel_name_variant_key(name: str) -> str:
    """Return a stable key for channels that are variants, not backup lines.

    Some EPG sources use short IDs such as CCTV4EUO/CCTV4AME while operator
    channel lists use Chinese display names.  These are separate channels from
    CCTV4, so they must not be grouped only by the generic CCTV4 tvg-id.
    """
    n = normalize_channel_name_for_group(name)
    if not n:
        return ""
    compact = n.replace("中文国际", "")
    if "CCTV4EUO" in compact or ("CCTV4" in compact and "欧洲" in compact):
        return "CCTV4EUO"
    if "CCTV4AME" in compact or ("CCTV4" in compact and "美洲" in compact):
        return "CCTV4AME"
    return ""


def channel_variant_key(ch: dict) -> str:
    """Return a distinct variant key from any known channel-name field."""
    for field in ("name", "tvg_name", "auto_name", "detected_name"):
        variant = channel_name_variant_key(str(ch.get(field) or ""))
        if variant:
            return variant
    return ""


def channel_group_key(ch: dict) -> str:
    """Return a stable group key: tvg_id > normalized name > raw key."""
    variant = channel_variant_key(ch)
    if variant:
        return f"name:{variant}"
    tvg_id = str(ch.get("tvg_id") or "").strip()
    if tvg_id:
        return f"id:{tvg_id}"
    name = str(ch.get("name") or "").strip()
    norm = normalize_channel_name_for_group(name)
    if norm:
        return f"name:{norm}"
    return f"raw:{ch.get('key', '')}"


def channel_primary_score(ch: dict) -> tuple:
    """Higher tuple = better candidate for primary source within a group.

    Tier ordering (higher = better):
      export health      ok=4 / unchecked=2 / timeout=1 / failed=0
      manual primary     user-selected primary wins when health is equal
      probe status        ok=3 / partial=2 / not_probed=1 / failed=0
      fcc/fec availability
      measured speed
      packet count
    """
    health_status = str(ch.get("export_health_status") or "").strip().lower()
    health = {
        "ok": 4,
        "partial": 3,
        "skipped": 2,
        "not_checked": 2,
        "": 2,
        "timeout": 1,
        "failed": 0,
        "error": 0,
    }.get(health_status, 2)
    manual = 1 if ch.get("is_primary") else 0
    ps = {"ok": 3, "partial": 2, "not_probed": 1, "failed": 0}.get(
        str(ch.get("probe_status", "not_probed")), 1
    )
    fcc = (2 if ch.get("fcc_ip") and ch.get("fcc_port") else 0) + (1 if ch.get("fec_port") else 0)
    speed = int(ch.get("export_health_speed", 0) or 0)
    pkts = int(ch.get("packets", 0) or 0)
    return (health, manual, ps, fcc, speed, pkts)
