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


def channel_group_key(ch: dict) -> str:
    """Return a stable group key: tvg_id > normalized name > raw key."""
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
      quality_group tier  4K高清=4 / 高清频道=3 / 普通频道=2 / other=1
      pixel count         w*h (distinguishes 1080p from 720p within 高清频道)
      probe status        ok=3 / partial=2 / not_probed=1 / failed=0
      fcc/fec availability
      packet count
    """
    qg = {"4K高清": 4, "高清频道": 3, "普通频道": 2}.get(str(ch.get("quality_group", "")), 1)
    try:
        px = int(ch.get("width") or 0) * int(ch.get("height") or 0)
    except (TypeError, ValueError):
        px = 0
    ps = {"ok": 3, "partial": 2, "not_probed": 1, "failed": 0}.get(
        str(ch.get("probe_status", "not_probed")), 1
    )
    fcc = (2 if ch.get("fcc_ip") and ch.get("fcc_port") else 0) + (1 if ch.get("fec_port") else 0)
    pkts = int(ch.get("packets", 0) or 0)
    return (qg, px, ps, fcc, pkts)
