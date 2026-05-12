#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared validation and sorting helpers."""
from __future__ import annotations

import ipaddress
import re
from typing import Any


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
    if width > 0 and height > 0:
        return "普通频道"
    return "未识别"
