#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Data models used by IPTV Sniffer Web."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class StreamRecord:
    host: str
    port: int
    packets: int
    first_seen: float
    last_seen: float

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["key"] = self.key
        return payload


@dataclass
class ChannelRecord:
    key: str
    host: str
    port: int
    name: str
    category: str
    packets: int = 0
    probe_status: str = "not_probed"
    probe_message: str = "未检测"
    codec_name: str = ""
    width: int | None = None
    height: int | None = None
    frame_rate: str = ""
    resolution_label: str = "未识别"
    quality_group: str = "未识别"
    fcc_ip: str = ""
    fcc_port: int | None = None
    fec_port: int | None = None
    tvg_id: str = ""
    tvg_name: str = ""
    tvg_logo: str = ""
    epg_source: str = ""
    is_primary: bool = False
    export_health_status: str = ""
    export_health_http_code: int | None = None
    export_health_bytes: int = 0
    export_health_speed: int = 0
    export_health_elapsed_ms: int = 0
    export_health_checked_at: int | None = None
    export_health_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
