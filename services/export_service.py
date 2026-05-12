#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Playlist export logic for M3U, TXT and CSV."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from config import CATEGORY_OPTIONS, CATEGORY_ORDER
from models import ChannelRecord
from utils import ip_sort_key, natural_key, stream_quality_group

QUALITY_GROUP_OPTIONS = ["4K高清", "普通频道"]


class ExportService:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def make_http_url(http_host: str, http_port: int, path_mode: str, host: str, port: int) -> str:
        return f"http://{http_host}:{http_port}/{path_mode}/{host}:{port}"

    @staticmethod
    def make_source_url(path_mode: str, host: str, port: int) -> str:
        scheme = "rtp" if path_mode == "rtp" else "udp"
        return f"{scheme}://{host}:{port}"

    def _normalize_channels(self, rows: list[dict[str, Any]]) -> list[ChannelRecord]:
        channels: list[ChannelRecord] = []
        seen_keys: set[str] = set()
        for row in rows:
            name = str(row.get("name", "")).strip()
            if not name:
                continue
            host = str(row.get("host", "")).strip()
            try:
                port = int(row.get("port"))
                packets = int(row.get("packets", 0))
            except (TypeError, ValueError) as exc:
                raise ValueError("频道数据中存在无效端口或包数") from exc
            key = str(row.get("key") or f"{host}:{port}")
            if key in seen_keys:
                continue
            category = str(row.get("category", "其它频道")).strip()
            if category not in CATEGORY_OPTIONS:
                category = "其它频道"
            width = self._safe_int(row.get("width"))
            height = self._safe_int(row.get("height"))
            quality_group = str(row.get("quality_group") or stream_quality_group(width, height)).strip()
            if quality_group not in {"4K高清", "普通频道", "未识别"}:
                quality_group = stream_quality_group(width, height)
            channels.append(ChannelRecord(
                key=key,
                host=host,
                port=port,
                name=name,
                category=category,
                packets=packets,
                probe_status=str(row.get("probe_status", "not_probed")),
                probe_message=str(row.get("probe_message", "未检测")),
                codec_name=str(row.get("codec_name", "")),
                width=width,
                height=height,
                frame_rate=str(row.get("frame_rate", "")),
                resolution_label=str(row.get("resolution_label", "未识别")),
                quality_group=quality_group,
            ))
            seen_keys.add(key)
        channels.sort(key=self._channel_sort_key)
        return channels

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _channel_sort_key(item: ChannelRecord) -> tuple[Any, ...]:
        return (
            CATEGORY_ORDER.get(item.category, 99),
            natural_key(item.name),
            ip_sort_key(item.host),
            item.port,
        )

    @staticmethod
    def _quality_sort_key(item: ChannelRecord) -> tuple[Any, ...]:
        return (
            natural_key(item.name),
            ip_sort_key(item.host),
            item.port,
        )

    def export(self, rows: list[dict[str, Any]], settings: dict[str, Any]) -> dict[str, Any]:
        channels = self._normalize_channels(rows)
        if not channels:
            raise ValueError("没有填写任何频道名称，未生成输出文件")
        http_host = str(settings.get("http_host", "")).strip()
        http_port = int(settings.get("http_port", 8686))
        path_mode = str(settings.get("path_mode", "rtp")).strip().lower()
        if path_mode not in {"rtp", "udp"}:
            path_mode = "rtp"
        m3u_path = self.output_dir / "channels.m3u"
        txt_path = self.output_dir / "channels.txt"
        csv_path = self.output_dir / "channels.csv"
        quality_groups = self._quality_groups(channels)
        self._write_m3u(channels, quality_groups, m3u_path, http_host, http_port, path_mode)
        self._write_txt(channels, quality_groups, txt_path, http_host, http_port, path_mode)
        self._write_csv(channels, quality_groups, csv_path, http_host, http_port, path_mode)
        return {
            "count": len(channels),
            "quality_group_counts": {name: len(quality_groups.get(name, [])) for name in QUALITY_GROUP_OPTIONS},
            "unclassified_resolution_count": sum(1 for channel in channels if channel.quality_group not in QUALITY_GROUP_OPTIONS),
            "files": {
                "m3u": m3u_path.name,
                "txt": txt_path.name,
                "csv": csv_path.name,
            },
        }

    def _quality_groups(self, channels: list[ChannelRecord]) -> dict[str, list[ChannelRecord]]:
        grouped = {name: [] for name in QUALITY_GROUP_OPTIONS}
        for channel in channels:
            if channel.quality_group in grouped:
                grouped[channel.quality_group].append(channel)
        for group_channels in grouped.values():
            group_channels.sort(key=self._quality_sort_key)
        return grouped

    def _write_m3u(
        self,
        channels: list[ChannelRecord],
        quality_groups: dict[str, list[ChannelRecord]],
        target: Path,
        http_host: str,
        http_port: int,
        path_mode: str,
    ) -> None:
        with target.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write("#EXTM3U\n")
            for channel in channels:
                self._write_m3u_item(handle, channel, channel.category, http_host, http_port, path_mode)
            for group_name in QUALITY_GROUP_OPTIONS:
                for channel in quality_groups.get(group_name, []):
                    self._write_m3u_item(handle, channel, group_name, http_host, http_port, path_mode)

    def _write_m3u_item(self, handle, channel: ChannelRecord, group: str, http_host: str, http_port: int, path_mode: str) -> None:
        safe_group = group.replace('"', "'")
        tvg_name = channel.name.replace('"', "'")
        url = self.make_http_url(http_host, http_port, path_mode, channel.host, channel.port)
        handle.write(f'#EXTINF:-1 tvg-name="{tvg_name}" group-title="{safe_group}",{channel.name}\n')
        handle.write(f"{url}\n")

    def _write_txt(
        self,
        channels: list[ChannelRecord],
        quality_groups: dict[str, list[ChannelRecord]],
        target: Path,
        http_host: str,
        http_port: int,
        path_mode: str,
    ) -> None:
        grouped: dict[str, list[ChannelRecord]] = {category: [] for category in CATEGORY_OPTIONS}
        for channel in channels:
            grouped.setdefault(channel.category, []).append(channel)
        for group_channels in grouped.values():
            group_channels.sort(key=self._quality_sort_key)
        ordered_sections: list[tuple[str, list[ChannelRecord]]] = []
        ordered_sections.extend((category, grouped.get(category, [])) for category in CATEGORY_OPTIONS)
        ordered_sections.extend((group_name, quality_groups.get(group_name, [])) for group_name in QUALITY_GROUP_OPTIONS)
        with target.open("w", encoding="utf-8", newline="\n") as handle:
            first_group = True
            for category, group_channels in ordered_sections:
                if not group_channels:
                    continue
                if not first_group:
                    handle.write("\n")
                first_group = False
                handle.write(f"{category},#genre#\n")
                for channel in group_channels:
                    url = self.make_http_url(http_host, http_port, path_mode, channel.host, channel.port)
                    handle.write(f"{channel.name},{url}\n")

    def _write_csv(
        self,
        channels: list[ChannelRecord],
        quality_groups: dict[str, list[ChannelRecord]],
        target: Path,
        http_host: str,
        http_port: int,
        path_mode: str,
    ) -> None:
        with target.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow([
                "展示分组",
                "原始分类",
                "频道名称",
                "清晰度分组",
                "分辨率",
                "编码",
                "帧率",
                "源地址",
                "播放地址",
                "组播IP",
                "端口",
                "抓到包数",
            ])
            for channel in channels:
                self._write_csv_row(writer, channel, channel.category, http_host, http_port, path_mode)
            for group_name in QUALITY_GROUP_OPTIONS:
                for channel in quality_groups.get(group_name, []):
                    self._write_csv_row(writer, channel, group_name, http_host, http_port, path_mode)

    def _write_csv_row(self, writer: csv.writer, channel: ChannelRecord, display_group: str, http_host: str, http_port: int, path_mode: str) -> None:
        source = self.make_source_url(path_mode, channel.host, channel.port)
        url = self.make_http_url(http_host, http_port, path_mode, channel.host, channel.port)
        resolution = f"{channel.width}x{channel.height}" if channel.width and channel.height else channel.resolution_label
        writer.writerow([
            display_group,
            channel.category,
            channel.name,
            channel.quality_group,
            resolution,
            channel.codec_name,
            channel.frame_rate,
            source,
            url,
            channel.host,
            channel.port,
            channel.packets,
        ])
