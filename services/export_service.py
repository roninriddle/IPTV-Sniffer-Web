#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Playlist export logic for M3U, TXT and CSV."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from config import CATEGORY_OPTIONS, CATEGORY_ORDER
from models import ChannelRecord
from utils import channel_group_key, channel_primary_score, ip_sort_key, natural_key, stream_quality_group

QUALITY_GROUP_OPTIONS = ["4K高清", "高清频道", "普通频道"]


class ExportService:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def make_http_url(
        http_host: str,
        http_port: int,
        path_mode: str,
        host: str,
        port: int,
        fcc_ip: str = "",
        fcc_port: int | None = None,
        fec_port: int | None = None,
        fcc_type: str = "",
    ) -> str:
        url = f"http://{http_host}:{http_port}/{path_mode}/{host}:{port}"
        params: list[str] = []
        if fcc_ip and fcc_port:
            params.append(f"fcc={fcc_ip}:{int(fcc_port)}")
            if fcc_type:
                params.append(f"fcc-type={fcc_type}")
        if fec_port:
            params.append(f"fec={int(fec_port)}")
        if params:
            url += "?" + "&".join(params)
        return url

    @staticmethod
    def make_source_url(
        path_mode: str,
        host: str,
        port: int,
        fcc_ip: str = "",
        fcc_port: int | None = None,
        fec_port: int | None = None,
        fcc_type: str = "",
    ) -> str:
        scheme = "rtp" if path_mode == "rtp" else "udp"
        url = f"{scheme}://{host}:{port}"
        params: list[str] = []
        if fcc_ip and fcc_port:
            params.append(f"fcc={fcc_ip}:{int(fcc_port)}")
            if fcc_type:
                params.append(f"fcc-type={fcc_type}")
        if fec_port:
            params.append(f"fec={int(fec_port)}")
        if params:
            url += "?" + "&".join(params)
        return url

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
            # When actual dimensions are known, always recompute quality_group from
            # them — a stale value (e.g. "高清频道" carried on a 3840x2160 stream)
            # must not survive into export grouping or the quality statistics.
            if width and height:
                quality_group = stream_quality_group(width, height)
            else:
                quality_group = str(row.get("quality_group") or stream_quality_group(width, height)).strip()
                if quality_group not in {"4K高清", "高清频道", "普通频道", "未识别"}:
                    quality_group = stream_quality_group(width, height)
            channels.append(ChannelRecord(
                key=key,
                host=host,
                port=port,
                name=name,
                category=category,
                packets=packets,
                probe_status=str(row.get("probe_status", "not_probed")),
                probe_message=str(row.get("probe_message", "未识别")),
                codec_name=str(row.get("codec_name", "")),
                width=width,
                height=height,
                frame_rate=str(row.get("frame_rate", "")),
                resolution_label=str(row.get("resolution_label", "未识别")),
                quality_group=quality_group,
                fcc_ip=str(row.get("fcc_ip", "") or "").strip(),
                fcc_port=self._safe_int(row.get("fcc_port")),
                fec_port=self._safe_int(row.get("fec_port")),
                tvg_id=str(row.get("tvg_id", "") or "").strip(),
                tvg_name=str(row.get("tvg_name", "") or "").strip(),
                tvg_logo=str(row.get("tvg_logo", "") or "").strip(),
                epg_source=str(row.get("epg_source", "") or "").strip(),
                is_primary=bool(row.get("is_primary", False)),
                export_health_status=str(row.get("export_health_status", "") or "").strip(),
                export_health_http_code=self._safe_int(row.get("export_health_http_code")),
                export_health_bytes=self._safe_int(row.get("export_health_bytes")) or 0,
                export_health_speed=self._safe_int(row.get("export_health_speed")) or 0,
                export_health_elapsed_ms=self._safe_int(row.get("export_health_elapsed_ms")) or 0,
                export_health_checked_at=self._safe_int(row.get("export_health_checked_at")),
                export_health_message=str(row.get("export_health_message", "") or "").strip(),
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

    def export(self, rows: list[dict[str, Any]], settings: dict[str, Any], operator_channels: dict[str, Any] | None = None) -> dict[str, Any]:
        channels = self._normalize_channels(rows)
        if not channels:
            raise ValueError("没有填写任何频道名称，未生成输出文件")
        http_host = str(settings.get("http_host", "")).strip()
        http_port = int(settings.get("http_port", 5140))
        path_mode = str(settings.get("path_mode", "rtp")).strip().lower()
        if path_mode not in {"rtp", "udp"}:
            path_mode = "rtp"
        epg_url = str(settings.get("epg_url", "") or "").strip()
        catchup_days = int(settings.get("catchup_days", 7) or 0)
        catchup_template = str(settings.get("catchup_source_template", "") or "").strip()
        fcc_type = str(settings.get("fcc_type", "") or "").strip()
        op_ch = operator_channels or {}
        best_channels = self._select_best_channels(channels)
        quality_group_counts = self._quality_group_counts(channels)
        m3u_kwargs = dict(http_host=http_host, http_port=http_port, path_mode=path_mode,
                          epg_url=epg_url, catchup_days=catchup_days,
                          catchup_template=catchup_template, op_ch=op_ch, fcc_type=fcc_type)
        # New canonical files
        best_m3u_path  = self.output_dir / "channels-best.m3u"
        all_m3u_path   = self.output_dir / "channels-all.m3u"
        rtp_best_path  = self.output_dir / "channels-rtp2httpd-best.m3u"
        rtp_all_path   = self.output_dir / "channels-rtp2httpd-all.m3u"
        # Legacy aliases (same content as best)
        direct_m3u_path = self.output_dir / "channels-direct.m3u"
        source_m3u_path = self.output_dir / "channels-rtp2httpd-source.m3u"
        json_path = self.output_dir / "channels.json"
        txt_path  = self.output_dir / "channels.txt"
        csv_path  = self.output_dir / "channels.csv"
        self._write_m3u(best_channels, best_m3u_path,  url_mode="direct", **m3u_kwargs)
        self._write_m3u(channels,      all_m3u_path,   url_mode="direct", **m3u_kwargs)
        self._write_m3u(best_channels, rtp_best_path,  url_mode="source", **m3u_kwargs)
        self._write_m3u(channels,      rtp_all_path,   url_mode="source", **m3u_kwargs)
        # Write aliases (same bytes as new files)
        import shutil as _shutil
        _shutil.copy2(best_m3u_path, direct_m3u_path)
        _shutil.copy2(rtp_best_path, source_m3u_path)
        self._write_playlist_json(channels, json_path, path_mode, fcc_type=fcc_type)
        self._write_txt(channels, txt_path, http_host, http_port, path_mode, fcc_type=fcc_type)
        self._write_csv(channels, csv_path, http_host, http_port, path_mode, fcc_type=fcc_type)
        return {
            "count": len(channels),
            "best_count": len(best_channels),
            "quality_group_counts": quality_group_counts,
            "unclassified_resolution_count": sum(1 for channel in channels if channel.quality_group not in QUALITY_GROUP_OPTIONS),
            "files": {
                "best_m3u": best_m3u_path.name,
                "all_m3u": all_m3u_path.name,
                "rtp_best_m3u": rtp_best_path.name,
                "rtp_all_m3u": rtp_all_path.name,
                "direct_m3u": direct_m3u_path.name,
                "source_m3u": source_m3u_path.name,
                "json": json_path.name,
                "txt": txt_path.name,
                "csv": csv_path.name,
            },
        }

    def _select_best_channels(self, channels: list[ChannelRecord]) -> list[ChannelRecord]:
        """Return one best channel per group (primary source per tvg-id/name group)."""
        groups: dict[str, list[ChannelRecord]] = {}
        for ch in channels:
            gk = channel_group_key({"tvg_id": ch.tvg_id, "name": ch.name, "key": ch.key})
            groups.setdefault(gk, []).append(ch)
        best: list[ChannelRecord] = []
        for members in groups.values():
            primary = max(members, key=lambda c: channel_primary_score({
                "quality_group": c.quality_group, "probe_status": c.probe_status,
                "width": c.width, "height": c.height,
                "fcc_ip": c.fcc_ip, "fcc_port": c.fcc_port,
                "fec_port": c.fec_port, "packets": c.packets,
                "is_primary": c.is_primary,
                "export_health_status": c.export_health_status,
                "export_health_speed": c.export_health_speed,
            }))
            best.append(primary)
        best.sort(key=self._channel_sort_key)
        return best

    def _quality_group_counts(self, channels: list[ChannelRecord]) -> dict[str, int]:
        counts = {name: 0 for name in QUALITY_GROUP_OPTIONS}
        for channel in channels:
            if channel.quality_group in counts:
                counts[channel.quality_group] += 1
        return counts

    def _write_m3u(
        self,
        channels: list[ChannelRecord],
        target: Path,
        http_host: str,
        http_port: int,
        path_mode: str,
        url_mode: str,
        epg_url: str = "",
        catchup_days: int = 0,
        catchup_template: str = "",
        fcc_type: str = "",
        op_ch: dict[str, Any] | None = None,
    ) -> None:
        # Each source is written exactly once, grouped by its original category.
        op_ch = op_ch or {}
        with target.open("w", encoding="utf-8", newline="\n") as handle:
            if epg_url:
                safe_epg_url = epg_url.replace('"', "%22")
                handle.write(f'#EXTM3U x-tvg-url="{safe_epg_url}"\n')
            else:
                handle.write("#EXTM3U\n")
            for channel in channels:
                self._write_m3u_item(handle, channel, channel.category, http_host, http_port, path_mode, url_mode, catchup_days, catchup_template, op_ch, fcc_type)

    def _write_m3u_item(
        self,
        handle,
        channel: ChannelRecord,
        group: str,
        http_host: str,
        http_port: int,
        path_mode: str,
        url_mode: str,
        catchup_days: int = 0,
        catchup_template: str = "",
        op_ch: dict[str, Any] | None = None,
        fcc_type: str = "",
    ) -> None:
        safe_group = group.replace('"', "'")
        tvg_name = (channel.tvg_name or channel.name).replace('"', "'")
        tvg_id = (channel.tvg_id or channel.tvg_name or channel.name).replace('"', "'")
        tvg_logo = channel.tvg_logo.replace('"', "%22")
        if url_mode == "source" or not http_host:
            url = self.make_source_url(path_mode, channel.host, channel.port, channel.fcc_ip, channel.fcc_port, channel.fec_port, fcc_type)
        else:
            url = self.make_http_url(http_host, http_port, path_mode, channel.host, channel.port, channel.fcc_ip, channel.fcc_port, channel.fec_port, fcc_type)
        logo_attr = f' tvg-logo="{tvg_logo}"' if tvg_logo else ""
        # Catchup attributes for channels that support time-shift
        catchup_attr = ""
        if catchup_days > 0 and op_ch:
            ch_info = op_ch.get(channel.key) or {}
            if ch_info.get("time_shift"):
                catchup_source_attr = ""
                if catchup_template:
                    channel_id = ch_info.get("channel_id", "") or tvg_id
                    safe_cu = catchup_template.replace("{channel_id}", str(channel_id)).replace('"', "%22")
                    catchup_source_attr = f' catchup-source="{safe_cu}"'
                catchup_attr = f' catchup="default" catchup-days="{catchup_days}"{catchup_source_attr}'
        handle.write(f'#EXTINF:-1 tvg-id="{tvg_id}" tvg-name="{tvg_name}"{logo_attr} group-title="{safe_group}"{catchup_attr},{channel.name}\n')
        handle.write(f"{url}\n")

    def _write_txt(
        self,
        channels: list[ChannelRecord],
        target: Path,
        http_host: str,
        http_port: int,
        path_mode: str,
        fcc_type: str = "",
    ) -> None:
        # Each source is written exactly once, grouped by its original category.
        grouped: dict[str, list[ChannelRecord]] = {category: [] for category in CATEGORY_OPTIONS}
        for channel in channels:
            grouped.setdefault(channel.category, []).append(channel)
        for group_channels in grouped.values():
            group_channels.sort(key=self._quality_sort_key)
        ordered_sections: list[tuple[str, list[ChannelRecord]]] = [
            (category, grouped.get(category, [])) for category in CATEGORY_OPTIONS
        ]
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
                    if http_host:
                        url = self.make_http_url(http_host, http_port, path_mode, channel.host, channel.port, channel.fcc_ip, channel.fcc_port, channel.fec_port, fcc_type)
                    else:
                        url = self.make_source_url(path_mode, channel.host, channel.port, channel.fcc_ip, channel.fcc_port, channel.fec_port, fcc_type)
                    handle.write(f"{channel.name},{url}\n")

    def _write_csv(
        self,
        channels: list[ChannelRecord],
        target: Path,
        http_host: str,
        http_port: int,
        path_mode: str,
        fcc_type: str = "",
    ) -> None:
        # Each source is written exactly once; the row carries both its
        # original category and its quality group as columns.
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
                "EPG ID",
                "EPG名称",
                "台标",
                "EPG来源",
                "FCC服务器IP",
                "FCC服务器端口",
                "源地址",
                "播放地址",
                "组播IP",
                "端口",
                "抓到包数",
            ])
            for channel in channels:
                self._write_csv_row(writer, channel, channel.category, http_host, http_port, path_mode, fcc_type)

    def _write_csv_row(self, writer: csv.writer, channel: ChannelRecord, display_group: str, http_host: str, http_port: int, path_mode: str, fcc_type: str = "") -> None:
        source = self.make_source_url(path_mode, channel.host, channel.port, channel.fcc_ip, channel.fcc_port, channel.fec_port, fcc_type)
        if http_host:
            url = self.make_http_url(http_host, http_port, path_mode, channel.host, channel.port, channel.fcc_ip, channel.fcc_port, channel.fec_port, fcc_type)
        else:
            url = source
        resolution = f"{channel.width}x{channel.height}" if channel.width and channel.height else channel.resolution_label
        writer.writerow([
            display_group,
            channel.category,
            channel.name,
            channel.quality_group,
            resolution,
            channel.codec_name,
            channel.frame_rate,
            channel.tvg_id,
            channel.tvg_name,
            channel.tvg_logo,
            channel.epg_source,
            channel.fcc_ip,
            channel.fcc_port or "",
            source,
            url,
            channel.host,
            channel.port,
            channel.packets,
        ])

    def _write_playlist_json(self, channels: list[ChannelRecord], target: Path, path_mode: str, fcc_type: str = "") -> None:
        payload: dict[str, Any] = {}
        for index, channel in enumerate(channels, start=1):
            source = self.make_source_url(path_mode, channel.host, channel.port, channel.fcc_ip, channel.fcc_port, channel.fec_port, fcc_type)
            definition = channel.resolution_label if channel.resolution_label != "未识别" else ""
            payload[channel.name] = {
                "chno": index,
                "tvg_id": channel.tvg_id or channel.name,
                "tvg_name": channel.tvg_name or channel.name,
                "tvg_logo": channel.tvg_logo,
                "epg_source": channel.epg_source,
                "group_title": channel.category,
                "definition": definition,
                "flag": [] if channel.probe_status != "failed" else ["probe_failed"],
                "live": {
                    "local-multicast": {
                        "type": "rtp" if path_mode == "rtp" else "udp",
                        "addr": source,
                    },
                },
                "timeshift": {},
                "sniffer": {
                    "key": channel.key,
                    "packets": channel.packets,
                    "codec": channel.codec_name,
                    "width": channel.width,
                    "height": channel.height,
                    "fcc": f"{channel.fcc_ip}:{channel.fcc_port}" if channel.fcc_ip and channel.fcc_port else "",
                    "fec": channel.fec_port or "",
                    "export_health": {
                        "status": channel.export_health_status,
                        "http_code": channel.export_health_http_code,
                        "bytes": channel.export_health_bytes,
                        "speed": channel.export_health_speed,
                        "elapsed_ms": channel.export_health_elapsed_ms,
                        "checked_at": channel.export_health_checked_at,
                        "message": channel.export_health_message,
                    },
                },
            }
        with target.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")

    def hls_m3u(self, channels_data: dict, base_url: str, epg_url: str = "") -> str:
        """Generate in-memory M3U with HLS stream URLs for browser-based players."""
        channels = self._normalize_channels(list(channels_data.values()))
        best = self._select_best_channels(channels)
        best.sort(key=self._channel_sort_key)
        lines: list[str] = []
        safe_epg = epg_url.replace('"', "%22")
        lines.append(f'#EXTM3U x-tvg-url="{safe_epg}"' if epg_url else "#EXTM3U")
        for ch in best:
            hls_key = f"{ch.host}_{ch.port}"
            url = f"{base_url}/hls/{hls_key}/stream.m3u8"
            tvg_id = (ch.tvg_id or ch.tvg_name or ch.name).replace('"', "'")
            tvg_name = (ch.tvg_name or ch.name).replace('"', "'")
            safe_group = ch.category.replace('"', "'")
            logo_attr = f' tvg-logo="{ch.tvg_logo.replace(chr(34), "%22")}"' if ch.tvg_logo else ""
            lines.append(
                f'#EXTINF:-1 tvg-id="{tvg_id}" tvg-name="{tvg_name}"{logo_attr} group-title="{safe_group}",{ch.name}'
            )
            lines.append(url)
        return "\n".join(lines) + "\n"
