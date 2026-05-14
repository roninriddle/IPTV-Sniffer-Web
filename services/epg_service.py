#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XMLTV EPG cache and channel matcher."""
from __future__ import annotations

import gzip
import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from xml.etree import ElementTree

from services.log_service import AppLogger

EPG_REFRESH_INTERVAL = 12 * 3600
EPG_FETCH_TIMEOUT = 25


def _atomic_dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, path)
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass


def _safe_load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def normalize_channel_name(value: str) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("＋", "+").replace("－", "-")
    replacements = (
        "频道高清", "超高清", "高清", "超清", "标清", "频道", "电视台",
        "iptv", "uhd", "hd",
    )
    for token in replacements:
        text = text.replace(token, "")
    text = re.sub(r"[\s\-_·•.。:：/\\|()\[\]【】,，+]+", "", text)
    text = re.sub(r"cctv0+(\d+)", r"cctv\1", text)
    return text


class EpgService:
    def __init__(self, logger: AppLogger, cache_path: Path) -> None:
        self.logger = logger
        self.cache_path = cache_path
        self._lock = threading.RLock()
        self._refresh_thread: threading.Thread | None = None
        self._boot_thread_started = False
        self._cache: dict[str, Any] = {
            "url": "",
            "logo_url": "",
            "channels": [],
            "logos": [],
            "last_refresh": None,
            "last_error": "",
        }
        self._index: dict[str, dict[str, Any]] = {}
        self._logo_index: dict[str, dict[str, Any]] = {}
        # Per-source channel/logo lists — keyed by URL, merged into _index at rebuild time
        self._source_channels: dict[str, list[dict[str, Any]]] = {}
        self._source_logos: dict[str, list[dict[str, Any]]] = {}
        self._source_refresh_times: dict[str, float] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        data = _safe_load_json(self.cache_path)
        channels = data.get("channels")
        if not isinstance(channels, list):
            channels = []
        logos = data.get("logos")
        if not isinstance(logos, list):
            logos = []
        payload = {
            "url": str(data.get("url", "")),
            "logo_url": str(data.get("logo_url", "")),
            "channels": [item for item in channels if isinstance(item, dict)],
            "logos": [item for item in logos if isinstance(item, dict)],
            "last_refresh": data.get("last_refresh"),
            "last_error": str(data.get("last_error", "")),
        }
        with self._lock:
            self._cache = payload
            url = payload.get("url", "")
            if url and payload.get("channels"):
                self._source_channels[url] = payload["channels"]
                if payload.get("last_refresh"):
                    self._source_refresh_times[url] = float(payload["last_refresh"])
            if url and payload.get("logos"):
                self._source_logos[url] = payload["logos"]
            self._rebuild_index_locked()

    def _save_cache_locked(self) -> None:
        _atomic_dump_json(self.cache_path, self._cache)

    def _rebuild_index_locked(self) -> None:
        # Merge channels from all known sources; primary source (_cache url) has first-write priority
        index: dict[str, dict[str, Any]] = {}
        primary_url = self._cache.get("url", "")
        # Build ordered list: primary source first, then rest
        all_channel_lists: list[list[dict[str, Any]]] = []
        if primary_url and primary_url in self._source_channels:
            all_channel_lists.append(self._source_channels[primary_url])
        for url, channels in self._source_channels.items():
            if url != primary_url:
                all_channel_lists.append(channels)
        # Fall back to _cache if _source_channels not yet populated
        if not all_channel_lists:
            all_channel_lists = [self._cache.get("channels", [])]
        for channels in all_channel_lists:
            for channel in channels:
                names = [str(channel.get("name", "")), *(str(item) for item in channel.get("names", []) or [])]
                for name in names:
                    normalized = normalize_channel_name(name)
                    if normalized and normalized not in index:
                        index[normalized] = channel
        self._index = index
        logo_index: dict[str, dict[str, Any]] = {}
        all_logo_lists: list[list[dict[str, Any]]] = []
        if primary_url and primary_url in self._source_logos:
            all_logo_lists.append(self._source_logos[primary_url])
        for url, logos in self._source_logos.items():
            if url != primary_url:
                all_logo_lists.append(logos)
        if not all_logo_lists:
            all_logo_lists = [self._cache.get("logos", [])]
        for logos in all_logo_lists:
            for logo in logos:
                names = [str(logo.get("name", "")), *(str(item) for item in logo.get("names", []) or [])]
                for name in names:
                    normalized = normalize_channel_name(name)
                    if normalized and normalized not in logo_index:
                        logo_index[normalized] = logo
        self._logo_index = logo_index

    def start_auto_refresh(self, settings_store: Any) -> None:
        with self._lock:
            if self._boot_thread_started:
                return
            self._boot_thread_started = True

        def worker() -> None:
            settings = settings_store.load()
            if not settings.get("auto_epg", True):
                return
            url = str(settings.get("epg_url", "")).strip()
            if not url:
                return
            logo_url = str(settings.get("logo_url", "")).strip()
            with self._lock:
                last_refresh = self._cache.get("last_refresh")
                fresh = isinstance(last_refresh, (int, float)) and time.time() - float(last_refresh) < EPG_REFRESH_INTERVAL
            if fresh and self.count() > 0:
                return
            self.refresh(url, logo_url)

        threading.Thread(target=worker, daemon=True).start()

    def refresh_async(self, url: str, logo_url: str = "") -> dict[str, Any]:
        url = str(url or "").strip()
        logo_url = str(logo_url or "").strip()
        if not url:
            raise ValueError("EPG 地址不能为空")
        with self._lock:
            if self._refresh_thread and self._refresh_thread.is_alive():
                return self.status()
            self._cache["url"] = url
            self._cache["logo_url"] = logo_url
            self._cache["last_error"] = ""

        def worker() -> None:
            self.refresh(url, logo_url)

        self._refresh_thread = threading.Thread(target=worker, daemon=True)
        self._refresh_thread.start()
        return self.status()

    def refresh(self, url: str, logo_url: str = "") -> dict[str, Any]:
        url = str(url or "").strip()
        logo_url = str(logo_url or "").strip()
        if not url:
            raise ValueError("EPG 地址不能为空")
        with self._lock:
            self._cache["url"] = url
            self._cache["logo_url"] = logo_url
            self._cache["last_error"] = ""
        try:
            raw = self._fetch(url)
            channels = self._parse_xmltv(raw)
            logos = self._fetch_logo_map(logo_url) if logo_url else list(self._cache.get("logos", []))
            payload = {
                "url": url,
                "logo_url": logo_url,
                "channels": channels,
                "logos": logos,
                "last_refresh": int(time.time()),
                "last_error": "",
            }
            with self._lock:
                self._cache = payload
                self._source_channels[url] = channels
                self._source_refresh_times[url] = float(payload["last_refresh"])
                if logos:
                    self._source_logos[url] = logos
                self._rebuild_index_locked()
                self._save_cache_locked()
            self.logger.info(f"EPG 刷新完成：{url}，频道 {len(channels)} 个，台标 {len(logos)} 个，已合并来源 {len(self._source_channels)} 个")
            return self.status()
        except Exception as exc:
            message = str(exc)
            with self._lock:
                self._cache["url"] = url
                self._cache["last_error"] = message
                self._save_cache_locked()
            self.logger.warning(f"EPG 刷新失败：{url}，{message}")
            return self.status()

    def refresh_logo(self, logo_url: str) -> int:
        """Fetch a standalone logo M3U source and rebuild the logo index. Returns logo count."""
        logo_url = str(logo_url or "").strip()
        if not logo_url:
            return 0
        logos = self._fetch_logo_map(logo_url)
        with self._lock:
            self._source_logos[logo_url] = logos
            self._rebuild_index_locked()
        self.logger.info(f"台标刷新完成：{logo_url}，台标 {len(logos)} 个")
        return len(logos)

    def _fetch(self, url: str) -> bytes:
        request = Request(url, headers={"User-Agent": "IPTV-Sniffer-Web/EPG"})
        with urlopen(request, timeout=EPG_FETCH_TIMEOUT) as response:
            data = response.read()
        if url.lower().endswith(".gz") or data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        return data

    @staticmethod
    def _parse_xmltv(raw: bytes) -> list[dict[str, Any]]:
        root = ElementTree.fromstring(raw)
        channels: list[dict[str, Any]] = []
        for element in root:
            if not element.tag.lower().endswith("channel"):
                continue
            channel_id = str(element.attrib.get("id", "")).strip()
            names: list[str] = []
            logo = ""
            for child in element:
                tag = child.tag.split("}")[-1].lower()
                if tag == "display-name":
                    name = str(child.text or "").strip()
                    if name and name not in names:
                        names.append(name)
                elif tag == "icon" and not logo:
                    logo = str(child.attrib.get("src", "")).strip()
            if not channel_id and not names:
                continue
            primary_name = names[0] if names else channel_id
            channels.append({
                "id": channel_id or primary_name,
                "name": primary_name,
                "names": names,
                "logo": logo,
            })
        return channels

    def _fetch_logo_map(self, url: str) -> list[dict[str, Any]]:
        text = self._fetch(url).decode("utf-8", errors="ignore")
        logos: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in text.splitlines():
            if not line.startswith("#EXTINF"):
                continue
            attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', line))
            logo_url = str(attrs.get("tvg-logo", "")).strip()
            if not logo_url:
                continue
            title = line.rsplit(",", 1)[-1].strip() if "," in line else ""
            names = [str(attrs.get("tvg-name", "")).strip(), title]
            names = [name for name in names if name]
            if not names:
                continue
            normalized = normalize_channel_name(names[0])
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            logos.append({"name": names[0], "names": names, "logo": logo_url})
        return logos

    def count(self) -> int:
        with self._lock:
            return len(self._cache.get("channels", []) or [])

    def source_stats(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            result = {}
            for url, channels in self._source_channels.items():
                result[url] = {
                    "channels": len(channels),
                    "last_refresh": self._source_refresh_times.get(url),
                }
            return result

    def status(self, summary: bool = False) -> dict[str, Any]:
        with self._lock:
            refreshing = bool(self._refresh_thread and self._refresh_thread.is_alive())
            payload = {
                "url": self._cache.get("url", ""),
                "logo_url": self._cache.get("logo_url", ""),
                "channels": len(self._cache.get("channels", []) or []),
                "logos": len(self._cache.get("logos", []) or []),
                "last_refresh": self._cache.get("last_refresh"),
                "last_error": self._cache.get("last_error", ""),
                "refreshing": refreshing,
                "file": str(self.cache_path),
            }
            if summary:
                payload.pop("file", None)
            return payload

    def match(self, name: str) -> dict[str, Any] | None:
        normalized = normalize_channel_name(name)
        if not normalized:
            return None
        with self._lock:
            if normalized in self._index:
                return dict(self._index[normalized])
            candidates: list[tuple[int, dict[str, Any]]] = []
            for key, channel in self._index.items():
                if not key:
                    continue
                if normalized in key or key in normalized:
                    score = min(len(normalized), len(key))
                    candidates.append((score, channel))
            if not candidates:
                return None
            candidates.sort(key=lambda item: item[0], reverse=True)
            return dict(candidates[0][1])

    def match_logo(self, name: str) -> dict[str, Any] | None:
        normalized = normalize_channel_name(name)
        if not normalized:
            return None
        with self._lock:
            if normalized in self._logo_index:
                return dict(self._logo_index[normalized])
            candidates: list[tuple[int, dict[str, Any]]] = []
            for key, logo in self._logo_index.items():
                if not key:
                    continue
                if normalized in key or key in normalized:
                    candidates.append((min(len(normalized), len(key)), logo))
            if not candidates:
                return None
            candidates.sort(key=lambda item: item[0], reverse=True)
            return dict(candidates[0][1])

    def enrich_item(self, item: dict[str, Any], epg_url: str = "", only_missing: bool = True) -> dict[str, Any]:
        name = str(item.get("name", "")).strip()
        if not name:
            return item
        if not (only_missing and str(item.get("tvg_id", "")).strip()):
            match = self.match(name)
            if match:
                item["tvg_id"] = str(match.get("id", "") or match.get("name", "")).strip()
                item["tvg_name"] = str(match.get("name", "") or name).strip()
                item["tvg_logo"] = str(match.get("logo", "")).strip()
                item["epg_source"] = str(self.status(summary=True).get("url") or epg_url or "").strip()
                item["epg_matched_at"] = int(time.time())
        if not str(item.get("tvg_logo", "")).strip():
            logo_match = self.match_logo(str(item.get("tvg_name") or name))
            if logo_match:
                item["tvg_logo"] = str(logo_match.get("logo", "")).strip()
        return item
