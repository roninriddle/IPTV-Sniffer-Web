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
from urllib.request import Request, build_opener
from services.io_limits import HttpOnlyRedirects, validate_http_url, read_bounded, gunzip_bounded, MAX_HTTP_BYTES
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
    text = text.replace("cctv4中文国际欧洲", "cctv4euo")
    text = text.replace("cctv4欧洲", "cctv4euo")
    text = text.replace("cctv4中文国际美洲", "cctv4ame")
    text = text.replace("cctv4美洲", "cctv4ame")
    return text


class EpgService:
    def __init__(self, logger: AppLogger, cache_path: Path) -> None:
        self.logger = logger
        self.cache_path = cache_path
        self._lock = threading.RLock()
        self._refresh_thread: threading.Thread | None = None
        self._boot_thread_started = False
        self._stop_event = threading.Event()
        self._auto_thread = None
        self._refresh_mutex = threading.Lock()
        self._last_attempt = {}
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
        # Primary URL is fixed to the first source loaded/refreshed; does not shift on subsequent refreshes
        self._primary_url: str = ""
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
            primary_url = payload.get("url", "")
            if primary_url:
                self._primary_url = primary_url
            # Restore all persisted per-source data
            saved_sources = data.get("_source_channels", {})
            if isinstance(saved_sources, dict):
                for url, chans in saved_sources.items():
                    if url and isinstance(chans, list):
                        self._source_channels[url] = [c for c in chans if isinstance(c, dict)]
            saved_logos = data.get("_source_logos", {})
            if isinstance(saved_logos, dict):
                for url, lgos in saved_logos.items():
                    if url and isinstance(lgos, list):
                        self._source_logos[url] = [l for l in lgos if isinstance(l, dict)]
            saved_times = data.get("_source_refresh_times", {})
            if isinstance(saved_times, dict):
                for url, ts in saved_times.items():
                    if url and isinstance(ts, (int, float)):
                        self._source_refresh_times[url] = float(ts)
            # Fall back: populate from primary cache entry if source dict was empty
            if primary_url and primary_url not in self._source_channels and payload.get("channels"):
                self._source_channels[primary_url] = payload["channels"]
                if payload.get("last_refresh"):
                    self._source_refresh_times[primary_url] = float(payload["last_refresh"])
            if primary_url and primary_url not in self._source_logos and payload.get("logos"):
                self._source_logos[primary_url] = payload["logos"]
            self._rebuild_index_locked()

    def _save_cache_locked(self) -> None:
        data = dict(self._cache)
        data["_source_channels"] = dict(self._source_channels)
        data["_source_logos"] = dict(self._source_logos)
        data["_source_refresh_times"] = dict(self._source_refresh_times)
        _atomic_dump_json(self.cache_path, data)

    def _rebuild_index_locked(self) -> None:
        # Primary URL is stable (_primary_url); it gets first-write priority in the merged index.
        index: dict[str, dict[str, Any]] = {}
        primary_url = self._primary_url
        # Build ordered list: primary source first, then the rest in insertion order
        ordered_sources: list[tuple[str, list[dict[str, Any]]]] = []
        if primary_url and primary_url in self._source_channels:
            ordered_sources.append((primary_url, self._source_channels[primary_url]))
        for url, channels in self._source_channels.items():
            if url != primary_url:
                ordered_sources.append((url, channels))
        # Fall back to _cache entry if _source_channels not yet populated
        if not ordered_sources:
            ordered_sources = [("", self._cache.get("channels", []))]
        for source_url, channels in ordered_sources:
            for channel in channels:
                names = [str(channel.get("name", "")), *(str(item) for item in channel.get("names", []) or [])]
                for name in names:
                    normalized = normalize_channel_name(name)
                    if normalized and normalized not in index:
                        # Annotate with the actual source so enrich_item can record it accurately
                        index[normalized] = {**channel, "_source_url": source_url}
        self._index = index
        logo_index: dict[str, dict[str, Any]] = {}
        ordered_logo_sources: list[tuple[str, list[dict[str, Any]]]] = []
        if primary_url and primary_url in self._source_logos:
            ordered_logo_sources.append((primary_url, self._source_logos[primary_url]))
        for url, logos in self._source_logos.items():
            if url != primary_url:
                ordered_logo_sources.append((url, logos))
        if not ordered_logo_sources:
            ordered_logo_sources = [("", self._cache.get("logos", []))]
        for _, logos in ordered_logo_sources:
            for logo in logos:
                names = [str(logo.get("name", "")), *(str(item) for item in logo.get("names", []) or [])]
                for name in names:
                    normalized = normalize_channel_name(name)
                    if normalized and normalized not in logo_index:
                        logo_index[normalized] = logo
        self._logo_index = logo_index

    def select_primary(self, url: str, logo_url: str = "") -> None:
        """The selected settings URL wins; other cached sources remain fallbacks."""
        with self._lock:
            if self._primary_url == url:
                return
            self._primary_url = url
            self._cache.update(url=url, logo_url=logo_url,
                channels=self._source_channels.get(url, []),
                logos=self._source_logos.get(url, []),
                last_refresh=self._source_refresh_times.get(url), last_error="")
            self._rebuild_index_locked()
            self._save_cache_locked()

    def auto_refresh_tick(self, settings):
        url = str(settings.get("epg_url") or "").strip()
        logo = str(settings.get("logo_url") or "").strip() if settings.get("use_logo", True) else ""
        self.select_primary(url, logo)
        if not url or not settings.get("auto_epg", True) or not settings.get("use_epg", True):
            return
        with self._lock:
            previous = max(self._source_refresh_times.get(url, 0), self._last_attempt.get(url, 0))
        if not previous or time.time() - previous >= EPG_REFRESH_INTERVAL:
            self.refresh_async(url, logo)

    def start_auto_refresh(self, settings_store: Any) -> None:
        with self._lock:
            if self._boot_thread_started:
                return
            self._boot_thread_started = True
        def worker():
            while not self._stop_event.is_set():
                try:
                    self.auto_refresh_tick(settings_store.load())
                except Exception as exc:
                    self.logger.warning(f"EPG 定时检查失败：{exc}")
                self._stop_event.wait(60)
        self._auto_thread = threading.Thread(target=worker, daemon=True, name="epg-refresh")
        self._auto_thread.start()

    def shutdown(self):
        self._stop_event.set()
        if self._auto_thread and self._auto_thread is not threading.current_thread():
            self._auto_thread.join(timeout=2)

    def refresh_async(self, url: str, logo_url: str = "") -> dict[str, Any]:
        url, logo_url = str(url or "").strip(), str(logo_url or "").strip()
        if not url:
            raise ValueError("EPG 地址不能为空")
        validate_http_url(url)
        if logo_url:
            validate_http_url(logo_url)
        with self._lock:
            if self._refresh_thread and self._refresh_thread.is_alive():
                return self.status()
            self._cache["last_error"] = ""
            self._last_attempt[url] = time.time()
            self._refresh_thread = threading.Thread(target=self.refresh, args=(url, logo_url), daemon=True)
            self._refresh_thread.start()
            return self.status()

    def refresh(self, url: str, logo_url: str = "") -> dict[str, Any]:
        with self._refresh_mutex:
            return self._refresh(url, logo_url)

    def _refresh(self, url: str, logo_url: str = "") -> dict[str, Any]:
        url = str(url or "").strip()
        logo_url = str(logo_url or "").strip()
        if not url:
            raise ValueError("EPG 地址不能为空")
        try:
            raw = self._fetch(url)
            channels = self._parse_xmltv(raw)
            logos = self._fetch_logo_map(logo_url) if logo_url else []
            now = int(time.time())
            with self._lock:
                # _primary_url is set once (first source); subsequent refreshes don't displace it
                if not self._primary_url:
                    self._primary_url = url
                is_primary = (url == self._primary_url)
                # Update the single-source cache entry only for the primary source
                if is_primary:
                    self._cache.update({
                        "url": url,
                        "logo_url": logo_url,
                        "channels": channels,
                        "logos": logos,
                        "last_refresh": now,
                        "last_error": "",
                    })
                else:
                    self._cache["last_error"] = ""
                self._source_channels[url] = channels
                self._source_refresh_times[url] = float(now)
                if logos:
                    self._source_logos[url] = logos
                self._rebuild_index_locked()
                self._save_cache_locked()
            self.logger.info(f"EPG 刷新完成：{url}，频道 {len(channels)} 个，台标 {len(logos)} 个，已合并来源 {len(self._source_channels)} 个")
            return self.status()
        except Exception as exc:
            message = str(exc)
            with self._lock:
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
        validate_http_url(url)
        request = Request(url, headers={"User-Agent": "IPTV-Sniffer-Web/EPG"})
        with build_opener(HttpOnlyRedirects()).open(request, timeout=EPG_FETCH_TIMEOUT) as response:
            validate_http_url(response.geturl())
            data = read_bounded(response, MAX_HTTP_BYTES)
        if url.lower().endswith(".gz") or data[:2] == b"\x1f\x8b":
            data = gunzip_bounded(data)
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

    @staticmethod
    def _substring_match_ok(a: str, b: str) -> bool:
        """True if a is substring of b (or vice versa) without a digit-boundary collision.

        Single-character names are only eligible for exact matching.  Allowing them
        into fuzzy matching makes an EPG alias such as "C" match every unmatched
        CCTV/CETV/CGTV channel and can replace the operator-provided display name.

        Prevents "cctv1" from matching "cctv10" / "cctv12" — after the shared prefix,
        if the very next character in the longer string is a digit AND the shorter string
        already ends with a digit, it means they share only a numeric prefix, not the
        same channel number.
        """
        if min(len(a), len(b)) < 2:
            return False
        longer, shorter = (b, a) if len(b) >= len(a) else (a, b)
        idx = longer.find(shorter)
        if idx == -1:
            return False
        after = longer[idx + len(shorter):]
        if after and after[0].isdigit() and shorter and shorter[-1].isdigit():
            return False
        return True

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
                if self._substring_match_ok(normalized, key):
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
                if self._substring_match_ok(normalized, key):
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
                item["epg_source"] = str(match.get("_source_url") or epg_url or "").strip()
                item["epg_matched_at"] = int(time.time())
        if not str(item.get("tvg_logo", "")).strip():
            logo_match = self.match_logo(str(item.get("tvg_name") or name))
            if logo_match:
                item["tvg_logo"] = str(logo_match.get("logo", "")).strip()
        return item
