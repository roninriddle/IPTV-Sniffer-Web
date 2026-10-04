#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""On-demand FFmpeg HLS remux for browser-compatible IPTV live streaming."""
from __future__ import annotations

import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from utils import valid_ipv4_multicast
from services.media_task_service import MediaTaskManager, MediaCapacityError, reap_process

HLS_BASE_DIR = Path("/tmp/iptv-hls")
HLS_IDLE_TIMEOUT = 60       # seconds before auto-stop
HLS_SEGMENT_DURATION = 2    # seconds per .ts segment
HLS_LIST_SIZE = 5           # segments kept in playlist
HLS_START_TIMEOUT = 10      # seconds to wait for first playlist


class HlsService:
    def __init__(self, logger: Any, tasks=None) -> None:
        self.logger = logger
        self.tasks = tasks or MediaTaskManager()
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._streams: dict[str, dict[str, Any]] = {}
        self._waiters = set()
        threading.Thread(target=self._watchdog, daemon=True, name="hls-watchdog").start()

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def make_key(host: str, port: int) -> str:
        """Convert host:port to filesystem-safe HLS key."""
        return f"{host}_{port}"

    @staticmethod
    def parse_key(hls_key: str) -> tuple[str, int] | None:
        """Parse hls_key back to (host, port), or None if invalid."""
        idx = hls_key.rfind("_")
        if idx < 1:
            return None
        try:
            host, port = hls_key[:idx], int(hls_key[idx + 1:])
            if not valid_ipv4_multicast(host) or not 1 <= port <= 65535:
                return None
            if HlsService.make_key(host, port) != hls_key:
                return None
            return host, port
        except ValueError:
            return None

    def _watchdog(self) -> None:
        while not self._stop_event.wait(15):
            now = time.time()
            to_stop: list[str] = []
            with self._lock:
                for k, s in self._streams.items():
                    dead = s["proc"].poll() is not None
                    idle = (now - s["last_access"]) > HLS_IDLE_TIMEOUT
                    if dead or idle:
                        to_stop.append(k)
            for k in to_stop:
                with self._lock:
                    current = self._streams.get(k)
                    if current and (current["proc"].poll() is not None or time.time()-current["last_access"] > HLS_IDLE_TIMEOUT):
                        self._stop_locked(k)

    def _stop_locked(self, key: str) -> None:
        s = self._streams.pop(key, None)
        if not s:
            return
        reap_process(s["proc"])
        if s.get("lease"):
            s["lease"].close()
        shutil.rmtree(s["dir"], ignore_errors=True)
        self.logger.info(f"HLS 转流已停止：{s['host']}:{s['port']}")

    def _stop(self, key: str) -> None:
        with self._lock:
            self._stop_locked(key)

    # ── public API ────────────────────────────────────────────────────────────

    def ensure(self, host: str, port: int, path_mode: str = "rtp", localaddr: str = "") -> tuple[str, Path]:
        """Start HLS stream if not already running. Returns (hls_key, hls_dir)."""
        key = self.make_key(host, port)
        if self.parse_key(key) is None:
            raise ValueError("HLS 仅支持有效的 IPv4 组播地址与端口")
        with self._lock:
            s = self._streams.get(key)
            if s and s["proc"].poll() is None and s.get("path_mode", "rtp") == path_mode and s.get("localaddr", "") == localaddr:
                s["last_access"] = time.time()
                return key, s["dir"]
            if s:
                self._stop_locked(key)

            hls_dir = HLS_BASE_DIR / key

            scheme = "rtp" if path_mode == "rtp" else "udp"
            iurl = f"{scheme}://{host}:{port}"
            if localaddr:
                iurl += f"?localaddr={localaddr}"

            cmd = [
                "ffmpeg", "-y",
                "-i", iurl,
                "-c", "copy",
                "-f", "hls",
                "-hls_time", str(HLS_SEGMENT_DURATION),
                "-hls_list_size", str(HLS_LIST_SIZE),
                "-hls_flags", "delete_segments+temp_file",
                "-hls_segment_filename", str(hls_dir / "%05d.ts"),
                str(hls_dir / "stream.m3u8"),
            ]
            lease = self.tasks.acquire("hls", key)
            try:
                hls_dir.mkdir(parents=True, exist_ok=True)
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                lease.close()
                shutil.rmtree(hls_dir, ignore_errors=True)
                raise
            self._streams[key] = {
                "proc": proc,
                "path_mode": path_mode,
                "localaddr": localaddr,
                "lease": lease,
                "dir": hls_dir,
                "last_access": time.time(),
                "host": host,
                "port": port,
            }
            lease.attach(lambda: self._stop(key))
            self.logger.info(
                f"HLS 转流已启动：{host}:{port}" + (f"，localaddr={localaddr}" if localaddr else "")
            )
            return key, hls_dir

    def claim_waiter(self, key):
        with self._lock:
            if key in self._waiters:
                raise MediaCapacityError("该频道正在起播，请稍后重试")
            self._waiters.add(key)

    def release_waiter(self, key):
        with self._lock:
            self._waiters.discard(key)

    def existing_directory(self, key: str) -> Path | None:
        """A segment read may touch an active stream, but must never create one."""
        if self.parse_key(key) is None:
            return None
        with self._lock:
            stream = self._streams.get(key)
            if not stream or stream["proc"].poll() is not None:
                return None
            stream["last_access"] = time.time()
            return stream["dir"]

    def touch(self, key: str) -> None:
        with self._lock:
            if key in self._streams:
                self._streams[key]["last_access"] = time.time()

    def stop(self, key: str) -> None:
        self._stop(key)

    def shutdown(self) -> None:
        self._stop_event.set()
        self.stop_all()

    def stop_all(self) -> None:
        with self._lock:
            keys = list(self._streams.keys())
        for k in keys:
            self._stop(k)

    def status(self) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            return [
                {
                    "key": k,
                    "host": s["host"],
                    "port": s["port"],
                    "running": s["proc"].poll() is None,
                    "idle_seconds": int(now - s["last_access"]),
                }
                for k, s in self._streams.items()
            ]

    @staticmethod
    def read_playlist(m3u8_path: Path) -> str:
        """Return playlist content with segment names normalised to basename only."""
        text = m3u8_path.read_text(encoding="utf-8", errors="replace")
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            # Non-comment, non-empty lines are segment filenames
            if stripped and not stripped.startswith("#"):
                stripped = Path(stripped).name
            lines.append(stripped)
        return "\n".join(lines) + "\n"
