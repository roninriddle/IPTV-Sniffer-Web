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

HLS_BASE_DIR = Path("/tmp/iptv-hls")
HLS_IDLE_TIMEOUT = 60       # seconds before auto-stop
HLS_SEGMENT_DURATION = 2    # seconds per .ts segment
HLS_LIST_SIZE = 5           # segments kept in playlist
HLS_START_TIMEOUT = 10      # seconds to wait for first playlist


class HlsService:
    def __init__(self, logger: Any) -> None:
        self.logger = logger
        self._lock = threading.RLock()
        self._streams: dict[str, dict[str, Any]] = {}
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
            return hls_key[:idx], int(hls_key[idx + 1:])
        except ValueError:
            return None

    def _watchdog(self) -> None:
        while True:
            time.sleep(15)
            now = time.time()
            to_stop: list[str] = []
            with self._lock:
                for k, s in self._streams.items():
                    dead = s["proc"].poll() is not None
                    idle = (now - s["last_access"]) > HLS_IDLE_TIMEOUT
                    if dead or idle:
                        to_stop.append(k)
            for k in to_stop:
                self._stop(k)

    def _stop_locked(self, key: str) -> None:
        s = self._streams.pop(key, None)
        if not s:
            return
        p = s["proc"]
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(s["dir"], ignore_errors=True)
        self.logger.info(f"HLS 转流已停止：{s['host']}:{s['port']}")

    def _stop(self, key: str) -> None:
        with self._lock:
            self._stop_locked(key)

    # ── public API ────────────────────────────────────────────────────────────

    def ensure(self, host: str, port: int, path_mode: str = "rtp", localaddr: str = "") -> tuple[str, Path]:
        """Start HLS stream if not already running. Returns (hls_key, hls_dir)."""
        key = self.make_key(host, port)
        with self._lock:
            s = self._streams.get(key)
            if s and s["proc"].poll() is None:
                s["last_access"] = time.time()
                return key, s["dir"]
            if s:
                self._stop_locked(key)

            hls_dir = HLS_BASE_DIR / key
            hls_dir.mkdir(parents=True, exist_ok=True)

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
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._streams[key] = {
                "proc": proc,
                "dir": hls_dir,
                "last_access": time.time(),
                "host": host,
                "port": port,
            }
            self.logger.info(
                f"HLS 转流已启动：{host}:{port}" + (f"，localaddr={localaddr}" if localaddr else "")
            )
            return key, hls_dir

    def touch(self, key: str) -> None:
        with self._lock:
            if key in self._streams:
                self._streams[key]["last_access"] = time.time()

    def stop(self, key: str) -> None:
        self._stop(key)

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
