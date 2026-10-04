"""Bounded, deduplicated JPEG previews using the configured media interface."""
from collections import OrderedDict
import subprocess
import threading
import time
from services.media_task_service import MediaCapacityError, reap_process


class SnapshotService:
    def __init__(self, tasks, ttl=30, max_entries=32, max_bytes=16*1024*1024):
        self.tasks, self.ttl = tasks, ttl
        self.max_entries, self.max_bytes = max_entries, max_bytes
        self.cache = OrderedDict()
        self.pending = set()
        self.lock = threading.RLock()

    def get(self, host, port, mode, local_ip):
        key = (host, port, mode, local_ip)
        with self.lock:
            now = time.monotonic()
            for stale in [k for k, (at, _) in self.cache.items() if now-at >= self.ttl]:
                self.cache.pop(stale)
            if key in self.cache:
                self.cache.move_to_end(key)
                return self.cache[key][1]
            if key in self.pending:
                raise MediaCapacityError("该频道截图正在生成，请稍后重试")
            self.pending.add(key)
        lease = None
        try:
            lease = self.tasks.acquire("snapshot", f"{host}:{port}")
            source = f"{mode}://{host}:{port}?timeout=12000000"
            if local_ip:
                source += f"&localaddr={local_ip}"
            proc = subprocess.Popen(["ffmpeg", "-v", "error", "-i", source,
                "-frames:v", "1", "-vf", "scale=640:-2", "-f", "image2",
                "-vcodec", "mjpeg", "-q:v", "4", "pipe:1"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            lease.attach(lambda: reap_process(proc))
            data, _ = proc.communicate(timeout=22)
            if proc.returncode or not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
                raise ValueError("上游未返回有效 JPEG 图像")
            if len(data) > self.max_bytes:
                raise ValueError("截图超过缓存容量限制")
            with self.lock:
                self.cache[key] = (time.monotonic(), data)
                while len(self.cache) > self.max_entries or sum(len(v[1]) for v in self.cache.values()) > self.max_bytes:
                    self.cache.popitem(last=False)
            return data
        finally:
            try:
                if lease:
                    lease.close()
            finally:
                with self.lock:
                    self.pending.discard(key)
