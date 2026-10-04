"""Bounded media ownership, cancellation and process reaping."""
from __future__ import annotations

import subprocess
import threading
import time
import uuid


class MediaCapacityError(RuntimeError):
    pass


def reap_process(proc, timeout=3):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout)
    for stream in (getattr(proc, "stdout", None), getattr(proc, "stderr", None)):
        if stream:
            stream.close()


class MediaLease:
    def __init__(self, manager, kind, key):
        self.manager, self.kind, self.key = manager, kind, key
        self.id = uuid.uuid4().hex
        self.started_at = time.time()
        self.cleanup = None
        self.closed = False
        self.cancel_callback = None
        self.cancel_requested = False

    def attach(self, cleanup):
        with self.manager.lock:
            if not self.closed:
                self.cleanup = cleanup
                return
        cleanup()

    def request_cancel(self):
        with self.manager.lock:
            self.cancel_requested = True
            callback = self.cancel_callback
        if callback:
            callback()  # Worker retains capacity until its finally block exits.
        else:
            self.close()

    def close(self):
        with self.manager.lock:
            if self.closed:
                return
            self.closed = True
            cleanup, self.cleanup = self.cleanup, None
        try:
            if cleanup:
                cleanup()
        finally:
            with self.manager.lock:
                self.manager.tasks.pop(self.id, None)


class MediaTaskManager:
    def __init__(self, limit=4, limits=None):
        self.limit = max(1, int(limit))
        self.limits = limits or {"hls": 2, "catchup": 2, "snapshot": 1, "diagnose": 1}
        self.lock = threading.RLock()
        self.tasks = {}
        self.closed = False

    def acquire(self, kind, key=""):
        with self.lock:
            count = sum(t.kind == kind for t in self.tasks.values())
            if self.closed or len(self.tasks) >= self.limit or count >= self.limits.get(kind, self.limit):
                raise MediaCapacityError("媒体任务已达并发上限，请结束已有任务后重试")
            lease = MediaLease(self, kind, key)
            self.tasks[lease.id] = lease
            return lease

    def status(self):
        with self.lock:
            return {"limit": self.limit, "limits": dict(self.limits), "active": [
                {"id": t.id, "kind": t.kind, "key": t.key,
                 "cancel_requested": t.cancel_requested, "elapsed_seconds": int(time.time() - t.started_at)} for t in self.tasks.values()]}

    def cancel(self, task_id):
        with self.lock:
            task = self.tasks.get(task_id)
        if task:
            task.request_cancel()
        return task is not None

    def shutdown(self):
        with self.lock:
            self.closed = True
            tasks = list(self.tasks.values())
        for task in tasks:
            try:
                task.request_cancel()
            except Exception:
                # One failed cleanup must not strand the other owned resources.
                continue


class ProcessTail:
    """Continuously drain stderr while retaining only a bounded diagnostic tail."""
    def __init__(self, stream, limit=32768):
        self.stream, self.limit = stream, limit
        self.data = bytearray()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._read, daemon=True, name='media-stderr')
        self.thread.start()

    def _read(self):
        try:
            while True:
                chunk = self.stream.read(4096)
                if not chunk:
                    return
                with self.lock:
                    self.data.extend(chunk)
                    del self.data[:-self.limit]
        except (ValueError, OSError):
            return

    def text(self):
        self.thread.join(timeout=1)
        with self.lock:
            return bytes(self.data).decode(errors='replace')
