"""Injectable, persistent refresh scheduling without Flask dependencies."""
import json
import threading
import time
from pathlib import Path


class CatchupScheduler:
    def __init__(self, state=None, lock=None, path=None):
        self.state = state if state is not None else {}
        self.lock = lock or threading.RLock()
        self.path = Path(path) if path else None
        self.stop_event = threading.Event()
        self.thread = None

    @staticmethod
    def interval(settings):
        return max(1, min(168, int(settings.get("catchup_auto_refresh_hours") or 12))) * 3600

    @staticmethod
    def enabled(settings):
        return bool(settings.get("catchup_enabled") and settings.get("catchup_auto_refresh_enabled"))

    def load(self):
        if self.path and self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                with self.lock:
                    for key in ("next_run_at", "last_run_at", "last_success_at", "schedule_interval"):
                        if type(data.get(key)) is int and data[key] >= 0:
                            self.state[key] = data[key]
                    self.state["running"] = False
            except (ValueError, OSError):
                pass

    def persist(self):
        if not self.path:
            return
        # Persist timestamps only, never auth data or operator response values.
        from services.storage_service import _atomic_dump_json
        _atomic_dump_json(self.path, {k: self.state.get(k) for k in (
            "next_run_at", "last_run_at", "last_success_at", "schedule_interval")})

    def next_run(self, settings, now):
        with self.lock:
            interval = self.interval(settings)
            if not self.enabled(settings):
                changed = self.state.get("next_run_at") is not None or self.state.get("schedule_interval") is not None
                self.state.update(next_run_at=None, schedule_interval=None)
                if changed:
                    self.persist()
                return None
            if self.state.get("next_run_at") is None or self.state.get("schedule_interval") != interval:
                last = max(int(self.state.get("last_run_at") or 0), int(self.state.get("last_success_at") or 0))
                self.state.update(next_run_at=(last or now)+interval, schedule_interval=interval)
                self.persist()
            return int(self.state["next_run_at"])

    def run(self, settings, source, refresh, sanitize):
        with self.lock:
            if self.state.get("running"):
                raise RuntimeError("回看地址刷新正在执行，请稍后再试")
            self.state.update(running=True, last_run_at=int(time.time()), last_error="")
        try:
            result = dict(refresh())
            now = int(time.time())
            result.update(source=source, refreshed_at=now)
            with self.lock:
                self.state.update(last_success_at=now, last_result=result,
                    token_expires_at=result.get("token_expires_at"),
                    token_expiry_note=result.get("token_expiry_note") or "未暴露明确有效期")
            return result
        except Exception as exc:
            with self.lock:
                self.state["last_error"] = sanitize(str(exc))
            raise
        finally:
            with self.lock:
                self.state.update(running=False, schedule_interval=self.interval(settings),
                    next_run_at=int(time.time())+self.interval(settings) if self.enabled(settings) else None)
                self.persist()

    def start(self, settings, refresh, logger):
        if self.thread and self.thread.is_alive():
            return
        self.load()
        def worker():
            while not self.stop_event.is_set():
                try:
                    current = settings()
                    due = self.next_run(current, int(time.time()))
                    if due is not None and time.time() >= due and not self.state.get("running"):
                        refresh(current, "auto")
                except Exception:
                    logger.warning("定时回看刷新失败，详情见刷新状态；将按周期重试")
                self.stop_event.wait(60)
        self.thread = threading.Thread(target=worker, daemon=True, name="catchup-refresh")
        self.thread.start()

    def shutdown(self):
        self.stop_event.set()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=2)
