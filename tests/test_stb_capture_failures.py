"""STB 频道发现的静默失败回归测试。

这些断言针对的是「抓包失败时用户看不到任何错误」的问题：
- runtime_check 只检查二进制存在，不验证权限与接口可列
- Popen 之后不检查进程是否立即退出（tcpdump 秒退 → 状态永为 capturing）
- stderr 管道从未被读取（报错丢失，且管道写满会阻塞 tcpdump）
- _analyze 无条件设 STATUS_DONE，不校验 pcap 是否抓到数据
- _live_watcher 吞掉所有异常

每个测试都必须在修复前失败、修复后通过。
"""

from __future__ import annotations

import os
import subprocess
import struct
import sys
import time
from pathlib import Path

import pytest

from services.log_service import AppLogger
from services.stb_discovery_service import StbDiscoveryService


@pytest.fixture()
def service(tmp_path: Path) -> StbDiscoveryService:
    logger = AppLogger(tmp_path / "app.log")
    return StbDiscoveryService(logger=logger, archive_dir=tmp_path / "stb-captures")


def _wait_for(service: StbDiscoveryService, want: set[str], timeout: float = 5.0) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = service.status()["status"]
        if status in want:
            return status
        time.sleep(0.05)
    return service.status()["status"]


class TestRuntimeCheckVerifiesPermissions:
    """runtime_check 必须验证 tcpdump 真的能列出抓包接口，而不只是which 找到它。"""

    def test_missing_binary_is_reported(self, service, monkeypatch):
        monkeypatch.setattr("services.stb_discovery_service.shutil.which", lambda name: None)
        result = service.runtime_check()
        assert result["ok"] is False
        assert any("tcpdump" in err for err in result["errors"])

    def test_interface_listing_failure_is_reported(self, service, monkeypatch):
        """which 成功但 tcpdump -D 失败（缺 NET_RAW /非 root）时必须报错。"""
        monkeypatch.setattr("services.stb_discovery_service.shutil.which", lambda name: f"/usr/bin/{name}")

        def _boom(cmd, *a, **kw):
            raise FileNotFoundError("tcpdump: you don't have permission")

        monkeypatch.setattr("services.stb_discovery_service._probe_tcpdump_interfaces", _boom)
        result = service.runtime_check()
        assert result["ok"] is False
        assert result["errors"], "tcpdump -D 失败时必须给出错误，不能只查 which"

    def test_error_message_mentions_container_requirements(self, service, monkeypatch):
        """权限不足的提示要指明容器需要 host 网络 + NET_ADMIN/NET_RAW。"""
        monkeypatch.setattr("services.stb_discovery_service.shutil.which", lambda name: f"/usr/bin/{name}")

        def _boom(cmd, *a, **kw):
            raise PermissionError("Operation not permitted")

        monkeypatch.setattr("services.stb_discovery_service._probe_tcpdump_interfaces", _boom)
        result = service.runtime_check()
        assert result["ok"] is False
        joined = " ".join(result["errors"])
        assert "NET_RAW" in joined or "NET_ADMIN" in joined or "host" in joined


class TestCaptureStartupFailure:
    """tcpdump 启动后立即退出时，必须置为 error 而不是停在 capturing。"""

    def test_immediate_exit_sets_error_state(self, service, monkeypatch):
        class _DeadProc:
            """模拟 tcpdump 立即退出（如 -i any 不支持混杂模式）。"""

            def __init__(self, *a, **kw):
                self.stderr = None
                self.returncode = 1

            def poll(self):
                return 1

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 1

        monkeypatch.setattr("services.stb_discovery_service.shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr("services.stb_discovery_service._probe_tcpdump_interfaces", lambda: "")
        monkeypatch.setattr("services.stb_discovery_service.subprocess.Popen", _DeadProc)
        monkeypatch.setattr("services.stb_discovery_service.time.sleep", lambda *a: None)

        with pytest.raises(RuntimeError):
            service.start("172.203.69.247", "any")

        state = service.status()
        assert state["status"] == StbDiscoveryService.STATUS_ERROR
        assert state["error"], "tcpdump 秒退时必须记录 error原因"

    def test_stderr_thread_drains_pipe(self, service, monkeypatch):
        """长时间抓包时 stderr 无人读取会写满管道并阻塞 tcpdump，必须有消费线程。"""
        started: list[str] = []

        class _Proc:
            def __init__(self, cmd, **kw):
                started.append("process")
                self.stderr = None
                self.returncode = None

            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

        monkeypatch.setattr("services.stb_discovery_service.shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr("services.stb_discovery_service._probe_tcpdump_interfaces", lambda: "")
        monkeypatch.setattr("services.stb_discovery_service.subprocess.Popen", _Proc)
        monkeypatch.setattr("services.stb_discovery_service.time.sleep", lambda *a: None)
        monkeypatch.setattr(
            "services.stb_discovery_service.threading.Thread",
            _thread_recorder(started),
        )

        service.start("172.203.69.247", "eth1")
        assert "_stderr_reader" in started, "必须启动 stderr 消费线程，否则管道写满会阻塞 tcpdump"


class _thread_recorder:
    """替换 threading.Thread，记录启动的线程目标名。"""

    def __init__(self, sink: list[str]) -> None:
        self._sink = sink

    def __call__(self, target=None, args=(), **kwargs):
        if target is not None:
            name = getattr(target, "__name__", "")
            self._sink.append(name or "anon")
        return _FakeThread()


class _FakeThread:
    def start(self) -> None:
        return None

    def join(self, timeout=None) -> None:
        return None


class TestAnalyzeReportsMissingData:
    """_analyze 不能在没抓到数据时也报 done。"""

    def test_empty_pcap_is_reported_as_error(self, service, monkeypatch, tmp_path):
        """抓到一个空 pcap 时必须报错，而不是 STATUS_DONE + 0 频道。"""
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")

        monkeypatch.setattr(
            "services.stb_discovery_service.analyze_pcap_for_channels", lambda *a, **kw: []
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._reassemble_tcp_streams", lambda *a, **kw: {}
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_dhcp_from_pcap", lambda *a, **kw: {}
        )
        monkeypatch.setattr(service, "_archive_pcap", lambda *a, **kw: None)
        service._pcap_path = str(empty)
        service._state["status"] = StbDiscoveryService.STATUS_CAPTURING
        service._state["stb_ip"] = "172.203.69.247"

        service.stop()
        _wait_for(service, {StbDiscoveryService.STATUS_DONE, StbDiscoveryService.STATUS_ERROR})
        state = service.status()

        assert state["status"] == StbDiscoveryService.STATUS_ERROR
        assert state["error"], "0 包时必须给出错误原因，不能静默报成功"
        assert state["channel_count"] == 0

    def test_capture_with_data_but_no_channels_still_succeeds(self, service, monkeypatch, tmp_path):
        """有数据但没频道（解析器不匹配）时，仍应 done，但必须附带可诊断信息。"""
        pcap = tmp_path / "data.pcap"
        pcap.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 0, 0, 64, 64) + b"x" * 64)

        monkeypatch.setattr(
            "services.stb_discovery_service.analyze_pcap_for_channels", lambda *a, **kw: []
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._reassemble_tcp_streams", lambda *a, **kw: {("a", 1, "b", 2): b"x"}
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_dhcp_from_pcap", lambda *a, **kw: {"mac": "aa:bb"}
        )
        monkeypatch.setattr(service, "_archive_pcap", lambda *a, **kw: None)
        service._pcap_path = str(pcap)
        service._state["status"] = StbDiscoveryService.STATUS_CAPTURING
        service._state["stb_ip"] = "172.203.69.247"

        service.stop()
        _wait_for(service, {StbDiscoveryService.STATUS_DONE, StbDiscoveryService.STATUS_ERROR})
        state = service.status()

        assert state["status"] == StbDiscoveryService.STATUS_DONE
        # 关键：必须区分「没抓到包」和「有包但没解析出频道」
        assert state.get("pcap_size", 0) > 0
        diagnostics = state.get("diagnostics")
        assert diagnostics, "必须给出诊断信息以便区分失败原因"
        assert diagnostics["pcap_size"] > 0
        assert diagnostics["channels"] == 0


class TestLiveWatcherDoesNotSwallowErrors:
    """_live_watcher 的异常必须记录，不得静默 pass。"""

    def test_watcher_records_exception(self, service, monkeypatch):
        """分析抛异常时，_live_watcher 必须记录错误，而不是静默 pass。"""
        state = service._state
        state["status"] = StbDiscoveryService.STATUS_CAPTURING

        def _boom(*a, **kw):
            raise RuntimeError("解析炸了")

        monkeypatch.setattr("services.stb_discovery_service.analyze_pcap_for_channels", _boom)

        # _live_watcher 的顺序是 sleep -> 检查状态 -> 解析，所以第一次 sleep
        # 必须保持 capturing 让它进入解析分支，第二次才退出循环。
        sleeps = {"n": 0}

        def _sleep(_seconds):
            sleeps["n"] += 1
            if sleeps["n"] >= 2:
                state["status"] = StbDiscoveryService.STATUS_DONE

        monkeypatch.setattr("services.stb_discovery_service.time.sleep", _sleep)

        service._live_watcher("x.pcap", "1.1.1.1", service._generation)

        assert state.get("live_watcher_errors", 0) >= 1, (
            "live watcher 异常必须被计数，当前被 `except Exception: pass` 静默吞掉"
        )
        assert state.get("live_last_error"), "必须记录异常信息以便诊断"
