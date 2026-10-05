"""STB 抓包支持按 MAC 过滤。

背景：当前只能用 IP 过滤（`host <stb_ip>`），而 IP 依赖 DHCP 分配。
抓包启动时STB 可能还没拿到地址，此时按 IP 过滤会漏掉全部流量；
IP 变化后用户重填也容易与实际不符。MAC 在二层稳定，可在链路层直接匹配。

这些测试验证 BPF 表达式与参数校验，不依赖真实 tcpdump。
"""

from __future__ import annotations

import io
import re
import time
from pathlib import Path

import pytest

from services.log_service import AppLogger
from services.stb_discovery_service import StbDiscoveryService


@pytest.fixture()
def service(tmp_path: Path) -> StbDiscoveryService:
    logger = AppLogger(tmp_path / "app.log")
    svc = StbDiscoveryService(logger=logger, archive_dir=tmp_path / "stb-captures")
    return svc


@pytest.fixture()
def captured_command(monkeypatch, tmp_path):
    """捕获 Popen 的命令行，并让启动检查通过。"""
    commands: list[list[str]] = []

    class _Proc:
        stdout = io.BytesIO()
        stderr = io.StringIO()
        returncode = None

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    class _FakeThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr("services.stb_discovery_service._probe_tcpdump_interfaces", lambda: "eth1")
    monkeypatch.setattr("services.stb_discovery_service._validate_mac_filter", lambda *a: None)
    monkeypatch.setattr("services.stb_discovery_service.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("services.stb_discovery_service.tempfile.mktemp", lambda **kw: str(tmp_path / "c.pcap"))
    monkeypatch.setattr(
        "services.stb_discovery_service.subprocess.Popen",
        lambda cmd, **kw: commands.append(list(cmd)) or _Proc(),
    )
    monkeypatch.setattr("services.stb_discovery_service.threading.Thread", _FakeThread)
    monkeypatch.setattr("services.stb_discovery_service.time.sleep", lambda *a: None)
    return commands


MAC = "48:57:02:25:bb:e3"
IP = "172.203.69.247"


def _bpf(commands: list[list[str]]) -> str:
    return commands[0][-1]


class TestMacFilter:
    """提供 MAC 时用 ether host 过滤，不依赖 IP。"""

    def test_mac_filter_uses_ether_host(self, service, captured_command):
        service.start(IP, "eth1", stb_mac=MAC)
        expr = _bpf(captured_command)
        assert "ether host 48:57:02:25:bb:e3" in expr, f"应使用二层 MAC 过滤，实际：{expr}"

    def test_mac_filter_ignores_stale_ip(self, service, captured_command):
        """IP 填错也不影响 MAC 过滤——这正是要解决的问题。"""
        service.start("1.1.1.1", "eth1", stb_mac=MAC)
        expr = _bpf(captured_command)
        assert "ether host 48:57:02:25:bb:e3" in expr
        assert "host 1.1.1.1" not in expr, f"不应再用可能过期的 IP 过滤：{expr}"

    def test_dhcp_still_included(self, service, captured_command):
        """MAC 过滤不能丢掉 DHCP，否则拿不到认证字段。"""
        service.start(IP, "eth1", stb_mac=MAC)
        expr = _bpf(captured_command)
        assert "port 67" in expr and "port 68" in expr, f"需保留 DHCP：{expr}"

    def test_full_capture_keeps_no_filter(self, service, captured_command):
        """full_capture 仍应完全不加过滤。"""
        service.start(IP, "eth1", stb_mac=MAC, full_capture=True)
        expr = _bpf(captured_command)
        assert "ether host" not in expr
        assert "host " not in expr

    def test_state_records_mac(self, service, captured_command):
        service.start(IP, "eth1", stb_mac=MAC)
        assert service.status()["stb_mac"] == MAC


class TestIpFilterFallback:
    """未提供 MAC 时保持原有 IP 过滤行为，避免破坏既有用户。"""

    def test_without_mac_uses_ip_filter(self, service, captured_command):
        service.start(IP, "eth1")
        expr = _bpf(captured_command)
        assert f"host {IP}" in expr
        assert "ether host" not in expr

    def test_ip_and_mac_combined(self, service, captured_command):
        """同时提供时以 MAC 为准，但保留 IP 作为附加条件。"""
        service.start(IP, "eth1", stb_mac=MAC)
        expr = _bpf(captured_command)
        assert "ether host 48:57:02:25:bb:e3" in expr
        # 不应出现裸的 host <ip> 主条件
        assert not re.search(r"(?<!ether )\bhost\s+" + re.escape(IP), expr)


class TestMacValidation:
    """MAC 格式校验要在启动前拦截，避免 tcpdump 拿到无效表达式。"""

    @pytest.mark.parametrize("bad", [
        "48:57:02:25:bb",                 # 少一段
        "48:57-02:25-bb-e3",              # 分隔符混用
        "48:57:02:25:bb:e3:ff",           # 多一段
        "zz:57:02:25:bb:e3",              # 非十六进制
        "48:57:02:25:bb:gg",              # 末段非法
        "4857.0225.bb",                   # Cisco 风格不完整
        "48-57-02-25-bb",                 # 少一段
    ])
    def test_invalid_mac_rejected(self, service, captured_command, bad):
        with pytest.raises(ValueError, match="MAC"):
            service.start(IP, "eth1", stb_mac=bad)
        assert not captured_command, "非法 MAC 不应启动 tcpdump"

    @pytest.mark.parametrize("good", [
        "48:57:02:25:bb:e3",
        "48-57-02-25-BB-E3",
        "4857.0225.bbe3",
    ])
    def test_valid_mac_accepted(self, service, captured_command, good):
        service.start(IP, "eth1", stb_mac=good)
        expr = _bpf(captured_command)
        # 无论输入格式如何，输出统一为小写冒号分隔
        assert "ether host 48:57:02:25:bb:e3" in expr

    def test_empty_mac_falls_back_to_ip(self, service, captured_command):
        service.start(IP, "eth1", stb_mac="")
        assert f"host {IP}" in _bpf(captured_command)
