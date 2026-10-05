"""MAC 过滤的可用性增强：自动回填与未命中提示。

用户拿到 MAC 的成本不该由用户承担——DHCP 报文的 chaddr 字段天然携带 MAC，
抓包时项目已经在解析它，只是没有回填到界面。另一个问题是填错 MAC 时
`ether host` 仍是合法 BPF，tcpdump 会正常启动并安静地抓 0 包，用户无从判断。
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from services.log_service import AppLogger
from services.stb_discovery_service import StbDiscoveryService


MAC = "48:57:02:25:bb:e3"
IP = "172.203.69.247"


@pytest.fixture()
def service(tmp_path: Path) -> StbDiscoveryService:
    return StbDiscoveryService(
        logger=AppLogger(tmp_path / "app.log"),
        archive_dir=tmp_path / "stb-captures",
    )


class _FakeThread:
    """替换 capture 期间启动的后台线程，避免测试真的去跑。"""

    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass


def _classic_pcap(frames: list[bytes], linktype: int = 1) -> bytes:
    """把裸帧包装成 classic pcap，供解析函数直接读取。"""
    import struct

    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
    for frame in frames:
        out += struct.pack("<IIII", 0, 0, len(frame), len(frame))
        out += frame
    return bytes(out)


def _eth(dst_mac: str, src_mac: str, payload: bytes = b"\x00" * 40) -> bytes:
    return bytes.fromhex(dst_mac.replace(":", "")) + bytes.fromhex(src_mac.replace(":", "")) + payload


class TestMacAutoFill:
    """抓包时项目已经能从 DHCP chaddr 拿到 MAC，应当回填给用户。"""

    def test_state_exposes_detected_mac(self, service, tmp_path, monkeypatch):
        """_live_watcher 解析到 DHCP 后应把 MAC 放进 state，供前端回填。"""
        service._state["status"] = StbDiscoveryService.STATUS_CAPTURING
        monkeypatch.setattr(
            "services.stb_discovery_service.analyze_pcap_for_channels", lambda *a, **kw: []
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_dhcp_from_pcap",
            lambda *a, **kw: {"mac": MAC, "assigned_ip": ""},
        )
        sleeps = {"n": 0}

        def _sleep(_s):
            sleeps["n"] += 1
            if sleeps["n"] >= 2:
                service._state["status"] = StbDiscoveryService.STATUS_DONE

        monkeypatch.setattr("services.stb_discovery_service.time.sleep", _sleep)
        path = service.archive_dir.parent / "x.pcap"
        path.write_bytes(_classic_pcap([]))
        service._live_watcher(str(path), IP, service._generation)

        state = service.status()
        assert state["detected_mac"] == MAC, "应把 DHCP chaddr 解析出的 MAC 暴露给前端"

    def test_detected_mac_empty_when_no_dhcp(self, service, monkeypatch):
        """没抓到 DHCP 时不应给出误导性的 MAC。"""
        service._state["status"] = StbDiscoveryService.STATUS_CAPTURING
        monkeypatch.setattr(
            "services.stb_discovery_service.analyze_pcap_for_channels", lambda *a, **kw: []
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_dhcp_from_pcap", lambda *a, **kw: {}
        )
        sleeps = {"n": 0}

        def _sleep(_s):
            sleeps["n"] += 1
            if sleeps["n"] >= 2:
                service._state["status"] = StbDiscoveryService.STATUS_DONE

        monkeypatch.setattr("services.stb_discovery_service.time.sleep", _sleep)
        path = service.archive_dir.parent / "x.pcap"
        path.write_bytes(_classic_pcap([]))
        service._live_watcher(str(path), IP, service._generation)

        assert service.status()["detected_mac"] == ""

    def test_initial_state_has_field(self, service):
        assert service.status()["detected_mac"] == ""

    def test_start_resets_detected_mac(self, service):
        """一次成功的新捕获要清掉上一轮的探测结果，不能沿用。"""
        service._state["detected_mac"] = MAC
        service._state["status"] = StbDiscoveryService.STATUS_IDLE

        with pytest.raises(ValueError):
            # MAC 格式校验发生在状态重置之前，失败时不应改动已有状态。
            service.start(IP, "eth1", stb_mac="not-a-mac")

        assert service._state["detected_mac"] == MAC, "启动失败时不应改动已有状态"

    def test_detected_mac_cleared_on_new_capture(self, service, monkeypatch, tmp_path):
        service._state["detected_mac"] = MAC
        service._state["status"] = StbDiscoveryService.STATUS_IDLE

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

        monkeypatch.setattr("services.stb_discovery_service._probe_tcpdump_interfaces", lambda: "eth1")
        monkeypatch.setattr("services.stb_discovery_service._validate_mac_filter", lambda *a: None)
        monkeypatch.setattr("services.stb_discovery_service.shutil.which", lambda n: f"/usr/bin/{n}")
        monkeypatch.setattr("services.stb_discovery_service.tempfile.mktemp", lambda **kw: str(tmp_path / "c.pcap"))
        monkeypatch.setattr("services.stb_discovery_service.subprocess.Popen", lambda cmd, **kw: _Proc())
        monkeypatch.setattr("services.stb_discovery_service.threading.Thread", lambda *a, **kw: _FakeThread())
        monkeypatch.setattr("services.stb_discovery_service.time.sleep", lambda *a: None)

        service.start(IP, "eth1", stb_mac=MAC)
        assert service.status()["detected_mac"] == "", "新一轮捕获应清空上轮探测结果"


class TestMacNotSeen:
    """填了 MAC 但抓包里看不到它，必须提示而不是安静地 0 频道。"""

    def test_count_mac_occurrences(self, service, tmp_path):
        from services.stb_discovery_service import _capture_diagnostics

        pcap = tmp_path / "with.pcap"
        pcap.write_bytes(_classic_pcap([
            _eth("ff:ff:ff:ff:ff:ff", MAC),
            _eth("ff:ff:ff:ff:ff:ff", MAC),
            _eth(MAC, "00:11:22:33:44:55"),
        ]))
        diag = _capture_diagnostics(str(pcap), IP, {}, [], MAC)
        assert diag["mac_seen_count"] == 3
        assert _capture_diagnostics(str(pcap), IP, {}, [], "00:11:22:33:44:55")["mac_seen_count"] == 1

    def test_counts_ignore_non_ethernet_links(self, service, tmp_path):
        """SLL 等链路的偏移不同，不能误读出垃圾 MAC。"""
        from services.stb_discovery_service import _capture_diagnostics

        pcap = tmp_path / "sll.pcap"
        sll = bytes.fromhex("00000000" + "0001" + "0800") + b"\x00" * 40
        pcap.write_bytes(_classic_pcap([sll], linktype=113))
        diag = _capture_diagnostics(str(pcap), IP, {}, [], MAC)
        assert diag["mac_supported"] is False
        assert diag["mac_not_seen"] is False
        assert "mac_seen_count" not in diag

    def test_analyze_flags_unseen_mac(self, service, tmp_path, monkeypatch):
        """指定的 MAC 在 pcap 里零命中时应提示查设备 MAC 与抓包点。"""
        pcap = tmp_path / "nomac.pcap"
        pcap.write_bytes(_classic_pcap([_eth("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")]))

        monkeypatch.setattr("services.stb_discovery_service._reassemble_tcp_streams", lambda *a, **kw: {})
        monkeypatch.setattr(
            "services.stb_discovery_service.analyze_pcap_for_channels", lambda *a, **kw: []
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_dhcp_from_pcap", lambda *a, **kw: {}
        )
        monkeypatch.setattr(service, "_archive_pcap", lambda *a, **kw: None)
        monkeypatch.setattr(
            "services.stb_discovery_service._detect_timeshift_host", lambda *a, **kw: ""
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_epg_credentials", lambda *a, **kw: {}
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_ctc_portal_auth", lambda *a, **kw: {}
        )
        monkeypatch.setattr(
            service, "_persist_protocol_artifacts", lambda *a, **kw: {"saved": False}
        )
        service._pcap_path = str(pcap)
        service._state["status"] = StbDiscoveryService.STATUS_CAPTURING
        service._state["stb_ip"] = IP
        service._state["stb_mac"] = MAC

        service.stop()
        import time

        deadline = time.time() + 5
        while time.time() < deadline:
            if service.status()["status"] in (
                StbDiscoveryService.STATUS_DONE,
                StbDiscoveryService.STATUS_ERROR,
            ):
                break
            time.sleep(0.05)

        state = service.status()
        assert state["status"] == StbDiscoveryService.STATUS_DONE
        diag = state.get("diagnostics") or {}
        assert diag.get("mac_requested") == MAC
        assert diag.get("mac_seen_count") == 0
        assert diag.get("mac_not_seen"), "MAC 零命中时必须给出提示"

    def test_no_warning_when_mac_matches_user_input(self, service, tmp_path, monkeypatch):
        """填的 MAC 与探测到的 MAC 一致时不该报未命中。"""
        pcap = tmp_path / "hit.pcap"
        pcap.write_bytes(_classic_pcap([_eth("ff:ff:ff:ff:ff:ff", MAC)]))

        monkeypatch.setattr("services.stb_discovery_service._reassemble_tcp_streams", lambda *a, **kw: {})
        monkeypatch.setattr(
            "services.stb_discovery_service.analyze_pcap_for_channels", lambda *a, **kw: []
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_dhcp_from_pcap",
            lambda *a, **kw: {"mac": MAC},
        )
        monkeypatch.setattr(service, "_archive_pcap", lambda *a, **kw: None)
        monkeypatch.setattr(
            "services.stb_discovery_service._detect_timeshift_host", lambda *a, **kw: ""
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_epg_credentials", lambda *a, **kw: {}
        )
        monkeypatch.setattr(
            "services.stb_discovery_service._extract_ctc_portal_auth", lambda *a, **kw: {}
        )
        monkeypatch.setattr(
            service, "_persist_protocol_artifacts", lambda *a, **kw: {"saved": False}
        )
        service._pcap_path = str(pcap)
        service._state["status"] = StbDiscoveryService.STATUS_CAPTURING
        service._state["stb_ip"] = IP
        service._state["stb_mac"] = MAC

        service.stop()
        import time

        deadline = time.time() + 5
        while time.time() < deadline:
            if service.status()["status"] in (
                StbDiscoveryService.STATUS_DONE,
                StbDiscoveryService.STATUS_ERROR,
            ):
                break
            time.sleep(0.05)

        diag = service.status().get("diagnostics") or {}
        assert diag.get("mac_seen_count") == 1
        assert not diag.get("mac_not_seen"), "MAC 命中时不应告警"
