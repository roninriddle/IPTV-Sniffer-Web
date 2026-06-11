"""Regression tests for v0.9.6 fixes.

Covers:
- pcap TCP reassembly: Ethernet / SLL (DLT=113) / SLL2 (DLT=276)
- CUSetConfig channel parsing: single-quote outer, double-quote outer
- Export URL: FCC / fcc-type / FEC parameter generation
- IPTV auth helper script generation
- quality_group derived from is_hd on operator channel import
"""
import os
import struct
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.stb_discovery_service import _parse_chanlist_html, _reassemble_tcp_streams
from services.export_service import ExportService
from services.iptv_auth_service import IptvAuthService
from services.log_service import AppLogger
from app import _parse_rtp2httpd_config_text, enrich_channel_rows


# ── pcap helpers ─────────────────────────────────────────────────────────

def _ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def _build_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, payload):
    src = _ip_bytes(src_ip)
    dst = _ip_bytes(dst_ip)
    tcp = struct.pack(
        ">HHIIHHHH",
        src_port, dst_port,
        seq, 0,       # seq, ack
        0x5018,       # data_offset=5 (20 bytes), PSH+ACK
        65535, 0, 0,  # window, checksum, urgent
    ) + payload
    total = 20 + len(tcp)
    ip_hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0,    # version+IHL, DSCP
        total,
        0, 0,       # id, flags+frag
        64, 6,      # TTL, protocol=TCP
        0,          # checksum (zero for tests)
        src, dst,
    )
    return ip_hdr + tcp


def _eth_frame(src_ip, dst_ip, src_port, dst_port, seq, payload):
    eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
    return eth + _build_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, payload)


def _sll_frame(src_ip, dst_ip, src_port, dst_port, seq, payload):
    # SLL v1 (DLT=113): 16-byte header; EtherType at bytes 14-15
    sll = struct.pack(">HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800)
    return sll + _build_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, payload)


def _sll2_frame(src_ip, dst_ip, src_port, dst_port, seq, payload):
    # SLL v2 (DLT=276): 20-byte header; EtherType at bytes 0-1
    sll2 = struct.pack(">HHIHBB8s", 0x0800, 0, 0, 1, 0, 6, b"\x00" * 8)
    return sll2 + _build_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, payload)


def _make_pcap(linktype: int, frames: list) -> bytes:
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    records = b""
    for frame in frames:
        records += struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    return hdr + records


def _write_pcap(linktype: int, frames: list) -> str:
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    with open(path, "wb") as f:
        f.write(_make_pcap(linktype, frames))
    return path


# ── pcap link-type tests ──────────────────────────────────────────────────

SRV = "10.7.10.132"
STB = "192.168.100.13"
SPORT = 80
DPORT = 54321
SEQ = 1000
PAYLOAD = b"test-payload"


class TestPcapLinkTypes:
    def _assert_stream(self, linktype, frame_fn):
        frame = frame_fn(SRV, STB, SPORT, DPORT, SEQ, PAYLOAD)
        path = _write_pcap(linktype, [frame])
        try:
            streams = _reassemble_tcp_streams(path)
        finally:
            os.unlink(path)
        key = (SRV, SPORT, STB, DPORT)
        assert key in streams, f"DLT={linktype}: 4-tuple not found in streams"
        assert PAYLOAD in streams[key], f"DLT={linktype}: payload not in reassembled stream"

    def test_ethernet_dlt1(self):
        self._assert_stream(1, _eth_frame)

    def test_sll_dlt113(self):
        self._assert_stream(113, _sll_frame)

    def test_sll2_dlt276(self):
        self._assert_stream(276, _sll2_frame)

    def test_tcp_seq_ordering(self):
        """Packets written in reverse order must be reassembled in seq order."""
        p1 = _eth_frame(SRV, STB, SPORT, DPORT, 100, b"first ")
        p2 = _eth_frame(SRV, STB, SPORT, DPORT, 200, b"second")
        # Write p2 before p1
        path = _write_pcap(1, [p2, p1])
        try:
            streams = _reassemble_tcp_streams(path)
        finally:
            os.unlink(path)
        data = streams[(SRV, SPORT, STB, DPORT)]
        assert data.index(b"first ") < data.index(b"second")


# ── CUSetConfig parsing tests ─────────────────────────────────────────────

_CH1_SQ = (
    b"CUSetConfig('Channel',"
    b"'ChannelName=\"CCTV1\" UserChannelID=\"1\""
    b" ChannelURL=\"igmp://239.3.1.241:8008\" ChannelID=\"1\""
    b" IsHDChannel=\"0\" TimeShift=\"0\""
    b" ChannelFCCIP=\"10.7.10.1\" ChannelFCCPort=\"9000\" ChannelFECPort=\"9090\"')"
)
_CH2_SQ = (
    b"CUSetConfig('Channel',"
    b"'ChannelName=\"CCTV2\" UserChannelID=\"2\""
    b" ChannelURL=\"igmp://239.3.1.242:8008\" ChannelID=\"2\""
    b" IsHDChannel=\"2\" TimeShift=\"1\""
    b" ChannelFCCIP=\"\" ChannelFCCPort=\"\" ChannelFECPort=\"\"')"
)
_CH1_DQ = (
    b"CUSetConfig(\"Channel\","
    b" \"ChannelName='CCTV1' UserChannelID='1'"
    b" ChannelURL='igmp://239.3.1.241:8008' ChannelID='1'\")"
)


class TestCUSetConfigParsing:
    def test_single_quote_two_channels(self):
        html = b"<html>" + _CH1_SQ + b"\n" + _CH2_SQ + b"</html>"
        channels = _parse_chanlist_html(html)
        assert len(channels) == 2

    def test_single_quote_fields(self):
        channels = _parse_chanlist_html(b"<html>" + _CH1_SQ + b"</html>")
        assert len(channels) == 1
        ch = channels[0]
        assert ch["name"] == "CCTV1"
        assert ch["ip"] == "239.3.1.241"
        assert ch["port"] == 8008
        assert ch["fcc_ip"] == "10.7.10.1"
        assert ch["fcc_port"] == 9000
        assert ch["fec_port"] == 9090
        assert ch["is_hd"] is False

    def test_single_quote_is_hd_and_timeshift(self):
        channels = _parse_chanlist_html(b"<html>" + _CH2_SQ + b"</html>")
        assert channels[0]["is_hd"] is True
        assert channels[0]["time_shift"] is True

    def test_double_quote_outer(self):
        channels = _parse_chanlist_html(b"<html>" + _CH1_DQ + b"</html>")
        assert len(channels) == 1
        assert channels[0]["name"] == "CCTV1"
        assert channels[0]["ip"] == "239.3.1.241"
        assert channels[0]["port"] == 8008

    def test_empty_html(self):
        assert _parse_chanlist_html(b"<html></html>") == []

    def test_no_ip_skipped(self):
        html = b"CUSetConfig('Channel','ChannelName=\"Test\" UserChannelID=\"1\" ChannelURL=\"\"')"
        assert _parse_chanlist_html(html) == []

    def test_sorted_by_channel_num(self):
        html = b"<html>" + _CH2_SQ + b"\n" + _CH1_SQ + b"</html>"
        channels = _parse_chanlist_html(html)
        assert channels[0]["num"] == 1
        assert channels[1]["num"] == 2


# ── Export URL tests ──────────────────────────────────────────────────────

class TestExportUrl:
    def test_basic(self):
        url = ExportService.make_http_url("127.0.0.1", 5140, "rtp", "239.1.1.1", 8008)
        assert url == "http://127.0.0.1:5140/rtp/239.1.1.1:8008"

    def test_fcc(self):
        url = ExportService.make_http_url("h", 5140, "rtp", "239.1.1.1", 8008, "10.0.0.1", 9000)
        assert "?fcc=10.0.0.1:9000" in url

    def test_fcc_type_with_fcc(self):
        url = ExportService.make_http_url("h", 5140, "rtp", "239.1.1.1", 8008,
                                          "10.0.0.1", 9000, fcc_type="telecom")
        assert "fcc-type=telecom" in url

    def test_fcc_type_without_fcc_omitted(self):
        url = ExportService.make_http_url("h", 5140, "rtp", "239.1.1.1", 8008, fcc_type="telecom")
        assert "fcc-type" not in url

    def test_fec(self):
        url = ExportService.make_http_url("h", 5140, "rtp", "239.1.1.1", 8008, fec_port=8090)
        assert "fec=8090" in url

    def test_fec_independent_of_fcc(self):
        url = ExportService.make_http_url("h", 5140, "rtp", "239.1.1.1", 8008,
                                          fec_port=8090, fcc_type="huawei")
        assert "fec=8090" in url
        assert "fcc-type" not in url  # fcc_type only appended when fcc_ip+fcc_port present

    def test_all_params_order(self):
        url = ExportService.make_http_url("h", 5140, "rtp", "239.1.1.1", 8008,
                                          fcc_ip="10.0.0.1", fcc_port=9000,
                                          fec_port=8090, fcc_type="huawei")
        assert url.startswith("http://h:5140/rtp/239.1.1.1:8008?")
        assert "fcc=10.0.0.1:9000" in url
        assert "fcc-type=huawei" in url
        assert "fec=8090" in url


# ── Export file generation: dedup + quality_group recompute ───────────────

class TestExportFiles:
    def _export(self, tmp_path, rows, settings=None):
        svc = ExportService(tmp_path)
        return svc, svc.export(rows, settings or {})

    def _row(self, name, host, port, **kw):
        r = {"name": name, "host": host, "port": port, "packets": 10,
             "category": "央视频道"}
        r.update(kw)
        return r

    def test_all_m3u_lists_each_source_once(self, tmp_path):
        rows = [self._row("CCTV1", "239.1.1.1", 8001, width=1920, height=1080),
                self._row("CCTV2", "239.1.1.2", 8002, width=720, height=576)]
        svc, _ = self._export(tmp_path, rows)
        text = (tmp_path / "channels-all.m3u").read_text(encoding="utf-8")
        # Each multicast URL must appear exactly once (no quality-group duplicate).
        assert text.count("rtp://239.1.1.1:8001") == 1
        assert text.count("rtp://239.1.1.2:8002") == 1

    def test_rtp_all_m3u_lists_each_source_once(self, tmp_path):
        rows = [self._row("CCTV1", "239.1.1.1", 8001, width=1920, height=1080)]
        self._export(tmp_path, rows)
        text = (tmp_path / "channels-rtp2httpd-all.m3u").read_text(encoding="utf-8")
        assert text.count("rtp://239.1.1.1:8001") == 1

    def test_txt_lists_each_source_once(self, tmp_path):
        rows = [self._row("CCTV1", "239.1.1.1", 8001, width=1920, height=1080)]
        self._export(tmp_path, rows)
        text = (tmp_path / "channels.txt").read_text(encoding="utf-8")
        assert text.count("rtp://239.1.1.1:8001") == 1

    def test_csv_lists_each_source_once(self, tmp_path):
        rows = [self._row("CCTV1", "239.1.1.1", 8001, width=1920, height=1080)]
        self._export(tmp_path, rows)
        text = (tmp_path / "channels.csv").read_text(encoding="utf-8-sig")
        # One header + exactly one data row for the channel (no quality dup row).
        data_rows = [ln for ln in text.splitlines() if ",CCTV1," in ln]
        assert len(data_rows) == 1

    def test_stale_quality_group_recomputed_from_dimensions(self, tmp_path):
        # 4K stream carrying a stale "高清频道" must be regrouped as 4K高清.
        rows = [self._row("CCTV4K", "239.1.1.9", 8009,
                          width=3840, height=2160, quality_group="高清频道")]
        svc, result = self._export(tmp_path, rows)
        assert result["quality_group_counts"]["4K高清"] == 1
        assert result["quality_group_counts"]["高清频道"] == 0

    def test_quality_group_preserved_when_no_dimensions(self, tmp_path):
        # Without dimensions, an explicit valid quality_group is kept.
        rows = [self._row("CCTV1", "239.1.1.1", 8001, quality_group="4K高清")]
        svc, result = self._export(tmp_path, rows)
        assert result["quality_group_counts"]["4K高清"] == 1


# ── Multicast link diagnostic ─────────────────────────────────────────────

class TestMulticastDiagnostic:
    def _service(self, tmp_path):
        from services.capture_service import CaptureService
        from services.log_service import AppLogger
        return CaptureService(AppLogger(tmp_path / "t.log"))

    def test_non_multicast_address_skips(self, tmp_path):
        svc = self._service(tmp_path)
        result = svc.diagnose_multicast("8.8.8.8", 5000)
        assert result["verdict"] == "skip"
        assert result["errors"]

    def test_stop_tcpdump_counts_udp_and_igmp(self, tmp_path):
        svc = self._service(tmp_path)

        class _FakeProc:
            def __init__(self, text):
                self._text = text
            def poll(self):
                return 0
            def communicate(self, timeout=None):
                return self._text, ""

        out = "\n".join([
            "IP 192.168.1.5 > 224.0.0.22: igmp v3 report, 1 group record(s)",
            "IP 10.0.0.2.51000 > 239.1.1.1.8001: UDP, length 1316",
            "IP 10.0.0.2.51000 > 239.1.1.1.8001: UDP, length 1316",
        ])
        counts = svc._stop_diag_tcpdump(_FakeProc(out), "239.1.1.1", 8001)
        assert counts["udp"] == 2
        assert counts["igmp"] == 1


# ── rtp2httpd config parser ───────────────────────────────────────────────

def test_parse_rtp2httpd_config_extracts_interfaces_and_external_m3u():
    parsed = _parse_rtp2httpd_config_text("""
[global]
upstream-interface = enp3s0
upstream-interface-fcc = enp2s0
external-m3u = file:///vol1/@appshare/rtp2httpd/channels.m3u
status-page-path = /status

[bind]
* 5140
""")
    values = parsed["values"]
    assert values["upstream-interface"] == "enp3s0"
    assert values["upstream-interface-fcc"] == "enp2s0"
    assert values["external-m3u"].endswith("channels.m3u")
    assert parsed["bind"] == ["* 5140"]


# ── IPTV auth helper ──────────────────────────────────────────────────────

def test_iptv_auth_scripts_include_option60_and_interface(tmp_path):
    svc = IptvAuthService(tmp_path / "auth-backup.json", tmp_path, AppLogger(tmp_path / "app.log"))
    result = svc.scripts({
        "interface": "enp3s0",
        "mac": "d4:c1:c8:ee:9b:1f",
        "hostname": "18000413001338300000D4C1C8EE9B1F",
        "vendor_class": "00001f3901c4693f",
        "requested_ip": "10.193.235.26",
        "gateway": "10.193.224.1",
        "route_mode": "multicast",
    })
    assert 'interface "enp3s0"' in result["dhclient_conf"]
    assert "00:00:1f:39:01:c4:69:3f" in result["dhclient_conf"]
    assert "-i enp3s0" in result["udhcpc_command"]
    assert "-x 0x3c:00001f3901c4693f" in result["udhcpc_command"]
    assert "224.0.0.0/4" in result["udhcpc_hook"]


# ── quality_group derivation from is_hd ──────────────────────────────────

class TestQualityGroupFromIsHd:
    def _row(self, is_hd, quality_group=None):
        r = {"key": "239.1.1.1:8008", "host": "239.1.1.1", "port": 8008,
             "name": "Test", "is_hd": is_hd}
        if quality_group is not None:
            r["quality_group"] = quality_group
        return r

    def test_hd_channel_gets_hd_group(self):
        enriched = enrich_channel_rows([self._row(True)])
        assert enriched[0]["quality_group"] == "高清频道"

    def test_sd_channel_gets_normal_group(self):
        enriched = enrich_channel_rows([self._row(False)])
        assert enriched[0]["quality_group"] == "普通频道"

    def test_probed_quality_group_not_overwritten(self):
        """If ffprobe already set quality_group, is_hd must not override it."""
        enriched = enrich_channel_rows([self._row(False, quality_group="4K高清")])
        assert enriched[0]["quality_group"] == "4K高清"

    def test_channel_without_is_hd_stays_unset(self):
        row = {"key": "239.1.1.2:8008", "host": "239.1.1.2", "port": 8008, "name": "Test"}
        enriched = enrich_channel_rows([row])
        assert enriched[0].get("quality_group") in (None, "", "未识别")

    # ── Operator re-import must not clobber probed quality_group ──────────
    # Root cause: _do_operator_import rows omitted width/height/probe_status,
    # so enrich_channel_rows fell into the is_hd branch and overwrote "4K高清".
    # Fix: _do_operator_import now seeds those fields from the stored channel.

    def test_4k_preserved_when_dimensions_present(self):
        """Row carrying actual probe dimensions must compute 4K高清, not 高清频道."""
        row = {
            "key": "239.1.1.1:8008", "host": "239.1.1.1", "port": 8008,
            "name": "CCTV4K",
            "is_hd": True,           # from operator channel (is_hd=True)
            "probe_status": "ok",
            "width": 3840, "height": 2160,
            "quality_group": "",     # simulates: no quality_group in incoming row
        }
        enriched = enrich_channel_rows([row])
        assert enriched[0]["quality_group"] == "4K高清", (
            "4K dimensions must override is_hd-derived '高清频道'"
        )

    def test_1080p_gets_hd_not_4k(self):
        row = {
            "key": "239.1.1.2:8008", "host": "239.1.1.2", "port": 8008,
            "name": "CCTV1HD",
            "is_hd": True,
            "probe_status": "ok",
            "width": 1920, "height": 1080,
            "quality_group": "",
        }
        enriched = enrich_channel_rows([row])
        assert enriched[0]["quality_group"] == "高清频道"

    def test_4k_not_overwritten_by_reimport_without_dims(self):
        """If a re-import row has no dimensions but quality_group is already 4K高清,
        enrich must not downgrade it (the elif guard must hold)."""
        row = {
            "key": "239.1.1.3:8008", "host": "239.1.1.3", "port": 8008,
            "name": "CCTV4K",
            "is_hd": True,
            "quality_group": "4K高清",   # preserved from stored channel
            # no width/height (not yet in this re-import row)
        }
        enriched = enrich_channel_rows([row])
        assert enriched[0]["quality_group"] == "4K高清"
