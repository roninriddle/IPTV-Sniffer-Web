"""Regression tests for v0.9.6 fixes.

Covers:
- pcap TCP reassembly: Ethernet / SLL (DLT=113) / SLL2 (DLT=276)
- CUSetConfig channel parsing: single-quote outer, double-quote outer
- Export URL: FCC / fcc-type / FEC parameter generation
- OpenWrt UCI parser + analyzer API contract
"""
import os
import struct
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.stb_discovery_service import _parse_chanlist_html, _reassemble_tcp_streams
from services.export_service import ExportService
from app import _parse_uci_network, _analyze_uci_interfaces


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


# ── OpenWrt UCI parser + analyzer ─────────────────────────────────────────

_R4S_CONFIG = """
config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1'
    option netmask '255.0.0.0'

config interface 'lan'
    option device 'eth1'
    option proto 'static'
    option ipaddr '192.168.10.1'

config interface 'wan'
    option device 'eth0'
    option proto 'dhcp'

config interface 'wan6'
    option device 'eth0'
    option proto 'dhcpv6'
"""

_R4S_CONFIGURED = """
config interface 'lan'
    option device 'eth1'
    option proto 'static'

config interface 'iptv_sniff'
    option device 'eth0'
    option proto 'none'
"""

_UNKNOWN_CONFIG = """
config interface 'lan'
    option device 'br-lan'
    option proto 'static'

config interface 'wan'
    option device 'eth1'
    option proto 'pppoe'
"""


class TestUciParser:
    def test_parses_interface_names(self):
        ifaces = _parse_uci_network(_R4S_CONFIG)
        assert "lan" in ifaces
        assert "wan" in ifaces

    def test_parses_option_values(self):
        ifaces = _parse_uci_network(_R4S_CONFIG)
        assert ifaces["lan"]["device"] == "eth1"
        assert ifaces["wan"]["device"] == "eth0"
        assert ifaces["wan"]["proto"] == "dhcp"

    def test_empty_config(self):
        assert _parse_uci_network("") == {}


class TestUciAnalyzer:
    def test_r4s_needs_setup(self):
        ifaces = _parse_uci_network(_R4S_CONFIG)
        result = _analyze_uci_interfaces(ifaces)
        assert result["status"] == "needs_setup"
        assert result["is_r4s"] is True
        assert result["wan_occupies_eth0"] is True
        assert result["recommended_capture_iface"] == "eth0"

    def test_r4s_configured(self):
        ifaces = _parse_uci_network(_R4S_CONFIGURED)
        result = _analyze_uci_interfaces(ifaces)
        assert result["status"] == "configured"
        assert result["iptv_configured"] is True
        assert result["recommended_capture_iface"] == "eth0"

    def test_unknown_topology(self):
        ifaces = _parse_uci_network(_UNKNOWN_CONFIG)
        result = _analyze_uci_interfaces(ifaces)
        assert result["status"] == "unknown"
        assert result["recommended_capture_iface"] == ""

    def test_result_keys_present(self):
        """API contract: these keys must always be present."""
        ifaces = _parse_uci_network(_R4S_CONFIG)
        result = _analyze_uci_interfaces(ifaces)
        for key in ("lan_device", "wan_device", "iptv_sniff_device",
                    "iptv_configured", "wan_occupies_eth0", "is_r4s",
                    "status", "message", "recommended_capture_iface",
                    "all_interfaces"):
            assert key in result, f"missing key: {key}"
