"""Regression tests for v0.9.6 fixes.

Covers:
- pcap TCP reassembly: Ethernet / SLL (DLT=113) / SLL2 (DLT=276)
- CUSetConfig channel parsing: single-quote outer, double-quote outer
- Export URL: FCC / fcc-type / FEC parameter generation
- IPTV auth guarded executor payload / hook generation
"""
import os
import json
import struct
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.stb_discovery_service import _extract_ctc_portal_auth, _parse_channel_acquire_json, _parse_chanlist_html, _reassemble_tcp_streams
from services.export_service import ExportService
from services.epg_refresh_service import _pad_des_plaintext
from services.iptv_auth_service import IptvAuthService
import services.iptv_auth_service as iptv_auth_module
from services.log_service import AppLogger
import app as app_module
from app import _parse_rtp2httpd_config_text, fill_channel_name_from_metadata
from services.epg_service import normalize_channel_name
from services.storage_service import ChannelStore
from utils import channel_group_key, redact_sensitive_text


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


def test_beijing_unicom_channel_acquire_json_is_parsed():
    body = json.dumps({
        "channelCount": "2",
        "channleInfoStruct": [
            {
                "channelName": "CCTV1",
                "groupName": "\u592e\u89c6\u9891\u9053",
                "userChannelID": "1",
                "channelID": "1001",
                "channelURL": "igmp://239.3.1.161:8001?fcc=10.7.10.172:8027&fec=9000",
                "timeShift": "1",
                "timeShiftLength": "14400",
                "timeShiftURL": "rtsp://61.135.88.136/PLTV/1001",
                "isHDChannel": "2",
            },
            {
                "channelName": "\u5317\u4eac\u536b\u89c6",
                "groupName": "\u5317\u4eac\u9891\u9053",
                "userChannelID": "2",
                "channelID": "1002",
                "channelURL": "igmp://239.3.1.162:8002",
                "channelFCCIP": "10.7.10.173",
                "channelFCCPort": "8028",
                "channelFECPort": "9001",
                "timeShift": "0",
            },
        ],
    }, ensure_ascii=False).encode("gb18030")
    channels = _parse_channel_acquire_json(body)
    assert len(channels) == 2
    assert channels[0]["name"] == "CCTV1"
    assert channels[0]["ip"] == "239.3.1.161"
    assert channels[0]["port"] == 8001
    assert channels[0]["fcc_ip"] == "10.7.10.172"
    assert channels[0]["fcc_port"] == 8027
    assert channels[0]["fec_port"] == 9000
    assert channels[0]["time_shift"] is True
    assert channels[0]["time_shift_days"] == 14400
    assert channels[0]["backtv_url"].startswith("rtsp://61.135.88.136/")
    assert channels[0]["is_hd"] is True
    assert channels[0]["category"] == "\u592e\u89c6\u9891\u9053"
    assert channels[0]["operator_group"] == "\u592e\u89c6\u9891\u9053"
    assert channels[1]["name"] == "\u5317\u4eac\u536b\u89c6"
    assert channels[1]["category"] == "\u5317\u4eac\u9891\u9053"
    assert channels[1]["operator_group"] == "\u5317\u4eac\u9891\u9053"
    assert channels[1]["fcc_ip"] == "10.7.10.173"
    assert channels[1]["fcc_port"] == 8028
    assert channels[1]["fec_port"] == 9001


def test_channel_store_preserves_operator_custom_category(tmp_path):
    store = ChannelStore(tmp_path / "channels.json")
    result = store.save_rows([{
        "key": "239.3.1.162:8002",
        "host": "239.3.1.162",
        "port": 8002,
        "name": "\u5317\u4eac\u536b\u89c6",
        "category": "\u5317\u4eac\u9891\u9053",
        "operator_group": "\u5317\u4eac\u9891\u9053",
    }])
    assert result["saved"] == 1
    saved = store.get("239.3.1.162:8002")
    assert saved["category"] == "\u5317\u4eac\u9891\u9053"
    assert saved["operator_group"] == "\u5317\u4eac\u9891\u9053"


def test_ctc_portal_auth_fields_are_extracted_from_stb_boot_streams():
    stb_ip = "192.168.100.13"
    srv_ip = "10.7.10.10"
    request = (
        b"GET /auth?UserID=10001&Action=Login&Mode=MENU HTTP/1.1\r\n"
        b"User-Agent: test-stb-agent\r\n"
        b"Host: itv.example:8298\r\n\r\n"
        b"POST /uploadAuthInfo HTTP/1.1\r\n"
        b"Host: itv.example:8298\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"UserID=10001&Authenticator=ABC&AccessMethod=dhcp&AccessUserName=acc001&STBID=STB123"
        b"&STBType=EC6108V9&STBVersion=V100R005"
    )
    response_body = b"Authentication.CTCGetAuthInfo('AUTHINFO123')"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: " + str(len(response_body)).encode() + b"\r\n\r\n" + response_body +
        b"HTTP/1.1 200 OK\r\n"
        b"Set-Cookie: UserToken=TOKEN123; Path=/\r\n"
        b"X-Frame-Sessionid: SESSION123\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    parsed = _extract_ctc_portal_auth({
        (stb_ip, 50000, srv_ip, 8298): request,
        (srv_ip, 8298, stb_ip, 50000): response,
    }, stb_ip)
    assert parsed["portal_auth_host"] == "itv.example:8298"
    assert parsed["epg_user_id"] == "10001"
    assert parsed["epg_stb_id"] == "STB123"
    assert parsed["access_user_name"] == "acc001"
    assert parsed["epg_stb_type"] == "EC6108V9"
    assert parsed["epg_stb_version"] == "V100R005"
    assert parsed["epg_user_agent"] == "test-stb-agent"
    assert parsed["ctc_auth_info"] == "AUTHINFO123"
    assert parsed["user_token"] == "TOKEN123"
    assert parsed["x_frame_session_id"] == "SESSION123"


def test_des_authenticator_defaults_to_pkcs5_padding():
    assert _pad_des_plaintext(b"12345678") == b"12345678" + (b"\x08" * 8)
    assert _pad_des_plaintext(b"12345678", padding="zero") == b"12345678"


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


# ── Export file generation: dedup + source selection ─────────────────────

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

    def test_operator_custom_category_is_exported(self, tmp_path):
        rows = [self._row("\u5317\u4eac\u536b\u89c6", "239.3.1.162", 8002, category="\u5317\u4eac\u9891\u9053")]
        self._export(tmp_path, rows)
        m3u = (tmp_path / "channels-all.m3u").read_text(encoding="utf-8")
        txt = (tmp_path / "channels.txt").read_text(encoding="utf-8")
        assert 'group-title="\u5317\u4eac\u9891\u9053"' in m3u
        assert "\u5317\u4eac\u9891\u9053,#genre#" in txt
        assert "其它频道,#genre#" not in txt

    def test_csv_lists_each_source_once(self, tmp_path):
        rows = [self._row("CCTV1", "239.1.1.1", 8001, width=1920, height=1080)]
        self._export(tmp_path, rows)
        text = (tmp_path / "channels.csv").read_text(encoding="utf-8-sig")
        # One header + exactly one data row for the channel (no quality dup row).
        data_rows = [ln for ln in text.splitlines() if ",CCTV1," in ln]
        assert len(data_rows) == 1

    def test_export_summary_has_no_resolution_buckets(self, tmp_path):
        rows = [self._row("CCTV1", "239.1.1.1", 8001, width=1920, height=1080)]
        _, result = self._export(tmp_path, rows)
        assert "quality_group_counts" not in result
        assert "unclassified_resolution_count" not in result

    def test_csv_header_keeps_only_source_and_epg_columns(self, tmp_path):
        rows = [self._row("CCTV1", "239.1.1.1", 8001, width=1920, height=1080)]
        self._export(tmp_path, rows)
        header = (tmp_path / "channels.csv").read_text(encoding="utf-8-sig").splitlines()[0].split(",")
        assert header == [
            "展示分组",
            "原始分类",
            "频道名称",
            "编码",
            "帧率",
            "EPG ID",
            "EPG名称",
            "台标",
            "EPG来源",
            "FCC服务器IP",
            "FCC服务器端口",
            "源地址",
            "播放地址",
            "组播IP",
            "端口",
            "抓到包数",
        ]

    def test_manual_primary_is_used_for_best_exports(self, tmp_path):
        rows = [
            self._row(
                "CCTV4K", "239.1.1.9", 8009,
                tvg_id="106",
                probe_status="ok", fcc_ip="10.0.0.1", fcc_port=9000,
                fec_port=8008,
            ),
            self._row(
                "CCTV4K", "239.1.1.10", 8010,
                tvg_id="106",
                probe_status="not_probed", is_primary=True,
            ),
        ]
        self._export(tmp_path, rows)
        text = (tmp_path / "channels-rtp2httpd-best.m3u").read_text(encoding="utf-8")
        assert "rtp://239.1.1.10:8010" in text
        assert "rtp://239.1.1.9:8009" not in text

    def test_export_health_ok_beats_failed_high_spec_source(self, tmp_path):
        rows = [
            self._row(
                "CCTV4K", "239.1.1.9", 8009,
                tvg_id="106",
                probe_status="ok", fcc_ip="10.0.0.1", fcc_port=9000,
                fec_port=8008, export_health_status="failed",
                export_health_http_code=503,
            ),
            self._row(
                "CCTV4K", "239.1.1.10", 8010,
                tvg_id="106",
                probe_status="not_probed", export_health_status="ok",
                export_health_speed=1200000,
            ),
        ]
        self._export(tmp_path, rows)
        text = (tmp_path / "channels-rtp2httpd-best.m3u").read_text(encoding="utf-8")
        assert "rtp://239.1.1.10:8010" in text
        assert "rtp://239.1.1.9:8009" not in text

    def test_export_health_speed_breaks_equal_playable_sources(self, tmp_path):
        rows = [
            self._row(
                "CCTV4K", "239.1.1.9", 8009,
                tvg_id="106", export_health_status="ok",
                export_health_speed=1000000,
            ),
            self._row(
                "CCTV4K", "239.1.1.10", 8010,
                tvg_id="106", export_health_status="ok",
                export_health_speed=3000000,
            ),
        ]
        self._export(tmp_path, rows)
        text = (tmp_path / "channels-rtp2httpd-best.m3u").read_text(encoding="utf-8")
        assert "rtp://239.1.1.10:8010" in text
        assert "rtp://239.1.1.9:8009" not in text

    def test_hls_m3u_omits_catchup_when_disabled(self, tmp_path):
        svc = ExportService(tmp_path)
        rows = {
            "239.1.1.1:8001": self._row("CCTV1", "239.1.1.1", 8001),
        }
        op_channels = {
            "239.1.1.1:8001": {
                "time_shift": True,
                "time_shift_days": 14400,
                "backtv_url": "rtsp://10.7.10.1/PLTV/888?accountinfo=secret-token",
            }
        }
        text = svc.hls_m3u(
            rows,
            "http://127.0.0.1:8787",
            operator_channels=op_channels,
            catchup_enabled=False,
            catchup_days=7,
        )
        assert "catchup-source" not in text
        assert "catchup-correction" not in text
        assert "rtsp://10.7.10.1" not in text

    def test_hls_m3u_emits_local_catchup_proxy_when_enabled(self, tmp_path):
        svc = ExportService(tmp_path)
        rows = {
            "239.1.1.1:8001": self._row("CCTV1", "239.1.1.1", 8001),
        }
        op_channels = {
            "239.1.1.1:8001": {
                "time_shift": True,
                "time_shift_days": 14400,
                "backtv_url": "rtsp://10.7.10.1/PLTV/888?accountinfo=secret-token",
            }
        }
        text = svc.hls_m3u(
            rows,
            "http://127.0.0.1:8787",
            operator_channels=op_channels,
            catchup_enabled=True,
            catchup_days=7,
        )
        assert 'catchup-correction="8"' in text
        assert 'catchup-days="10"' in text
        assert "http://127.0.0.1:8787/hls/239.1.1.1_8001/catchup" in text
        assert "rtsp://10.7.10.1" not in text


def test_sensitive_iptv_tokens_are_redacted_before_logging():
    text = (
        "ffmpeg failed rtsp://10.7.10.1/PLTV/888?"
        "accountinfo=very-secret&UserToken=abc123 "
        "Authenticator=deadbeef UserPassword=pw"
    )
    redacted = redact_sensitive_text(text)
    assert "very-secret" not in redacted
    assert "abc123" not in redacted
    assert "deadbeef" not in redacted
    assert "UserPassword=pw" not in redacted
    assert "rtsp://<redacted>" in redacted


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

def test_iptv_auth_payload_and_hook_include_option60_and_interface(tmp_path):
    svc = IptvAuthService(tmp_path / "auth-backup.json", tmp_path, AppLogger(tmp_path / "app.log"))
    payload = svc._payload({
        "interface": "enp3s0",
        "mac": "d4:c1:c8:ee:9b:1f",
        "hostname": "18000413001338300000D4C1C8EE9B1F",
        "vendor_class": "00001f3901c4693f",
        "requested_ip": "10.193.235.26",
        "gateway": "10.193.224.1",
        "route_mode": "multicast",
    })
    hook = svc._udhcpc_hook_content(payload["interface"], payload["route_mode"])
    assert payload["interface"] == "enp3s0"
    assert payload["vendor_class"] == "00001f3901c4693f"
    assert payload["vendor_class_colon"] == "00:00:1f:39:01:c4:69:3f"
    assert 'LOG="/app/data/iptv-auth-enp3s0.log"' in hook
    assert 'ip -4 route replace 224.0.0.0/4 dev "$interface"' in hook


def test_iptv_auth_detects_egress_bpf_and_clsact_drops(tmp_path, monkeypatch):
    svc = IptvAuthService(tmp_path / "auth-backup.json", tmp_path, AppLogger(tmp_path / "app.log"))

    def fake_which(name):
        return f"/sbin/{name}" if name in {"ip", "tc"} else None

    def fake_run(cmd, timeout=12, check=False):
        if cmd == ["ip", "link", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "3: enp3s0", "stderr": ""}
        if cmd == ["ip", "-details", "link", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "3: enp3s0: <UP> prog/xdp id 50", "stderr": ""}
        if cmd == ["tc", "-s", "qdisc", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "qdisc clsact ffff:\n Sent 100 bytes 10 pkt (dropped 3, overlimits 0 requeues 0)", "stderr": ""}
        if cmd == ["tc", "-s", "filter", "show", "dev", "enp3s0", "egress"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "filter protocol all pref 49152 bpf chain 0 handle 0x1 handle_egress:[53]", "stderr": ""}
        return {"cmd": " ".join(cmd), "returncode": 1, "stdout": "", "stderr": "unexpected"}

    monkeypatch.setattr(iptv_auth_module.shutil, "which", fake_which)
    monkeypatch.setattr(iptv_auth_module, "_run", fake_run)
    status = svc.egress_bpf_status("enp3s0")
    assert status["xdp_present"] is True
    assert status["egress_bpf_present"] is True
    assert status["handle_egress_present"] is True
    assert status["clsact_dropped"] == 3
    assert status["suspected_igmp_block"] is True
    assert status["command_preview"] == "tc filter del dev enp3s0 egress protocol all pref 49152"


def test_iptv_auth_clear_egress_bpf_only_targets_selected_interface(tmp_path, monkeypatch):
    svc = IptvAuthService(tmp_path / "auth-backup.json", tmp_path, AppLogger(tmp_path / "app.log"))
    deleted = {"done": False}
    calls = []

    def fake_which(name):
        return f"/sbin/{name}" if name in {"ip", "tc"} else None

    def fake_run(cmd, timeout=12, check=False):
        calls.append(cmd)
        if cmd == ["ip", "link", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "3: enp3s0", "stderr": ""}
        if cmd == ["ip", "-details", "link", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "3: enp3s0: <UP>", "stderr": ""}
        if cmd == ["tc", "-s", "qdisc", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "qdisc clsact ffff:\n Sent 100 bytes 10 pkt (dropped 3, overlimits 0 requeues 0)", "stderr": ""}
        if cmd == ["tc", "-s", "filter", "show", "dev", "enp3s0", "egress"]:
            stdout = "" if deleted["done"] else "filter protocol all pref 49152 bpf chain 0 handle 0x1 handle_egress:[53]"
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": stdout, "stderr": ""}
        if cmd == ["tc", "filter", "del", "dev", "enp3s0", "egress", "protocol", "all", "pref", "49152"]:
            deleted["done"] = True
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "", "stderr": ""}
        return {"cmd": " ".join(cmd), "returncode": 1, "stdout": "", "stderr": "unexpected"}

    monkeypatch.setattr(iptv_auth_module.shutil, "which", fake_which)
    monkeypatch.setattr(iptv_auth_module, "_run", fake_run)
    result = svc.clear_egress_bpf({"interface": "enp3s0", "confirm": "确认解除"})
    assert result["changed"] is True
    assert result["interface"] == "enp3s0"
    assert ["tc", "filter", "del", "dev", "enp3s0", "egress", "protocol", "all", "pref", "49152"] in calls
    assert all("enp2s0" not in cmd for cmd in calls)


def test_iptv_auth_watch_requires_confirmation_when_enabling(tmp_path, monkeypatch):
    svc = IptvAuthService(tmp_path / "auth-backup.json", tmp_path, AppLogger(tmp_path / "app.log"))

    def fake_run(cmd, timeout=12, check=False):
        if cmd == ["ip", "link", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "3: enp3s0", "stderr": ""}
        return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(iptv_auth_module, "_run", fake_run)
    with pytest.raises(ValueError):
        svc.configure_egress_bpf_watch({
            "enabled": True,
            "interface": "enp3s0",
            "interval_seconds": 30,
            "confirm": "wrong",
        })
    data = svc.configure_egress_bpf_watch({
        "enabled": True,
        "interface": "enp3s0",
        "interval_seconds": 5,
        "confirm": "确认恢复",
    })
    assert data["config"]["enabled"] is True
    assert data["config"]["interface"] == "enp3s0"
    assert data["config"]["interval_seconds"] == 10


def test_iptv_auth_watch_tick_auto_clears_selected_egress_bpf(tmp_path, monkeypatch):
    svc = IptvAuthService(tmp_path / "auth-backup.json", tmp_path, AppLogger(tmp_path / "app.log"))
    deleted = {"done": False}
    calls = []

    def fake_which(name):
        return f"/sbin/{name}" if name in {"ip", "tc"} else None

    def fake_run(cmd, timeout=12, check=False):
        calls.append(cmd)
        if cmd == ["ip", "link", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "3: enp3s0", "stderr": ""}
        if cmd == ["ip", "-details", "link", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "3: enp3s0: <UP> prog/xdp id 50", "stderr": ""}
        if cmd == ["tc", "-s", "qdisc", "show", "dev", "enp3s0"]:
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "qdisc clsact ffff:\n Sent 100 bytes 10 pkt (dropped 9, overlimits 0 requeues 0)", "stderr": ""}
        if cmd == ["tc", "-s", "filter", "show", "dev", "enp3s0", "egress"]:
            stdout = "" if deleted["done"] else "filter protocol all pref 49152 bpf chain 0 handle 0x1 handle_egress:[53]"
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": stdout, "stderr": ""}
        if cmd == ["tc", "filter", "del", "dev", "enp3s0", "egress", "protocol", "all", "pref", "49152"]:
            deleted["done"] = True
            return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "", "stderr": ""}
        return {"cmd": " ".join(cmd), "returncode": 1, "stdout": "", "stderr": "unexpected"}

    monkeypatch.setattr(iptv_auth_module.shutil, "which", fake_which)
    monkeypatch.setattr(iptv_auth_module, "_run", fake_run)
    result = svc._egress_bpf_watch_tick("enp3s0")
    runtime = svc.egress_bpf_watch_status()["runtime"]
    assert result["result"]["changed"] is True
    assert runtime["check_count"] == 1
    assert runtime["fix_count"] == 1
    assert ["tc", "filter", "del", "dev", "enp3s0", "egress", "protocol", "all", "pref", "49152"] in calls
    assert all("enp2s0" not in cmd for cmd in calls)


# ── CCTV4 regional variants ──────────────────────────────────────────────

def test_cctv4_regional_names_match_distinct_epg_ids():
    assert normalize_channel_name("CCTV4中文国际欧洲") == "cctv4euo"
    assert normalize_channel_name("CCTV4EUO") == "cctv4euo"
    assert normalize_channel_name("CCTV4中文国际美洲") == "cctv4ame"
    assert normalize_channel_name("CCTV4AME") == "cctv4ame"


def test_cctv4_regional_variants_are_not_grouped_as_cctv4_backups():
    generic = channel_group_key({"name": "CCTV4", "tvg_id": "4"})
    europe = channel_group_key({"name": "CCTV4", "auto_name": "CCTV4中文国际欧洲", "tvg_id": "4"})
    america = channel_group_key({"name": "CCTV4", "auto_name": "CCTV4中文国际美洲", "tvg_id": "4"})
    assert generic != europe
    assert generic != america
    assert europe != america


def test_cctv4_regional_auto_name_beats_generic_epg_display_name():
    item = {
        "name": "CCTV4",
        "auto_name": "CCTV4中文国际欧洲",
        "tvg_id": "4",
        "tvg_name": "CCTV4",
    }
    fill_channel_name_from_metadata(item, allow_epg_name=True)
    assert item["name"] == "CCTV4中文国际欧洲"


def test_cctv4_regional_auto_name_beats_short_epg_alias():
    item = {
        "name": "CCTV4EUO",
        "auto_name": "CCTV4中文国际欧洲",
        "tvg_id": "22",
        "tvg_name": "CCTV4EUO",
    }
    fill_channel_name_from_metadata(item, allow_epg_name=True)
    assert item["name"] == "CCTV4中文国际欧洲"


# ── Removed UDP candidate sniffer flow ───────────────────────────────────

def test_udp_candidate_sniffer_endpoints_are_retired():
    client = app_module.app.test_client()
    for path, method in [
        ("/api/status", "get"),
        ("/api/streams", "get"),
        ("/api/capture/start", "post"),
        ("/api/capture/stop", "post"),
        ("/api/capture/reset", "post"),
    ]:
        resp = getattr(client, method)(path, json={} if method == "post" else None)
        assert resp.status_code == 410
        assert "运营商频道发现" in resp.get_json()["error"]


def test_export_without_channels_uses_saved_channel_list(tmp_path):
    original_store = app_module.channel_store
    original_output = app_module.export_service.output_dir
    try:
        app_module.channel_store = ChannelStore(tmp_path / "channels.json")
        app_module.channel_store.save_rows([{
            "key": "239.1.1.1:8001",
            "host": "239.1.1.1",
            "port": 8001,
            "name": "CCTV1",
            "category": "央视频道",
            "packets": 10,
        }])
        app_module.export_service.output_dir = tmp_path
        resp = app_module.app.test_client().post("/api/export", json={"http_host": "", "http_port": 5140})
        assert resp.status_code == 200
        assert resp.get_json()["data"]["count"] == 1
    finally:
        app_module.channel_store = original_store
        app_module.export_service.output_dir = original_output
