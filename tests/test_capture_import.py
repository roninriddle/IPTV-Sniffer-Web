"""External PCAP/PCAPNG import, PPPoE normalization and client detection."""
import io
import struct

from services.io_limits import iter_pcap_packets
from services.log_service import AppLogger
from services.stb_discovery_service import StbDiscoveryService, inspect_pcap


CLIENT = "10.25.18.33"
SERVER = "10.12.34.56"


def _ip(value):
    return bytes(int(part) for part in value.split("."))


def _tcp_ipv4(src_ip, dst_ip, src_port, dst_port, seq, payload):
    tcp = struct.pack(">HHIIHHHH", src_port, dst_port, seq, 0, 0x5018, 65535, 0, 0) + payload
    return struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
        _ip(src_ip), _ip(dst_ip),
    ) + tcp


def _pppoe_frame(src_ip, dst_ip, src_port, dst_port, seq, payload, vlan=True):
    ip_packet = _tcp_ipv4(src_ip, dst_ip, src_port, dst_port, seq, payload)
    ppp = b"\x00\x21" + ip_packet
    pppoe = b"\x11\x00\x00\x01" + struct.pack(">H", len(ppp)) + ppp
    ethernet = bytes.fromhex("020000000002020000000001")
    if vlan:
        return ethernet + b"\x81\x00\x00\x64\x88\x64" + pppoe
    return ethernet + b"\x88\x64" + pppoe


def _frames():
    request = b"GET /EDS/jsp/AuthenticationURL?UserID=test HTTP/1.1\r\nHost: epg\r\n\r\n"
    body = (b"CUSetConfig('Channel','ChannelName=\"CCTV1\" UserChannelID=\"1\" "
            b"ChannelURL=\"igmp://239.1.1.1:8000\" ChannelID=\"1\" "
            b"ChannelFCCIP=\"10.0.0.8\" ChannelFCCPort=\"9000\"')")
    response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    return [
        _pppoe_frame(CLIENT, SERVER, 50000, 8082, 1, request),
        _pppoe_frame(SERVER, CLIENT, 8082, 50000, 1, response),
    ]


def _pcap(frames):
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"".join(
        struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame for frame in frames
    )


def _block(block_type, body):
    padding = b"\x00" * ((-len(body)) % 4)
    total = 12 + len(body) + len(padding)
    return struct.pack("<II", block_type, total) + body + padding + struct.pack("<I", total)


def _pcapng(frames):
    section = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = _block(1, struct.pack("<HHI", 1, 0, 65535))
    packets = b"".join(_block(6, struct.pack("<IIIII", 0, 0, index, len(frame), len(frame)) + frame)
                       for index, frame in enumerate(frames, 1))
    return section + interface + packets


def test_pcapng_reader_and_pppoe_preflight(tmp_path):
    path = tmp_path / "ikuai-wan2.pcapng"
    path.write_bytes(_pcapng(_frames()))
    assert len(list(iter_pcap_packets(path))) == 2
    report = inspect_pcap(str(path), path.name)
    assert report["format"] == "PCAPNG"
    assert report["has_vlan"] and report["has_pppoe"]
    assert report["has_epg_auth"] and report["has_channel_data"] and report["has_fcc"]
    assert report["client_candidates"][0]["ip"] == CLIENT
    assert report["ready"] is True


def test_import_is_private_and_analysis_reuses_channel_pipeline(tmp_path):
    service = StbDiscoveryService(AppLogger(tmp_path / "app.log"), archive_dir=tmp_path / "archives")
    report = service.import_capture(io.BytesIO(_pcap(_frames())), "router capture.pcap")
    stored = tmp_path / "archives" / report["archive_name"]
    assert stored.is_file()
    assert stored.stat().st_mode & 0o777 == 0o600
    state = service.analyze_archive(report["archive_name"], CLIENT)
    assert state["status"] == "done"
    assert state["source_mode"] == "imported"
    assert state["stb_ip"] == CLIENT
    assert state["channel_count"] == 1
    assert state["channels"][0]["ip"] == "239.1.1.1"


def test_import_rejects_wrong_extension_before_writing(tmp_path):
    service = StbDiscoveryService(AppLogger(tmp_path / "app.log"), archive_dir=tmp_path / "archives")
    try:
        service.import_capture(io.BytesIO(_pcap(_frames())), "capture.txt")
    except ValueError as exc:
        assert ".pcap" in str(exc)
    else:
        raise AssertionError("wrong extension must be rejected")
    assert not (tmp_path / "archives").exists()


def test_capture_import_api_keeps_preflight_and_analysis_separate(tmp_path, monkeypatch):
    import app as app_module

    service = StbDiscoveryService(AppLogger(tmp_path / "app.log"), archive_dir=tmp_path / "archives")
    monkeypatch.setattr(app_module, "stb_discovery_service", service)
    client = app_module.app.test_client()
    response = client.post(
        "/api/stb_discovery/capture-import/preflight",
        data={"file": (io.BytesIO(_pcap(_frames())), "ikuai-wan2.pcap")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    report = response.get_json()["data"]
    assert report["ready"] is True
    assert service.status()["channel_count"] == 0

    analyzed = client.post(
        "/api/stb_discovery/capture-import/analyze",
        json={"archive_name": report["archive_name"], "client_ip": CLIENT},
    )
    assert analyzed.status_code == 200
    assert analyzed.get_json()["data"]["channel_count"] == 1
