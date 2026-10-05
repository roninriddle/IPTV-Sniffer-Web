"""Behavior regressions found while integrating PRs 7, 8, 10 and 11."""
import pytest
from services.rtp2httpd_config import parse_config, effective_config
import io
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
from pathlib import Path
import services.stb_discovery_service as stb
from services.log_service import AppLogger


def pcap_bytes(frames=(), linktype=1, endian='<', magic=0xa1b2c3d4):
    return struct.pack(endian+'IHHiIII', magic, 2, 4, 0, 0, 65535, linktype) + b''.join(
        struct.pack(endian+'IIII', 1, 0, len(frame), len(frame)) + frame for frame in frames)


def wait_status(service, status, timeout=4):
    deadline = time.monotonic() + timeout
    while service.status()['status'] != status and time.monotonic() < deadline:
        time.sleep(.02)
    assert service.status()['status'] == status
    return service.status()


@pytest.fixture
def capture(tmp_path):
    service = stb.StbDiscoveryService(AppLogger(tmp_path / 'capture.log'), archive_dir=tmp_path / 'archives')
    yield service
    service.reset()


def test_header_only_capture_reports_zero_packets(capture, tmp_path):
    path = tmp_path / 'empty.pcap'
    path.write_bytes(pcap_bytes())
    capture._pcap_path = str(path)
    capture._state.update(status=capture.STATUS_CAPTURING, stb_ip='192.0.2.20')
    capture.stop()
    state = wait_status(capture, 'error')
    assert state['diagnostics']['packet_count'] == 0
    assert state['diagnostics']['pcap_size'] == 24
    assert 'any' not in state['error']


def test_closed_stderr_is_safe(capture):
    stream = io.BytesIO()
    stream.close()
    capture._stderr_reader(SimpleNamespace(stderr=stream), capture._generation)


def test_late_process_exit_is_reported_and_reaped(capture, monkeypatch):
    real_popen = subprocess.Popen
    processes = []
    def spawn(cmd, **kwargs):
        Path(cmd[cmd.index('-w')+1]).write_bytes(pcap_bytes())
        proc = real_popen([sys.executable, '-c', 'import time,sys; time.sleep(.6); sys.stderr.write("synthetic failure"); sys.exit(2)'], **kwargs)
        processes.append(proc)
        return proc
    monkeypatch.setattr(capture, 'runtime_check', lambda: {'ok': True})
    monkeypatch.setattr(stb.subprocess, 'Popen', spawn)
    capture.start('192.0.2.20')
    state = wait_status(capture, 'error')
    assert '退出码 2' in state['error']
    assert 'synthetic failure' in state['error']
    assert processes[0].poll() == 2 and processes[0].stderr.closed


def test_old_generation_cannot_fail_new_capture(capture):
    proc = SimpleNamespace()
    capture._state['status'] = capture.STATUS_CAPTURING
    capture._proc = proc
    assert not capture._capture_failed(proc, capture._generation - 1, 'old error')
    assert capture.status()['status'] == 'capturing'
    capture._proc = None


def test_uci_comments_and_quoted_url_fragment():
    parsed = effective_config(parse_config("""config rtp2httpd 'main'
option upstream_interface 'eth1' # IPTV
option external_m3u 'https://example.test/list?a=1#fragment' # comment
list listen '[::]:5140' # bind
"""))
    assert parsed['values']['upstream-interface'] == 'eth1'
    assert parsed['values']['external-m3u'] == 'https://example.test/list?a=1#fragment'
    assert parsed['bind'] == ['[::]:5140']


def test_uci_effective_instance_and_simple_mode():
    parsed = effective_config(parse_config("""config rtp2httpd 'off'
option disabled '1'
option upstream_interface 'wrong0'
list listen '127.0.0.1:5141'
config rtp2httpd 'main'
option upstream_interface 'eth1'
option advanced_interface_settings '0'
option upstream_interface_multicast 'old0'
list listen '[::]:5140'
"""))
    assert parsed['values']['upstream-interface'] == 'eth1'
    assert 'upstream-interface-multicast' not in parsed['values']
    assert parsed['bind'] == ['[::]:5140']


@pytest.mark.parametrize('text', [
    "config rtp2httpd 'a'\nconfig rtp2httpd 'b'",
    "config rtp2httpd\noption disabled '1'",
    "config rtp2httpd\noption use_config_file '1'",
    "config rtp2httpd\noption disabled 'invalid'",
])
def test_uci_uncertain_config_is_not_reported_as_effective(text):
    with pytest.raises(ValueError):
        effective_config(parse_config(text))


def test_uci_advanced_mode_does_not_fall_back_to_inactive_default():
    parsed = effective_config(parse_config("""config rtp2httpd
option upstream_interface 'old0'
option advanced_interface_settings '1'
option upstream_interface_fcc 'eth1'
"""))
    assert 'upstream-interface' not in parsed['values']
    assert parsed['values']['upstream-interface-fcc'] == 'eth1'


def channel_frame(mac='02:00:00:00:00:20', linktype=1):
    addr = bytes.fromhex(mac.replace(':', ''))
    body = b"CUSetConfig('Channel','ChannelName=\"Test\" UserChannelID=\"1\" ChannelURL=\"igmp://239.1.1.1:8000\" ChannelID=\"1\"')"
    http = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
    tcp = struct.pack('>HHIIHHHH', 80, 50000, 1, 0, 0x5018, 65535, 0, 0) + http
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20+len(tcp), 0, 0, 64, 6, 0,
                     bytes([192,0,2,1]), bytes([192,0,2,20])) + tcp
    if linktype == 113:
        return struct.pack('>HHH8sH', 0, 1, 6, addr+b'\x00\x00', 0x800)+ip
    if linktype == 276:
        return struct.pack('>HHIHBB8s', 0x800, 0, 1, 1, 0, 6, addr+b'\x00\x00')+ip
    return addr + bytes.fromhex('020000000001') + b'\x08\x00' + ip


def dhcp_frames(mac, ip, message_type=5):
    # Reuse the existing independent synthetic DHCP generator (xid collision intentional).
    from test_regression_v134 import dhcp_packet
    return [dhcp_packet(123, mac, ip, 3)[16:], dhcp_packet(123, mac, ip, message_type)[16:]]


@pytest.mark.parametrize('requested_ip', ['192.0.2.19', ''])
def test_mac_dhcp_new_ip_extracts_channel_end_to_end(capture, tmp_path, requested_ip):
    mac = '02:00:00:00:00:20'
    frames = dhcp_frames('02:00:00:00:00:99', '192.0.2.99')
    frames += dhcp_frames(mac, '192.0.2.20') + [channel_frame()]
    path = tmp_path / 'new-ip.pcap'
    path.write_bytes(pcap_bytes(frames))
    capture._pcap_path = str(path)
    capture._state.update(status='capturing', stb_ip=requested_ip, stb_mac=mac)
    capture.stop()
    state = wait_status(capture, 'done')
    assert state['stb_ip'] == '192.0.2.20'
    assert state['channel_count'] == 1
    assert state['auth_info']['mac'] == mac
    assert state['diagnostics']['identity_source'] == 'dhcp_ack'
    assert state['diagnostics']['matched_response_streams'] == 1


def test_mac_identity_needs_ack_not_offer_or_other_client(tmp_path):
    mac = '02:00:00:00:00:20'
    path = tmp_path / 'offer.pcap'
    path.write_bytes(pcap_bytes(dhcp_frames(mac, '192.0.2.20', 2) + dhcp_frames('02:00:00:00:00:99', '192.0.2.99')))
    actual, auth = stb._capture_identity(str(path), '192.0.2.19', mac)
    assert actual == '192.0.2.19' and not auth['lease_confirmed']


@pytest.mark.parametrize('endian,magic', [('>',0xa1b2c3d4), ('<',0xa1b23c4d), ('>',0xa1b23c4d)])
def test_mac_statistics_use_bounded_multiformat_reader(tmp_path, endian, magic):
    path = tmp_path / 'format.pcap'
    path.write_bytes(pcap_bytes([channel_frame()], endian=endian, magic=magic))
    diag = stb._capture_diagnostics(str(path), '192.0.2.20', {}, [], '02:00:00:00:00:20')
    assert diag['packet_count'] == 1 and diag['mac_seen_count'] == 1
    assert diag['mac_supported'] and not diag['mac_not_seen']


@pytest.mark.parametrize('linktype', [113,276])
def test_cooked_capture_can_parse_without_false_mac_warning(capture, tmp_path, linktype):
    path = tmp_path / 'cooked.pcap'
    path.write_bytes(pcap_bytes([channel_frame(linktype=linktype)], linktype=linktype))
    capture._pcap_path = str(path)
    capture._state.update(status='capturing', stb_ip='192.0.2.20', stb_mac='02:00:00:00:00:20')
    capture.stop()
    state = wait_status(capture, 'done')
    assert state['channel_count'] == 1
    assert state['diagnostics']['mac_supported'] is False
    assert state['diagnostics']['mac_not_seen'] is False


def test_any_mac_filter_rejected_before_process_start(capture, monkeypatch):
    monkeypatch.setattr(stb.subprocess, 'Popen', lambda *a, **k: pytest.fail('must reject before spawn'))
    with pytest.raises(ValueError, match='实际接口'):
        capture.start('', 'any', stb_mac='02:00:00:00:00:20')
    assert capture.status()['status'] == 'idle'


def test_api_accepts_mac_only_and_returns_diagnostics(capture, monkeypatch):
    import app as app_module
    monkeypatch.setattr(app_module, 'stb_discovery_service', capture)
    calls = []
    monkeypatch.setattr(capture, 'start', lambda *a, **k: calls.append((a,k)))
    response = app_module.app.test_client().post('/api/stb_discovery/start', json={
        'stb_mac':'02:00:00:00:00:20', 'interface':'eth0'})
    assert response.status_code == 200
    assert calls[0][1]['stb_mac'] == '02:00:00:00:00:20'
    assert 'diagnostics' in response.get_json()['data']
