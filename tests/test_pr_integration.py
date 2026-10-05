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
