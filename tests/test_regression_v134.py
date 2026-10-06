"""v1.3.4-test regressions with synthetic data and no device operations."""
import io
import json
import re
import socket
import struct
import threading
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import app as a
from services.hls_service import HlsService
from services.iptv_auth_service import IptvAuthService
from services.stb_discovery_service import StbDiscoveryService, _extract_dhcp_from_pcap
from services.storage_service import (ChannelStore, SettingsStore, LocalSecretStore,
    OperatorChannelStore, SubscriptionStore, FccStore)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    for name, cls, filename in [
        ("settings_store", SettingsStore, "settings.json"),
        ("channel_store", ChannelStore, "channels.json"),
        ("operator_channel_store", OperatorChannelStore, "operator_channels.json"),
        ("subscription_store", SubscriptionStore, "subscription_candidates.json"),
        ("fcc_store", FccStore, "fcc.json"),
        ("epg_key_store", LocalSecretStore, "epg-key.secret"),
    ]:
        monkeypatch.setattr(a, name, cls(tmp_path / filename))
    a.settings_store.save({"auto_epg": False, "use_epg": False, "use_logo": False,
                           "http_host": "192.0.2.10", "http_port": 5140})
    monkeypatch.setattr(a.epg_service, "refresh_async", lambda *args: None)
    monkeypatch.setattr(a, "enrich_channel_rows", lambda rows, settings, **kwargs: rows)
    monkeypatch.setattr(a, "_iptv_local_ip", lambda settings: "")
    monkeypatch.setattr(a, "DATA_DIR", tmp_path)
    monkeypatch.setattr(a, "_BACKUP_FILES", [
        ("settings", tmp_path / "settings.json"), ("channels", tmp_path / "channels.json"),
    ])
    return a.app.test_client()


def operator(host):
    return {"ip": host, "port": 5000, "name": "Audit News", "channel_id": "101"}


def archives(tmp_path, count):
    archive = tmp_path / "archives"
    archive.mkdir()
    for i in range(count):
        pcap = archive / f"stb-boot-audit-{i:03}.pcap"
        pcap.write_bytes(b"synthetic pcap")
        artifacts = archive / f"{pcap.stem}.artifacts"
        artifacts.mkdir()
        (artifacts / "manifest.json").write_text("{}")
    return archive


def test_disaster_127_capture_pairs_restore_on_fresh_instance(isolated, tmp_path, monkeypatch):
    archive = archives(tmp_path, 127)
    service = SimpleNamespace(archive_dir=archive)
    monkeypatch.setattr(a, "stb_discovery_service", service)
    exported = isolated.post("/api/backup/disaster-export", json={
        "confirmed": True, "modules": ["pcap_archives"]})
    assert exported.status_code == 200
    blob = exported.get_data()
    exported.close()
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        assert len(zf.infolist()) == 258
    service.archive_dir = tmp_path / "restored"
    restored = isolated.post("/api/backup/disaster-import", data={
        "confirmed": "true", "file": (io.BytesIO(blob), "audit.zip")})
    assert restored.status_code == 200
    assert restored.get_json()["data"]["pcap_archives_restored"] == 127
    assert restored.get_json()["data"]["protocol_manifests_restored"] == 127
    assert len(list(service.archive_dir.glob("*.pcap"))) == 127
    assert not list(tmp_path.glob(".iptv-disaster-*.zip"))


@pytest.mark.parametrize("limit,value", [("_DISASTER_MAX_FILES", 4), ("_DISASTER_MAX_UNCOMPRESSED_BYTES", 50)])
def test_disaster_export_rejects_packages_outside_import_limits(isolated, tmp_path, monkeypatch, limit, value):
    monkeypatch.setattr(a, "stb_discovery_service", SimpleNamespace(archive_dir=archives(tmp_path, 1)))
    monkeypatch.setattr(a, limit, value)
    response = isolated.post("/api/backup/disaster-export", json={
        "confirmed": True, "modules": ["pcap_archives"]})
    assert response.status_code == 400
    assert "限制" in response.get_json()["error"]
    assert not list(tmp_path.glob(".iptv-disaster-*.zip"))


def test_json_round_trip_preserves_same_name_sources_and_import_routing(isolated, tmp_path):
    rows = [{"key": f"239.1.1.{i}:5000", "host": f"239.1.1.{i}", "port": 5000,
             "name": "Audit News", "fcc_ip": "192.0.2.50", "fcc_port": 8000+i,
             "fec_port": 9000+i} for i in (1, 2)]
    target = tmp_path / "export.json"
    a.export_service._write_playlist_json(a.export_service._normalize_channels(rows), target, "rtp")
    content = target.read_text()
    payload = json.loads(content)
    assert payload["schema_version"] == 2
    assert len(payload["items"]) == 2
    # The browser probes JSON as a global backup before trying channel import.
    assert isolated.post("/api/backup/inspect", json={"backup": payload}).status_code == 400
    response = isolated.post("/api/channels/import-export", json={"content": content, "filename": "channels.json"})
    assert response.status_code == 200
    assert response.get_json()["data"]["saved"] == 2
    saved = a.channel_store.load()
    for row in rows:
        assert saved[row["key"]]["name"] == row["name"]
        assert saved[row["key"]]["fcc_port"] == row["fcc_port"]
        assert saved[row["key"]]["fec_port"] == row["fec_port"]


def test_rtp_subscription_uses_current_operator_source_and_keeps_manual_alternate(isolated):
    a._do_operator_import([operator("239.1.1.1")])
    a.subscription_store.save(["c-101"])
    a._do_operator_import([operator("239.1.1.2")])
    a.channel_store.save_rows([{"host": "239.1.1.3", "port": 5000, "name": "Audit News"}])
    assert "239.1.1.2:5000" in isolated.get("/live/c-101").headers["Location"]
    best = isolated.get("/playlist-rtp2httpd.m3u").get_data(as_text=True)
    all_sources = isolated.get("/playlist-rtp2httpd-all.m3u").get_data(as_text=True)
    assert "239.1.1.1:5000" not in best + all_sources
    assert "239.1.1.2:5000" in best
    assert "239.1.1.3:5000" in all_sources
    # History remains editable; it is only excluded from the active subscription.
    assert a.channel_store.get("239.1.1.1:5000")


@pytest.mark.parametrize("key", ["127.0.0.1_1234", "239.1.1.1_0", "239.1.1.1_65536", "239.1.1.1_05000", "evil_5000"])
def test_hls_invalid_source_rejected_without_creating_process(isolated, monkeypatch, key):
    monkeypatch.setattr(a.hls_service, "ensure", lambda *args: pytest.fail("unexpected stream creation"))
    assert isolated.get(f"/hls/{key}/stream.m3u8").status_code == 400
    assert isolated.get(f"/hls/{key}/00000.ts").status_code == 404


def test_hls_segments_only_read_existing_running_stream(isolated, tmp_path, monkeypatch):
    service = object.__new__(HlsService)
    service._lock = threading.RLock()
    service._streams = {}
    monkeypatch.setattr(a, "hls_service", service)
    monkeypatch.setattr(service, "ensure", lambda *args: pytest.fail("unexpected stream creation"))
    url = "/hls/239.1.1.1_5000/00000.ts"
    assert isolated.get(url).status_code == 404
    (tmp_path / "00000.ts").write_bytes(b"synthetic-segment")
    service._streams["239.1.1.1_5000"] = {"dir": tmp_path, "proc": SimpleNamespace(poll=lambda: None), "last_access": 0}
    response = isolated.get(url)
    assert response.status_code == 200 and response.data == b"synthetic-segment"
    response.close()
    assert service._streams["239.1.1.1_5000"]["last_access"] > 0
    service._streams["239.1.1.1_5000"]["proc"] = SimpleNamespace(poll=lambda: 1)
    assert isolated.get(url).status_code == 404


@pytest.mark.parametrize("invalid", [
    {"clear_epg_des3_key": "false"}, {"catchup_days": "bad"}, {"catchup_days": -1}, {"http_port": 65536},
    {"http_port": None}, {"catchup_auto_refresh_hours": 0}, {"catchup_enabled": "false"},
    {"path_mode": "file"}, {"rtp2httpd_path_prefix": "/../bad"},
])
def test_invalid_settings_rejected_before_any_secret_or_setting_write(isolated, invalid):
    before = a.settings_store.load()
    a.epg_key_store.set_epg_key("synthetic-original")
    response = isolated.post("/api/settings", json={**invalid, "epg_des3_key": "synthetic-replacement"})
    assert response.status_code == 400
    assert a.settings_store.load() == before
    assert a.epg_key_store.get_epg_key() == "synthetic-original"
    assert isolated.get("/playlist.m3u").status_code == 200


def test_invalid_backup_settings_rejected_before_restoring_other_modules(isolated, tmp_path):
    payload = {"settings": {"catchup_days": "bad"}, "channels": {"must-not-write": {}},
               "credentials": {"epg_des3_key": "synthetic-replacement"}}
    response = isolated.post("/api/backup/import", json={"backup": payload, "modules": ["settings", "channels", "credentials"]})
    assert response.status_code == 400
    assert not (tmp_path / "channels.json").exists()
    assert not a.epg_key_store.get_epg_key()


def test_status_and_pre_apply_preserve_original_restore_point(isolated, tmp_path, monkeypatch):
    service = IptvAuthService(tmp_path / "auth.json", tmp_path, a.logger)
    original = {"mac": "02:00:00:00:00:01", "ipv4": [{"local": "192.0.2.20", "prefixlen": 24}]}
    current = {"mac": "02:00:00:00:00:02", "ipv4": [{"local": "10.0.0.20", "prefixlen": 24}]}
    monkeypatch.setattr(service, "snapshot", lambda iface: original)
    service.status("audit0")
    monkeypatch.setattr(service, "snapshot", lambda iface: current)
    service.status("audit0")
    service._ensure_backup("audit0")
    assert service.backup_export("audit0")["initial"] == original
    calls = []
    monkeypatch.setattr(service, "_interface_exists", lambda iface: True)
    monkeypatch.setattr("services.iptv_auth_service._run", lambda cmd, **kw:
                        (calls.append(cmd) or {"returncode": 0, "stdout": "", "stderr": ""}))
    monkeypatch.setattr(service, "snapshot", lambda iface: {"interface": iface, **original})
    service.restore({"interface": "audit0", "confirmed": True})
    assert ["ip", "link", "set", "dev", "audit0", "address", original["mac"]] in calls
    assert not any(current["mac"] in cmd for cmd in calls)


def dhcp_packet(xid, mac, ip, message_type):
    response = message_type in (2, 5, 6)
    body = bytearray(240)
    body[0:3] = bytes([2 if response else 1, 1, 6])
    body[4:8] = struct.pack(">I", xid)
    body[16:20] = socket.inet_aton(ip if response else "0.0.0.0")
    body[28:34] = bytes.fromhex(mac.replace(":", ""))
    body[236:240] = b"\x63\x82\x53\x63"
    body.extend(bytes([53, 1, message_type, 50, 4]) + socket.inet_aton(ip) + b"\xff")
    udp = struct.pack(">HHHH", 67 if response else 68, 68 if response else 67, len(body)+8, 0) + body
    ip_header = bytearray(20)
    ip_header[0], ip_header[9] = 0x45, 17
    ip_header[2:4] = struct.pack(">H", len(udp)+20)
    frame = b"\x00" * 12 + b"\x08\x00" + ip_header + udp
    return struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame


def test_dhcp_uses_target_identity_even_with_colliding_xids(isolated, tmp_path):
    archive = tmp_path / "pcaps"
    archive.mkdir()
    pcap = archive / "stb-boot-target.pcap"
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for mac, ip in [("02:00:00:00:00:01", "192.0.2.30"), ("02:00:00:00:00:02", "192.0.2.40")]:
        data += dhcp_packet(1, mac, ip, 3) + dhcp_packet(1, mac, ip, 5)
    pcap.write_bytes(data)
    service = StbDiscoveryService(a.logger, None)
    service.archive_dir = archive
    result = service.reanalyze_latest_archive("192.0.2.40")
    assert result["auth_info"]["mac"] == "02:00:00:00:00:02"
    assert result["auth_info"]["assigned_ip"] == "192.0.2.40"
    assert _extract_dhcp_from_pcap(str(pcap)) == {}
    assert _extract_dhcp_from_pcap(str(pcap), "192.0.2.99") == {}


def test_dhcp_prefers_ack_to_offer_and_rejects_nak(tmp_path):
    path = tmp_path / "dhcp.pcap"
    mac = "02:00:00:00:00:01"
    prefix = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = dhcp_packet(1, mac, "192.0.2.30", 3) + dhcp_packet(1, mac, "192.0.2.20", 2)
    path.write_bytes(prefix + body + dhcp_packet(1, mac, "192.0.2.30", 5))
    assert _extract_dhcp_from_pcap(str(path), "192.0.2.30")["assigned_ip"] == "192.0.2.30"
    path.write_bytes(prefix + body + dhcp_packet(1, mac, "192.0.2.30", 6))
    assert _extract_dhcp_from_pcap(str(path), "192.0.2.30") == {}


def test_first_refresh_deadline_does_not_slide_and_configuration_reschedules(isolated, monkeypatch):
    monkeypatch.setattr(a, "_catchup_auto_state", {})
    settings = {"catchup_enabled": True, "catchup_auto_refresh_enabled": True, "catchup_auto_refresh_hours": 1}
    assert a._next_catchup_run_locked(settings, 1000) == 4600
    assert a._next_catchup_run_locked(settings, 2000) == 4600
    assert a._next_catchup_run_locked(settings, 5000) == 4600
    assert a._next_catchup_run_locked({**settings, "catchup_auto_refresh_enabled": False}, 5000) is None
    assert a._next_catchup_run_locked(settings, 6000) == 9600
    assert a._next_catchup_run_locked({**settings, "catchup_auto_refresh_hours": 2}, 6000) == 13200


def test_auto_loop_actually_runs_first_refresh(isolated, monkeypatch):
    a.settings_store.save({"catchup_enabled": True, "catchup_auto_refresh_enabled": True,
                           "catchup_auto_refresh_hours": 1})
    monkeypatch.setattr(a, "_catchup_auto_state", {})
    monkeypatch.setattr(a, "_catchup_auto_thread_started", False)
    captured, called = [], []
    monkeypatch.setattr(a.threading, "Thread", lambda target, **kw: SimpleNamespace(start=lambda: captured.append(target)))
    clock = [1800000000]
    class EndSimulation(Exception): pass
    def sleep(seconds):
        clock[0] += 3600
        if len(called) == 1:
            raise EndSimulation()
    def refresh(settings, source):
        called.append(source)
        a._catchup_auto_state.update(last_success_at=clock[0], next_run_at=clock[0]+3600)
        return {"updated": 1, "total": 1}
    monkeypatch.setattr(a.time, "time", lambda: clock[0])
    monkeypatch.setattr(a.catchup_scheduler, "path", None)
    monkeypatch.setattr(a.catchup_scheduler, "thread", None)
    monkeypatch.setattr(a.catchup_scheduler.stop_event, "wait", sleep)
    monkeypatch.setattr(a, "_refresh_backtv_with_state", refresh)
    a._start_catchup_auto_refresh_loop()
    with pytest.raises(EndSimulation): captured[0]()
    assert called == ["auto"]


def test_failed_refresh_backoff_not_overridden_by_old_success(isolated, monkeypatch):
    settings = {**a.settings_store.load(), "catchup_enabled": True,
                "catchup_auto_refresh_enabled": True, "catchup_auto_refresh_hours": 1}
    monkeypatch.setattr(a, "_catchup_auto_state", {"last_success_at": 1000})
    monkeypatch.setattr(a, "_effective_stb_auth_info", lambda: {})
    monkeypatch.setattr(a.time, "time", lambda: 10000)
    def fail(*args): raise RuntimeError("synthetic failure")
    monkeypatch.setattr(a, "refresh_backtv_urls", fail)
    with pytest.raises(RuntimeError): a._refresh_backtv_with_state(settings, "auto")
    assert a._next_catchup_run_locked(settings, 10060) == 13600
    assert a._catchup_auto_state["running"] is False


def test_multicast_datagram_counts_sender_address_correctly(isolated, monkeypatch):
    import services.capture_service as cap
    class FakeSocket:
        def setsockopt(self, *args): pass
        def bind(self, *args): pass
        def setblocking(self, *args): pass
        def close(self): pass
        def recvfrom(self, size): return b"synthetic-ts", ("192.0.2.50", 5000)
    monkeypatch.setattr(cap.shutil, "which", lambda name: None)
    monkeypatch.setattr(a.capture_service, "_interface_ipv4", lambda iface: "192.0.2.100")
    monkeypatch.setattr(cap.socket, "socket", lambda *args: FakeSocket())
    monkeypatch.setattr(cap.select, "select", lambda r, w, x, t: (r, [], []))
    ticks = iter([1800000000, 1800000000, 1800000000, 1800000004])
    monkeypatch.setattr(cap.time, "time", lambda: next(ticks))
    result = a.capture_service.diagnose_multicast("239.1.1.1", 5000, "audit0")
    assert result["socket_active_packets"] == 1
    assert result["verdict"] == "ok"


def test_image_tags_match_application_version():
    from config import APP_VERSION
    root = Path(__file__).resolve().parents[1]
    for filename in ("docker-compose.yml", "docker-bake.hcl"):
        tags = re.findall(r"roninriddle/iptv-sniffer-web:([\w.-]+)", (root / filename).read_text())
        assert tags == [APP_VERSION]


def test_json_v2_rejects_non_string_names():
    rows, skipped = a.parse_exported_channels_json({"_format": "iptv-sniffer-channels",
        "schema_version": 2, "items": [{"name": ["bad"]}, {"name": {"bad": 1}}]})
    assert rows == [] and skipped == 2


@pytest.mark.parametrize("latest,current,expected", [
    ("1.3.3", "1.3.4-test", False), ("1.3.4", "1.3.4-test", True),
    ("v1.3.4-test", "1.3.4-test", False), ("1.3.5-test", "1.3.4-test", True),
    ("1.3.4-test", "1.3.4", False), ("unknown", "1.3.4-test", False),
])
def test_test_version_update_detection(monkeypatch, latest, current, expected):
    monkeypatch.setattr(a, "APP_VERSION", current)
    monkeypatch.setattr(a, "_version_check", {})
    monkeypatch.setattr(a, "urlopen", lambda *args, **kwargs:
                        io.BytesIO(json.dumps([{"name": latest}]).encode()))
    a._do_version_check()
    assert a._version_check["update_available"] is expected
