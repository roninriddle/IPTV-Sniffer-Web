"""Regressions for DHCP lease detection and interface restoration in v1.3.6-test."""
import json
from types import SimpleNamespace

import pytest

from services.iptv_auth_service import IptvAuthService, _usable_ipv4_addresses
from services.log_service import AppLogger
import services.iptv_auth_service as auth_module


def service(tmp_path):
    return IptvAuthService(
        tmp_path / "iptv_auth_backups.json",
        tmp_path,
        AppLogger(tmp_path / "app.log"),
    )


def ok_result(cmd):
    return {"cmd": " ".join(cmd), "returncode": 0, "stdout": "", "stderr": ""}


def test_usable_ipv4_accepts_non_10_dhcp_lease():
    snapshot = {"ipv4": [
        {"local": "172.203.69.247", "prefixlen": 22},
        {"local": "169.254.1.2", "prefixlen": 16},
        {"local": "127.0.0.1", "prefixlen": 8},
    ]}
    assert _usable_ipv4_addresses(snapshot) == ["172.203.69.247"]


def test_apply_accepts_non_10_dhcp_lease(tmp_path, monkeypatch):
    svc = service(tmp_path)
    monkeypatch.setattr(svc, "_interface_exists", lambda iface: True)
    monkeypatch.setattr(svc, "_ensure_backup", lambda iface: {})
    monkeypatch.setattr(svc, "snapshot", lambda iface: {
        "interface": iface,
        "mac": "02:00:00:00:00:09",
        "ipv4": [{"local": "172.203.69.247", "prefixlen": 22}],
        "routes": [],
    })
    monkeypatch.setattr(auth_module.shutil, "which", lambda name: f"/sbin/{name}")
    monkeypatch.setattr(auth_module, "_run", lambda cmd, **kwargs: ok_result(cmd))

    process = SimpleNamespace(pid=1234, poll=lambda: None, terminate=lambda: pytest.fail("lease client terminated"))
    monkeypatch.setattr(auth_module.subprocess, "Popen", lambda *args, **kwargs: process)

    result = svc.apply({
        "confirmed": True,
        "interface": "eth1",
        "mac": "02:00:00:00:00:09",
        "hostname": "iptv-stb",
        "vendor_class": "IPTV",
        "requested_ip": "172.203.69.247",
        "route_mode": "none",
    })

    assert result["snapshot"]["ipv4"][0]["local"] == "172.203.69.247"
    saved = json.loads((tmp_path / "iptv_auth_backups.json").read_text())
    assert saved["interfaces"]["eth1"]["last_apply"]["payload"]["requested_ip"] == "172.203.69.247"


def test_restore_repairs_v133_overwritten_initial_snapshot(tmp_path, monkeypatch):
    svc = service(tmp_path)
    original = {"mac": "02:00:00:00:00:01", "ipv4": [], "routes": [], "operstate": "UP"}
    authenticated = {"mac": "02:00:00:00:00:09", "ipv4": [], "routes": [], "operstate": "UP"}
    svc._write_backup_data({"interfaces": {"eth1": {
        "initial": authenticated,
        "latest_pre_apply": authenticated,
        "history": [{"kind": "pre_apply", **original}],
        "last_apply": {"payload": {"mac": authenticated["mac"]}, "snapshot": authenticated},
    }}})
    monkeypatch.setattr(svc, "_interface_exists", lambda iface: True)
    calls = []
    monkeypatch.setattr(auth_module, "_run", lambda cmd, **kwargs: calls.append(cmd) or ok_result(cmd))
    monkeypatch.setattr(svc, "snapshot", lambda iface: {**original, "interface": iface})

    result = svc.restore({"interface": "eth1", "confirmed": True})

    assert result["legacy_backup_repaired"] is True
    assert ["ip", "link", "set", "dev", "eth1", "address", original["mac"]] in calls
    repaired = json.loads((tmp_path / "iptv_auth_backups.json").read_text())
    assert repaired["interfaces"]["eth1"]["initial"]["mac"] == original["mac"]
    assert repaired["interfaces"]["eth1"]["history"][-1]["kind"] == "repair_initial_from_pre_apply"


def test_restore_reports_mac_command_failure(tmp_path, monkeypatch):
    svc = service(tmp_path)
    original = {"mac": "02:00:00:00:00:01", "ipv4": [], "routes": [], "operstate": "UP"}
    svc._write_backup_data({"interfaces": {"eth1": {"initial": original, "history": []}}})
    monkeypatch.setattr(svc, "_interface_exists", lambda iface: True)

    def run(cmd, **kwargs):
        if cmd[:6] == ["ip", "link", "set", "dev", "eth1", "address"]:
            return {"cmd": " ".join(cmd), "returncode": 2, "stdout": "", "stderr": "device busy"}
        return ok_result(cmd)

    monkeypatch.setattr(auth_module, "_run", run)
    with pytest.raises(RuntimeError, match="device busy"):
        svc.restore({"interface": "eth1", "confirmed": True})


def test_restore_verifies_mac_after_successful_command(tmp_path, monkeypatch):
    svc = service(tmp_path)
    original = {"mac": "02:00:00:00:00:01", "ipv4": [], "routes": [], "operstate": "UP"}
    svc._write_backup_data({"interfaces": {"eth1": {"initial": original, "history": []}}})
    monkeypatch.setattr(svc, "_interface_exists", lambda iface: True)
    monkeypatch.setattr(auth_module, "_run", lambda cmd, **kwargs: ok_result(cmd))
    monkeypatch.setattr(svc, "snapshot", lambda iface: {
        "interface": iface,
        "mac": "02:00:00:00:00:09",
        "ipv4": [],
        "routes": [],
    })

    with pytest.raises(RuntimeError, match="MAC 恢复验证失败"):
        svc.restore({"interface": "eth1", "confirmed": True})
