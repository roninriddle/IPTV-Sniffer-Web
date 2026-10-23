import json
import struct

import pytest
import app as app_module
import services.stb_discovery_service as discovery
from services.parsers.fcc import parse_fcc_request
from services.uios_catchup_service import extract_uios_session


def fcc_packet(protocol="telecom", group="239.1.2.3", port=5000):
    size = 40 if protocol == "telecom" else 32
    payload = bytearray(size)
    payload[:4] = struct.pack("!BBH", 0x82 if protocol == "telecom" else 0x85, 205, size // 4 - 1)
    group_bytes = bytes(map(int, group.split(".")))
    payload[8:12] = group_bytes
    if protocol == "telecom":
        payload[18:20] = struct.pack("!H", port)
        payload[20:24] = group_bytes
    return bytes(payload)


@pytest.mark.parametrize("protocol", ["telecom", "huawei"])
def test_fcc_request_extracts_group_and_protocol(protocol):
    assert parse_fcc_request(fcc_packet(protocol), {"239.1.2.3": {5000}}) == {
        "ip": "239.1.2.3", "port": 5000, "fcc_protocol": protocol,
    }


def test_fcc_rejects_truncation_unrelated_udp_and_ambiguous_huawei_ports():
    assert parse_fcc_request(fcc_packet()[:-1], {}) is None
    assert parse_fcc_request(bytes.fromhex("1101ac0000000000") + bytes(164), {}) is None
    assert parse_fcc_request(fcc_packet("huawei"), {"239.1.2.3": {5000, 6000}}) is None
    assert parse_fcc_request(fcc_packet(group="192.0.2.3"), {}) is None


def test_udp_fcc_merges_with_channel_and_keeps_provenance(monkeypatch):
    payload = fcc_packet()
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 17
    ip[12:16] = bytes([192, 0, 2, 1])
    ip[16:20] = bytes([192, 0, 2, 9])
    udp = struct.pack("!HHHH", 40000, 15970, len(payload) + 8, 0)
    monkeypatch.setattr(discovery, "iter_ipv4_packets", lambda _: iter([{"ip": bytes(ip) + udp + payload}]))
    channel = {"ip": "239.1.2.3", "port": 5000, "provenance": {"sources": [], "fields": {}}}
    discovery._merge_fcc_requests("fixture.pcap", "192.0.2.1", {"239.1.2.3:5000": channel})
    assert (channel["fcc_ip"], channel["fcc_port"]) == ("192.0.2.9", 15970)
    assert channel["provenance"]["sources"][0]["parser"] == "fcc-rtcp-request"
    assert channel["provenance"]["fields"]["fcc_ip"] == 0


def test_uios_public_settings_explain_key_requirements_without_exposing_session(monkeypatch):
    private = {"authorization": "private-fixture-token", "endpoint": "http://192.0.2.9:33200/EPG/jsp/getPlayURL4UIOS.jsp",
               "login": {"UserID": "fixture-user", "STBID": "fixture-box"}, "server_expiry": "2030-01-02 03:04:05"}
    monkeypatch.setattr(app_module.token_store, "load_uios_session", lambda: private)
    monkeypatch.setattr(app_module.epg_key_store, "get_epg_key", lambda: "")
    public = app_module._public_settings({"timeshift_host": "192.0.2.10"})
    status = public["catchup_auth"]
    assert status["profile"] == "bj_unicom_uios" and status["session_saved"]
    assert status["requires_des_key"] is False
    assert status["server_expiry"] == "2030-01-02 03:04:05"
    assert status["user_id_present"] and status["stb_id_present"]
    assert "private-fixture-token" not in json.dumps(public)
    assert "fixture-user" not in json.dumps(public)
    assert "catchup_auth" not in app_module._backup_settings()
    monkeypatch.setattr(app_module, "_merged_stb_auth_info", lambda: {})
    monkeypatch.setattr(app_module.token_store, "load", lambda: {})
    assert app_module.app.test_client().get("/api/stb-summary").get_json()["data"]["has_token"] is True


def test_uios_expiry_belongs_to_the_playback_token_only():
    request = b'POST /EPG/jsp/getPlayURL4UIOS.jsp HTTP/1.1\r\nHost: 192.0.2.9:33200\r\nAuthorization: playback-token\r\nContent-Length: 2\r\n\r\n{}'
    def response(token, expiry):
        body = json.dumps({"userToken": token, "tokenExpiredTime": expiry}).encode()
        return b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
    streams = {("192.0.2.1", 1234, "192.0.2.9", 33200): request,
               ("192.0.2.8", 8080, "192.0.2.1", 1235): response("unrelated-portal-token", "2099-01-01 00:00:00") + response("playback-token", "2030-01-02 03:04:05")}
    assert extract_uios_session(streams, "192.0.2.1")["server_expiry"] == "2030-01-02 03:04:05"
