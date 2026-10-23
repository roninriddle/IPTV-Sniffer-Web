import json
import stat
from datetime import datetime
from urllib.parse import parse_qs, urlsplit

import pytest

import app as app_module
from services.storage_service import StbTokenStore
from services.uios_catchup_service import extract_uios_session, resolve_playback_url, UiosCatchupError
from services.uios_catchup_service import LOCAL_TIME
from services.subscription_service import _subscription_m3u
from services.iptv_auth_service import IptvAuthService
from services.log_service import AppLogger
import services.stb_discovery_service as discovery


def request(path, body, authorization="opaque-test-token", host="192.0.2.9:33200"):
    encoded = json.dumps(body).encode()
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {authorization}\r\n"
            f"Content-Length: {len(encoded)}\r\n\r\n").encode() + encoded


def session():
    return {"endpoint": "http://192.0.2.9:33200/EPG/jsp/getPlayURL4UIOS.jsp",
            "authorization": "opaque-test-token", "schedule_base": "http://192.0.2.8"}


def test_capture_extracts_correct_opaque_authorization_and_not_unrelated_dsm_token(tmp_path):
    raw = request("/EPG/jsp/index4UIOS.jsp", {"STBID": "stb", "UserID": "user"})
    raw += request("/EPG/jsp/getPlayURL4UIOS.jsp", {"ContentType": "live", "ContentID": "123"})
    captured = extract_uios_session({("192.0.2.1", 1234, "192.0.2.9", 33200): raw}, "192.0.2.1")
    assert captured["authorization"] == "opaque-test-token"
    assert captured["login"] == {"STBID": "stb", "UserID": "user"}
    assert not extract_uios_session({("192.0.2.1", 1234, "192.0.2.9", 33200): raw}, "192.0.2.2")
    store = StbTokenStore(tmp_path / "token.json")
    store.save_uios_session(captured)
    assert stat.S_IMODE((tmp_path / "uios-session.secret").stat().st_mode) == 0o600
    assert store.load_uios_session() == captured
    assert "opaque-test-token" not in json.dumps(store.load())


def test_lookback_uses_program_id_converts_utc_and_preserves_signed_parameters():
    calls = []
    def fetch(url, body=None, **options):
        calls.append((url, body, options))
        if "/schedules/" in url:
            return {"schedules": [{"code": "program-123", "starttime": "2026-10-23 18:51:00", "endtime": "2026-10-23 19:00:00"}]}
        assert body == {"ContentType": "lookback", "ContentID": "program-123"}
        assert options["authorization"] == "opaque-test-token"
        assert options["interface"] == "end0"
        return {"ResultCode": 0, "URLs": [{"playurl": "rtsp://192.0.2.10/TVOD/a.smil?accountinfo=signature&zoneoffset=480&it=abc&playseek=old"}]}
    value = resolve_playback_url(session(), {"channel_id": "channel-1"}, "20261023105200-20261023105900", "end0", fetch,
                                 now=datetime(2026, 10, 24, tzinfo=LOCAL_TIME))
    assert "channel-1_20261023.json" in calls[0][0]
    assert parse_qs(urlsplit(value).query) == {"accountinfo": ["signature"], "zoneoffset": ["480"], "it": ["abc"], "playseek": ["20261023185200-20261023185900"]}


def test_timeshift_fallback_and_midnight_date_conversion():
    calls = []
    def fetch(url, body=None, **options):
        calls.append((url, body))
        if "/schedules/" in url:
            raise UiosCatchupError("schedule unavailable")
        assert body == {"ContentType": "live", "ContentID": "channel-1"}
        return {"URLs": [{"timeshifturl": "rtsp://192.0.2.10/PLTV/a.smil?accountinfo=signature"}]}
    url = resolve_playback_url(session(), {"channel_id": "channel-1"}, "20261023170000-20261023170500", request_json=fetch)
    assert "_20261024.json" in calls[0][0]
    assert parse_qs(urlsplit(url).query)["playseek"] == ["20261024010000-20261024010500"]


def test_ongoing_programme_uses_pltv_instead_of_incomplete_tvod():
    def fetch(url, body=None, **options):
        if "/schedules/" in url:
            return {"schedules": [{"code": "program-123", "starttime": "2026-10-23 18:00:00", "endtime": "2026-10-23 19:00:00"}]}
        assert body == {"ContentType": "live", "ContentID": "channel-1"}
        return {"URLs": [{"timeshifturl": "rtsp://192.0.2.10/PLTV/a.smil?accountinfo=signature"}]}
    url = resolve_playback_url(session(), {"channel_id": "channel-1"}, "20261023103000-20261023103500", request_json=fetch,
                               now=datetime(2026, 10, 23, 18, 40, tzinfo=LOCAL_TIME))
    assert "/PLTV/" in url


def test_uios_subscription_does_not_apply_timezone_shift_twice():
    settings = {"catchup_enabled": True, "catchup_days": 7}
    default = _subscription_m3u(settings, {}, [], "http://example.invalid")
    uios = _subscription_m3u(settings, {}, [], "http://example.invalid", utc_catchup=True)
    assert 'catchup-correction="8"' in default
    assert 'catchup-correction="0"' in uios


def test_uios_extracts_unicast_routes_without_saving_signed_urls():
    raw = request("/EPG/jsp/getPlayURL4UIOS.jsp", {"ContentType": "live", "ContentID": "123"})
    streams = {("192.0.2.1", 1234, "192.0.2.9", 33200): raw,
               ("192.0.2.10", 554, "192.0.2.1", 4567): b"RTSP/1.0 302 Redirect\r\nLocation: rtsp://192.0.2.11/TVOD/a.smil?accountinfo=private\r\n\r\n"}
    captured = extract_uios_session(streams, "192.0.2.1")
    assert captured["server_ips"] == ["192.0.2.11", "192.0.2.9"]
    assert "accountinfo" not in json.dumps(captured)


def test_dhcp_renew_restores_only_validated_uios_host_routes(tmp_path):
    service = IptvAuthService(tmp_path / "backups.json", tmp_path, AppLogger(tmp_path / "test.log", 10))
    auth = {"mac": "02:00:00:00:00:01", "hostname": "stb", "vendor_class": "01"}
    data = {"interface": "end0", "unicast_hosts": ["192.0.2.9", "192.0.2.10"]}
    payload = service._payload(data, auth)
    hook = service._udhcpc_hook_content("end0", "multicast", payload["unicast_hosts"])
    assert 'for server in 192.0.2.10 192.0.2.9;' in hook
    assert 'route replace "$server/32"' in hook
    assert 'route replace default' not in hook
    assert service._payload({**data, "route_mode": "none"}, auth)["unicast_hosts"] == []
    with pytest.raises(ValueError):
        service._payload({**data, "unicast_hosts": ["192.0.2.9; touch /tmp/bad"]}, auth)


def test_failed_authorization_is_user_safe_and_no_unsigned_fallback():
    def fetch(*args, **kwargs):
        return {"ResultCode": 403, "ResultDesc": "opaque-test-token"}
    with pytest.raises(UiosCatchupError) as error:
        resolve_playback_url(session(), {"channel_id": "channel-1"}, "20261023100000-20261023100500", request_json=fetch)
    assert "opaque-test-token" not in str(error.value)


def test_app_uses_dynamic_signed_url_once_with_uios_transport(monkeypatch):
    from services.media_task_service import MediaTaskManager
    monkeypatch.setattr(app_module, "media_tasks", MediaTaskManager())
    monkeypatch.setattr(app_module.operator_channel_store, "load", lambda: {"239.1.1.1:5000": {"channel_id": "1", "backtv_url": "rtsp://192.0.2.10/a.smil"}})
    monkeypatch.setattr(app_module.token_store, "load_uios_session", session)
    monkeypatch.setattr(app_module.settings_store, "load", lambda: {"interface": "end0"})
    signed = "rtsp://192.0.2.10/a.smil?accountinfo=signature&playseek=local"
    monkeypatch.setattr(app_module, "resolve_playback_url", lambda *args: signed)
    observed = []
    class Media:
        def __init__(self, url, agent, **options):
            observed.append((url, options))
        def close(self):
            pass
        def open(self):
            return b"\x47" * 188
        def iter_payloads(self, first):
            yield first
    monkeypatch.setattr(app_module, "CombinedRtspUdpSession", Media)
    response = app_module.app.test_client().get("/hls/239.1.1.1_5000/catchup?playseek=20261023100000-20261023100500")
    assert response.status_code == 200
    assert response.data == b"\x47" * 188
    response.close()
    assert observed == [(signed, {"interface": "end0", "transport_profile": "uios"})]


def test_large_video_response_does_not_hide_later_control_on_keepalive(monkeypatch):
    key = ("192.0.2.9", 80, "192.0.2.1", 1234)
    size = 36 * 1024 * 1024
    header = f"HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nContent-Length: {size}\r\n\r\n".encode()
    control = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
    def segments(_):
        # Header fragments arrive out of order and are retransmitted.
        yield key, 1020, header[20:]
        yield key, 1000, header[:20]
        yield key, 1000, header
        for off in range(0, size, 4096):
            yield key, 1000 + len(header) + off, b"x" * 4096
        yield key, 1000 + len(header) + size, control
    monkeypatch.setattr(discovery, "_tcp_segments", segments)
    assert discovery._reassemble_tcp_streams("unused")[key] == control


def test_unknown_large_tcp_still_obeys_memory_limit(monkeypatch):
    def segments(_):
        for off in range(0, 33 * 1024 * 1024, 16384):
            yield ("192.0.2.9", 80, "192.0.2.1", 1234), off, b"x" * 16384
    monkeypatch.setattr(discovery, "_tcp_segments", segments)
    with pytest.raises(ValueError, match="32 MiB"):
        discovery._reassemble_tcp_streams("unused")
