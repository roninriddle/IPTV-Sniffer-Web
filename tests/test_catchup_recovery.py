"""Regression coverage for rebuilding catchup mappings after data restoration."""

import io

import pytest

import app as app_module
from services.epg_refresh_service import _update_backtv_from_channel_text
from services.rtsp_catchup_service import RtspCatchupError
from services.storage_service import OperatorChannelStore, SettingsStore


def test_epg_refresh_rebuilds_missing_operator_channel_mapping():
    channels = {}
    text = (
        "CUSetConfig('Channel', 'ChannelName=\"News\" ChannelID=\"1001\" "
        "ChannelURL=\"igmp://239.1.2.3:5000\" TimeShiftLength=\"10080\" "
        "TimeShiftURL=\"rtsp://10.0.0.5/live?token=secret\"')"
    )

    updated, rebuilt, total = _update_backtv_from_channel_text(text, channels)

    assert (updated, rebuilt, total) == (0, 1, 1)
    channel = channels["239.1.2.3:5000"]
    assert channel["time_shift"] is True
    assert channel["time_shift_minutes"] == 10080
    assert channel["channel_id"] == "1001"
    assert channel["source"] == "epg_refresh_rebuild"
    assert channel["backtv_url"].startswith("rtsp://10.0.0.5/")


def test_epg_refresh_updates_existing_mapping_without_rebuilding():
    channels = {
        "239.1.2.3:5000": {
            "key": "239.1.2.3:5000",
            "time_shift": False,
            "backtv_url": "",
        }
    }
    text = (
        'CUSetConfig("Channel", "ChannelURL=\'udp://239.1.2.3:5000\' '
        'TimeShiftURL=\'rtsp://10.0.0.5/live?token=fresh\'")'
    )

    updated, rebuilt, total = _update_backtv_from_channel_text(text, channels)

    assert (updated, rebuilt, total) == (1, 0, 1)
    assert channels["239.1.2.3:5000"]["time_shift"] is True
    assert channels["239.1.2.3:5000"]["backtv_url"].endswith("token=fresh")


def test_catchup_prefers_canonical_smil_url_then_keeps_captured_fallback():
    candidates = app_module._catchup_rtsp_candidates(
        "rtsp://example.invalid/live/channel.smil?token=private",
        "20260831120000-20260831120500",
    )

    assert [mode for mode, _ in candidates] == ["canonical_smil", "captured"]
    assert candidates[0][1].endswith(".smil?playseek=20260831120000-20260831120500")
    assert "token=private" in candidates[1][1]


def test_catchup_failure_category_never_returns_raw_ffmpeg_text():
    assert app_module._catchup_failure_category("server returned 401 unauthorized", "") == "rtsp_unauthorized"
    assert app_module._catchup_failure_category("method SETUP failed: 461", "") == "rtsp_transport_unsupported"
    assert app_module._catchup_failure_category("unexpected output", "回看上游在 15 秒内未返回数据") == "rtsp_no_media"


def test_effective_stb_auth_prefers_current_authenticated_iptv_lease(monkeypatch):
    monkeypatch.setattr(app_module, "_merged_stb_auth_info", lambda: {"assigned_ip": "10.0.0.9"})
    monkeypatch.setattr(app_module.settings_store, "load", lambda: {"interface": "enp3s0"})
    monkeypatch.setattr(
        app_module.iptv_auth_service,
        "snapshot",
        lambda interface: {"ipv4": [{"local": "10.0.0.88"}]},
    )

    assert app_module._effective_stb_auth_info()["assigned_ip"] == "10.0.0.88"


def test_iptv_auth_apply_persists_active_interface(tmp_path, monkeypatch):
    original_settings_store = app_module.settings_store
    try:
        app_module.settings_store = SettingsStore(tmp_path / "settings.json")
        monkeypatch.setattr(
            app_module.iptv_auth_service,
            "apply",
            lambda data, auth: {"interface": "enp3s0"},
        )
        monkeypatch.setattr(app_module, "_latest_stb_auth_info", lambda: {})

        response = app_module.app.test_client().post("/api/iptv-auth/apply", json={})

        assert response.status_code == 200
        assert app_module.settings_store.load()["interface"] == "enp3s0"
    finally:
        app_module.settings_store = original_settings_store


def test_public_settings_infers_timeshift_host_without_exposing_full_url(monkeypatch):
    monkeypatch.setattr(
        app_module.operator_channel_store,
        "load",
        lambda: {"239.1.2.3:5000": {"backtv_url": "rtsp://10.0.0.5:554/live?UserToken=secret"}},
    )
    monkeypatch.setattr(app_module.epg_key_store, "get_epg_key", lambda: "")

    public = app_module._public_settings({"timeshift_host": ""})

    assert public["timeshift_host"] == "10.0.0.5:554"
    assert public["timeshift_host_inferred"] is True
    assert "secret" not in public["timeshift_host"]


def test_catchup_refresh_fails_fast_when_iptv_interface_has_no_lease(monkeypatch):
    monkeypatch.setattr(app_module.epg_key_store, "get_epg_key", lambda: "")
    monkeypatch.setattr(app_module.iptv_auth_service, "snapshot", lambda interface: {"ipv4": []})

    with pytest.raises(ValueError, match="先在认证页执行一键认证"):
        app_module._refresh_backtv_with_state(
            {"interface": "enp3s0", "epg_auth_host": "10.0.0.9:8082"},
            source="manual",
        )


def test_catchup_returns_gateway_timeout_and_stops_ffmpeg(tmp_path, monkeypatch):
    original_store = app_module.operator_channel_store
    store = OperatorChannelStore(tmp_path / "operator_channels.json")
    store.save_dict({
        "239.1.2.3:5000": {
            "key": "239.1.2.3:5000", "backtv_url": "rtsp://10.0.0.5/live?token=secret",
        }
    })

    class FakeProc:
        def __init__(self):
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO(b"upstream timeout")
            self.terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.terminated = True

    proc = FakeProc()
    commands = []
    class FailedCombinedSession:
        def close(self):
            pass

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            raise RtspCatchupError("rtsp_timeout")

    try:
        app_module.operator_channel_store = store
        monkeypatch.setattr(app_module, "CombinedRtspUdpSession", FailedCombinedSession)
        monkeypatch.setattr(app_module.shutil, "which", lambda name: "/usr/bin/ffmpeg")
        monkeypatch.setattr(app_module.subprocess, "Popen", lambda command, **kwargs: commands.append(command) or proc)
        monkeypatch.setattr(app_module, "_wait_for_catchup_first_chunk", lambda process: (b"", "回看上游在 15 秒内未返回数据"))

        response = app_module.app.test_client().get(
            "/hls/239.1.2.3_5000/catchup?playseek=20260831120000-20260831120500"
        )

        assert response.status_code == 504
        assert proc.terminated is True
        assert "-rw_timeout" in commands[0]
        assert str(app_module._CATCHUP_FFMPEG_READ_TIMEOUT_MICROSECONDS) in commands[0]
        assert response.json["catchup_diagnostic"] == "rtsp_timeout"
        assert b"secret" not in response.data
    finally:
        app_module.operator_channel_store = original_store


def test_catchup_reuses_configured_stb_user_agent(tmp_path, monkeypatch):
    original_store = app_module.operator_channel_store
    original_settings_store = app_module.settings_store
    store = OperatorChannelStore(tmp_path / "operator_channels.json")
    store.save_dict({
        "239.1.2.3:5000": {
            "key": "239.1.2.3:5000", "backtv_url": "rtsp://10.0.0.5/live?token=secret",
        }
    })

    class FakeProc:
        def __init__(self):
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()

        def poll(self):
            return 0

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    commands = []
    class FailedCombinedSession:
        def close(self):
            pass

        def __init__(self, *args, **kwargs):
            pass

        def open(self):
            raise RtspCatchupError("rtsp_transport_unsupported")

    try:
        app_module.operator_channel_store = store
        app_module.settings_store = SettingsStore(tmp_path / "settings.json")
        app_module.settings_store.save({"epg_user_agent": "test-stb-agent"})
        monkeypatch.setattr(app_module, "CombinedRtspUdpSession", FailedCombinedSession)
        monkeypatch.setattr(app_module.shutil, "which", lambda name: "/usr/bin/ffmpeg")
        monkeypatch.setattr(app_module.subprocess, "Popen", lambda command, **kwargs: commands.append(command) or FakeProc())
        monkeypatch.setattr(app_module, "_wait_for_catchup_first_chunk", lambda process: (b"G" * 188, ""))

        response = app_module.app.test_client().get(
            "/hls/239.1.2.3_5000/catchup?playseek=20260831120000-20260831120500"
        )

        assert response.status_code == 200
        assert commands[0][commands[0].index("-user_agent") + 1] == "test-stb-agent"
        assert commands[0][commands[0].index("-rtsp_transport") + 1] == "udp+tcp"
        assert b"secret" not in response.data
    finally:
        app_module.operator_channel_store = original_store
        app_module.settings_store = original_settings_store


def test_catchup_prefers_combined_rtsp_media_without_ffmpeg(tmp_path, monkeypatch):
    original_store = app_module.operator_channel_store
    store = OperatorChannelStore(tmp_path / "operator_channels.json")
    store.save_dict({
        "239.1.2.3:5000": {
            "key": "239.1.2.3:5000", "backtv_url": "rtsp://10.0.0.5/live?token=secret",
        }
    })

    class SuccessfulCombinedSession:
        def close(self):
            pass

        def __init__(self, url, user_agent):
            self.url = url
            self.user_agent = user_agent

        def open(self):
            return b"\x47" + b"\x00" * 187

        def iter_payloads(self, first):
            yield first

    try:
        app_module.operator_channel_store = store
        monkeypatch.setattr(app_module, "CombinedRtspUdpSession", SuccessfulCombinedSession)
        monkeypatch.setattr(app_module.shutil, "which", lambda name: None)

        response = app_module.app.test_client().get(
            "/hls/239.1.2.3_5000/catchup?playseek=20260831120000-20260831120500"
        )

        assert response.status_code == 200
        assert response.data.startswith(b"\x47")
        assert b"secret" not in response.data
    finally:
        app_module.operator_channel_store = original_store
