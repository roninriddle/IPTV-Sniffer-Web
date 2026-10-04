"""Pure channel protocol parser; no device or network operations."""
import json
import re
import urllib.parse
from typing import Any
from .common import (_extract_json_object, _parse_pc_channel_catalog, _decode_payload_text, _safe_int, _truthy, _first_text, _first_int, _clean_group_name, _channel_category_from_group, _fallback_classify_channel_name, _parse_multicast_url, _parse_stream_params, _iter_channel_dicts, _extract_channel_objects_from_partial_json)

def _parse_channel_acquire_json(body: bytes) -> list[dict[str, Any]]:
    """Parse Beijing Unicom /bj_stb/V1/STB/channelAcquire channel list JSON."""
    text = _decode_payload_text(body).lstrip("\ufeff").strip()
    # Strip HTTP chunked transfer-encoding size lines embedded in body fragments
    # (e.g. "\r\n2000\r\n" appearing mid-string when first TCP segments are missing).
    text = re.sub(r"\r\n[0-9a-fA-F]{1,8}\r\n", "", text)
    if not text or "channel" not in text.lower():
        return []

    data: Any = None
    try:
        data = json.loads(text)
    except Exception:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start : end + 1])
            except Exception:
                pass

    if data is None:
        # Last resort: brace-counted per-object extraction for partially captured
        # responses where the JSON array opening is in the missing TCP segments.
        channel_list = _extract_channel_objects_from_partial_json(text)
        if not channel_list:
            return []
        data = channel_list  # treat as a flat list of channel dicts

    channels: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ch in _iter_channel_dicts(data):
        name = _first_text(ch, "channelName", "ChannelName", "name", "Name")
        channel_url = _first_text(ch, "channelURL", "ChannelURL", "url", "mediaURL", "broadcastURL")
        ip, port = _parse_multicast_url(channel_url)
        if not ip or not port:
            ip, port = _parse_multicast_url(_first_text(ch, "channelSDP", "ChannelSDP", "sdp"))
        if not ip or not port or not name:
            continue
        key = f"{ip}:{port}"
        if key in seen:
            continue
        seen.add(key)
        user_chan_id = _first_text(ch, "userChannelID", "UserChannelID", "channelNO", "channelNum", "num")
        channel_id = _first_text(ch, "channelID", "ChannelID", "id", "ID")
        time_shift_minutes = _first_int(ch, "timeShiftLength", "TimeShiftLength", "timeShiftDuration")
        fcc_ip, fcc_port, fec_port = _parse_stream_params(ch)
        group_name = _first_text(
            ch,
            "groupName",
            "GroupName",
            "channelGroup",
            "ChannelGroup",
            "channelGroupName",
            "ChannelGroupName",
            "category",
            "Category",
            "categoryName",
            "CategoryName",
            "channelTypeName",
            "ChannelTypeName",
            "subjectName",
            "SubjectName",
            "genre",
            "Genre",
        )
        channels.append({
            "num": int(user_chan_id) if user_chan_id.isdigit() else 0,
            "name": name,
            "category": _channel_category_from_group(group_name, name),
            "operator_group": _clean_group_name(group_name),
            "ip": ip,
            "port": port,
            "channel_id": channel_id,
            "user_channel_id": user_chan_id,
            "is_hd": _truthy(_first_text(ch, "isHDChannel", "IsHDChannel", "isHD", "hd")),
            "time_shift": _truthy(_first_text(ch, "timeShift", "TimeShift", "timeshift")),
            "time_shift_minutes": time_shift_minutes,
            "fcc_ip": fcc_ip,
            "fcc_port": fcc_port,
            "fec_port": fec_port,
            "backtv_url": _first_text(ch, "timeShiftURL", "TimeShiftURL", "backtvURL", "BacktimeURL", "BackUrl"),
        })
    channels.sort(key=lambda x: (x["num"] or 9999, x["name"], x["ip"], x["port"]))
    return channels

