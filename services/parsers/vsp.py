"""Pure channel protocol parser; no device or network operations."""
import json
import re
import urllib.parse
from typing import Any
from .common import (_extract_json_object, _parse_pc_channel_catalog, _decode_payload_text, _safe_int, _truthy, _first_text, _first_int, _clean_group_name, _channel_category_from_group, _fallback_classify_channel_name, _parse_multicast_url, _parse_stream_params, _iter_channel_dicts, _extract_channel_objects_from_partial_json)

def _parse_vsp_json(body: bytes) -> list[dict[str, Any]]:
    """Parse /VSP/V3/QueryChannelListBySubject JSON response."""
    channels: list[dict[str, Any]] = []
    try:
        data = json.loads(body)
    except Exception:
        return channels
    for ch in data.get("channelDetails") or []:
        if not isinstance(ch, dict):
            continue
        name = str(ch.get("name", "")).strip()
        chan_no = ch.get("channelNO", "")
        chan_id = str(ch.get("ID", "")).strip()
        group_name = str(ch.get("groupName") or ch.get("subjectName") or ch.get("categoryName") or "").strip()
        if not name:
            continue
        # Extract multicast URL from physicalChannels
        for pc in ch.get("physicalChannels") or []:
            if not isinstance(pc, dict):
                continue
            btv = pc.get("btvCR") or {}
            if isinstance(btv, dict):
                url = str(btv.get("mediaURL", "") or btv.get("broadcastURL", "")).strip()
                m = re.match(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", url)
                if m:
                    channels.append(
                        {
                            "num": int(chan_no) if str(chan_no).isdigit() else 0,
                            "name": name,
                            "category": _channel_category_from_group(group_name, name),
                            "operator_group": _clean_group_name(group_name),
                            "ip": m.group(1),
                            "port": int(m.group(2)),
                            "channel_id": chan_id,
                            "is_hd": False,
                            "time_shift": False,
                            "fcc_ip": "",
                            "fcc_port": None,
                            "fec_port": None,
                        }
                    )
    return channels

