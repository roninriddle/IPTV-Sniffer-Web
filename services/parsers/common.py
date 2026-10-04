"""Pure channel protocol parser; no device or network operations."""
import json
import re
import urllib.parse
from typing import Any

def _extract_json_object(text: str, start: int) -> dict[str, Any] | None:
    """Decode one JSON object starting at or after *start* using brace counting."""
    start = text.find("{", start)
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    value = json.loads(text[start:index + 1])
                except (TypeError, ValueError):
                    return None
                return value if isinstance(value, dict) else None
    return None


def _parse_pc_channel_catalog(body: bytes) -> dict[str, dict[str, str]]:
    """Parse Jiangsu Telecom PC_ChannelList metadata used by its EPG player."""
    text = _decode_payload_text(body)
    marker = re.search(r"packageData\s*\(\s*['\"]PC_ChannelList['\"]\s*,", text)
    if not marker:
        return {}
    payload = _extract_json_object(text, marker.end())
    if not payload:
        return {}
    catalog: dict[str, dict[str, str]] = {}
    for item in payload.get("channelAllList") or []:
        if not isinstance(item, dict):
            continue
        channel_id = str(item.get("channelcode") or "").strip()
        if not channel_id:
            continue
        column_code = str(item.get("columncode") or "").strip().upper()
        category, operator_group = _NANJING_COLUMN_GROUPS.get(column_code, ("", ""))
        catalog[channel_id] = {
            "name": str(item.get("channelname") or "").strip(),
            "category": category,
            "operator_group": operator_group,
            "mixno": str(item.get("mixno") or "").strip(),
        }
    return catalog


def _decode_payload_text(body: bytes) -> str:
    """Decode STB HTTP payloads that may be UTF-8 or GB18030."""
    for encoding in ("utf-8", "gb18030"):
        try:
            return body.decode(encoding)
        except UnicodeDecodeError:
            continue
    return body.decode("utf-8", errors="replace")


def _safe_int(value: Any) -> int | None:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 65535 else None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "2", "true", "yes", "y", "on", "enable", "enabled"}


def _first_text(obj: dict[str, Any], *keys: str) -> str:
    lowered = {str(k).lower(): v for k, v in obj.items()}
    for key in keys:
        val = lowered.get(key.lower())
        if val not in (None, ""):
            return str(val).strip()
    return ""


def _first_int(obj: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = _first_text(obj, key)
        number = _safe_int(value)
        if number is not None:
            return number
    return None


def _clean_group_name(value: str) -> str:
    group = re.sub(r"[\x00-\x1f\x7f]+", "", str(value or "")).strip()
    group = re.sub(r"\s+", " ", group).strip(" ,;，；/\\")
    return group[:40]


def _channel_category_from_group(group: str, name: str) -> str:
    raw = _clean_group_name(group)
    if raw:
        upper = raw.upper()
        if "CCTV" in upper or "央视" in raw or "中央" in raw:
            return "央视频道"
        if "卫视" in raw:
            return "卫视频道"
        if raw in {"央视频道", "卫视频道", "其它频道"}:
            return raw
        return raw
    return "其它频道" if not name else _fallback_classify_channel_name(name)


def _fallback_classify_channel_name(name: str) -> str:
    normalized = str(name or "").strip().upper()
    if not normalized:
        return "其它频道"
    if "CCTV" in normalized or "央视" in name or "中央" in name:
        return "央视频道"
    if "卫视" in name:
        return "卫视频道"
    return "其它频道"


def _parse_multicast_url(url: str) -> tuple[str, int]:
    match = re.search(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", str(url or ""), re.IGNORECASE)
    return (match.group(1), int(match.group(2))) if match else ("", 0)


def _parse_stream_params(ch: dict[str, Any]) -> tuple[str, int | None, int | None]:
    """Extract FCC/FEC params from direct fields, query strings, or SDP snippets."""
    fcc_ip = _first_text(ch, "channelFCCIP", "ChannelFCCIP", "fccIP", "fcc_ip")
    fcc_port = _first_int(ch, "channelFCCPort", "ChannelFCCPort", "fccPort", "fcc_port")
    fec_port = _first_int(ch, "channelFECPort", "ChannelFECPort", "fecPort", "fec_port")
    raw_parts = [
        _first_text(ch, "channelURL", "ChannelURL", "url", "mediaURL", "broadcastURL"),
        _first_text(ch, "channelSDP", "ChannelSDP", "sdp"),
    ]
    for raw in raw_parts:
        if not raw:
            continue
        parsed = urllib.parse.urlparse(raw)
        query = urllib.parse.parse_qs(parsed.query)
        if not fcc_ip:
            fcc_val = (query.get("fcc") or [""])[0]
            if ":" in fcc_val:
                fcc_ip = fcc_val.split(":", 1)[0].strip()
                if fcc_port is None:
                    fcc_port = _safe_int(fcc_val.split(":", 1)[1])
            else:
                fcc_ip = (query.get("ChannelFCCIP") or query.get("fcc_ip") or [""])[0].strip()
        if fcc_port is None:
            fcc_port = _safe_int((query.get("ChannelFCCPort") or query.get("fcc_port") or [""])[0])
        if fec_port is None:
            fec_port = _safe_int((query.get("fec") or query.get("ChannelFECPort") or query.get("fec_port") or [""])[0])
        if not fcc_ip:
            m = re.search(r"(?:ChannelFCCIP|fcc[_-]?ip)\s*[=:]\s*([0-9.]+)", raw, re.IGNORECASE)
            if m:
                fcc_ip = m.group(1)
        if fcc_port is None:
            m = re.search(r"(?:ChannelFCCPort|fcc[_-]?port)\s*[=:]\s*(\d{1,5})", raw, re.IGNORECASE)
            if m:
                fcc_port = _safe_int(m.group(1))
        if fec_port is None:
            m = re.search(r"(?:ChannelFECPort|fec[_-]?port)\s*[=:]\s*(\d{1,5})", raw, re.IGNORECASE)
            if m:
                fec_port = _safe_int(m.group(1))
    return fcc_ip, fcc_port, fec_port


def _iter_channel_dicts(data: Any):
    """Yield likely channel entries from regional JSON payloads."""
    if isinstance(data, dict):
        for key in (
            "channleInfoStruct",  # Beijing Unicom / Hisense IP811N typo
            "channelInfoStruct",
            "channelDetails",
            "channelList",
            "channels",
            "ChannelList",
        ):
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
        for value in data.values():
            if isinstance(value, (dict, list)):
                yield from _iter_channel_dicts(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                if any(k.lower() in {"channelurl", "channelname", "channelid", "userchannelid"} for k in item):
                    yield item
                else:
                    yield from _iter_channel_dicts(item)
            elif isinstance(item, list):
                yield from _iter_channel_dicts(item)


def _extract_channel_objects_from_partial_json(text: str) -> list[dict[str, Any]]:
    """Extract individual channel JSON objects from truncated or malformed JSON.

    Used when the HTTP response headers and the opening of the JSON array are
    missing (e.g. the first N TCP segments were not captured).  Uses brace
    counting so each top-level ``{\u2026}`` object is extracted and parsed
    independently; objects that look like channel entries are returned.
    """
    result: list[dict[str, Any]] = []
    depth = 0
    start = -1
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    obj_text = text[start : i + 1]
                    try:
                        obj = json.loads(obj_text)
                    except Exception:
                        start = -1
                        continue
                    if isinstance(obj, dict) and any(
                        k.lower() in {
                            "channelurl", "channelname", "channelid", "userchannelid"
                        }
                        for k in obj
                    ):
                        result.append(obj)
                    start = -1
    return result



_NANJING_COLUMN_GROUPS = {
    "0204": ("央视频道", "CCTV"),
    "0205": ("江苏频道", "江苏"),
    "0206": ("其它频道", "其它"),
    "0207": ("卫视频道", "卫视"),
    "020B": ("广播频道", "广播"),
}
