"""Pure channel protocol parser; no device or network operations."""
import json
import re
import urllib.parse
from typing import Any
from .common import (_extract_json_object, _parse_pc_channel_catalog, _decode_payload_text, _safe_int, _truthy, _first_text, _first_int, _clean_group_name, _channel_category_from_group, _fallback_classify_channel_name, _parse_multicast_url, _parse_stream_params, _iter_channel_dicts, _extract_channel_objects_from_partial_json)

def _parse_chanlist_html(html: bytes) -> list[dict[str, Any]]:
    """Parse CTC/CU middleware Channel config calls into channel dicts."""
    text = _decode_payload_text(html)
    call_re = re.compile(
        r"""(?:(?:Authentication\.)?(?:CUSetConfig|CTCSetConfig)|jsSetConfig)\s*\(
            \s*(?P<key_quote>['"])Channel(?P=key_quote)\s*,
            \s*(?P<value_quote>['"])(?P<value>.*?)(?P=value_quote)\s*\)
        """,
        re.DOTALL | re.VERBOSE,
    )
    blocks = [match.group("value") for match in call_re.finditer(text)]
    channels: list[dict[str, Any]] = []
    for block in blocks:
        raw = re.findall(r"""(\w+)=(?:"([^"]*)"|'([^']*)')""", block)
        pairs = {k: (dq or sq) for k, dq, sq in raw}
        chan_name = pairs.get("ChannelName", "").strip()
        user_chan_id = pairs.get("UserChannelID", "")
        channel_url = pairs.get("ChannelURL", "")
        chan_id = pairs.get("ChannelID", "")
        is_hd = pairs.get("IsHDChannel", "0") == "2"
        time_shift = pairs.get("TimeShift", "0") == "1"
        time_shift_minutes_s = pairs.get("TimeShiftLength", "")
        fcc_ip = pairs.get("ChannelFCCIP", "").strip()
        fcc_port_s = pairs.get("ChannelFCCPort", "")
        fcc_addr = (
            pairs.get("ChannelFCCServerAddr") or pairs.get("ChannelFccAgentAddr") or
            pairs.get("ChannelFCCAddr") or ""
        ).strip()
        if fcc_addr:
            addr_host, sep, addr_port = fcc_addr.rpartition(":")
            if sep and addr_host:
                fcc_ip = fcc_ip or addr_host.strip()
                fcc_port_s = fcc_port_s or addr_port.strip()
            elif not fcc_ip:
                fcc_ip = fcc_addr
        fec_port_s = pairs.get("ChannelFECPort", "")
        group_name = (
            pairs.get("GroupName") or pairs.get("ChannelGroupName") or pairs.get("ChannelGroup") or
            pairs.get("CategoryName") or pairs.get("Category") or pairs.get("ChannelTypeName") or ""
        ).strip()
        backtv_url = (
            pairs.get("TimeShiftURL") or pairs.get("BacktimeURL") or
            pairs.get("BackUrl") or pairs.get("TimeshiftUrl") or
            pairs.get("startOverUrl") or ""
        ).strip()
        m = re.match(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", channel_url, re.IGNORECASE)
        if not m:
            m = re.search(
                r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)",
                pairs.get("ChannelSDP", ""),
                re.IGNORECASE,
            )
        ip, port = (m.group(1), int(m.group(2))) if m else ("", 0)
        if not ip or not port or not chan_name:
            continue
        channels.append(
            {
                "num": int(user_chan_id) if user_chan_id.isdigit() else 0,
                "name": chan_name,
                "category": _channel_category_from_group(group_name, chan_name),
                "operator_group": _clean_group_name(group_name),
                "ip": ip,
                "port": port,
                "channel_id": chan_id,
                "is_hd": is_hd,
                "time_shift": time_shift,
                "time_shift_minutes": int(time_shift_minutes_s) if time_shift_minutes_s.isdigit() else None,
                "fcc_ip": fcc_ip,
                "fcc_port": int(fcc_port_s) if fcc_port_s.isdigit() else None,
                "fec_port": int(fec_port_s) if fec_port_s.isdigit() else None,
                "backtv_url": backtv_url,
            }
        )
    channels.sort(key=lambda x: x["num"])
    return channels

