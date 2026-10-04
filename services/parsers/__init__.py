"""Versioned adapters; region labels describe fixtures, never network defaults."""
from dataclasses import dataclass
from .ctc_setconfig import _parse_chanlist_html
from .vsp import _parse_vsp_json
from .channel_acquire import _parse_channel_acquire_json
from .common import _parse_pc_channel_catalog

@dataclass(frozen=True)
class ChannelAdapter:
    name: str
    version: str
    matches: object
    parse: object

ADAPTERS = (
    ChannelAdapter("channel-acquire", "1", lambda b: b'channelURL' in b or b'channleInfoStruct' in b or b'channelInfoStruct' in b, _parse_channel_acquire_json),
    ChannelAdapter("ctc-setconfig", "1", lambda b: b'SetConfig' in b and (b"'Channel'" in b or b'"Channel"' in b), _parse_chanlist_html),
    ChannelAdapter("vsp", "1", lambda b: b'"channelDetails"' in b and b'"channelNO"' in b, _parse_vsp_json),
)
