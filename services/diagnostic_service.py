"""Report observations at their actual layer, without claiming end-to-end play."""
from services.rtsp_catchup_service import CombinedRtspUdpSession


def is_transport_stream(packet):
    payload = packet if packet[:1] == b"\x47" else CombinedRtspUdpSession._rtp_payload(packet)
    return len(payload) >= 188 and all(payload[n] == 0x47 for n in range(0, len(payload)-187, 188))


def playback_evidence(link=None, fcc_reachable=None):
    link = link or {}
    def observed(value):
        return bool(value) if value is not None else None
    return [
        {"layer": "wire", "item": "线缆抓包可见", "ok": observed(link.get("wire_active_packets")),
         "detail": "抓包可见只说明流量经过接口，不代表应用 socket 或播放器能接收。"},
        {"layer": "igmp", "item": "组播加组请求", "ok": observed(link.get("join_requested")),
         "detail": "IP_ADD_MEMBERSHIP 调用结果；实际 IGMP 发包见下一项。"},
        {"layer": "igmp", "item": "实际观察到 IGMP", "ok": observed(link.get("igmp_observed")),
         "detail": "仅由抓包证据确认；抓包不可用时保留未验证。"},
        {"layer": "media", "item": "应用 socket 收到数据", "ok": observed(link.get("socket_active_packets")),
         "detail": f"收到 {link.get('socket_active_packets', 0)} 个数据报，不等同于首帧解码成功。"},
        {"layer": "media", "item": "检测到 MPEG-TS 同步字节", "ok": True if link.get("media_ts_packets") else None,
         "detail": "只检查 RTP/UDP 媒体封装；未检测到时不推断流一定无效。"},
        {"layer": "fcc", "item": "FCC 端口可达性", "ok": fcc_reachable,
         "detail": "TCP 连接结果，不代表运营商 FCC 请求、单播起播或组播切换成功。"},
        {"layer": "fcc", "item": "FCC 起播与组播切换", "ok": None,
         "detail": "未执行运营商协议握手或持续媒体观察，需要播放器实测。"},
        {"layer": "rtsp", "item": "RTSP 回看控制与收流", "ok": None,
         "detail": "未在诊断中消费回看认证令牌；请通过回看播放单独验证。"},
        {"layer": "player", "item": "播放器首帧与持续播放", "ok": None,
         "detail": "需记录客户端版本、首帧耗时及持续播放结果，不能由网络端口替代。"},
    ]


def diagnostic_verdict(checks):
    failed = sum(c.get("ok") is False for c in checks)
    unknown = sum(c.get("ok") is None for c in checks)
    if failed:
        return f"发现 {failed} 项检查未通过，另有 {unknown} 项未验证；详见分层证据。"
    return f"已执行的检查通过，仍有 {unknown} 项未验证；尚不能确认端到端播放成功。"
