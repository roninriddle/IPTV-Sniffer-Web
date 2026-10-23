"""Beijing Unicom UIOS dynamic playback authorization.

Opaque credentials stay in the local owner-only session store. Signed media
URLs are obtained for each playback request and are never logged or persisted.
The public catchup API accepts UTC; UIOS playseek/schedules use UTC+08:00.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

from utils import valid_playseek, with_playseek

LOCAL_TIME = timezone(timedelta(hours=8))
MAX_JSON_BYTES = 4 * 1024 * 1024


class UiosCatchupError(RuntimeError):
    """Errors deliberately contain no URLs, response bodies, or credentials."""


def extract_uios_session(streams, stb_ip):
    from services.stb_discovery_service import _iter_http_requests, _split_http_responses

    session = {}
    servers = set()
    for (src, _sport, dst, dport), raw in streams.items():
        if src != stb_ip:
            continue
        for method, path, request, *_ in _iter_http_requests(raw):
            header, _, body = request.partition(b"\r\n\r\n")
            headers = {}
            for line in header.split(b"\r\n")[1:]:
                if b":" in line:
                    name, value = line.split(b":", 1)
                    headers[name.decode("latin1").lower()] = value.decode("latin1").strip()
            url = urlsplit(path)
            host = headers.get("host") or f"{dst}:{dport}"
            if re.fullmatch(r"/schedules/[A-Za-z0-9._-]+_\d{8}\.json", url.path):
                session["schedule_base"] = f"http://{host}"
                servers.add(dst)
            if method == "POST" and url.path == "/EPG/jsp/index4UIOS.jsp":
                try:
                    data = json.loads(body)
                except (ValueError, UnicodeError):
                    continue
                if isinstance(data, dict) and data.get("STBID") and data.get("UserID"):
                    session["login"] = {key: str(data[key]) for key in ("STBID", "UserID")}
            if method == "POST" and url.path == "/EPG/jsp/getPlayURL4UIOS.jsp":
                authorization = headers.get("authorization", "")
                if authorization and len(authorization) <= 4096:
                    session.update(endpoint=f"http://{host}{url.path}",
                                   authorization=authorization,
                                   user_agent=headers.get("user-agent", ""))
                    servers.add(dst)
    if not session.get("endpoint") or not session.get("authorization"):
        return {}
    # Media redirects may select a different unicast server. Retain only IP
    # addresses, never duplicate the signed URLs in the session file.
    for raw in streams.values():
        for match in re.finditer(br'(?:rtsp|http)://[^\s"<>\\]+', raw):
            value = match[0].decode("latin1")
            try:
                parts = urlsplit(value)
                if not any(marker in parts.path for marker in ("/TVOD/", "/PLTV/")):
                    continue
                address = ipaddress.IPv4Address(parts.hostname)
                if not (address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local):
                    servers.add(str(address))
            except (ValueError, TypeError):
                pass
    session["server_ips"] = sorted(servers)[:32]
    for (src, _sport, dst, _dport), raw in streams.items():
        if dst != stb_ip or src == stb_ip:
            continue
        for _headers, body in _split_http_responses(raw):
            try:
                response = json.loads(body)
            except (ValueError, UnicodeError):
                continue
            if isinstance(response, dict) and response.get("userToken") == session["authorization"]:
                expiry = str(response.get("tokenExpiredTime") or "")
                if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", expiry):
                    session["server_expiry"] = expiry
    session.update(captured_at=int(time.time()), profile="bj_unicom_uios")
    return session


class _InterfaceHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, interface="", **kwargs):
        self.interface = interface
        super().__init__(*args, **kwargs)

    def connect(self):
        if not self.interface:
            return super().connect()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", self.interface):
            raise UiosCatchupError("IPTV 网卡名称无效")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode() + b"\0")
            sock.connect((self.host, self.port))
            self.sock = sock
        except BaseException:
            sock.close()
            raise


def _request_json(url, body=None, *, authorization="", user_agent="", interface=""):
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname or parts.username or parts.password:
        raise UiosCatchupError("UIOS 接口地址无效，请重新解析机顶盒抓包")
    conn = _InterfaceHTTPConnection(parts.hostname, parts.port or 80, timeout=10, interface=interface)
    try:
        headers = {"Accept": "application/json", "User-Agent": user_agent or "IPTV-Sniffer-Web"}
        if authorization:
            headers["Authorization"] = authorization
        encoded = None
        if body is not None:
            encoded = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        conn.request("POST" if body is not None else "GET", urlunsplit(("", "", parts.path, parts.query, "")), encoded, headers)
        response = conn.getresponse()
        # Do not forward an opaque Authorization header across redirects.
        if response.status in (401, 403):
            raise UiosCatchupError("联通 UIOS 会话已失效，请补抓机顶盒登录和回看后重新解析")
        if response.status != 200:
            raise UiosCatchupError(f"联通 UIOS 接口返回 HTTP {response.status}")
        raw = response.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise UiosCatchupError("联通 UIOS 响应超过大小上限")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise UiosCatchupError("联通 UIOS 响应格式无效")
        return result
    except UiosCatchupError:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        raise UiosCatchupError("无法通过 IPTV 网卡访问联通 UIOS 接口，请检查接管状态") from None
    finally:
        conn.close()


def resolve_playback_url(session, channel, playseek, interface="", request_json=None, *, now=None):
    """Resolve a fresh lookback URL using schedule IDs, or a live timeshift URL."""
    if not valid_playseek(playseek):
        raise UiosCatchupError("回看时间段无效")
    channel_id = str(channel.get("channel_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,96}", channel_id):
        raise UiosCatchupError("缺少 UIOS 频道编号，请重新导入频道表")
    request_json = request_json or _request_json
    start, end = (datetime.strptime(value, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).astimezone(LOCAL_TIME)
                  for value in playseek.split("-"))
    local_seek = f"{start:%Y%m%d%H%M%S}-{end:%Y%m%d%H%M%S}"
    now = now or datetime.now(LOCAL_TIME)
    endpoint = session["endpoint"]
    options = {"authorization": session["authorization"], "user_agent": session.get("user_agent", ""), "interface": interface}
    # The captured EPG index binds this token to the UIOS application session.
    validate_session(session, interface, request_json)
    program_id = ""
    base = session.get("schedule_base", "")
    if base:
        try:
            schedule = request_json(f"{base}/schedules/{channel_id}_{start:%Y%m%d}.json", interface=interface)
            for item in schedule.get("schedules", []):
                begin = datetime.strptime(item["starttime"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=LOCAL_TIME)
                finish = datetime.strptime(item["endtime"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=LOCAL_TIME)
                # An ongoing programme has no complete TVOD recording yet.
                # Use PLTV for seeking behind live until the programme ends.
                if begin <= start < finish and finish <= now:
                    program_id = str(item.get("code") or item.get("externalcode") or "")
                    break
        except (UiosCatchupError, ValueError, TypeError, KeyError):
            # Live timeshift remains available when the schedule service fails.
            pass
    attempts = [("lookback", program_id)] if program_id else []
    attempts.append(("live", channel_id))
    for kind, content_id in attempts:
        result = request_json(endpoint, {"ContentType": kind, "ContentID": content_id}, **options)
        if str(result.get("ResultCode", "0")) != "0":
            if kind == "lookback":
                continue
            raise UiosCatchupError("联通动态取链被拒绝，请检查会话有效期与 IPTV 接管状态")
        for entry in result.get("URLs", []):
            value = entry.get("playurl" if kind == "lookback" else "timeshifturl", "")
            parts = urlsplit(value)
            if parts.scheme == "rtsp" and parts.hostname and not any(c in value for c in "\r\n\0"):
                # Preserve every signature/authorization parameter. Only the
                # requested time window is replaced after UTC-to-local conversion.
                return with_playseek(value, local_seek)
    raise UiosCatchupError("联通动态取链接口未返回可用回看或时移地址")


def validate_session(session, interface="", request_json=None):
    request_json = request_json or _request_json
    if not session.get("login"):
        return
    result = request_json(session["endpoint"].rsplit("/", 1)[0] + "/index4UIOS.jsp", session["login"],
                          authorization=session["authorization"], user_agent=session.get("user_agent", ""),
                          interface=interface)
    if str(result.get("ResultCode", "0")) != "0":
        raise UiosCatchupError("联通 UIOS 登录会话失效，请重新解析机顶盒登录抓包")
