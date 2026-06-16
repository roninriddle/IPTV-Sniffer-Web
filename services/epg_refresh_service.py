#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EPG portal re-authentication and backtv_url token refresh for CU IPTV."""
from __future__ import annotations

import http.cookiejar
import random
import re
import string
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from services.log_service import AppLogger
from utils import redact_sensitive_text


def _pad_des_plaintext(plain_bytes: bytes, padding: str = "pkcs5") -> bytes:
    if padding == "zero":
        pad_len = (8 - len(plain_bytes) % 8) % 8
        return plain_bytes + b"\x00" * pad_len
    # Enshan/CTC reference flow uses Java DES/ECB/PKCS5Padding.
    pad_len = 8 - (len(plain_bytes) % 8)
    return plain_bytes + bytes([pad_len]) * pad_len


def _des_ecb_encrypt_hex(
    plaintext: str,
    key: str,
    padding: str = "pkcs5",
    crypto_mode: str = "auto",
) -> str:
    """
    Encrypt plaintext using ECB mode; returns uppercase hex string.

    Uses DES or Triple-DES ECB.  The CTC/HWCTC reference flow in
    supzhang/get_iptv_channels builds a 24-byte 3DES key as key + "0"*16.
    That degenerates to single-DES under modern pycryptodome, so we fall back
    to DES with the original 8-byte key when pycryptodome rejects it.
    """
    try:
        from Crypto.Cipher import DES, DES3
    except ImportError:
        raise RuntimeError(
            "缺少 pycryptodome 包，无法执行 DES/DES3 加密。"
            "请检查 requirements.txt 并重建 Docker 镜像。"
        )
    crypto_mode = (crypto_mode or "auto").strip().lower()
    key_bytes = key.encode("utf-8")
    plain_bytes = _pad_des_plaintext(plaintext.encode("utf-8"), padding)

    if crypto_mode == "ctc_des3_zero16" and len(key_bytes) == 8:
        try:
            cipher = DES3.new(key_bytes + (b"0" * 16), DES3.MODE_ECB)
        except ValueError:
            cipher = DES.new(key_bytes, DES.MODE_ECB)
    elif crypto_mode == "des" or (crypto_mode == "auto" and len(key_bytes) == 8):
        cipher = DES.new(key_bytes, DES.MODE_ECB)
    else:
        if len(key_bytes) < 16:
            key_bytes = (key_bytes * 3)[:24]
        elif len(key_bytes) < 24:
            key_bytes = key_bytes + key_bytes[:8]
        key_bytes = key_bytes[:24]
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
    return cipher.encrypt(plain_bytes).hex().upper()


def _build_opener_with_cookies() -> tuple[urllib.request.OpenerDirector, http.cookiejar.CookieJar]:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.addheaders = [
        ("User-Agent", "Mozilla/5.0"),
        ("Accept", "*/*"),
        ("Accept-Language", "zh-CN,zh;q=0.9"),
    ]
    return opener, jar


def _get_jsessionid(jar: http.cookiejar.CookieJar) -> str:
    for cookie in jar:
        if cookie.name == "JSESSIONID":
            return cookie.value or ""
    return ""


def _normalize_epg_host(value: str) -> str:
    return re.sub(r"^https?://", "", str(value or "").strip()).rstrip("/")


def _request_text(
    opener: urllib.request.OpenerDirector,
    url: str,
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> tuple[str, str]:
    body = urllib.parse.urlencode(data).encode("utf-8") if data is not None else None
    request = urllib.request.Request(url, data=body, headers=headers or {}, method="POST" if data is not None else "GET")
    with opener.open(request, timeout=timeout) as resp:
        final_url = resp.geturl()
        text = resp.read().decode("utf-8", errors="replace")
    return text, final_url


def _extract_first(patterns: list[str], text: str) -> str:
    for pattern in patterns:
        m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if m:
            return urllib.parse.unquote((m.group(1) or "").strip())
    return ""


def _session_expiry_info(jar: Any) -> tuple[int | None, str]:
    jsession_seen = False
    expiries: list[int] = []
    try:
        for cookie in jar:
            if str(getattr(cookie, "name", "")).upper() != "JSESSIONID":
                continue
            jsession_seen = True
            expires = getattr(cookie, "expires", None)
            if isinstance(expires, (int, float)) and expires > 0:
                expiries.append(int(expires))
    except Exception:
        pass
    if expiries:
        return min(expiries), "JSESSIONID Cookie 暴露了明确过期时间"
    if jsession_seen:
        return None, "门户只返回会话 Cookie，未暴露明确有效期"
    return None, "门户未暴露明确有效期"


def _update_backtv_from_channel_text(
    text: str,
    operator_channels: dict[str, dict[str, Any]],
) -> tuple[int, int]:
    blocks = re.findall(r"CUSetConfig\('Channel',\s*'([^']+)'\)", text)
    blocks += re.findall(r'CUSetConfig\("Channel",\s*"([^"]+)"\)', text)
    updated = 0
    total = len(blocks)
    for block in blocks:
        raw = re.findall(r"""(\w+)=(?:"([^"]*)"|'([^']*)')""", block)
        pairs = {k: (dq or sq) for k, dq, sq in raw}
        channel_url = pairs.get("ChannelURL", "")
        backtv = (
            pairs.get("TimeShiftURL") or pairs.get("BacktimeURL") or
            pairs.get("BackUrl") or pairs.get("TimeshiftUrl") or
            pairs.get("startOverUrl") or ""
        ).strip()
        if not channel_url or not backtv:
            continue
        m3 = re.match(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", channel_url)
        if not m3:
            continue
        key = f"{m3.group(1)}:{m3.group(2)}"
        if key in operator_channels:
            operator_channels[key]["backtv_url"] = backtv
            updated += 1
    return updated, total


def _refresh_ctc_hwctc(
    settings: dict[str, Any],
    operator_channels: dict[str, dict[str, Any]],
    epg_auth_host: str,
    user_id: str,
    stb_id: str,
    des_key: str,
    mac_plain: str,
    stb_ip: str,
    logger: AppLogger,
) -> dict[str, Any]:
    user_agent = str(settings.get("epg_user_agent") or "").strip()
    stb_type = str(settings.get("epg_stb_type") or "").strip()
    stb_version = str(settings.get("epg_stb_version") or "").strip()
    access_user_name = str(settings.get("epg_access_user_name") or "").strip()
    missing = []
    if not des_key:
        missing.append("DES/3DES key")
    if not user_agent:
        missing.append("UserAgent")
    if not stb_type:
        missing.append("STBType")
    if not stb_version:
        missing.append("STBVersion")
    if missing:
        raise ValueError("CTC-HWCTC 回看认证缺少：" + "、".join(missing))

    base_url = f"http://{epg_auth_host}"
    opener, jar = _build_opener_with_cookies()
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "X-Requested-With": "com.android.smart.terminal.iptv",
    }
    logger.info("CTC-HWCTC 步骤1：获取 AuthenticationURL / EncryptToken")
    token_url = f"{base_url}/EDS/jsp/AuthenticationURL?UserID={urllib.parse.quote(user_id)}&Action=Login"
    first_body, final_url = _request_text(opener, token_url, headers=headers, timeout=15)
    final_host = urllib.parse.urlparse(final_url).netloc or epg_auth_host

    login_url = f"http://{final_host}/EPG/jsp/authLoginHWCTC.jsp"
    login_headers = {
        "User-Agent": user_agent,
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": f"http://{final_host}/EPG/jsp/AuthenticationURL?UserID={urllib.parse.quote(user_id)}&Action=Login",
        "X-Requested-With": "com.android.smart.terminal.iptv",
    }
    login_body, _ = _request_text(opener, login_url, data={"UserID": user_id, "VIP": ""}, headers=login_headers, timeout=15)
    combined = first_body + "\n" + login_body
    encrypt_token = _extract_first([
        r'EncryptToken\s*=\s*["\']([^"\']+)["\']',
        r'userToken\.value\s*=\s*["\']([^"\']+)["\']',
        r"UserToken=([A-Za-z0-9+/=%]+)",
    ], combined)
    if not encrypt_token:
        raise RuntimeError("CTC-HWCTC 未能提取 EncryptToken")

    rand = "".join(random.choices(string.digits, k=8))
    plain = f"{rand}${encrypt_token}${user_id}${stb_id}${stb_ip}${mac_plain}$$CTC"
    crypto_mode = str(settings.get("epg_crypto_mode") or "auto").strip().lower()
    if crypto_mode == "auto":
        crypto_mode = "ctc_des3_zero16"
    padding = str(settings.get("epg_des_padding") or "pkcs5").strip().lower()
    authenticator = _des_ecb_encrypt_hex(plain, des_key, padding=padding, crypto_mode=crypto_mode)

    validate_url = f"http://{final_host}/EPG/jsp/ValidAuthenticationHWCTC.jsp"
    validate_data = {
        "UserID": user_id,
        "Lang": "",
        "SupportHD": "1",
        "NetUserID": "",
        "Authenticator": authenticator,
        "STBType": stb_type,
        "STBVersion": stb_version,
        "conntype": "",
        "STBID": stb_id,
        "templateName": str(settings.get("epg_template_name") or ""),
        "areaId": str(settings.get("epg_area_id") or ""),
        "userToken": encrypt_token,
        "userGroupId": "",
        "productPackageId": "",
        "mac": mac_plain,
        "UserField": "",
        "SoftwareVersion": "",
        "IsSmartStb": "undefined",
        "desktopId": "undefined",
        "stbmaker": "",
        "VIP": "",
    }
    if access_user_name:
        validate_data["AccessUserName"] = access_user_name
    logger.info("CTC-HWCTC 步骤2：提交 ValidAuthenticationHWCTC 获取 JSESSIONID")
    validate_body, _ = _request_text(
        opener,
        validate_url,
        data=validate_data,
        headers={"User-Agent": user_agent, "Content-Type": "application/x-www-form-urlencoded", "Referer": login_url},
        timeout=15,
    )
    jsessionid = _get_jsessionid(jar)
    user_token = _extract_first([
        r'UserToken["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']UserToken["\'][^>]+value=["\']([^"\']+)["\']',
        r"UserToken=([A-Za-z0-9+/=%]+)",
    ], validate_body) or encrypt_token
    stbid_from_resp = _extract_first([
        r'stbid["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']stbid["\'][^>]+value=["\']([^"\']+)["\']',
    ], validate_body) or stb_id
    if not jsessionid:
        raise RuntimeError("CTC-HWCTC 未获取到 JSESSIONID，请检查 key、UserAgent、STBType、STBVersion、MAC、STBID")

    errors: list[str] = []
    chanlist_body = ""
    logger.info("CTC-HWCTC 步骤3：拉取频道表并刷新回看地址")
    for endpoint in ("getchannellistHWCTC.jsp", "getchannellistHWCU.jsp"):
        chanlist_url = f"http://{final_host}/EPG/jsp/{endpoint}"
        try:
            body, _ = _request_text(
                opener,
                chanlist_url,
                data={
                    "conntype": "",
                    "UserToken": user_token,
                    "tempKey": "",
                    "stbid": stbid_from_resp,
                    "SupportHD": "1",
                    "UserID": user_id,
                    "Lang": "1",
                },
                headers={"User-Agent": user_agent, "Content-Type": "application/x-www-form-urlencoded"},
                timeout=20,
            )
            if "CUSetConfig" in body:
                chanlist_body = body
                break
            errors.append(f"{endpoint}: 响应中未找到 CUSetConfig 块")
        except Exception as exc:
            errors.append(f"{endpoint}: {exc}")
    if not chanlist_body:
        raise RuntimeError(f"CTC-HWCTC 无法获取频道表：{'; '.join(errors) or '响应为空'}")

    updated, total = _update_backtv_from_channel_text(chanlist_body, operator_channels)
    expires_at, expiry_note = _session_expiry_info(jar)
    logger.info(f"CTC-HWCTC 回看地址刷新完成：共解析 {total} 个频道块，更新 {updated} 个")
    return {
        "updated": updated,
        "total": total,
        "epg_host": final_host,
        "profile": "ctc_hwctc",
        "session": "ok",
        "token_expires_at": expires_at,
        "token_expiry_note": expiry_note,
        "errors": errors,
    }


def refresh_backtv_urls(
    settings: dict[str, Any],
    operator_channels: dict[str, dict[str, Any]],
    auth_info: dict[str, Any],
    logger: AppLogger,
) -> dict[str, Any]:
    """
    Re-authenticate to CU IPTV EPG portal and refresh backtv_url tokens.

    Returns {"updated": int, "total": int, "epg_host": str, "errors": list[str]}.
    """
    epg_auth_host = _normalize_epg_host(str(settings.get("epg_auth_host") or "").strip())
    user_id = str(settings.get("epg_user_id") or "").strip()
    stb_id = str(settings.get("epg_stb_id") or "").strip()
    des3_key = str(settings.get("epg_des3_key") or "").strip()
    password = str(settings.get("iptv_password") or "").strip()
    mac = str(auth_info.get("mac") or "").strip().lower()
    stb_ip = str(auth_info.get("assigned_ip") or "").strip()
    profile = str(settings.get("epg_auth_profile") or "auto").strip().lower()
    if profile not in {"auto", "ctc_hwctc", "cu_hwctc"}:
        profile = "auto"

    # Auto-detect EPG host from backtv_url if not configured
    if not epg_auth_host:
        for ch_info in operator_channels.values():
            backtv = str(ch_info.get("backtv_url") or "").strip()
            if backtv:
                m = re.match(r"rtsp://([^/:]+)", backtv)
                if m:
                    epg_auth_host = f"{m.group(1)}:8082"
                    logger.info(f"自动检测 EPG 服务器地址：{epg_auth_host}")
                    break

    if not epg_auth_host:
        raise ValueError("未能确定 EPG 服务器地址，请在「回看设置」中手动填写")
    if not user_id:
        raise ValueError("请在「回看设置」中填写用户ID（UserID）")
    if not stb_id:
        raise ValueError("请在「回看设置」中填写机顶盒设备ID（STBID）")
    if not mac:
        raise ValueError("未找到机顶盒 MAC 地址，请先完成 STB 开机捕获以记录认证信息")
    if not stb_ip:
        raise ValueError("未找到机顶盒 IP 地址，请先完成 STB 开机捕获以记录认证信息")

    mac_plain = mac.replace(":", "")
    cu_ready = bool(password)
    ctc_ready = bool(des3_key and settings.get("epg_user_agent") and settings.get("epg_stb_type") and settings.get("epg_stb_version"))

    # Auto mode tries Unicom (CU-HWCTC) first, then falls back to Telecom (CTC-HWCTC).
    if profile in {"auto", "cu_hwctc"} and (profile == "cu_hwctc" or cu_ready):
        try:
            return _refresh_cu_hwctc(
                settings, operator_channels, epg_auth_host, user_id, stb_id,
                des3_key, password, mac_plain, stb_ip, logger,
            )
        except Exception as exc:
            if profile == "cu_hwctc":
                raise
            logger.warning(f"CU-HWCTC 回看刷新失败，尝试 CTC-HWCTC 回退：{redact_sensitive_text(str(exc))}")

    if profile in {"auto", "ctc_hwctc"} and (profile == "ctc_hwctc" or ctc_ready):
        try:
            return _refresh_ctc_hwctc(
                settings, operator_channels, epg_auth_host, user_id, stb_id,
                des3_key, mac_plain, stb_ip, logger,
            )
        except Exception as exc:
            if profile == "ctc_hwctc":
                raise
            logger.warning(f"CTC-HWCTC 回看刷新失败：{redact_sensitive_text(str(exc))}")

    if not cu_ready and not ctc_ready:
        raise ValueError("CU-HWCTC 回看刷新需要 IPTV 密码；若使用电信 CTC-HWCTC，请填写 key、UserAgent、STBType、STBVersion")
    raise RuntimeError("CU-HWCTC 与 CTC-HWCTC 认证均失败，请检查认证参数或查看日志详情")


def _refresh_cu_hwctc(
    settings: dict[str, Any],
    operator_channels: dict[str, dict[str, Any]],
    epg_auth_host: str,
    user_id: str,
    stb_id: str,
    des3_key: str,
    password: str,
    mac_plain: str,
    stb_ip: str,
    logger: AppLogger,
) -> dict[str, Any]:
    if not password:
        raise ValueError("CU-HWCTC 回看刷新需要 IPTV 密码；若使用电信 CTC-HWCTC，请填写 key、UserAgent、STBType、STBVersion")

    errors: list[str] = []
    base_url = f"http://{epg_auth_host}"
    opener, jar = _build_opener_with_cookies()
    des_padding = str(settings.get("epg_des_padding") or "pkcs5").strip().lower()
    if des_padding not in {"pkcs5", "zero"}:
        des_padding = "pkcs5"

    # Step 1: fetch EncryptToken
    token_url = (
        f"{base_url}/EDS/jsp/AuthenticationURL"
        f"?UserID={urllib.parse.quote(user_id)}&Action=Login"
    )
    logger.info(f"EPG 步骤1：获取 EncryptToken — {token_url}")
    try:
        with opener.open(token_url, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise RuntimeError(f"连接 EPG 服务器失败（{epg_auth_host}）：{exc}")

    m = re.search(r"UserToken=([A-Za-z0-9+/=%]+)", body)
    if not m:
        raise RuntimeError(
            f"无法从 EPG 响应中提取 EncryptToken。"
            f"响应片段（前300字符）：{redact_sensitive_text(body[:300])}"
        )
    encrypt_token = urllib.parse.unquote(m.group(1)).strip()
    logger.info(f"EPG EncryptToken 获取成功（前20字符）：{encrypt_token[:20]}…")

    # Step 2: build Authenticator and login
    random8 = "".join(random.choices(string.digits, k=8))
    plain = f"{random8}${encrypt_token}${user_id}${stb_id}${stb_ip}${mac_plain}$$CTC"

    if des3_key:
        try:
            authenticator = _des_ecb_encrypt_hex(plain, des3_key, padding=des_padding)
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"DES3 加密失败：{exc}")
        auth_url = (
            f"{base_url}/EPG/jsp/authLoginHWCTC.jsp"
            f"?Authenticator={urllib.parse.quote(authenticator)}"
        )
    else:
        # Attempt without Authenticator (some operators allow plain UserID login)
        auth_url = (
            f"{base_url}/EPG/jsp/authLoginHWCTC.jsp"
            f"?UserID={urllib.parse.quote(user_id)}&STBType=VHTTV&UserType=1"
        )
        logger.warning("未配置 DES3 密钥，尝试无加密认证（可能不支持）")

    logger.info(f"EPG 步骤2：认证登录 — {redact_sensitive_text(auth_url)[:100]}…")
    try:
        with opener.open(auth_url, timeout=15) as resp:
            auth_body = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise RuntimeError(f"EPG 认证请求失败：{exc}")

    jsessionid = _get_jsessionid(jar)
    if not jsessionid:
        m2 = re.search(r"JSESSIONID=([A-Za-z0-9.]+)", auth_body)
        if m2:
            jsessionid = m2.group(1)
    if jsessionid:
        logger.info(f"EPG 获得 JSESSIONID：{jsessionid[:16]}…")
    else:
        logger.warning(f"EPG 认证未返回 JSESSIONID，尝试继续。响应片段：{redact_sensitive_text(auth_body[:200])}")

    # Step 3: validate with password
    validate_url = f"{base_url}/EPG/jsp/ValidAuthenticationHWCTC.jsp"
    validate_data = urllib.parse.urlencode({
        "UserID": user_id,
        "UserPassword": password,
        "STBID": stb_id,
        "MAC": mac_plain,
        "UserType": "1",
        "STBType": "VHTTV",
    }).encode("utf-8")
    logger.info("EPG 步骤3：提交密码验证…")
    try:
        with opener.open(
            urllib.request.Request(validate_url, data=validate_data, method="POST"),
            timeout=15,
        ) as resp:
            validate_body = resp.read().decode("utf-8", errors="replace")
        if "success" not in validate_body.lower() and "OK" not in validate_body:
            logger.warning(f"EPG 密码验证响应（前200字符）：{redact_sensitive_text(validate_body[:200])}")
    except Exception as exc:
        logger.warning(f"EPG 密码验证步骤失败（尝试继续获取频道列表）：{exc}")

    # Step 4: fetch fresh channel list
    chanlist_body = b""
    for endpoint in ("getchannellistHWCU.jsp", "getchannellistHWCTC.jsp"):
        chanlist_url = f"{base_url}/EPG/jsp/{endpoint}"
        logger.info(f"EPG 步骤4：获取频道列表 — {chanlist_url}")
        try:
            with opener.open(
                urllib.request.Request(chanlist_url, data=b"", method="POST"),
                timeout=20,
            ) as resp:
                body_bytes = resp.read()
            if b"CUSetConfig" in body_bytes:
                chanlist_body = body_bytes
                logger.info(f"从 {endpoint} 获取到频道列表数据")
                break
            else:
                errors.append(f"{endpoint}: 响应中未找到 CUSetConfig 块")
        except Exception as exc:
            errors.append(f"{endpoint}: {exc}")

    if not chanlist_body:
        raise RuntimeError(
            f"无法获取 EPG 频道列表。错误：{'; '.join(errors) or '响应为空'}"
        )

    # Step 5: parse and update backtv_url in operator_channels
    text = chanlist_body.decode("utf-8", errors="replace")
    updated, total = _update_backtv_from_channel_text(text, operator_channels)
    expires_at, expiry_note = _session_expiry_info(jar)

    logger.info(f"EPG 回看地址刷新完成：共解析 {total} 个频道块，更新 {updated} 个")
    return {
        "updated": updated,
        "total": total,
        "epg_host": epg_auth_host,
        "profile": "cu_hwctc",
        "token_expires_at": expires_at,
        "token_expiry_note": expiry_note,
        "errors": errors,
    }
