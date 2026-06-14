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


def _des_ecb_encrypt_hex(plaintext: str, key: str) -> str:
    """
    Encrypt plaintext using ECB mode; returns uppercase hex string.

    Uses DES (8-byte key) or Triple-DES (16/24-byte key).  Most CU-IPTV
    operators use an 8-digit numeric key which maps to single DES ECB.
    """
    try:
        from Crypto.Cipher import DES, DES3
    except ImportError:
        raise RuntimeError(
            "缺少 pycryptodome 包，无法执行 DES/DES3 加密。"
            "请检查 requirements.txt 并重建 Docker 镜像。"
        )
    key_bytes = key.encode("utf-8")
    plain_bytes = plaintext.encode("utf-8")
    # Zero-pad to multiple of 8 bytes
    pad_len = (8 - len(plain_bytes) % 8) % 8
    plain_bytes = plain_bytes + b"\x00" * pad_len

    if len(key_bytes) == 8:
        # Single DES ECB (common for 8-digit numeric operator keys)
        cipher = DES.new(key_bytes, DES.MODE_ECB)
    else:
        # Triple DES: extend to 16 or 24 bytes
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
    epg_auth_host = re.sub(r"^https?://", "", str(settings.get("epg_auth_host") or "").strip()).rstrip("/")
    user_id = str(settings.get("epg_user_id") or "").strip()
    stb_id = str(settings.get("epg_stb_id") or "").strip()
    des3_key = str(settings.get("epg_des3_key") or "").strip()
    password = str(settings.get("iptv_password") or "").strip()
    mac = str(auth_info.get("mac") or "").strip().lower()
    stb_ip = str(auth_info.get("assigned_ip") or "").strip()

    errors: list[str] = []

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
    if not password:
        raise ValueError("请在「回看设置」中填写 IPTV 密码")
    if not mac:
        raise ValueError("未找到机顶盒 MAC 地址，请先完成 STB 开机捕获以记录认证信息")
    if not stb_ip:
        raise ValueError("未找到机顶盒 IP 地址，请先完成 STB 开机捕获以记录认证信息")

    mac_plain = mac.replace(":", "")
    base_url = f"http://{epg_auth_host}"
    opener, jar = _build_opener_with_cookies()

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
            f"响应片段（前300字符）：{body[:300]}"
        )
    encrypt_token = urllib.parse.unquote(m.group(1)).strip()
    logger.info(f"EPG EncryptToken 获取成功（前20字符）：{encrypt_token[:20]}…")

    # Step 2: build Authenticator and login
    random8 = "".join(random.choices(string.digits, k=8))
    plain = f"{random8}${encrypt_token}${user_id}${stb_id}${stb_ip}${mac_plain}$$CTC"

    if des3_key:
        try:
            authenticator = _des_ecb_encrypt_hex(plain, des3_key)
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

    logger.info(f"EPG 步骤2：认证登录 — {auth_url[:100]}…")
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
        logger.warning(f"EPG 认证未返回 JSESSIONID，尝试继续。响应片段：{auth_body[:200]}")

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
            logger.warning(f"EPG 密码验证响应（前200字符）：{validate_body[:200]}")
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

    logger.info(f"EPG 回看地址刷新完成：共解析 {total} 个频道块，更新 {updated} 个")
    return {"updated": updated, "total": total, "epg_host": epg_auth_host, "errors": errors}
