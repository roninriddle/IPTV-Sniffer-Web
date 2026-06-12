#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPTV DHCP authentication helper and guarded experimental executor."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

from services.log_service import AppLogger


CONFIRM_TEXT = "确认执行"
RESTORE_CONFIRM_TEXT = "确认恢复"


def _safe_load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def _atomic_dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, path)
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass


def _run(cmd: Sequence[str], timeout: int = 12, check: bool = False) -> dict[str, Any]:
    proc = subprocess.run(
        list(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    result = {
        "cmd": " ".join(str(x) for x in cmd),
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }
    if check and proc.returncode != 0:
        raise RuntimeError(result["stderr"] or result["stdout"] or f"命令执行失败：{result['cmd']}")
    return result


def _normalize_hex(value: str) -> str:
    text = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if not text:
        return ""
    if len(text) % 2:
        raise ValueError("Option60 十六进制长度必须是偶数")
    if len(text) > 1024:
        raise ValueError("Option60 过长，疑似粘贴内容不正确")
    return text.lower()


def _colon_hex(value: str) -> str:
    text = _normalize_hex(value)
    return ":".join(text[i : i + 2] for i in range(0, len(text), 2))


def _valid_iface(value: str) -> str:
    iface = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,48}", iface):
        raise ValueError("接口名不合法")
    if iface == "any":
        raise ValueError("IPTV 认证不能使用 any，请选择真实网口")
    return iface


def _valid_mac(value: str) -> str:
    mac = str(value or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac):
        raise ValueError("MAC 地址格式不正确")
    return mac


def _mask_to_prefix(mask: str) -> int | None:
    try:
        parts = [int(x) for x in str(mask or "").split(".")]
        if len(parts) != 4 or any(x < 0 or x > 255 for x in parts):
            return None
        bits = "".join(f"{x:08b}" for x in parts)
        if "01" in bits:
            return None
        return bits.count("1")
    except Exception:
        return None


class IptvAuthService:
    """Validates IPTV auth payloads and runs a guarded udhcpc-based flow."""

    def __init__(self, backup_path: Path, data_dir: Path, logger: AppLogger) -> None:
        self.backup_path = backup_path
        self.data_dir = data_dir
        self.logger = logger

    def _backup_data(self) -> dict[str, Any]:
        data = _safe_load_json(self.backup_path, {"interfaces": {}})
        if not isinstance(data, dict):
            data = {"interfaces": {}}
        data.setdefault("interfaces", {})
        return data

    def _write_backup_data(self, data: dict[str, Any]) -> None:
        _atomic_dump_json(self.backup_path, data)

    def _json_cmd(self, cmd: Sequence[str]) -> Any:
        result = _run(cmd, timeout=8, check=False)
        if result["returncode"] != 0 or not result["stdout"]:
            return []
        try:
            return json.loads(result["stdout"])
        except Exception:
            return []

    def _interface_exists(self, iface: str) -> bool:
        return _run(["ip", "link", "show", "dev", iface], timeout=5)["returncode"] == 0

    def snapshot(self, interface: str) -> dict[str, Any]:
        iface = _valid_iface(interface)
        link_json = self._json_cmd(["ip", "-j", "link", "show", "dev", iface])
        addr_json = self._json_cmd(["ip", "-j", "addr", "show", "dev", iface])
        route_json = self._json_cmd(["ip", "-j", "-4", "route", "show", "dev", iface])
        link = link_json[0] if isinstance(link_json, list) and link_json else {}
        addr = addr_json[0] if isinstance(addr_json, list) and addr_json else {}
        mac = ""
        if isinstance(addr, dict):
            mac = str(addr.get("address") or "").lower()
        if not mac:
            try:
                mac = Path(f"/sys/class/net/{iface}/address").read_text(encoding="utf-8").strip().lower()
            except Exception:
                mac = ""
        ipv4 = [
            {
                "local": item.get("local"),
                "prefixlen": item.get("prefixlen"),
                "broadcast": item.get("broadcast", ""),
            }
            for item in (addr.get("addr_info") or [])
            if item.get("family") == "inet" and item.get("local") and item.get("prefixlen") is not None
        ] if isinstance(addr, dict) else []
        routes = route_json if isinstance(route_json, list) else []
        has_multicast_route = any(
            str(r.get("dst") or "").startswith("224.") for r in routes
        )
        return {
            "created_at": time.time(),
            "interface": iface,
            "exists": bool(link or addr),
            "mac": mac,
            "operstate": str(addr.get("operstate") or link.get("operstate") or ""),
            "flags": list(link.get("flags") or addr.get("flags") or []),
            "ipv4": ipv4,
            "routes": routes,
            "has_multicast_route": has_multicast_route,
            "link": link,
            "addr": addr,
        }

    def _ensure_backup(self, interface: str) -> dict[str, Any]:
        iface = _valid_iface(interface)
        snap = self.snapshot(iface)
        data = self._backup_data()
        entry = data["interfaces"].setdefault(iface, {"history": []})
        if "initial" not in entry:
            entry["initial"] = snap
        entry.setdefault("history", []).append({"kind": "pre_apply", **snap})
        entry["latest_pre_apply"] = snap
        self._write_backup_data(data)
        return entry

    def backup_summary(self, interface: str) -> dict[str, Any]:
        iface = _valid_iface(interface)
        entry = self._backup_data().get("interfaces", {}).get(iface) or {}
        initial = entry.get("initial") or None
        latest = entry.get("latest_pre_apply") or None
        return {
            "has_initial": bool(initial),
            "initial": initial,
            "latest_pre_apply": latest,
            "history_count": len(entry.get("history") or []),
        }

    def _payload(self, data: dict[str, Any], auth_info: dict[str, Any] | None = None) -> dict[str, Any]:
        auth = auth_info or {}
        interface = _valid_iface(data.get("interface") or data.get("iface") or "")
        mac = _valid_mac(data.get("mac") or auth.get("mac") or "")
        hostname = str(data.get("hostname") or auth.get("hostname") or "").strip()
        option60 = _normalize_hex(data.get("vendor_class") or data.get("option60") or auth.get("vendor_class") or "")
        if not hostname:
            raise ValueError("Hostname 不能为空，请先捕获机顶盒认证信息")
        if not option60:
            raise ValueError("Option60 不能为空，请先捕获机顶盒认证信息")
        requested_ip = str(data.get("requested_ip") or auth.get("assigned_ip") or "").strip()
        route_mode = str(data.get("route_mode") or "multicast").strip()
        if route_mode not in {"none", "multicast", "iptv_private"}:
            route_mode = "multicast"
        gateway = str(data.get("gateway") or auth.get("gateway") or "").strip()
        client_id = _normalize_hex(data.get("client_id") or auth.get("client_id") or "")
        option125 = _normalize_hex(data.get("vendor_specific_125_raw") or auth.get("vendor_specific_125_raw") or "")
        return {
            "interface": interface,
            "mac": mac,
            "hostname": hostname,
            "vendor_class": option60,
            "vendor_class_colon": _colon_hex(option60),
            "requested_ip": requested_ip,
            "gateway": gateway,
            "route_mode": route_mode,
            "client_id": client_id,
            "option125": option125,
        }

    def _udhcpc_hook_content(self, interface: str, route_mode: str) -> str:
        iface = _valid_iface(interface)
        route_mode = route_mode if route_mode in {"none", "multicast", "iptv_private"} else "multicast"
        return f"""#!/bin/sh
set -eu
LOG="/app/data/iptv-auth-{iface}.log"
[ "${{interface:-}}" = "{iface}" ] || exit 1
mask2cidr() {{
  python3 - "$1" <<'PY'
import sys
mask = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    nums = [int(x) for x in mask.split(".")]
    bits = "".join(f"{{x:08b}}" for x in nums)
    print(bits.count("1") if len(nums) == 4 and "01" not in bits else 24)
except Exception:
    print(24)
PY
}}
echo "$(date '+%F %T') udhcpc event=$1 iface=$interface ip=${{ip:-}} router=${{router:-}}" >> "$LOG"
case "$1" in
  deconfig)
    ip -4 addr flush dev "$interface" || true
    ;;
  bound|renew)
    prefix="$(mask2cidr "${{subnet:-255.255.255.0}}")"
    ip -4 addr flush dev "$interface" || true
    if [ -n "${{broadcast:-}}" ]; then
      ip -4 addr add "$ip/$prefix" broadcast "$broadcast" dev "$interface"
    else
      ip -4 addr add "$ip/$prefix" dev "$interface"
    fi
    ip link set "$interface" up
    if [ "{route_mode}" = "multicast" ] || [ "{route_mode}" = "iptv_private" ]; then
      ip -4 route replace 224.0.0.0/4 dev "$interface" || true
    fi
    if [ "{route_mode}" = "iptv_private" ] && [ -n "${{router:-}}" ]; then
      ip -4 route replace 10.0.0.0/8 via "$router" dev "$interface" metric 50 || true
    fi
    ;;
esac
exit 0
"""

    def status(self, interface: str, auth_info: dict[str, Any] | None = None) -> dict[str, Any]:
        iface = _valid_iface(interface)
        snap = self.snapshot(iface)
        tools = {
            "ip": bool(shutil.which("ip")),
            "udhcpc": bool(shutil.which("udhcpc")),
        }
        caps = {
            "root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
            "net_admin_hint": self._capability_enabled(12),
            "net_raw_hint": self._capability_enabled(13),
        }
        # Update initial backup snapshot on every status refresh
        bk_data = self._backup_data()
        iface_entry = bk_data["interfaces"].setdefault(iface, {"history": []})
        iface_entry["initial"] = snap
        self._write_backup_data(bk_data)
        auth = auth_info or {}
        has_auth = bool(auth.get("mac") and auth.get("hostname") and auth.get("vendor_class"))
        ipv4 = snap.get("ipv4") or []
        has_iptv_ip = any(str(item.get("local", "")).startswith("10.") for item in ipv4)
        return {
            "interface": iface,
            "snapshot": snap,
            "tools": tools,
            "caps": caps,
            "auth_ready": has_auth,
            "has_iptv_ip": has_iptv_ip,
            "backup": self.backup_summary(iface),
            "confirm_text": CONFIRM_TEXT,
            "restore_confirm_text": RESTORE_CONFIRM_TEXT,
        }

    def _capability_enabled(self, cap_number: int) -> bool:
        try:
            text = Path("/proc/self/status").read_text(encoding="utf-8", errors="replace")
            match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)$", text, re.MULTILINE)
            if not match:
                return False
            value = int(match.group(1), 16)
            return bool(value & (1 << cap_number))
        except Exception:
            return False

    def apply(self, data: dict[str, Any], auth_info: dict[str, Any] | None = None) -> dict[str, Any]:
        confirm = str(data.get("confirm") or "").strip()
        if confirm != CONFIRM_TEXT:
            raise ValueError(f"请输入确认文本：{CONFIRM_TEXT}")
        p = self._payload(data, auth_info)
        iface = p["interface"]
        if not self._interface_exists(iface):
            raise ValueError(f"接口不存在：{iface}")
        if not shutil.which("udhcpc"):
            raise RuntimeError("容器内未找到 udhcpc，无法执行一键认证")

        self._ensure_backup(iface)
        hook_content = self._udhcpc_hook_content(iface, p["route_mode"])
        hook_path = self.data_dir / f"iptv-auth-{iface}.udhcpc.sh"
        hook_path.write_text(hook_content, encoding="utf-8")
        hook_path.chmod(0o700)

        steps: list[dict[str, Any]] = []

        def run_step(cmd: Sequence[str], timeout: int = 12, check: bool = True) -> None:
            res = _run(cmd, timeout=timeout, check=False)
            steps.append(res)
            if check and res["returncode"] != 0:
                raise RuntimeError(res["stderr"] or res["stdout"] or f"命令执行失败：{res['cmd']}")

        pid_path = self.data_dir / f"iptv-auth-{iface}.pid"
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text(encoding="utf-8").strip())
                run_step(["kill", str(pid)], timeout=3, check=False)
            except Exception:
                pass

        run_step(["ip", "-4", "addr", "flush", "dev", iface], check=False)
        run_step(["ip", "link", "set", "dev", iface, "down"])
        run_step(["ip", "link", "set", "dev", iface, "address", p["mac"]])
        run_step(["ip", "link", "set", "dev", iface, "up"])

        suppress_default_clientid = bool(p["client_id"])
        dhcp_opts = [
            "-i", iface,
            *(["-C"] if suppress_default_clientid else []),
            "-s", str(hook_path),
            "-p", str(pid_path),
            "-x", f"hostname:{p['hostname']}",
            "-x", f"0x3c:{p['vendor_class_colon']}",
        ]
        if p["client_id"]:
            dhcp_opts.extend(["-x", f"0x3d:{_colon_hex(p['client_id'])}"])
        if p["requested_ip"]:
            dhcp_opts.extend(["-r", p["requested_ip"]])

        # Phase 1: synchronous one-shot — confirms authentication succeeded.
        run_step(["udhcpc", "-f", "-q", "-n", "-t", "4", "-T", "3"] + dhcp_opts, timeout=35)

        # Phase 2: background renewal daemon — keeps the lease alive indefinitely.
        # Without -f the process daemonizes; without -q it stays running and renews.
        run_step(["udhcpc", "-n", "-t", "4", "-T", "3"] + dhcp_opts, timeout=5, check=False)

        # Belt-and-suspenders: explicitly set multicast route after udhcpc.
        # The udhcpc hook does this too, but runs in a subprocess and may race
        # with the snapshot; doing it here ensures the route is present.
        if p["route_mode"] in {"multicast", "iptv_private"}:
            run_step(["ip", "-4", "route", "replace", "224.0.0.0/4", "dev", iface], check=False)
        if p["route_mode"] == "iptv_private":
            snap_for_gw = self.snapshot(iface)
            gw = p.get("gateway") or next(
                (r.get("gateway") for r in snap_for_gw.get("routes", []) if r.get("gateway")),
                "",
            )
            if gw:
                run_step(["ip", "-4", "route", "replace", "10.0.0.0/8", "via", gw, "dev", iface, "metric", "50"], check=False)

        snap = self.snapshot(iface)
        data_store = self._backup_data()
        entry = data_store["interfaces"].setdefault(iface, {"history": []})
        entry["last_apply"] = {"created_at": time.time(), "payload": p, "snapshot": snap}
        self._write_backup_data(data_store)
        self.logger.warning(f"实验性 IPTV 认证已执行：接口={iface}，MAC={p['mac']}，route_mode={p['route_mode']}")
        return {"interface": iface, "payload": p, "snapshot": snap, "steps": steps, "backup": self.backup_summary(iface)}

    def restore(self, data: dict[str, Any]) -> dict[str, Any]:
        confirm = str(data.get("confirm") or "").strip()
        if confirm != RESTORE_CONFIRM_TEXT:
            raise ValueError(f"请输入确认文本：{RESTORE_CONFIRM_TEXT}")
        iface = _valid_iface(data.get("interface") or "")
        entry = self._backup_data().get("interfaces", {}).get(iface) or {}
        initial = entry.get("initial")
        if not initial:
            raise ValueError("没有可恢复的初始备份")
        if not self._interface_exists(iface):
            raise ValueError(f"接口不存在：{iface}")

        steps: list[dict[str, Any]] = []

        def run_step(cmd: Sequence[str], timeout: int = 12, check: bool = True) -> None:
            res = _run(cmd, timeout=timeout, check=False)
            steps.append(res)
            if check and res["returncode"] != 0:
                raise RuntimeError(res["stderr"] or res["stdout"] or f"命令执行失败：{res['cmd']}")

        pid_path = self.data_dir / f"iptv-auth-{iface}.pid"
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text(encoding="utf-8").strip())
                run_step(["kill", str(pid)], timeout=3, check=False)
            except Exception:
                pass

        run_step(["ip", "-4", "addr", "flush", "dev", iface], check=False)
        run_step(["ip", "-4", "route", "flush", "dev", iface], check=False)
        run_step(["ip", "link", "set", "dev", iface, "down"], check=False)
        if initial.get("mac"):
            run_step(["ip", "link", "set", "dev", iface, "address", str(initial["mac"])], check=False)
        run_step(["ip", "link", "set", "dev", iface, "up"], check=False)

        for item in initial.get("ipv4") or []:
            local = item.get("local")
            prefix = item.get("prefixlen")
            if not local or prefix is None:
                continue
            cmd = ["ip", "-4", "addr", "add", f"{local}/{prefix}"]
            if item.get("broadcast"):
                cmd.extend(["broadcast", str(item["broadcast"])])
            cmd.extend(["dev", iface])
            run_step(cmd, check=False)

        for route in initial.get("routes") or []:
            dst = str(route.get("dst") or "default")
            cmd = ["ip", "-4", "route", "replace", dst]
            if route.get("gateway"):
                cmd.extend(["via", str(route["gateway"])])
            cmd.extend(["dev", iface])
            if route.get("prefsrc"):
                cmd.extend(["src", str(route["prefsrc"])])
            if route.get("metric") is not None:
                cmd.extend(["metric", str(route["metric"])])
            run_step(cmd, check=False)

        if str(initial.get("operstate", "")).upper() == "DOWN":
            run_step(["ip", "link", "set", "dev", iface, "down"], check=False)

        snap = self.snapshot(iface)
        self.logger.warning(f"IPTV 认证恢复已执行：接口={iface}，恢复到初始备份")
        return {"interface": iface, "snapshot": snap, "steps": steps, "backup": self.backup_summary(iface)}

    def backup_export(self, iface: str) -> dict[str, Any]:
        entry = self._backup_data().get("interfaces", {}).get(iface) or {}
        initial = entry.get("initial")
        if not initial:
            raise ValueError(f"接口 {iface} 尚无初始备份，请先刷新状态以创建备份。")
        return {"interface": iface, "initial": initial}

    def backup_import(self, data: dict[str, Any]) -> dict[str, Any]:
        iface = str(data.get("interface") or "").strip()
        initial = data.get("initial")
        if not iface or not isinstance(initial, dict):
            raise ValueError("备份文件格式无效，需包含 interface 和 initial 字段。")
        raw = self._backup_data()
        entry = raw["interfaces"].setdefault(iface, {"history": []})
        entry["initial"] = initial
        self._write_backup_data(raw)
        self.logger.info(f"IPTV 认证备份已导入：接口={iface}")
        return {"interface": iface, "saved": True}
