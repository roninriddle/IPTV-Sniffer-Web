"""Current operator endpoints, stored history and durable player subscriptions."""
import hashlib
import re
from typing import Any
from utils import valid_ipv4_multicast, natural_key
from services.epg_service import normalize_channel_name
_STABLE_CHANNEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")

def _valid_stable_channel_id(value: str) -> str:
    text = str(value or "").strip()
    return text if _STABLE_CHANNEL_ID_RE.fullmatch(text) else ""

def _stable_channel_id(row: dict[str, Any], operator: dict[str, Any] | None = None) -> str:
    """Choose a durable, URL-safe identity without exposing source addresses.

    An operator ChannelID survives multicast/FCC changes, so it takes priority.
    Locally saved IDs preserve the fallback identity for non-operator imports.
    """
    operator = operator or {}
    channel_id = str(operator.get("channel_id") or row.get("channel_id") or "").strip()
    if channel_id:
        normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", channel_id).strip(".-")
        candidate = _valid_stable_channel_id(f"c-{normalized}")
        if candidate:
            return candidate
    saved = _valid_stable_channel_id(row.get("stable_id", ""))
    if saved:
        return saved
    # A saved source keeps its generated identity when metadata is later edited.
    fingerprint = "|".join([
        str(row.get("tvg_id") or "").strip(),
        normalize_channel_name(str(row.get("name") or "").strip()),
        str(row.get("key") or "").strip(),
    ])
    digest = hashlib.sha1(fingerprint.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"m-{digest}"

def _stable_channel_catalog(stored, operator_channels, fill_channel_name_from_metadata) -> dict[str, dict[str, Any]]:
    """Return current channel mappings keyed by durable public IDs.

    When an operator table is available it is authoritative for the active
    multicast endpoint.  Old channel-store entries are intentionally excluded,
    so a re-import cannot leave a stable URL pointing at a stale source.
    """
    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    if operator_channels:
        for key, operator in operator_channels.items():
            if not isinstance(operator, dict):
                continue
            host = str(operator.get("host") or "").strip()
            try:
                port = int(operator.get("port"))
            except (TypeError, ValueError):
                continue
            if not valid_ipv4_multicast(host) or not 1 <= port <= 65535:
                continue
            row = dict(stored.get(key) or {})
            row.update({"key": key, "host": host, "port": port})
            for field in ("fcc_ip", "fcc_port", "fec_port", "operator_group", "is_hd"):
                if operator.get(field) not in (None, "", 0, False):
                    row[field] = operator.get(field)
            if not str(row.get("name") or "").strip():
                row["name"] = str(operator.get("name") or "").strip()
            if not str(row.get("category") or "").strip():
                row["category"] = str(operator.get("category") or "").strip() or "其它频道"
            row["source_state"] = "current"
            row["source_origin"] = "operator"
            candidates.append((row, operator))
        # Keep explicitly manual sources usable alongside operator channels.
        for key, row in stored.items():
            if key not in operator_channels and isinstance(row, dict) and not str(row.get("stable_id") or "").startswith("c-"):
                candidates.append(({**row, "source_state": "current", "source_origin": "manual"}, {}))
    else:
        candidates = [(dict(row), {}) for row in stored.values() if isinstance(row, dict)]

    catalog: dict[str, dict[str, Any]] = {}
    for row, operator in candidates:
        row = fill_channel_name_from_metadata(row, allow_epg_name=False)
        if not str(row.get("name") or "").strip():
            continue
        stable_id = _stable_channel_id(row, operator)
        if stable_id in catalog:
            suffix = hashlib.sha1(str(row.get("key") or "").encode("utf-8")).hexdigest()[:8]
            stable_id = f"{stable_id}-{suffix}"
        row["stable_id"] = stable_id
        catalog[stable_id] = {"row": row, "operator": operator}
    return catalog

def _operator_time_shift_minutes(operator: dict[str, Any]) -> int:
    """Read the canonical minutes field, accepting pre-1.3.1 data."""
    raw = operator.get("time_shift_minutes", operator.get("time_shift_days", 0))
    try:
        return max(0, int(raw or 0))
    except (TypeError, ValueError):
        return 0

def _subscription_m3u(settings, catalog, candidate_ids, base_url, hls_compat: bool = False) -> str:
    """Build a fast, state-only subscription; never run health checks here."""
    records = [catalog[stable_id] for stable_id in candidate_ids]
    # The active catalog already keeps one current source per durable channel
    # ID.  "全部" is retained as a stable public endpoint for clients that
    # need it; it contains every selected logical channel rather than bypassing
    # the owner's candidate list.
    records.sort(key=lambda item: natural_key(str(item["row"].get("name") or "")))

    epg_url = str(settings.get("epg_url") or "").strip() if settings.get("use_epg", True) else ""
    catchup_enabled = bool(settings.get("catchup_enabled")) and int(settings.get("catchup_days") or 0) > 0
    lines = [f'#EXTM3U x-tvg-url="{base_url}/epg.xml"' if epg_url else "#EXTM3U"]
    if catchup_enabled:
        lines[0] += ' catchup-correction="8"'
    for item in records:
        row = item["row"]
        operator = item["operator"]
        stable_id = row["stable_id"]
        tvg_id = str(row.get("tvg_id") or row.get("tvg_name") or row.get("name") or "").replace('"', "'")
        tvg_name = str(row.get("tvg_name") or row.get("name") or "").replace('"', "'")
        group = str(row.get("category") or "其它频道").replace('"', "'")
        logo = str(row.get("tvg_logo") or "").replace('"', "%22")
        logo_attr = f' tvg-logo="{logo}"' if logo else ""
        catchup_attr = ""
        backtv = str(operator.get("backtv_url") or "").strip()
        if catchup_enabled and backtv:
            raw_minutes = _operator_time_shift_minutes(operator)
            try:
                days = max(1, raw_minutes // 1440) if raw_minutes else int(settings.get("catchup_days") or 7)
            except (TypeError, ValueError):
                days = int(settings.get("catchup_days") or 7)
            catchup_source = f"{base_url}/catchup/{stable_id}?playseek=${{(b)yyyyMMddHHmmss:utc}}-${{(e)yyyyMMddHHmmss:utc}}"
            catchup_attr = f' catchup="default" catchup-days="{days}" catchup-source="{catchup_source}"'
        lines.append(f'#EXTINF:-1 tvg-id="{tvg_id}" tvg-name="{tvg_name}"{logo_attr} group-title="{group}"{catchup_attr},{row["name"]}')
        suffix = "?format=hls" if hls_compat else ""
        lines.append(f"{base_url}/live/{stable_id}{suffix}")
    return "\n".join(lines) + "\n"

def source_state(row, operator_channels):
    if row.get("source_origin") == "operator" or str(row.get("stable_id") or "").startswith("c-"):
        return "current" if row.get("key") in operator_channels else "historical"
    return "current"
