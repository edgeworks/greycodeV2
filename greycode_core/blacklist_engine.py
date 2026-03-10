# blacklist_engine.py
from __future__ import annotations

import json
import time
import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    # worker containers: /app/greycode_core/...
    from greycode_core.alerts.router import AlertRouter
    from greycode_core.alerts.models import AlertEvent
except ModuleNotFoundError:
    # core container: /app/alerts/...
    from alerts.router import AlertRouter
    from alerts.models import AlertEvent


CFG_KEY = "greycode:cfg"
VENDORS_KEY = "greycode:blacklist:vendors"

SET_IP_PREFIX = "greycode:blacklist:set:ip:"
SET_DOMAIN_PREFIX = "greycode:blacklist:set:domain:"
CIDR_IP_PREFIX = "greycode:blacklist:cidr:ip:"

HIST_PREFIX_IP = "greycode:history:ip:"
HIST_PREFIX_DOMAIN = "greycode:history:domain:"


DEFAULT_VENDORS = [
    {
        "key": "threatfox_domains_recent",
        "name": "ThreatFox Domains (recent)",
        "enabled": True,
        "type": "domain_json",
        "url": "https://threatfox-api.abuse.ch/files/exports/domains_recent.json",
        "requires_api_key": True,
        "api_key_setting": "threatfox_api_key_enc",
        "min_fetch_min": 60,
    },
    {
        "key": "threatfox_ipport_recent",
        "name": "ThreatFox IP:Port (recent)",
        "enabled": True,
        "type": "ip_port_json",
        "url": "https://threatfox-api.abuse.ch/files/exports/ip-port_recent.json",
        "requires_api_key": True,
        "api_key_setting": "threatfox_api_key_enc",
        "min_fetch_min": 60,
    },
    {
        "key": "spamhaus_drop",
        "name": "Spamhaus DROP",
        "enabled": True,
        "type": "ip_cidr",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "requires_api_key": False,
        "api_key_setting": "",
        "min_fetch_min": 1440,
    },
]


def _now() -> float:
    return time.time()


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _json_loads(s: str, default: Any) -> Any:
    try:
        return json.loads(s)
    except Exception:
        return default


def normalize_domain(qname: str) -> str:
    d = (qname or "").strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


def normalize_ip(ip: str) -> str:
    return str(ipaddress.ip_address((ip or "").strip()))


def split_ip_port(value: str) -> tuple[str, str]:
    """
    Best-effort split for IPv4 '1.2.3.4:443' and bracketed IPv6 '[2001:db8::1]:443'.
    Returns (ip, port). Port may be "" if not present/parseable.
    """
    s = (value or "").strip()
    if not s:
        return ("", "")

    if s.startswith("[") and "]" in s:
        end = s.find("]")
        host = s[1:end]
        rest = s[end + 1:]
        port = rest[1:] if rest.startswith(":") else ""
        return (host.strip(), port.strip())

    if s.count(":") == 1:
        host, port = s.rsplit(":", 1)
        return (host.strip(), port.strip())

    # likely plain IP (or unbracketed IPv6 with no port handling)
    return (s, "")


@dataclass
class Vendor:
    key: str
    name: str
    enabled: bool
    type: str               # ip | domain | url | ip_cidr | domain_json | ip_port_json
    url: str
    requires_api_key: bool = False
    api_key_setting: str = ""
    min_fetch_min: int = 60
    etag: str = ""
    last_modified: str = ""
    last_fetch_at: float = 0.0


async def load_vendors(r) -> List[Vendor]:
    raw = await r.get(VENDORS_KEY)
    if not raw:
        vendors = DEFAULT_VENDORS
    else:
        vendors = _json_loads(raw, DEFAULT_VENDORS)
        if not isinstance(vendors, list):
            vendors = DEFAULT_VENDORS

    out: List[Vendor] = []
    for v in vendors:
        try:
            out.append(
                Vendor(
                    key=str(v.get("key") or ""),
                    name=str(v.get("name") or v.get("key") or ""),
                    enabled=bool(v.get("enabled")),
                    type=str(v.get("type") or ""),
                    url=str(v.get("url") or ""),
                    requires_api_key=bool(v.get("requires_api_key")),
                    api_key_setting=str(v.get("api_key_setting") or ""),
                    min_fetch_min=int(v.get("min_fetch_min") or 60),
                    etag=str(v.get("etag") or ""),
                    last_modified=str(v.get("last_modified") or ""),
                    last_fetch_at=float(v.get("last_fetch_at") or 0.0),
                )
            )
        except Exception:
            continue

    out = [v for v in out if v.key and v.type and v.url]
    return out


async def save_vendors(r, vendors: List[Vendor]) -> None:
    payload = [
        {
            "key": v.key,
            "name": v.name,
            "enabled": v.enabled,
            "type": v.type,
            "url": v.url,
            "requires_api_key": v.requires_api_key,
            "api_key_setting": v.api_key_setting,
            "min_fetch_min": v.min_fetch_min,
            "etag": v.etag,
            "last_modified": v.last_modified,
            "last_fetch_at": v.last_fetch_at,
        }
        for v in vendors
    ]
    await r.set(VENDORS_KEY, _json_dumps(payload))


def vendor_set_key(v: Vendor) -> str:
    if v.type in ("ip", "ip_port_json"):
        return f"{SET_IP_PREFIX}{v.key}"
    if v.type in ("domain", "domain_json"):
        return f"{SET_DOMAIN_PREFIX}{v.key}"
    if v.type == "url":
        return f"greycode:blacklist:set:url:{v.key}"
    if v.type == "ip_cidr":
        return f"{CIDR_IP_PREFIX}{v.key}"
    raise ValueError(f"Unknown vendor type: {v.type}")


# ----------------------------
# Parsers (simple, pragmatic)
# ----------------------------

def parse_ip_lines(text: str) -> List[str]:
    out: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        token = line.split()[0].split(";")[0].strip()
        try:
            out.append(normalize_ip(token))
        except Exception:
            continue
    return out


def parse_domain_lines(text: str) -> List[str]:
    out: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        token = line.split()[0].split(";")[0].strip()
        d = normalize_domain(token)
        if d:
            out.append(d)
    return out


def parse_spamhaus_drop_cidrs(text: str) -> List[str]:
    cidrs: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        token = line.split(";")[0].strip()
        try:
            _ = ipaddress.ip_network(token, strict=False)
            cidrs.append(token)
        except Exception:
            continue
    return cidrs


def parse_threatfox_domains_json(text: str) -> List[str]:
    payload = _json_loads(text or "{}", {})
    rows: List[dict] = []

    print(f"[parser:threatfox_domains] payload_type={type(payload).__name__}")

    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                rows.append(item)
        print(f"[parser:threatfox_domains] list_rows={len(rows)}")

    elif isinstance(payload, dict):
        if isinstance(payload.get("data"), list):
            for item in payload["data"]:
                if isinstance(item, dict):
                    rows.append(item)
            print(f"[parser:threatfox_domains] branch=data rows={len(rows)}")

        elif isinstance(payload.get("results"), list):
            for item in payload["results"]:
                if isinstance(item, dict):
                    rows.append(item)
            print(f"[parser:threatfox_domains] branch=results rows={len(rows)}")

        elif isinstance(payload.get("ioc_list"), list):
            for item in payload["ioc_list"]:
                if isinstance(item, dict):
                    rows.append(item)
            print(f"[parser:threatfox_domains] branch=ioc_list rows={len(rows)}")

        else:
            top_keys = list(payload.keys())[:5]
            print(f"[parser:threatfox_domains] branch=dict_values top_keys={top_keys}")
            for value in payload.values():
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            rows.append(item)
                elif isinstance(value, dict):
                    rows.append(value)
            print(f"[parser:threatfox_domains] branch=dict_values rows={len(rows)}")

    if rows:
        print(f"[parser:threatfox_domains] first_row_keys={list(rows[0].keys())[:10]}")
        print(f"[parser:threatfox_domains] first_row={rows[0]}")

    out: List[str] = []
    for row in rows:
        candidates = [
            row.get("domain"),
            row.get("ioc_value"),
            row.get("ioc"),
            row.get("host"),
        ]

        for candidate in candidates:
            d = normalize_domain(str(candidate or ""))
            if d:
                out.append(d)
                break

    out = sorted(set(out))
    print(f"[parser:threatfox_domains] extracted={len(out)} sample={out[:5]}")
    return out


def parse_threatfox_ip_port_json(text: str) -> List[str]:
    payload = _json_loads(text or "{}", {})
    rows: List[dict] = []

    print(f"[parser:threatfox_ipport] payload_type={type(payload).__name__}")

    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                rows.append(item)
        print(f"[parser:threatfox_ipport] list_rows={len(rows)}")

    elif isinstance(payload, dict):
        if isinstance(payload.get("data"), list):
            for item in payload["data"]:
                if isinstance(item, dict):
                    rows.append(item)
            print(f"[parser:threatfox_ipport] branch=data rows={len(rows)}")

        elif isinstance(payload.get("results"), list):
            for item in payload["results"]:
                if isinstance(item, dict):
                    rows.append(item)
            print(f"[parser:threatfox_ipport] branch=results rows={len(rows)}")

        elif isinstance(payload.get("ioc_list"), list):
            for item in payload["ioc_list"]:
                if isinstance(item, dict):
                    rows.append(item)
            print(f"[parser:threatfox_ipport] branch=ioc_list rows={len(rows)}")

        else:
            top_keys = list(payload.keys())[:5]
            print(f"[parser:threatfox_ipport] branch=dict_values top_keys={top_keys}")
            for value in payload.values():
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            rows.append(item)
                elif isinstance(value, dict):
                    rows.append(value)
            print(f"[parser:threatfox_ipport] branch=dict_values rows={len(rows)}")

    if rows:
        print(f"[parser:threatfox_ipport] first_row_keys={list(rows[0].keys())[:10]}")
        print(f"[parser:threatfox_ipport] first_row={rows[0]}")

    out: List[str] = []
    for row in rows:
        candidates = [
            row.get("ip"),
            row.get("ip_address"),
            row.get("ioc_value"),
            row.get("ioc"),
            row.get("ip_port"),
        ]

        for candidate in candidates:
            raw = str(candidate or "").strip()
            if not raw:
                continue

            host, _port = split_ip_port(raw)
            try:
                out.append(normalize_ip(host))
                break
            except Exception:
                continue

    out = sorted(set(out))
    print(f"[parser:threatfox_ipport] extracted={len(out)} sample={out[:5]}")
    return out


# ---------------------------------
# Membership check (fast path)
# ---------------------------------

class CidrCache:
    """
    CIDR membership is more expensive; cache parsed networks in-memory per vendor for TTL.
    """
    def __init__(self, ttl_sec: int = 60):
        self.ttl_sec = ttl_sec
        self._last: Dict[str, float] = {}
        self._nets: Dict[str, List[ipaddress._BaseNetwork]] = {}

    async def get_networks(self, r, vendor_key: str) -> List[ipaddress._BaseNetwork]:
        now = _now()
        if vendor_key in self._nets and (now - self._last.get(vendor_key, 0.0)) < self.ttl_sec:
            return self._nets[vendor_key]

        raw = await r.get(f"{CIDR_IP_PREFIX}{vendor_key}")
        cidrs = _json_loads(raw or "[]", [])
        nets: List[ipaddress._BaseNetwork] = []
        if isinstance(cidrs, list):
            for c in cidrs:
                try:
                    nets.append(ipaddress.ip_network(str(c), strict=False))
                except Exception:
                    continue

        self._nets[vendor_key] = nets
        self._last[vendor_key] = now
        return nets


cidr_cache = CidrCache(ttl_sec=60)


async def check_indicator_hits(r, *, indicator_type: str, indicator: str, vendors: List[Vendor]) -> List[str]:
    """
    Return list of vendor keys that currently contain this indicator.
    """
    hits: List[str] = []

    if indicator_type == "ip":
        ip_norm = normalize_ip(indicator)
        ip_obj = ipaddress.ip_address(ip_norm)

        for v in vendors:
            if not v.enabled:
                continue

            if v.type in ("ip", "ip_port_json"):
                if await r.sismember(f"{SET_IP_PREFIX}{v.key}", ip_norm):
                    hits.append(v.key)

            elif v.type == "ip_cidr":
                nets = await cidr_cache.get_networks(r, v.key)
                for net in nets:
                    if ip_obj in net:
                        hits.append(v.key)
                        break

        return hits

    if indicator_type == "domain":
        dom = normalize_domain(indicator)
        for v in vendors:
            if not v.enabled:
                continue

            if v.type in ("domain", "domain_json"):
                if await r.sismember(f"{SET_DOMAIN_PREFIX}{v.key}", dom):
                    hits.append(v.key)

        return hits

    raise ValueError(f"Unsupported indicator_type: {indicator_type}")


# ---------------------------------
# Transition-aware record update
# ---------------------------------

def _diff_lists(new: List[str], old: List[str]) -> Tuple[List[str], List[str]]:
    snew, sold = set(new), set(old)
    added = sorted(list(snew - sold))
    removed = sorted(list(sold - snew))
    return added, removed


async def _push_history(r, *, indicator_type: str, indicator: str, entry: Dict[str, Any], limit: int = 50) -> None:
    key = (HIST_PREFIX_IP if indicator_type == "ip" else HIST_PREFIX_DOMAIN) + indicator
    await r.lpush(key, _json_dumps(entry))
    await r.ltrim(key, 0, max(0, limit - 1))


async def update_indicator_record(
    r,
    alert_router: AlertRouter,
    *,
    indicator_type: str,           # "ip" | "domain"
    indicator: str,
    hits: List[str],               # vendor keys
    reason: str,                   # "ingest_check" | "periodic_recheck" | "vendor_update"
) -> None:
    """
    Update greycode:ip:<ip> or greycode:domain:<dom> with transition detection.
    Emit alerts on LISTED and DELISTED.
    """
    now = _now()

    if indicator_type == "ip":
        ind = normalize_ip(indicator)
        key = f"greycode:ip:{ind}"
    else:
        ind = normalize_domain(indicator)
        key = f"greycode:domain:{ind}"

    data = await r.hgetall(key)
    prev_state = (data.get("listing_state") or "PENDING").upper()
    prev_listed_by = _json_loads(data.get("listed_by") or "[]", [])
    if not isinstance(prev_listed_by, list):
        prev_listed_by = []

    new_state = "LISTED" if hits else "NO_LISTING"
    vendors_added, vendors_removed = _diff_lists(hits, prev_listed_by)

    mapping: Dict[str, str] = {
        "type": indicator_type,
        "source": "blacklist",
        "listing_state": new_state,
        "listed_by": _json_dumps(hits),
        "listed_count": str(len(hits)),
        "last_checked_at": str(now),
        "status": ("RED" if new_state == "LISTED" else "GREY"),
    }

    transitioned = (prev_state != new_state) and (prev_state != "PENDING")

    if transitioned:
        mapping.update(
            {
                "prev_listing_state": prev_state,
                "prev_listed_by": _json_dumps(prev_listed_by),
                "last_transition_at": str(now),
                "last_transition": ("LISTED" if new_state == "LISTED" else "DELISTED"),
            }
        )

        await _push_history(
            r,
            indicator_type=indicator_type,
            indicator=ind,
            entry={
                "ts": now,
                "reason": reason,
                "from": prev_state,
                "to": new_state,
                "vendors_added": vendors_added,
                "vendors_removed": vendors_removed,
            },
            limit=50,
        )

        if new_state == "LISTED":
            already = (data.get("alerted_listed_at") or "").strip()
            if not already:
                alert = AlertEvent(
                    alert_type=("IP_LISTED" if indicator_type == "ip" else "DOMAIN_LISTED"),
                    indicator=ind,
                    indicator_type=indicator_type,
                    transition="LISTED",
                    listed_by=hits,
                    vendors_added=vendors_added,
                    vendors_removed=vendors_removed,
                    source="blacklist",
                )
                await alert_router.send(alert)
                mapping["alerted_listed_at"] = str(now)

        else:
            already = (data.get("alerted_delisted_at") or "").strip()
            if not already:
                alert = AlertEvent(
                    alert_type=("IP_DELISTED" if indicator_type == "ip" else "DOMAIN_DELISTED"),
                    indicator=ind,
                    indicator_type=indicator_type,
                    transition="DELISTED",
                    listed_by=hits,
                    vendors_added=vendors_added,
                    vendors_removed=vendors_removed,
                    source="blacklist",
                )
                await alert_router.send(alert)
                mapping["alerted_delisted_at"] = str(now)

    if prev_state == "PENDING":
        mapping.update(
            {
                "prev_listing_state": prev_state,
                "prev_listed_by": _json_dumps(prev_listed_by),
                "last_transition_at": str(now),
                "last_transition": ("LISTED" if new_state == "LISTED" else "DELISTED"),
            }
        )
        await _push_history(
            r,
            indicator_type=indicator_type,
            indicator=ind,
            entry={
                "ts": now,
                "reason": reason,
                "from": "PENDING",
                "to": new_state,
                "vendors_added": vendors_added,
                "vendors_removed": vendors_removed,
            },
            limit=50,
        )

    await r.hset(key, mapping=mapping)