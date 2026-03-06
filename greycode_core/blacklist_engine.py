# blacklist_engine.py
from __future__ import annotations

import json
import time
import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from greycode_core.alerts import AlertRouter, AlertEvent


CFG_KEY = "greycode:cfg"
VENDORS_KEY = "greycode:blacklist:vendors"

SET_IP_PREFIX = "greycode:blacklist:set:ip:"
SET_DOMAIN_PREFIX = "greycode:blacklist:set:domain:"
CIDR_IP_PREFIX = "greycode:blacklist:cidr:ip:"  # optional, for CIDR-style feeds

HIST_PREFIX_IP = "greycode:history:ip:"
HIST_PREFIX_DOMAIN = "greycode:history:domain:"


DEFAULT_VENDORS = [
    {
        "key": "threatfox_ip",
        "name": "ThreatFox IPs",
        "enabled": True,
        "type": "ip",
        "url": "https://threatfox.abuse.ch/downloads/ipblocklist/",
        "min_fetch_min": 5,
    },
    {
        # URLhaus text list includes URLs; we keep it disabled for now unless you want it on.
        # When enabled, you probably want to extract domains instead of full URLs initially.
        "key": "urlhaus_text",
        "name": "URLhaus (text)",
        "enabled": False,
        "type": "domain",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "min_fetch_min": 60,
    },
    {
        # Spamhaus DROP is CIDR-based; keep disabled until you want CIDR membership support.
        "key": "spamhaus_drop",
        "name": "Spamhaus DROP (CIDR)",
        "enabled": False,
        "type": "ip_cidr",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "min_fetch_min": 1440,  # daily
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


@dataclass
class Vendor:
    key: str
    name: str
    enabled: bool
    type: str  # "ip" | "domain" | "url" | "ip_cidr"
    url: str
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
                    min_fetch_min=int(v.get("min_fetch_min") or 60),
                    etag=str(v.get("etag") or ""),
                    last_modified=str(v.get("last_modified") or ""),
                    last_fetch_at=float(v.get("last_fetch_at") or 0.0),
                )
            )
        except Exception:
            continue

    # discard broken entries
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
            "min_fetch_min": v.min_fetch_min,
            "etag": v.etag,
            "last_modified": v.last_modified,
            "last_fetch_at": v.last_fetch_at,
        }
        for v in vendors
    ]
    await r.set(VENDORS_KEY, _json_dumps(payload))


def vendor_set_key(v: Vendor) -> str:
    if v.type == "ip":
        return f"{SET_IP_PREFIX}{v.key}"
    if v.type == "domain":
        return f"{SET_DOMAIN_PREFIX}{v.key}"
    if v.type == "url":
        return f"greycode:blacklist:set:url:{v.key}"
    if v.type == "ip_cidr":
        # CIDR list stored separately
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
        # allow "ip ; comment"
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
            # keep as CIDR string
            _ = ipaddress.ip_network(token, strict=False)
            cidrs.append(token)
        except Exception:
            continue
    return cidrs


# ---------------------------------
# Membership check (fast path)
# ---------------------------------

class CidrCache:
    """
    CIDR membership is expensive; we cache parsed networks in-memory per vendor for TTL.
    Use only for ip_cidr vendors (which are disabled by default).
    """
    def __init__(self, ttl_sec: int = 60):
        self.ttl_sec = ttl_sec
        self._last = 0.0
        self._nets: Dict[str, List[ipaddress._BaseNetwork]] = {}

    async def get_networks(self, r, vendor_key: str) -> List[ipaddress._BaseNetwork]:
        now = _now()
        if (now - self._last) < self.ttl_sec and vendor_key in self._nets:
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
        self._last = now
        return nets


cidr_cache = CidrCache(ttl_sec=60)


async def check_indicator_hits(r, *, indicator_type: str, indicator: str, vendors: List[Vendor]) -> List[str]:
    """
    Return list of vendor keys that currently contain this indicator.
    """
    hits: List[str] = []

    if indicator_type == "ip":
        ip_norm = normalize_ip(indicator)
        for v in vendors:
            if not v.enabled:
                continue
            if v.type == "ip":
                if await r.sismember(f"{SET_IP_PREFIX}{v.key}", ip_norm):
                    hits.append(v.key)
            elif v.type == "ip_cidr":
                nets = await cidr_cache.get_networks(r, v.key)
                ip_obj = ipaddress.ip_address(ip_norm)
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
            if v.type == "domain":
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

    # Always update these fields (freshness)
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

        # Alert on both directions
        if new_state == "LISTED":
            # dedupe (simple)
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

        else:  # DELISTED
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

    # First-time initialization: if prev_state was PENDING, we still want to record history,
    # but we don't alert on first evaluation unless you explicitly want that.
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