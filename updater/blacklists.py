# updater/blacklists.py
import datetime
import json
import os
import ipaddress
from typing import Iterable, Set, Tuple, Optional

import httpx
import redis.asyncio as redis


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def normalize_ip(ip: str) -> str:
    ip = (ip or "").strip()
    return str(ipaddress.ip_address(ip))


def normalize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


# Redis keys
IP_SET = "greycode:bl:ip:feodo"
IP_META = "greycode:blmeta:ip:feodo"

DOM_SET = "greycode:bl:domain:threatfox"
DOM_META = "greycode:blmeta:domain:threatfox"

STAGED_IP = "greycode:staged:ip_candidates"
STAGED_DOM = "greycode:staged:domain_candidates"


FEODO_URL = os.getenv("FEODO_IPBLOCKLIST_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
THREATFOX_DOMAIN_URL = os.getenv("THREATFOX_DOMAIN_URL", "https://threatfox.abuse.ch/export/json/domain/")


async def _fetch_text(client: httpx.AsyncClient, url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (text, error). error is None on success.
    """
    try:
        r = await client.get(url, timeout=30.0)
        r.raise_for_status()
        return r.text, None
    except Exception as e:
        return None, str(e)


def parse_feodo_ipblocklist_json(text: str) -> Set[str]:
    """
    Feodo Tracker ipblocklist.json is JSON with IP entries.
    We keep it defensive: scan for values that look like IPs.
    """
    data = json.loads(text)
    out: Set[str] = set()

    # Common shapes: list of objects; sometimes nested keys.
    # We'll walk shallowly and pick anything that can normalize as IP.
    def try_add(val: str) -> None:
        try:
            out.add(normalize_ip(val))
        except Exception:
            return

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, str):
                        try_add(v)
            elif isinstance(item, str):
                try_add(item)

    elif isinstance(data, dict):
        # sometimes {"ip": "..."} or {"data": [...]}
        for k, v in data.items():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        for _, vv in item.items():
                            if isinstance(vv, str):
                                try_add(vv)
                    elif isinstance(item, str):
                        try_add(item)
            elif isinstance(v, str):
                try_add(v)

    return out


def parse_threatfox_domain_json(text: str) -> Set[str]:
    """
    ThreatFox domain export is JSON; entries often include domain indicators.
    We keep it defensive and accept strings that normalize as domains.
    """
    data = json.loads(text)
    out: Set[str] = set()

    def try_add(val: str) -> None:
        d = normalize_domain(val)
        if d and "." in d:
            out.add(d)

    if isinstance(data, dict):
        # ThreatFox export commonly: {"query_status":"ok","data":[...]}
        items = data.get("data")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    # Common fields: "ioc", "indicator", "domain"
                    for key in ("ioc", "indicator", "domain", "host"):
                        v = item.get(key)
                        if isinstance(v, str):
                            try_add(v)
                elif isinstance(item, str):
                    try_add(item)

    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for v in item.values():
                    if isinstance(v, str):
                        try_add(v)
            elif isinstance(item, str):
                try_add(item)

    return out


async def replace_set(r: redis.Redis, key: str, values: Iterable[str]) -> int:
    """
    Replace set contents using a temp key + RENAME.
    """
    tmp = f"{key}:tmp"
    pipe = r.pipeline()
    await pipe.delete(tmp)
    # SADD in chunks to avoid huge payloads
    batch = []
    count = 0
    for v in values:
        batch.append(v)
        if len(batch) >= 2000:
            await pipe.sadd(tmp, *batch)
            count += len(batch)
            batch = []
    if batch:
        await pipe.sadd(tmp, *batch)
        count += len(batch)
    await pipe.rename(tmp, key)
    await pipe.execute()
    return count


async def refresh_feeds(r: redis.Redis) -> None:
    async with httpx.AsyncClient(headers={"User-Agent": "greycodeV2-updater"}) as client:
        # IP feed
        text, err = await _fetch_text(client, FEODO_URL)
        if err:
            await r.hset(IP_META, mapping={"last_error": err, "fetched_at": now_iso()})
        else:
            ips = parse_feodo_ipblocklist_json(text)
            n = await replace_set(r, IP_SET, ips)
            await r.hset(IP_META, mapping={"last_error": "", "fetched_at": now_iso(), "count": str(n)})

        # Domain feed
        text, err = await _fetch_text(client, THREATFOX_DOMAIN_URL)
        if err:
            await r.hset(DOM_META, mapping={"last_error": err, "fetched_at": now_iso()})
        else:
            doms = parse_threatfox_domain_json(text)
            n = await replace_set(r, DOM_SET, doms)
            await r.hset(DOM_META, mapping={"last_error": "", "fetched_at": now_iso(), "count": str(n)})


async def process_staged_candidates(r: redis.Redis) -> None:
    """
    Process staged IPs/domains and set listing_state accordingly.
    Uses SPOP to atomically claim work.
    """
    batch_size = int(os.getenv("BLACKLIST_BATCH", "500"))

    # IPs
    ips = await r.spop(STAGED_IP, batch_size)
    if ips:
        if isinstance(ips, str):
            ips = [ips]
        for ip in ips:
            key = f"greycode:ip:{ip}"
            try:
                listed = await r.sismember(IP_SET, ip)
                if listed:
                    await r.hset(key, mapping={
                        "status": "RED",
                        "listing_state": "LISTED",
                        "source": "feodo",
                        "listed_at": now_iso(),
                        "last_checked": now_iso(),
                    })
                else:
                    await r.hset(key, mapping={
                        "status": "GREY",
                        "listing_state": "NO_LISTING",
                        "source": "feodo",
                        "last_checked": now_iso(),
                    })
            except Exception as e:
                await r.hset(key, mapping={
                    "status": "ERROR",
                    "listing_state": "",
                    "source": "feodo",
                    "last_error": str(e),
                    "last_checked": now_iso(),
                })

    # Domains
    doms = await r.spop(STAGED_DOM, batch_size)
    if doms:
        if isinstance(doms, str):
            doms = [doms]
        for d in doms:
            key = f"greycode:domain:{d}"
            try:
                listed = await r.sismember(DOM_SET, d)
                if listed:
                    await r.hset(key, mapping={
                        "status": "RED",
                        "listing_state": "LISTED",
                        "source": "threatfox",
                        "listed_at": now_iso(),
                        "last_checked": now_iso(),
                    })
                else:
                    await r.hset(key, mapping={
                        "status": "GREY",
                        "listing_state": "NO_LISTING",
                        "source": "threatfox",
                        "last_checked": now_iso(),
                    })
            except Exception as e:
                await r.hset(key, mapping={
                    "status": "ERROR",
                    "listing_state": "",
                    "source": "threatfox",
                    "last_error": str(e),
                    "last_checked": now_iso(),
                })
