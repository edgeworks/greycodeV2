import datetime
import ipaddress
import json
import os
from typing import Iterable, Set

import httpx
import redis.asyncio as redis

# run every 5 minutes (ThreatFox says the "recent" exports are generated every 5 min)
UPDATE_INTERVAL = int(os.getenv("THREATFOX_REFRESH_SECONDS", "300"))

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

URL = os.getenv(
    "THREATFOX_IPPORT_RECENT_URL",
    "https://threatfox.abuse.ch/export/json/ip-port/recent/",
)

SET_KEY = "greycode:bl:ip:threatfox_recent"
META_KEY = "greycode:blmeta:ip:threatfox_recent"


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def normalize_ip(ip: str) -> str:
    return str(ipaddress.ip_address((ip or "").strip()))


def extract_ip_from_ipport(value: str) -> str:
    """
    Accept:
      - "1.2.3.4:443"
      - "[2001:db8::1]:443"
      - "2001:db8::1:443" (rare; we only treat last ':<port>' as port if it is numeric)
    Returns normalized IP string or raises ValueError.
    """
    s = (value or "").strip()
    if not s:
        raise ValueError("empty")

    # bracketed IPv6: [addr]:port
    if s.startswith("[") and "]" in s:
        ip_part = s[1:s.index("]")]
        return normalize_ip(ip_part)

    # try plain IP first
    try:
        return normalize_ip(s)
    except Exception:
        pass

    # split last colon as port if numeric
    if ":" in s:
        left, right = s.rsplit(":", 1)
        if right.isdigit():
            # validate port range but ignore it
            port = int(right)
            if 0 < port <= 65535:
                return normalize_ip(left)

    # split last colon as port for IPv4 using ":" (already covered),
    # also accept "ip port" or "ip,port" if present
    for sep in (" ", ",", ";"):
        if sep in s:
            parts = s.split(sep)
            try:
                return normalize_ip(parts[0])
            except Exception:
                continue

    raise ValueError("cannot parse ip")


def parse_ipport_json(text: str) -> Set[str]:
    data = json.loads(text)
    out: Set[str] = set()

    def try_add(v: str) -> None:
        try:
            out.add(extract_ip_from_ipport(v))
        except Exception:
            return

    # ThreatFox recent format: { "<id>": [ { "ioc_value": "1.2.3.4:80", ... }, ... ], ... }
    if isinstance(data, dict):
        for _, arr in data.items():
            if not isinstance(arr, list):
                continue
            for item in arr:
                if isinstance(item, dict):
                    v = item.get("ioc_value") or item.get("ioc") or item.get("indicator")
                    if isinstance(v, str):
                        try_add(v)
                elif isinstance(item, str):
                    try_add(item)

    elif isinstance(data, list):
        # fallback if they ever return list-of-items
        for item in data:
            if isinstance(item, dict):
                v = item.get("ioc_value") or item.get("ioc") or item.get("indicator")
                if isinstance(v, str):
                    try_add(v)
            elif isinstance(item, str):
                try_add(item)

    return out



async def replace_set(r: redis.Redis, key: str, values: Iterable[str]) -> int:
    """
    Replace set contents using tmp key + RENAME.

    Important: Redis deletes set keys when they become empty, so we keep a dummy
    member until AFTER RENAME, then remove it from the final key.
    """
    tmp = f"{key}:tmp"
    dummy = "__dummy__"

    pipe = r.pipeline()
    pipe.delete(tmp)

    # Ensure tmp key exists
    pipe.sadd(tmp, dummy)

    count = 0
    batch = []
    for v in values:
        batch.append(v)
        if len(batch) >= 2000:
            pipe.sadd(tmp, *batch)
            count += len(batch)
            batch = []
    if batch:
        pipe.sadd(tmp, *batch)
        count += len(batch)

    # Swap atomically
    pipe.rename(tmp, key)

    # Remove dummy from the FINAL key
    pipe.srem(key, dummy)

    await pipe.execute()
    return count



async def update() -> None:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    fetched_at = now_iso()

    async with httpx.AsyncClient(headers={"User-Agent": "greycodeV2-updater"}) as client:
        try:
            resp = await client.get(URL, timeout=30.0)

            text = resp.text or ""
            await r.hset(
                META_KEY,
                mapping={
                    "fetched_at": fetched_at,
                    "http_status": str(resp.status_code),
                    "body_prefix": text[:160].replace("\n", " "),
                },
            )

            try:
                js = json.loads(text)
                if isinstance(js, dict) and "query_status" in js:
                    await r.hset(META_KEY, mapping={"query_status": str(js.get("query_status"))})
            except Exception:
                pass

            resp.raise_for_status()

            ips = parse_ipport_json(text)
            await r.hset(META_KEY, mapping={"parsed_count": str(len(ips))})
            n = await replace_set(r, SET_KEY, ips)

            await r.hset(
                META_KEY,
                mapping={
                    "last_error": "",
                    "fetched_at": fetched_at,
                    "count": str(n),
                },
            )

        except Exception as e:
            await r.hset(
                META_KEY,
                mapping={
                    "last_error": str(e),
                    "fetched_at": fetched_at,
                },
            )
