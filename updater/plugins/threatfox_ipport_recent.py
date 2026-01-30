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

    if isinstance(data, dict):
        items = data.get("data")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    for k in ("ioc", "ioc_value", "indicator", "ip", "ip_port", "ip-port"):
                        v = item.get(k)
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
    Must handle empty values (Redis won't create a set key unless SADD happens).
    """
    tmp = f"{key}:tmp"

    # Always create the tmp key so RENAME won't fail
    await r.delete(tmp)
    await r.sadd(tmp, "__dummy__")   # ensure key exists
    await r.srem(tmp, "__dummy__")   # remove dummy; key remains as an empty set

    batch = []
    count = 0
    pipe = r.pipeline()

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
