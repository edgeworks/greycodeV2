import datetime
import json
import os
from typing import Iterable, Set, Tuple, Optional

import httpx
import redis.asyncio as redis

# run every 5 minutes (ThreatFox says the "recent" exports are generated every 5 min)
UPDATE_INTERVAL = int(os.getenv("THREATFOX_REFRESH_SECONDS", "300"))

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

URL = os.getenv(
    "THREATFOX_DOMAINS_RECENT_URL",
    "https://threatfox.abuse.ch/export/json/domains/recent/",
)

SET_KEY = "greycode:bl:domain:threatfox_recent"
META_KEY = "greycode:blmeta:domain:threatfox_recent"


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def normalize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


def parse_domains_json(text: str) -> Set[str]:
    data = json.loads(text)
    out: Set[str] = set()

    def try_add(v: str) -> None:
        dom = normalize_domain(v)
        if dom and "." in dom:
            out.add(dom)

    # Defensive parsing: accept common structures
    if isinstance(data, dict):
        items = data.get("data")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    for k in ("ioc", "ioc_value", "indicator", "domain", "host"):
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
    tmp = f"{key}:tmp"
    pipe = r.pipeline()
    await pipe.delete(tmp)

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


async def update() -> None:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    async with httpx.AsyncClient(headers={"User-Agent": "greycodeV2-updater"}) as client:
        try:
            resp = await client.get(URL, timeout=30.0)
            resp.raise_for_status()
            domains = parse_domains_json(resp.text)
            n = await replace_set(r, SET_KEY, domains)
            await r.hset(META_KEY, mapping={"last_error": "", "fetched_at": now_iso(), "count": str(n)})
        except Exception as e:
            await r.hset(META_KEY, mapping={"last_error": str(e), "fetched_at": now_iso()})
