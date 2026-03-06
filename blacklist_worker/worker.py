# blacklist_worker/worker.py
from __future__ import annotations

import asyncio
import os
import time
from typing import List, Tuple

import httpx
import redis.asyncio as redis

from greycode_core.alerts.router import AlertRouter

from blacklist_engine import (
    Vendor,
    load_vendors,
    save_vendors,
    parse_ip_lines,
    parse_domain_lines,
    parse_spamhaus_drop_cidrs,
    vendor_set_key,
    SET_IP_PREFIX,
    SET_DOMAIN_PREFIX,
    CIDR_IP_PREFIX,
    check_indicator_hits,
    update_indicator_record,
)

CFG_KEY = "greycode:cfg"

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# Interval guardrails
MIN_INTERVAL_MIN = 5
MAX_INTERVAL_MIN = 1440

# Recheck scan tuning
DEFAULT_RECHECK_BATCH = 2000

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
alert_router = AlertRouter()


def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


async def _get_interval_min() -> int:
    v = await r.hget(CFG_KEY, "blacklist_update_interval_min")
    try:
        n = int(v) if v is not None else 60
    except Exception:
        n = 60
    return _clamp(n, MIN_INTERVAL_MIN, MAX_INTERVAL_MIN)


async def _get_recheck_batch() -> int:
    v = await r.hget(CFG_KEY, "blacklist_recheck_batch")
    try:
        n = int(v) if v is not None else DEFAULT_RECHECK_BATCH
    except Exception:
        n = DEFAULT_RECHECK_BATCH
    return max(200, min(20000, n))


async def fetch_vendor(v: Vendor, *, interval_min: int) -> Tuple[bool, Vendor]:
    """
    Returns (changed, updated_vendor_metadata).
    Enforces vendor.min_fetch_min, supports ETag/Last-Modified.
    """
    now = time.time()
    effective_min = max(int(v.min_fetch_min or 60), int(interval_min))
    due = (now - float(v.last_fetch_at or 0.0)) >= (effective_min * 60)

    if not v.enabled:
        return (False, v)
    if not due:
        return (False, v)

    headers = {}
    if v.etag:
        headers["If-None-Match"] = v.etag
    if v.last_modified:
        headers["If-Modified-Since"] = v.last_modified

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(v.url, headers=headers)
    except Exception:
        # don't update timestamps on failure
        return (False, v)

    if resp.status_code == 304:
        v.last_fetch_at = now
        return (False, v)

    if resp.status_code != 200:
        return (False, v)

    text = resp.text or ""

    # Parse and store
    if v.type == "ip":
        items = parse_ip_lines(text)
        set_key = f"{SET_IP_PREFIX}{v.key}"
        pipe = r.pipeline()
        pipe.delete(set_key)
        if items:
            pipe.sadd(set_key, *items)
        await pipe.execute()

    elif v.type == "domain":
        items = parse_domain_lines(text)
        set_key = f"{SET_DOMAIN_PREFIX}{v.key}"
        pipe = r.pipeline()
        pipe.delete(set_key)
        if items:
            pipe.sadd(set_key, *items)
        await pipe.execute()

    elif v.type == "ip_cidr":
        cidrs = parse_spamhaus_drop_cidrs(text)
        # store CIDR list as JSON string
        await r.set(f"{CIDR_IP_PREFIX}{v.key}", __import__("json").dumps(cidrs))

    else:
        # url or unknown: ignore for now
        return (False, v)

    # Update metadata
    v.last_fetch_at = now
    v.etag = resp.headers.get("ETag") or v.etag
    v.last_modified = resp.headers.get("Last-Modified") or v.last_modified

    return (True, v)


async def recheck_all_indicators(vendors: List[Vendor], *, batch: int) -> None:
    """
    Iterate all stored IP + domain records and recompute membership.
    This is linear time; keep it simple for now.
    """
    # IPs
    cursor = 0
    while True:
        cursor, keys = await r.scan(cursor=cursor, match="greycode:ip:*", count=batch)
        for key in keys:
            ip = key.split(":", 2)[-1]
            hits = await check_indicator_hits(r, indicator_type="ip", indicator=ip, vendors=vendors)
            await update_indicator_record(
                r, alert_router,
                indicator_type="ip",
                indicator=ip,
                hits=hits,
                reason="periodic_recheck",
            )
        if cursor == 0:
            break

    # Domains
    cursor = 0
    while True:
        cursor, keys = await r.scan(cursor=cursor, match="greycode:domain:*", count=batch)
        for key in keys:
            dom = key.split(":", 2)[-1]
            hits = await check_indicator_hits(r, indicator_type="domain", indicator=dom, vendors=vendors)
            await update_indicator_record(
                r, alert_router,
                indicator_type="domain",
                indicator=dom,
                hits=hits,
                reason="periodic_recheck",
            )
        if cursor == 0:
            break


async def update_cycle(run_reason: str) -> None:
    interval_min = await _get_interval_min()
    batch = await _get_recheck_batch()

    vendors = await load_vendors(r)

    # 1) fetch enabled vendors (respect min_fetch_min)
    changed_any = False
    new_vendors: List[Vendor] = []
    for v in vendors:
        changed, v2 = await fetch_vendor(v, interval_min=interval_min)
        changed_any = changed_any or changed
        new_vendors.append(v2)

    # persist vendor metadata (etag/last_modified/last_fetch_at)
    await save_vendors(r, new_vendors)
    vendors = new_vendors

    # 2) Recheck all records each cycle (your requested behavior)
    await recheck_all_indicators(vendors, batch=batch)


async def worker_loop() -> None:
    # Run once at startup (your requirement)
    await update_cycle(run_reason="startup")

    while True:
        interval_min = await _get_interval_min()
        await asyncio.sleep(interval_min * 60)
        await update_cycle(run_reason="interval")


async def main() -> None:
    await worker_loop()


if __name__ == "__main__":
    asyncio.run(main())