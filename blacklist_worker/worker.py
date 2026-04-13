# blacklist_worker/worker.py
from __future__ import annotations

import asyncio
import os
import time
from typing import List, Tuple
import redis.asyncio as redis

from greycode_core.alerts.router import AlertRouter
from greycode_core.index_sync import sync_ip_indexes, sync_domain_indexes

from greycode_core.blacklist_engine import (
    Vendor,
    load_vendors,
    save_vendors,
    fetch_vendor,
    check_indicator_hits,
    update_indicator_record,
)

CFG_KEY = "greycode:cfg"
KNOWN_IPS_SET = "greycode:known:ips"
KNOWN_DOMAINS_SET = "greycode:known:domains"

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


def _iso_to_epoch(ts: str | None) -> float:
    if not ts:
        return time.time()
    try:
        return __import__("datetime").datetime.fromisoformat(ts).timestamp()
    except Exception:
        return time.time()





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


async def recheck_all_indicators(vendors: List[Vendor], batch: int) -> None:
    cursor = 0
    while True:
        cursor, ips = await r.sscan(KNOWN_IPS_SET, cursor=cursor, count=batch)

        for ip in ips:
            hits = await check_indicator_hits(
                r,
                indicator_type="ip",
                indicator=ip,
                vendors=vendors,
            )

            await update_indicator_record(
                r,
                alert_router,
                indicator_type="ip",
                indicator=ip,
                hits=hits,
                reason="periodic_recheck",
            )
            await sync_ip_indexes(r, ip)

        if cursor == 0:
            break

    cursor = 0
    while True:
        cursor, domains = await r.sscan(KNOWN_DOMAINS_SET, cursor=cursor, count=batch)

        for dom in domains:
            hits = await check_indicator_hits(
                r,
                indicator_type="domain",
                indicator=dom,
                vendors=vendors,
            )

            print(f"[recheck-debug] domain={dom} hits={hits}", flush=True)

            await update_indicator_record(
                r,
                alert_router,
                indicator_type="domain",
                indicator=dom,
                hits=hits,
                reason="periodic_recheck",
            )

            data = await r.hmget(
                f"greycode:domain:{dom}",
                "listing_state",
                "status",
                "alerted_listed_at",
                "alerted_delisted_at",
                "last_transition",
            )
            print(
                f"[recheck-debug] domain={dom} post_update "
                f"listing_state={data[0]!r} status={data[1]!r} "
                f"alerted_listed_at={data[2]!r} alerted_delisted_at={data[3]!r} "
                f"last_transition={data[4]!r}",
                flush=True,
            )
            await sync_domain_indexes(r, dom)

        if cursor == 0:
            break


async def update_cycle(run_reason: str) -> None:
    interval_min = await _get_interval_min()
    batch = await _get_recheck_batch()

    vendors = await load_vendors(r)

    changed_any = False
    new_vendors: List[Vendor] = []
    for v in vendors:
        changed, v2 = await fetch_vendor(r, v, interval_min=interval_min)
        changed_any = changed_any or changed
        new_vendors.append(v2)

    await save_vendors(r, new_vendors)
    vendors = new_vendors

    await recheck_all_indicators(vendors, batch=batch)


async def worker_loop() -> None:
    # Run once at startup
    await update_cycle(run_reason="startup")

    while True:
        interval_min = await _get_interval_min()
        await asyncio.sleep(interval_min * 60)
        await update_cycle(run_reason="interval")


async def main() -> None:
    await worker_loop()


if __name__ == "__main__":
    asyncio.run(main())