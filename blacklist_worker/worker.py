# blacklist_worker/worker.py
from __future__ import annotations

import asyncio
import os
import time
import csv
import io
import urllib.request
import urllib.error
import redis.exceptions
from typing import List, Tuple
import redis.asyncio as redis
from redis.exceptions import BusyLoadingError

from greycode_core.alerts.router import AlertRouter
from greycode_core.index_sync import sync_ip_indexes, sync_domain_indexes
from greycode_core.geoip_engine import geoip_lookup_sync, geoip_available

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

KNOWN_COMPUTERS_SET = "greycode:known:computers"
INDEX_DIRTY_COMPUTER_SET = "greycode:index_dirty:computer"

AKARANK_SET = "greycode:akarank:top1m"
AKARANK_RANK_HASH = "greycode:akarank:rank"
AKARANK_META_KEY = "greycode:akarank:meta"

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



async def wait_for_redis(max_wait_sec: int = 300) -> None:
    start = time.time()

    while True:
        try:
            pong = await r.ping()
            if pong:
                return
        except BusyLoadingError:
            pass
        except Exception as e:
            print(f"[worker] redis not ready: {e}", flush=True)

        if time.time() - start >= max_wait_sec:
            raise RuntimeError(f"Redis did not become ready within {max_wait_sec}s")

        print("[worker] waiting for Redis to finish loading...", flush=True)
        await asyncio.sleep(3)

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

def normalize_domain(qname: str) -> str:
    d = (qname or "").strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


async def _get_akarank_enabled() -> bool:
    v = await r.hget(CFG_KEY, "akarank_enabled")
    return (v if v is not None else "1") == "1"


async def _get_akarank_url() -> str:
    v = await r.hget(CFG_KEY, "akarank_url")
    return (v or "https://www.akamai.com/pdata/akarank/prod/top1M.csv").strip()


async def _get_akarank_interval_min() -> int:
    v = await r.hget(CFG_KEY, "akarank_update_interval_min")
    try:
        n = int(v) if v is not None else 1440
    except Exception:
        n = 1440
    return _clamp(n, 60, 10080)


def _fetch_akarank_csv_sync(url: str, timeout: int = 60) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Greycode/akarank-fetcher",
            "Accept": "text/csv,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


async def get_akarank_match(domain: str) -> dict[str, str]:
    dom = normalize_domain(domain)
    if not dom:
        return {
            "akarank_top1m": "0",
            "akarank_domain": "",
            "akarank_rank": "",
        }

    parts = dom.split(".")
    candidates = [
        ".".join(parts[i:])
        for i in range(len(parts))
        if "." in ".".join(parts[i:])
    ]

    if not candidates:
        return {
            "akarank_top1m": "0",
            "akarank_domain": "",
            "akarank_rank": "",
        }

    pipe = r.pipeline()
    for candidate in candidates:
        pipe.hget(AKARANK_RANK_HASH, candidate)
    raw = await pipe.execute()

    for candidate, rank in zip(candidates, raw):
        if rank:
            return {
                "akarank_top1m": "1",
                "akarank_domain": candidate,
                "akarank_rank": str(rank),
            }

    return {
        "akarank_top1m": "0",
        "akarank_domain": "",
        "akarank_rank": "",
    }


async def apply_akarank_to_known_domains(batch: int = 1000) -> int:
    updated = 0
    cursor = 0

    while True:
        cursor, domains = await r.sscan(KNOWN_DOMAINS_SET, cursor=cursor, count=batch)

        for dom in domains:
            match = await get_akarank_match(dom)
            await r.hset(f"greycode:domain:{dom}", mapping=match)
            await sync_domain_indexes(r, dom)
            updated += 1

        if cursor == 0:
            break

    computers = await r.smembers(KNOWN_COMPUTERS_SET)
    if computers:
        await r.sadd(INDEX_DIRTY_COMPUTER_SET, *computers)

    return updated


async def maybe_fetch_akarank(run_reason: str) -> None:
    if not await _get_akarank_enabled():
        return

    interval_min = await _get_akarank_interval_min()
    meta = await r.hgetall(AKARANK_META_KEY)

    try:
        last_fetch = float(meta.get("last_fetch_at") or 0.0)
    except Exception:
        last_fetch = 0.0

    now = time.time()
    due = run_reason == "startup" and last_fetch <= 0
    due = due or ((now - last_fetch) >= interval_min * 60)

    if not due:
        return

    url = await _get_akarank_url()
    if not url:
        return

    print(f"[akarank] fetching url={url} reason={run_reason}", flush=True)

    try:
        body = await asyncio.to_thread(_fetch_akarank_csv_sync, url)
    except urllib.error.HTTPError as e:
        await r.hset(
            AKARANK_META_KEY,
            mapping={
                "last_error_at": str(time.time()),
                "last_error": f"HTTP {e.code}: {e.reason}",
                "last_url": url,
            },
        )
        print(f"[akarank] fetch failed HTTP {e.code}: {e.reason}", flush=True)
        return
    except Exception as e:
        await r.hset(
            AKARANK_META_KEY,
            mapping={
                "last_error_at": str(time.time()),
                "last_error": str(e),
                "last_url": url,
            },
        )
        print(f"[akarank] fetch failed: {e}", flush=True)
        return

    try:
        reader = csv.DictReader(io.StringIO(body))
        mapping: dict[str, str] = {}

        for row in reader:
            dom = normalize_domain(row.get("domain_name") or "")
            rank = (row.get("output_rank") or "").strip()

            if not dom or not rank:
                continue

            try:
                rank_int = int(rank)
            except ValueError:
                continue

            if rank_int < 1:
                continue

            mapping[dom] = str(rank_int)

        if not mapping:
            raise RuntimeError("AkaRank fetch returned no usable domains.")

        pipe = r.pipeline()
        pipe.delete(AKARANK_SET)
        pipe.delete(AKARANK_RANK_HASH)
        pipe.sadd(AKARANK_SET, *mapping.keys())
        pipe.hset(AKARANK_RANK_HASH, mapping=mapping)
        pipe.hset(
            AKARANK_META_KEY,
            mapping={
                "last_fetch_at": str(now),
                "last_fetch_by": "blacklist_worker",
                "last_url": url,
                "loaded": str(len(mapping)),
                "last_error": "",
                "last_error_at": "",
            },
        )
        await pipe.execute()

        updated_domains = await apply_akarank_to_known_domains()

        print(
            f"[akarank] loaded={len(mapping)} updated_known_domains={updated_domains}",
            flush=True,
        )

    except Exception as e:
        await r.hset(
            AKARANK_META_KEY,
            mapping={
                "last_error_at": str(time.time()),
                "last_error": str(e),
                "last_url": url,
            },
        )
        print(f"[akarank] processing failed: {e}", flush=True)
        return


async def enrich_known_ips_geoip(batch: int) -> int:
    enabled = (await r.hget(CFG_KEY, "geoip_enabled") or "0") == "1"
    if not enabled:
        print("[geoip] disabled", flush=True)
        return 0

    status = geoip_available()
    print(f"[geoip] status={status}", flush=True)

    updated = 0
    missed = 0
    scanned = 0
    cursor = 0

    while True:
        cursor, ips = await r.sscan(KNOWN_IPS_SET, cursor=cursor, count=batch)

        for ip in ips:
            scanned += 1
            geoip_data = await asyncio.to_thread(geoip_lookup_sync, ip)

            if not geoip_data:
                missed += 1
                continue

            await r.hset(f"greycode:ip:{ip}", mapping=geoip_data)
            await sync_ip_indexes(r, ip)
            updated += 1

        if cursor == 0:
            break

    print(
        f"[geoip] scanned={scanned} updated={updated} missed={missed}",
        flush=True,
    )

    return updated

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


            await sync_domain_indexes(r, dom)

        if cursor == 0:
            break


async def update_cycle(run_reason: str) -> None:
    interval_min = await _get_interval_min()
    batch = await _get_recheck_batch()

    try:
        await maybe_fetch_akarank(run_reason=run_reason)
    except Exception as e:
        print(f"[akarank] unexpected error ignored: {e}", flush=True)

    try:
        geoip_updated = await enrich_known_ips_geoip(batch=batch)
        if geoip_updated:
            print(f"[geoip] updated_known_ips={geoip_updated}", flush=True)
    except Exception as e:
        print(f"[geoip] update failed: {e}", flush=True)

    vendors = await load_vendors(r)

    changed_any = False
    new_vendors: List[Vendor] = []

    for v in vendors:
        try:
            changed, v2 = await fetch_vendor(r, v, interval_min=interval_min)
            changed_any = changed_any or changed
            new_vendors.append(v2)
        except Exception as e:
            print(f"[blacklist] vendor fetch failed key={getattr(v, 'key', '?')}: {e}", flush=True)
            new_vendors.append(v)

    await save_vendors(r, new_vendors)
    vendors = new_vendors

    try:
        await recheck_all_indicators(vendors, batch=batch)
    except Exception as e:
        print(f"[blacklist] recheck failed: {e}", flush=True)


async def worker_loop() -> None:
    await wait_for_redis()

    while True:
        try:
            await update_cycle(run_reason="startup")
            break
        except BusyLoadingError:
            print("[worker] Redis still loading during startup cycle...", flush=True)
            await asyncio.sleep(3)
        except Exception as e:
            print(f"[worker] startup cycle failed, continuing: {e}", flush=True)
            break

    while True:
        try:
            interval_min = await _get_interval_min()
        except BusyLoadingError:
            print("[worker] Redis busy/loading before sleep interval lookup...", flush=True)
            await asyncio.sleep(3)
            continue
        except Exception as e:
            print(f"[worker] failed to read interval, using 60 min: {e}", flush=True)
            interval_min = 60

        await asyncio.sleep(interval_min * 60)

        try:
            await update_cycle(run_reason="interval")
        except BusyLoadingError:
            print("[worker] Redis busy/loading during interval cycle...", flush=True)
        except Exception as e:
            print(f"[worker] interval cycle failed, continuing: {e}", flush=True)


async def main() -> None:
    await worker_loop()


if __name__ == "__main__":
    asyncio.run(main())