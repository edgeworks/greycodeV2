# blacklist_worker/worker.py
from __future__ import annotations

import asyncio
import os
import time
from typing import List, Tuple
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
import httpx
import redis.asyncio as redis

from greycode_core.alerts.router import AlertRouter
from greycode_core.indexes import update_listing_indexes, remove_from_all_indexes

from greycode_core.blacklist_engine import (
    Vendor,
    load_vendors,
    save_vendors,
    parse_ip_lines,
    parse_domain_lines,
    parse_spamhaus_drop_cidrs,
    parse_threatfox_domains_json,
    parse_threatfox_ip_port_json,
    SET_IP_PREFIX,
    SET_DOMAIN_PREFIX,
    CIDR_IP_PREFIX,
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

def _fernet() -> Fernet:
    secret = os.getenv("GREYCODE_SESSION_SECRET", "")
    if not secret:
        raise RuntimeError("GREYCODE_SESSION_SECRET not set (needed to decrypt vendor API keys).")
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""

def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def _iso_to_epoch(ts: str | None) -> float:
    if not ts:
        return time.time()
    try:
        return __import__("datetime").datetime.fromisoformat(ts).timestamp()
    except Exception:
        return time.time()


async def _sync_ip_indexes(ip_value: str) -> None:
    key = f"greycode:ip:{ip_value}"
    data = await r.hgetall(key)

    if not data:
        await remove_from_all_indexes(r, kind="ip", indicator=ip_value)
        await r.srem(KNOWN_IPS_SET, ip_value)
        return

    await r.sadd(KNOWN_IPS_SET, ip_value)

    await update_listing_indexes(
        r,
        kind="ip",
        indicator=ip_value,
        status=(data.get("status") or "GREY").upper(),
        count_total=int(data.get("count_total") or 0),
        last_seen_epoch=_iso_to_epoch(data.get("last_seen")),
        listing_state=(data.get("listing_state") or "").upper(),
    )


async def _sync_domain_indexes(domain_value: str) -> None:
    key = f"greycode:domain:{domain_value}"
    data = await r.hgetall(key)

    if not data:
        await remove_from_all_indexes(r, kind="domain", indicator=domain_value)
        await r.srem(KNOWN_DOMAINS_SET, domain_value)
        return

    await r.sadd(KNOWN_DOMAINS_SET, domain_value)

    await update_listing_indexes(
        r,
        kind="domain",
        indicator=domain_value,
        status=(data.get("status") or "GREY").upper(),
        count_total=int(data.get("count_total") or 0),
        last_seen_epoch=_iso_to_epoch(data.get("last_seen")),
        listing_state=(data.get("listing_state") or "").upper(),
    )


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

    print(f"[blacklist] vendor={v.key} enabled={v.enabled} type={v.type} due={due} effective_min={effective_min}")

    if not v.enabled:
        print(f"[blacklist] skip vendor={v.key} reason=disabled")
        return (False, v)
    if not due:
        print(f"[blacklist] skip vendor={v.key} reason=not_due last_fetch_at={v.last_fetch_at}")
        return (False, v)

    headers = {}
    if v.etag:
        headers["If-None-Match"] = v.etag
    if v.last_modified:
        headers["If-Modified-Since"] = v.last_modified

    effective_url = v.url
    if v.requires_api_key:
        enc = await r.hget(CFG_KEY, v.api_key_setting or "")
        api_key = decrypt_secret(enc or "")
        if not api_key:
            print(f"[blacklist] skip vendor={v.key} reason=missing_api_key setting={v.api_key_setting}")
            return (False, v)
        sep = "&" if "?" in effective_url else "?"
        effective_url = f"{effective_url}{sep}auth-key={api_key}"

    print(f"[blacklist] fetching vendor={v.key} url={effective_url}")

    try:
        async with httpx.AsyncClient(timeout=60.0, trust_env=True) as client:
            resp = await client.get(effective_url, headers=headers)
    except Exception as e:
        print(f"[blacklist] fetch failed vendor={v.key} error={type(e).__name__}: {e}")
        return (False, v)

    print(f"[blacklist] fetched vendor={v.key} status={resp.status_code} bytes={len(resp.text or '')}")

    if resp.status_code == 304:
        v.last_fetch_at = now
        print(f"[blacklist] vendor={v.key} not_modified")
        return (False, v)

    if resp.status_code != 200:
        print(f"[blacklist] vendor={v.key} unexpected_status={resp.status_code}")
        return (False, v)

    text = resp.text or ""
    print(f"[blacklist] vendor={v.key} body_head={text[:400]!r}")

    if v.type == "ip":
        items = parse_ip_lines(text)
        print(f"[blacklist] vendor={v.key} parsed_items={len(items)} sample={items[:5]}")
        set_key = f"{SET_IP_PREFIX}{v.key}"
        pipe = r.pipeline()
        pipe.delete(set_key)
        if items:
            pipe.sadd(set_key, *items)
        await pipe.execute()
        print(f"[blacklist] vendor={v.key} redis_set={set_key} count={len(items)}")

    elif v.type == "domain":
        items = parse_domain_lines(text)
        print(f"[blacklist] vendor={v.key} parsed_items={len(items)} sample={items[:5]}")
        set_key = f"{SET_DOMAIN_PREFIX}{v.key}"
        pipe = r.pipeline()
        pipe.delete(set_key)
        if items:
            pipe.sadd(set_key, *items)
        await pipe.execute()
        print(f"[blacklist] vendor={v.key} redis_set={set_key} count={len(items)}")

    elif v.type == "domain_json":
        items = parse_threatfox_domains_json(text)
        print(f"[blacklist] vendor={v.key} parsed_items={len(items)} sample={items[:5]}")
        set_key = f"{SET_DOMAIN_PREFIX}{v.key}"
        pipe = r.pipeline()
        pipe.delete(set_key)
        if items:
            pipe.sadd(set_key, *items)
        await pipe.execute()
        print(f"[blacklist] vendor={v.key} redis_set={set_key} count={len(items)}")

    elif v.type == "ip_port_json":
        items = parse_threatfox_ip_port_json(text)
        print(f"[blacklist] vendor={v.key} parsed_items={len(items)} sample={items[:5]}")
        set_key = f"{SET_IP_PREFIX}{v.key}"
        pipe = r.pipeline()
        pipe.delete(set_key)
        if items:
            pipe.sadd(set_key, *items)
        await pipe.execute()
        print(f"[blacklist] vendor={v.key} redis_set={set_key} count={len(items)}")

    elif v.type == "ip_cidr":
        cidrs = parse_spamhaus_drop_cidrs(text)
        print(f"[blacklist] vendor={v.key} parsed_cidrs={len(cidrs)} sample={cidrs[:5]}")
        await r.set(f"{CIDR_IP_PREFIX}{v.key}", __import__("json").dumps(cidrs))
        print(f"[blacklist] vendor={v.key} redis_cidr_key={CIDR_IP_PREFIX}{v.key} count={len(cidrs)}")

    else:
        print(f"[blacklist] vendor={v.key} unknown_type={v.type}")
        return (False, v)

    v.last_fetch_at = now
    v.etag = resp.headers.get("ETag") or v.etag
    v.last_modified = resp.headers.get("Last-Modified") or v.last_modified

    print(f"[blacklist] vendor={v.key} fetch_complete")
    return (True, v)


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
            await _sync_ip_indexes(ip)

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
            await _sync_domain_indexes(dom)

        if cursor == 0:
            break


async def update_cycle(run_reason: str) -> None:
    interval_min = await _get_interval_min()
    batch = await _get_recheck_batch()

    vendors = await load_vendors(r)

    changed_any = False
    new_vendors: List[Vendor] = []
    for v in vendors:
        changed, v2 = await fetch_vendor(v, interval_min=interval_min)
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