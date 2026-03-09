from __future__ import annotations

import asyncio
import os
import time
import datetime
import ipaddress

import redis.asyncio as redis

from indexes import (
    update_sha256_indexes,
    update_listing_indexes,
    remove_from_all_indexes,
)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

KNOWN_SHA256_SET = "greycode:known:sha256"
KNOWN_IPS_SET = "greycode:known:ips"
KNOWN_DOMAINS_SET = "greycode:known:domains"


def iso_to_epoch(ts: str | None) -> float:
    if not ts:
        return time.time()
    try:
        return datetime.datetime.fromisoformat(ts).timestamp()
    except Exception:
        return time.time()


def normalize_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if not ip:
        raise ValueError("empty ip")
    return str(ipaddress.ip_address(ip))


def normalize_domain(qname: str) -> str:
    d = (qname or "").strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


async def clear_index_space() -> None:
    patterns = [
        "greycode:index:sha256:*",
        "greycode:index:ip:*",
        "greycode:index:domain:*",
    ]
    for pattern in patterns:
        cursor = 0
        while True:
            cursor, keys = await r.scan(cursor=cursor, match=pattern, count=500)
            if keys:
                await r.delete(*keys)
            if cursor == 0:
                break

    await r.delete(KNOWN_SHA256_SET, KNOWN_IPS_SET, KNOWN_DOMAINS_SET)


async def reindex_sha256() -> int:
    count = 0
    cursor = 0
    pattern = "greycode:sha256:*"

    while True:
        cursor, keys = await r.scan(cursor=cursor, match=pattern, count=500)

        for key in keys:
            sha256_value = key.split(":", 2)[-1]
            data = await r.hgetall(key)
            if not data:
                continue

            await r.sadd(KNOWN_SHA256_SET, sha256_value)

            await update_sha256_indexes(
                r,
                sha256=sha256_value,
                status=(data.get("status") or "GREY").upper(),
                count_total=int(data.get("count_total") or 0),
                last_seen_epoch=iso_to_epoch(data.get("last_seen")),
                disposition=(data.get("disposition") or "").upper(),
            )
            count += 1

        if cursor == 0:
            break

    return count


async def reindex_ips() -> int:
    count = 0
    cursor = 0
    pattern = "greycode:ip:*"

    while True:
        cursor, keys = await r.scan(cursor=cursor, match=pattern, count=500)

        for key in keys:
            raw_ip = key.split(":", 2)[-1]
            try:
                ip_value = normalize_ip(raw_ip)
            except Exception:
                # remove broken index entries if any
                await remove_from_all_indexes(r, kind="ip", indicator=raw_ip)
                continue

            data = await r.hgetall(key)
            if not data:
                continue

            await r.sadd(KNOWN_IPS_SET, ip_value)

            await update_listing_indexes(
                r,
                kind="ip",
                indicator=ip_value,
                status=(data.get("status") or "GREY").upper(),
                count_total=int(data.get("count_total") or 0),
                last_seen_epoch=iso_to_epoch(data.get("last_seen")),
                listing_state=(data.get("listing_state") or "").upper(),
            )
            count += 1

        if cursor == 0:
            break

    return count


async def reindex_domains() -> int:
    count = 0
    cursor = 0
    pattern = "greycode:domain:*"

    while True:
        cursor, keys = await r.scan(cursor=cursor, match=pattern, count=500)

        for key in keys:
            raw_domain = key.split(":", 2)[-1]
            domain_value = normalize_domain(raw_domain)
            if not domain_value:
                await remove_from_all_indexes(r, kind="domain", indicator=raw_domain)
                continue

            data = await r.hgetall(key)
            if not data:
                continue

            await r.sadd(KNOWN_DOMAINS_SET, domain_value)

            await update_listing_indexes(
                r,
                kind="domain",
                indicator=domain_value,
                status=(data.get("status") or "GREY").upper(),
                count_total=int(data.get("count_total") or 0),
                last_seen_epoch=iso_to_epoch(data.get("last_seen")),
                listing_state=(data.get("listing_state") or "").upper(),
            )
            count += 1

        if cursor == 0:
            break

    return count


async def main() -> None:
    print("[reindex] clearing existing UI indexes...")
    await clear_index_space()

    print("[reindex] rebuilding sha256 indexes...")
    n_sha = await reindex_sha256()

    print("[reindex] rebuilding ip indexes...")
    n_ip = await reindex_ips()

    print("[reindex] rebuilding domain indexes...")
    n_dom = await reindex_domains()

    print("[reindex] done")
    print(f"[reindex] sha256: {n_sha}")
    print(f"[reindex] ip:     {n_ip}")
    print(f"[reindex] domain: {n_dom}")


if __name__ == "__main__":
    asyncio.run(main())