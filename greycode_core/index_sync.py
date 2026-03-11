import time
from typing import Optional

import redis.asyncio as redis

try:
    from indexes import (
        update_sha256_indexes,
        update_listing_indexes,
        remove_from_all_indexes,
    )
except ModuleNotFoundError:
    from greycode_core.indexes import (
        update_sha256_indexes,
        update_listing_indexes,
        remove_from_all_indexes,
    ) 


KNOWN_SHA256_SET = "greycode:known:sha256"
KNOWN_IPS_SET = "greycode:known:ips"
KNOWN_DOMAINS_SET = "greycode:known:domains"


def iso_to_epoch(ts: Optional[str]) -> float:
    if not ts:
        return time.time()
    try:
        return __import__("datetime").datetime.fromisoformat(ts).timestamp()
    except Exception:
        return time.time()


def record_key_for_kind(kind: str, indicator: str) -> str:
    if kind == "sha256":
        return f"greycode:sha256:{indicator}"
    if kind == "ip":
        return f"greycode:ip:{indicator}"
    if kind == "domain":
        return f"greycode:domain:{indicator}"
    raise ValueError(f"Unknown kind: {kind}")


async def sync_sha256_indexes(r: redis.Redis, sha256_value: str) -> None:
    key = f"greycode:sha256:{sha256_value}"
    data = await r.hgetall(key)

    if not data:
        await remove_from_all_indexes(r, kind="sha256", indicator=sha256_value)
        await r.srem(KNOWN_SHA256_SET, sha256_value)
        return

    await r.sadd(KNOWN_SHA256_SET, sha256_value)

    await update_sha256_indexes(
        r,
        sha256=sha256_value,
        status=(data.get("status") or "GREY").upper(),
        count_total=int(data.get("count_total") or 0),
        last_seen_epoch=iso_to_epoch(data.get("last_seen")),
        disposition=(data.get("disposition") or "").upper(),
    )


async def sync_ip_indexes(r: redis.Redis, ip_value: str) -> None:
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
        last_seen_epoch=iso_to_epoch(data.get("last_seen")),
        listing_state=(data.get("listing_state") or "").upper(),
    )


async def sync_domain_indexes(r: redis.Redis, domain_value: str) -> None:
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
        last_seen_epoch=iso_to_epoch(data.get("last_seen")),
        listing_state=(data.get("listing_state") or "").upper(),
    )