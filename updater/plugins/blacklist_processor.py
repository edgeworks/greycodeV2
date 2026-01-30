import datetime
import os

import redis.asyncio as redis

# process often
UPDATE_INTERVAL = int(os.getenv("BLACKLIST_PROCESS_SECONDS", "5"))

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

BATCH = int(os.getenv("BLACKLIST_BATCH", "500"))

# Staging sets (from greycode_core/main.py)
STAGED_IP = "greycode:staged:ip_candidates"
STAGED_DOM = "greycode:staged:domain_candidates"

# Feed cache sets
IP_FEED_SET = "greycode:bl:ip:threatfox_recent"
DOM_FEED_SET = "greycode:bl:domain:threatfox_recent"


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


async def _process_ip(r: redis.Redis) -> int:
    ips = await r.spop(STAGED_IP, BATCH)
    if not ips:
        return 0
    if isinstance(ips, str):
        ips = [ips]

    for ip in ips:
        key = f"greycode:ip:{ip}"
        try:
            listed = await r.sismember(IP_FEED_SET, ip)
            if listed:
                await r.hset(
                    key,
                    mapping={
                        "status": "RED",
                        "listing_state": "LISTED",
                        "source": "threatfox_recent",
                        "last_checked": now_iso(),
                        "listed_at": now_iso(),
                        "last_error": "",
                    },
                )
            else:
                await r.hset(
                    key,
                    mapping={
                        "status": "GREY",
                        "listing_state": "NO_LISTING",
                        "source": "threatfox_recent",
                        "last_checked": now_iso(),
                        "last_error": "",
                    },
                )
        except Exception as e:
            await r.hset(
                key,
                mapping={
                    "status": "ERROR",
                    "listing_state": "",
                    "source": "threatfox_recent",
                    "last_checked": now_iso(),
                    "last_error": str(e),
                },
            )

    return len(ips)


async def _process_domain(r: redis.Redis) -> int:
    doms = await r.spop(STAGED_DOM, BATCH)
    if not doms:
        return 0
    if isinstance(doms, str):
        doms = [doms]

    for d in doms:
        key = f"greycode:domain:{d}"
        try:
            listed = await r.sismember(DOM_FEED_SET, d)
            if listed:
                await r.hset(
                    key,
                    mapping={
                        "status": "RED",
                        "listing_state": "LISTED",
                        "source": "threatfox_recent",
                        "last_checked": now_iso(),
                        "listed_at": now_iso(),
                        "last_error": "",
                    },
                )
            else:
                await r.hset(
                    key,
                    mapping={
                        "status": "GREY",
                        "listing_state": "NO_LISTING",
                        "source": "threatfox_recent",
                        "last_checked": now_iso(),
                        "last_error": "",
                    },
                )
        except Exception as e:
            await r.hset(
                key,
                mapping={
                    "status": "ERROR",
                    "listing_state": "",
                    "source": "threatfox_recent",
                    "last_checked": now_iso(),
                    "last_error": str(e),
                },
            )

    return len(doms)


async def update() -> None:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    # process both every tick
    await _process_ip(r)
    await _process_domain(r)
