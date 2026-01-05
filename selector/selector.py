import asyncio
import datetime
import os
from typing import Optional

import redis.asyncio as redis


REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

VT_ENABLED = os.getenv("VT_ENABLED", "0") == "1"
RARE_MAX = int(os.getenv("RARE_MAX", "3"))
MIN_AGE_SECONDS = int(os.getenv("MIN_AGE_SECONDS", "600"))
VT_BUDGET_PER_HOUR = int(os.getenv("VT_BUDGET_PER_HOUR", "180"))
SELECTOR_INTERVAL_SECONDS = int(os.getenv("SELECTOR_INTERVAL_SECONDS", "10"))

STAGED_SET = "greycode:staged:vt_candidates"
VT_QUEUE = "greycode:queue:vt"

BUDGET_KEY = "greycode:budget:vt_per_hour"  # INCR with EXPIRE
BUDGET_WINDOW_SECONDS = 3600


def utcnow_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def parse_iso(ts: Optional[str]) -> Optional[datetime.datetime]:
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(ts)
    except ValueError:
        return None


async def budget_allow(r: redis.Redis) -> bool:
    """
    Simple hourly counter budget:
      - INCR a key
      - set EXPIRE on first use
      - allow while <= VT_BUDGET_PER_HOUR
    """
    current = await r.incr(BUDGET_KEY)
    if current == 1:
        await r.expire(BUDGET_KEY, BUDGET_WINDOW_SECONDS)
    return current <= VT_BUDGET_PER_HOUR


async def should_enqueue(r: redis.Redis, sha256: str) -> bool:
    key = f"greycode:sha256:{sha256}"
    data = await r.hgetall(key)
    if not data:
        return False

    status = (data.get("status") or "").upper()
    # skip already-final or already-queued
    if status in {"GREEN", "RED"}:
        return False
    if data.get("vt_queued_at"):
        return False

    # rarity
    try:
        count_total = int(data.get("count_total") or 0)
    except ValueError:
        count_total = 0

    if count_total <= 0 or count_total > RARE_MAX:
        return False

    # min age
    first_seen = parse_iso(data.get("first_seen"))
    if not first_seen:
        return False

    age = (datetime.datetime.utcnow() - first_seen).total_seconds()
    if age < MIN_AGE_SECONDS:
        return False

    return True


async def main():
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    while True:
        if not (os.getenv("VT_ENABLED", "0") == "1"):
            # training mode: do nothing; staged set can grow
            await asyncio.sleep(SELECTOR_INTERVAL_SECONDS)
            continue

        # pull a small batch to avoid blocking redis on large sets
        candidates = list(await r.srandmember(STAGED_SET, number=50))
        if not candidates:
            await asyncio.sleep(SELECTOR_INTERVAL_SECONDS)
            continue

        for sha256 in candidates:
            if not sha256:
                continue

            # check eligibility
            ok = await should_enqueue(r, sha256)
            if not ok:
                continue

            # enforce budget
            if not await budget_allow(r):
                # budget exhausted; wait a bit longer
                await asyncio.sleep(SELECTOR_INTERVAL_SECONDS)
                break

            # enqueue for worker
            await r.lpush(VT_QUEUE, sha256)
            await r.hset(f"greycode:sha256:{sha256}", mapping={"vt_queued_at": utcnow_iso()})
            await r.srem(STAGED_SET, sha256)

        await asyncio.sleep(SELECTOR_INTERVAL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
