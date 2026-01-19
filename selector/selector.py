import asyncio
import datetime
import os
import time
from typing import Optional, Tuple, List

import redis.asyncio as redis


REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# Selection policy
RARE_MAX = int(os.getenv("RARE_MAX", "3"))
MIN_AGE_SECONDS = int(os.getenv("MIN_AGE_SECONDS", "600"))

# Mix: allocate a share of the daily budget to "common" hashes
# Example: NUM=1, DEN=10 => 10% common, 90% rare
COMMON_SHARE_NUM = int(os.getenv("COMMON_SHARE_NUM", "1"))
COMMON_SHARE_DEN = int(os.getenv("COMMON_SHARE_DEN", "10"))
MIX_COUNTER_KEY = "greycode:selector:vt_mix_counter"

# Loop / batching
SELECTOR_INTERVAL_SECONDS = int(os.getenv("SELECTOR_INTERVAL_SECONDS", "10"))
CANDIDATE_BATCH = int(os.getenv("CANDIDATE_BATCH", "50"))
ENQUEUE_PER_TICK = int(os.getenv("ENQUEUE_PER_TICK", "25"))

# Queue lease to avoid permanent "stuck queued" hashes if worker crashes
VT_QUEUE_LEASE_SECONDS = int(os.getenv("VT_QUEUE_LEASE_SECONDS", "3600"))

# Rolling 24h VT budget (free tier default)
VT_BUDGET_24H = int(os.getenv("VT_BUDGET_24H", "500"))
BUDGET_24H_KEY = "greycode:budget:vt_24h"
BUDGET_24H_WINDOW_SECONDS = 86400

STAGED_SET = "greycode:staged:vt_candidates"
VT_QUEUE = "greycode:queue:vt"


def utcnow_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def parse_iso(ts: Optional[str]) -> Optional[datetime.datetime]:
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(ts)
    except ValueError:
        return None


def now_epoch() -> float:
    return time.time()


async def budget_24h_allow_and_spend(r: redis.Redis) -> Tuple[bool, Optional[float]]:
    """
    Rolling 24-hour limiter using a ZSET of timestamps.
    Returns: (allowed, next_retry_epoch_if_blocked)
    """
    now = int(now_epoch())
    cutoff = now - BUDGET_24H_WINDOW_SECONDS

    pipe = r.pipeline()
    pipe.zremrangebyscore(BUDGET_24H_KEY, 0, cutoff)
    pipe.zcard(BUDGET_24H_KEY)
    _, count = await pipe.execute()

    if count >= VT_BUDGET_24H:
        oldest = await r.zrange(BUDGET_24H_KEY, 0, 0, withscores=True)
        if oldest and len(oldest[0]) == 2:
            oldest_ts = float(oldest[0][1])
            return False, oldest_ts + BUDGET_24H_WINDOW_SECONDS
        return False, None

    member = f"{now}:{os.urandom(4).hex()}"
    await r.zadd(BUDGET_24H_KEY, {member: now})
    return True, None


async def _queued_lease_ok_or_clear(r: redis.Redis, key: str, queued_at_iso: str) -> bool:
    """
    If vt_queued_at exists and is "recent", treat as still queued.
    If too old, clear it (lease expired) and allow enqueue.
    """
    dt = parse_iso(queued_at_iso)
    if not dt:
        await r.hdel(key, "vt_queued_at")
        return True

    age = (datetime.datetime.utcnow() - dt).total_seconds()
    if age < VT_QUEUE_LEASE_SECONDS:
        return False

    await r.hdel(key, "vt_queued_at")
    return True


async def should_enqueue(r: redis.Redis, sha256: str) -> Tuple[bool, bool]:
    """
    Returns (eligible, is_common).
    eligible: passes all gating checks except the rare/common preference.
    is_common: True if count_total > RARE_MAX.
    """
    key = f"greycode:sha256:{sha256}"
    data = await r.hgetall(key)
    if not data:
        return False, False

    status = (data.get("status") or "").upper()
    if status in {"GREEN", "RED"}:
        return False, False

    # Respect queued lease
    queued_at = data.get("vt_queued_at")
    if queued_at:
        ok = await _queued_lease_ok_or_clear(r, key, queued_at)
        if not ok:
            return False, False

    # Respect per-hash retry backoff (set by worker on 429)
    nra = data.get("vt_next_retry_at")
    if nra:
        try:
            if float(nra) > now_epoch():
                return False, False
        except ValueError:
            pass

    # Need a count to classify as rare/common
    try:
        count_total = int(data.get("count_total") or 0)
    except ValueError:
        count_total = 0

    if count_total <= 0:
        return False, False

    is_common = count_total > RARE_MAX

    # Min age gate (avoid hammering brand-new patch waves immediately)
    first_seen = parse_iso(data.get("first_seen"))
    if not first_seen:
        return False, is_common

    age = (datetime.datetime.utcnow() - first_seen).total_seconds()
    if age < MIN_AGE_SECONDS:
        return False, is_common

    return True, is_common


async def want_common_slot(r: redis.Redis) -> bool:
    """
    Decide whether the next *budget spend* should prefer a common hash,
    based on a persistent counter:
      - common share = COMMON_SHARE_NUM / COMMON_SHARE_DEN
    """
    den = COMMON_SHARE_DEN
    num = COMMON_SHARE_NUM

    if den <= 0 or num <= 0:
        return False
    if num >= den:
        return True

    c = int(await r.get(MIX_COUNTER_KEY) or 0)
    return (c % den) < num


async def enqueue_one(r: redis.Redis, sha256: str) -> None:
    await r.lpush(VT_QUEUE, sha256)
    await r.hset(f"greycode:sha256:{sha256}", mapping={"vt_queued_at": utcnow_iso()})
    await r.srem(STAGED_SET, sha256)


async def main() -> None:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    while True:
        # Re-evaluate VT_ENABLED dynamically so you can toggle without restart
        if not (os.getenv("VT_ENABLED", "0") == "1"):
            await asyncio.sleep(SELECTOR_INTERVAL_SECONDS)
            continue

        candidates: List[str] = list(await r.srandmember(STAGED_SET, number=CANDIDATE_BATCH))
        if not candidates:
            await asyncio.sleep(SELECTOR_INTERVAL_SECONDS)
            continue

        rare_pool: List[str] = []
        common_pool: List[str] = []

        # Classify candidates
        for sha256 in candidates:
            if not sha256:
                continue
            ok, is_common = await should_enqueue(r, sha256)
            if not ok:
                continue
            if is_common:
                common_pool.append(sha256)
            else:
                rare_pool.append(sha256)

        enqueued = 0

        while enqueued < ENQUEUE_PER_TICK:
            if not rare_pool and not common_pool:
                break

            allowed, next_retry = await budget_24h_allow_and_spend(r)
            if not allowed:
                if next_retry:
                    await r.set("greycode:budget:vt_24h_next_retry_at", str(next_retry), ex=3600)
                break

            prefer_common = await want_common_slot(r)

            # Choose candidate according to target ratio, with fallback
            if prefer_common and common_pool:
                sha = common_pool.pop()
            elif rare_pool:
                sha = rare_pool.pop()
            elif common_pool:
                sha = common_pool.pop()
            else:
                break

            await enqueue_one(r, sha)
            await r.incr(MIX_COUNTER_KEY)
            enqueued += 1

        await asyncio.sleep(SELECTOR_INTERVAL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
