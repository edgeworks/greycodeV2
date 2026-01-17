# vt_worker/worker.py

import asyncio
import os
import redis.asyncio as redis
import httpx
import time
import datetime
from typing import Optional, Tuple

VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
r = redis.Redis(host="redis", port=6379, decode_responses=True)

RATE_LIMIT = 3  # VirusTotal free tier: 3 requests per minute
VT_24H_LIMIT = 500 # VirusTotal free tier: 500 requests per day
VT_24H_WINDOW_SECONDS = 86400 
VT_BUDGET_ZSET_KEY = "greycode:budget:vt:requests" 
VT_RETRY_SECONDS_429 = 120  # conservative backoff for 429 bursts

def vt_enabled() -> bool:
    return os.getenv("VT_ENABLED", "0") == "1"


async def vt_budget_allow_or_next_retry(r) -> Tuple[bool, Optional[float]]:
    """
    Rolling 24-hour limiter using a Redis sorted set.

    Returns:
      (allowed=True, next_retry_at=None) if under budget
      (allowed=False, next_retry_at=<epoch>) if budget exhausted
    """
    now = time.time()
    window_start = now - VT_24H_WINDOW_SECONDS

    # Trim old entries
    await r.zremrangebyscore(VT_BUDGET_ZSET_KEY, 0, window_start)

    count = await r.zcard(VT_BUDGET_ZSET_KEY)
    if count < VT_24H_LIMIT:
        return True, None

    # Budget exhausted. Next retry is when the oldest entry ages out.
    oldest = await r.zrange(VT_BUDGET_ZSET_KEY, 0, 0, withscores=True)
    if oldest:
        oldest_ts = float(oldest[0][1])
        return False, oldest_ts + VT_24H_WINDOW_SECONDS

    # Fallback: if the zset is unexpectedly empty, wait 1 hour
    return False, now + 3600


async def vt_budget_spend(r, sha256: str) -> None:
    """
    Record one VT request in the rolling window.
    """
    now = time.time()
    member = f"{sha256}:{now}"
    await r.zadd(VT_BUDGET_ZSET_KEY, {member: now})


async def query_virustotal(sha256: str):
    now = time.time()
    key = f"greycode:sha256:{sha256}"

    # 1) Rolling 24-hour budget gate
    allowed, next_retry = await vt_budget_allow_or_next_retry(r)
    if not allowed:
        await r.hset(
            key,
            mapping={
                "status": "GREY",
                "source": "vt",
                "vt_state": "RATE_LIMITED",
                "vt_http_status": "DAILY_LIMIT",
                "vt_last_checked": str(now),
                "vt_next_retry_at": str(next_retry) if next_retry else "",
            },
        )
        return

    # 2) Spend budget (conservative: spend when you actually attempt a call)
    await vt_budget_spend(r, sha256)

    headers = {"x-apikey": VT_API_KEY}
    url = VT_URL.format(sha256)

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(url, headers=headers)

    # 3) Handle responses
    if resp.status_code == 200:
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)

        status = "RED" if malicious > 0 else "GREEN"

        await r.hset(
            key,
            mapping={
                "status": status,
                "source": "vt",
                "vt_state": "FOUND",
                "vt_http_status": "200",
                "vt_malicious": str(malicious),
                "vt_suspicious": str(suspicious),
                "vt_last_checked": str(now),
                "vt_next_retry_at": "",
            },
        )
        return

    if resp.status_code == 404:
        # Distinguish from "never checked": NOT_FOUND
        await r.hset(
            key,
            mapping={
                "status": "GREY",
                "source": "vt",
                "vt_state": "NOT_FOUND",
                "vt_http_status": "404",
                "vt_last_checked": str(now),
                "vt_next_retry_at": "",
            },
        )
        return

    if resp.status_code == 429:
        # Expected: schedule retry rather than marking ERROR
        next_retry_at = now + VT_RETRY_SECONDS_429
        await r.hset(
            key,
            mapping={
                "status": "GREY",
                "source": "vt",
                "vt_state": "RATE_LIMITED",
                "vt_http_status": "429",
                "vt_last_checked": str(now),
                "vt_next_retry_at": str(next_retry_at),
            },
        )
        return

    # Other errors are operational errors
    await r.hset(
        key,
        mapping={
            "status": "ERROR",
            "source": "vt",
            "vt_state": "ERROR",
            "vt_http_status": str(resp.status_code),
            "vt_last_checked": str(now),
        },
    )


async def main():
    while True:
        # Block up to 5 seconds waiting for work
        item = await r.brpop("greycode:queue:vt", timeout=5)

        if not item:
            # Queue empty
            continue

        _, sha256 = item  # (key, value)

        if not sha256:
            continue

        if not vt_enabled():
            # Training mode: do not call VT, but do not lose candidates
            await r.sadd("greycode:staged:vt_candidates", sha256)
            continue

        # Skip until retry time if scheduled
        data = await r.hgetall(f"greycode:sha256:{sha256}")
        nra = data.get("vt_next_retry_at")
        if nra:
            try:
                if float(nra) > time.time():
                    # Not due yet: put back into staged set (dedupe) and move on
                    await r.sadd("greycode:staged:vt_candidates", sha256)
                    continue
            except ValueError:
                pass

        # Enrichment mode
        await query_virustotal(sha256)
        await asyncio.sleep(60 / RATE_LIMIT)


if __name__ == "__main__":
    asyncio.run(main())
