# vt_worker/worker.py

import asyncio
import os
import redis.asyncio as redis
import httpx
import time

VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
r = redis.Redis(host="redis", port=6379, decode_responses=True)

RATE_LIMIT = 3  # VirusTotal free tier: 3 requests per minute

def vt_enabled() -> bool:
    return os.getenv("VT_ENABLED", "0") == "1"

import time

async def query_virustotal(sha256: str):
    headers = {"x-apikey": VT_API_KEY}
    url = VT_URL.format(sha256)

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(url, headers=headers)

    now = time.time()
    key = f"greycode:sha256:{sha256}"

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
                "vt_malicious": str(malicious),
                "vt_suspicious": str(suspicious),
                "vt_last_checked": str(now),
            },
        )
        return

    if resp.status_code == 404:
        await r.hset(
            key,
            mapping={
                "status": "GREY",
                "source": "vt_not_found",
                "vt_last_checked": str(now),
            },
        )
        return

    # Rate limits and transient failures
    await r.hset(
        key,
        mapping={
            "status": "ERROR",
            "source": f"vt_http_{resp.status_code}",
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

        # Enrichment mode
        await query_virustotal(sha256)
        await asyncio.sleep(60 / RATE_LIMIT)


if __name__ == "__main__":
    asyncio.run(main())
