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

async def query_virustotal(sha256):
    headers = {"x-apikey": VT_API_KEY}
    url = VT_URL.format(sha256)
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            source = "vt"
            status = "RED" if malicious > 0 else "GREEN"
            await r.hset(f"greycode:sha256:{sha256}", mapping={
                "status": status,
                "source": source,
                "last_checked": time.time()
            })
        else:
            await r.hset(f"greycode:sha256:{sha256}", mapping={
                "status": "ERROR",
                "source": "vt",
                "last_checked": time.time()
            })

async def main():
    while True:
        sha256 = await r.rpop("greycode:queue:vt")
        if sha256:
            await query_virustotal(sha256)
            await asyncio.sleep(60 / RATE_LIMIT)
        else:
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
