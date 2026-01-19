# vt_worker/worker.py

import asyncio
import os
import time
from typing import Optional

import httpx
import redis.asyncio as redis

from greycode_core.alerts import AlertRouter, AlertEvent


VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/{}"

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

STAGED_SET = "greycode:staged:vt_candidates"
VT_QUEUE = "greycode:queue:vt"

RATE_LIMIT_PER_MINUTE = int(os.getenv("VT_RATE_LIMIT_PER_MINUTE", "3"))  # free tier: 3/min
VT_RETRY_SECONDS_429 = int(os.getenv("VT_RETRY_SECONDS_429", "120"))      # conservative backoff


def vt_enabled() -> bool:
    return os.getenv("VT_ENABLED", "0") == "1"


r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
alert_router = AlertRouter()


async def _stage_again(sha256: str) -> None:
    # SET semantics (dedupe) is what we want for staged candidates.
    await r.sadd(STAGED_SET, sha256)


async def _release_queue_lease(key: str) -> None:
    # selector uses vt_queued_at as a lease; release it when we are done (or backing off)
    await r.hdel(key, "vt_queued_at")


async def query_virustotal(sha256: str) -> None:
    now = time.time()
    key = f"greycode:sha256:{sha256}"

    prev = await r.hgetall(key)
    prev_status = (prev.get("status") or "GREY").upper()
    already_alerted = (prev.get("alerted_red") or "") == "1"

    headers = {"x-apikey": VT_API_KEY}
    url = VT_URL.format(sha256)

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, headers=headers)
    except Exception:
        # transient failure: stage again for later retry
        await r.hset(
            key,
            mapping={
                "status": "GREY",
                "source": "vt",
                "vt_state": "ERROR",
                "vt_http_status": "NET_ERROR",
                "vt_last_checked": str(now),
                "vt_next_retry_at": str(now + 300),
            },
        )
        await _release_queue_lease(key)
        await _stage_again(sha256)
        return

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

        if status == "RED" and prev_status != "RED" and not already_alerted:
            computer = prev.get("computer") or ""
            image = prev.get("image") or ""

            vt_link = f"https://www.virustotal.com/gui/file/{sha256}"
            ui_base = os.getenv("GREYCODE_UI_BASE_URL", "").rstrip("/")
            ui_link = f"{ui_base}/ui/hash/{sha256}" if ui_base else None

            alert = AlertEvent(
                alert_type="HASH_RED",
                sha256=sha256,
                status="RED",
                vt_malicious=malicious,
                vt_suspicious=suspicious,
                computer=computer,
                image=image,
                source="vt",
                vt_link=vt_link,
                ui_link=ui_link,
            )

            await alert_router.send(alert)
            await r.hset(key, mapping={"alerted_red": "1", "alerted_red_at": str(time.time())})

        await _release_queue_lease(key)
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
        await _release_queue_lease(key)
        return

    if resp.status_code == 429:
        # Expected: schedule retry rather than marking ERROR
        retry_after = resp.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            next_retry_at = now + int(retry_after)
        else:
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

        await _release_queue_lease(key)
        await _stage_again(sha256)
        return

    # Other errors are operational errors; stage for later retry
    await r.hset(
        key,
        mapping={
            "status": "ERROR",
            "source": "vt",
            "vt_state": "ERROR",
            "vt_http_status": str(resp.status_code),
            "vt_last_checked": str(now),
            "vt_next_retry_at": str(now + 600),
        },
    )
    await _release_queue_lease(key)
    await _stage_again(sha256)


async def worker_loop() -> None:
    # Fail-fast for a common misconfig
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY is not set (required for VT worker).")

    # pacing interval
    sleep_seconds = 60.0 / max(1, RATE_LIMIT_PER_MINUTE)

    while True:
        item = await r.brpop(VT_QUEUE, timeout=5)
        if not item:
            continue

        _, sha256 = item
        if not sha256:
            continue

        if not vt_enabled():
            # Training mode: don't call VT; don't lose candidate
            await _stage_again(sha256)
            # release lease if it exists
            await _release_queue_lease(f"greycode:sha256:{sha256}")
            continue

        # Respect retry time if present (defensive; selector should already enforce)
        data = await r.hgetall(f"greycode:sha256:{sha256}")
        nra = data.get("vt_next_retry_at")
        if nra:
            try:
                if float(nra) > time.time():
                    await _stage_again(sha256)
                    await _release_queue_lease(f"greycode:sha256:{sha256}")
                    continue
            except ValueError:
                pass

        await query_virustotal(sha256)
        await asyncio.sleep(sleep_seconds)


async def main() -> None:
    await worker_loop()


if __name__ == "__main__":
    asyncio.run(main())
