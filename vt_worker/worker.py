# vt_worker/worker.py

import asyncio
import os
import time
from typing import Dict, Optional
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

import httpx
import redis.asyncio as redis

from greycode_core.alerts import AlertRouter, AlertEvent
from greycode_core.indexes import update_sha256_indexes


VT_URL = "https://www.virustotal.com/api/v3/files/{}"

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

CFG_KEY = "greycode:cfg"
STAGED_SET = "greycode:staged:vt_candidates"
VT_QUEUE = "greycode:queue:vt"
KNOWN_SHA256_SET = "greycode:known:sha256"

# Defaults if cfg fields are missing
DEFAULT_VT_ENABLED = False
DEFAULT_RATE_LIMIT_PER_MIN = 3          # free tier: 3/min
DEFAULT_RETRY_SECONDS_429 = 120         # conservative backoff

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
alert_router = AlertRouter()


def _fernet() -> Fernet:
    secret = os.getenv("GREYCODE_SESSION_SECRET", "")
    if not secret:
        raise RuntimeError("GREYCODE_SESSION_SECRET not set (needed to decrypt vt_api_key_enc).")
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


def _boolish(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "enabled")


def _intish(v: Optional[str], default: int) -> int:
    try:
        return int(v) if v is not None else default
    except Exception:
        return default


class ConfigCache:
    def __init__(self, ttl_sec: int = 10):
        self.ttl_sec = ttl_sec
        self._last = 0.0
        self.data: Dict[str, str] = {}

    async def get(self) -> Dict[str, str]:
        now = time.time()
        if self.data and (now - self._last) < self.ttl_sec:
            return self.data
        self.data = await r.hgetall(CFG_KEY)
        self._last = now
        return self.data


cfg_cache = ConfigCache(ttl_sec=10)


async def _stage_again(sha256: str) -> None:
    await r.sadd(STAGED_SET, sha256)


async def _release_queue_lease(key: str) -> None:
    await r.hdel(key, "vt_queued_at")


async def _sync_sha256_indexes(sha256: str, *, fallback_ts: Optional[float] = None) -> None:
    """
    Keep UI indexes in sync with the canonical hash record.
    Uses last_seen if available, otherwise vt_last_checked, otherwise now/fallback_ts.
    """
    key = f"greycode:sha256:{sha256}"
    data = await r.hgetall(key)
    if not data:
        return

    await r.sadd(KNOWN_SHA256_SET, sha256)

    last_seen_epoch: float
    last_seen_iso = (data.get("last_seen") or "").strip()
    if last_seen_iso:
        try:
            last_seen_epoch = __import__("datetime").datetime.fromisoformat(last_seen_iso).timestamp()
        except Exception:
            last_seen_epoch = float(data.get("vt_last_checked") or fallback_ts or time.time())
    else:
        last_seen_epoch = float(data.get("vt_last_checked") or fallback_ts or time.time())

    await update_sha256_indexes(
        r,
        sha256=sha256,
        status=(data.get("status") or "GREY").upper(),
        count_total=int(data.get("count_total") or 0),
        last_seen_epoch=last_seen_epoch,
        disposition=(data.get("disposition") or "").upper(),
    )


async def _get_vt_runtime_config() -> dict:
    cfg = await cfg_cache.get()
    vt_enabled = _boolish(cfg.get("vt_enabled"), default=DEFAULT_VT_ENABLED)
    vt_api_key = decrypt_secret((cfg.get("vt_api_key_enc") or "").strip())
    rate_per_min = _intish(cfg.get("vt_budget_per_min"), default=DEFAULT_RATE_LIMIT_PER_MIN)
    retry_429 = _intish(cfg.get("vt_retry_seconds_429"), default=DEFAULT_RETRY_SECONDS_429)

    if rate_per_min < 1:
        rate_per_min = 1
    if retry_429 < 10:
        retry_429 = 10

    return {
        "vt_enabled": vt_enabled,
        "vt_api_key": vt_api_key,
        "rate_per_min": rate_per_min,
        "retry_429": retry_429,
    }


async def query_virustotal(sha256: str, *, api_key: str, retry_429: int) -> None:
    now = time.time()
    key = f"greycode:sha256:{sha256}"

    prev = await r.hgetall(key)
    prev_status = (prev.get("status") or "GREY").upper()
    already_alerted = (prev.get("alerted_red") or "") == "1"

    headers = {"x-apikey": api_key}
    url = VT_URL.format(sha256)

    try:
        async with httpx.AsyncClient(timeout=20.0, trust_env=True) as client:
            resp = await client.get(url, headers=headers)
    except Exception:
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
        await _sync_sha256_indexes(sha256, fallback_ts=now)
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
        await _sync_sha256_indexes(sha256, fallback_ts=now)

        if status == "RED" and prev_status != "RED" and not already_alerted:
            computer = prev.get("computer") or ""
            image = prev.get("image") or ""

            vt_link = f"https://www.virustotal.com/gui/file/{sha256}"
            ui_base = os.getenv("GREYCODE_UI_BASE_URL", "").rstrip("/")
            ui_link = f"{ui_base}/ui/sysmon/1?open={sha256}" if ui_base else None

            alert = AlertEvent(
                alert_type="HASH_RED",
                status="RED",
                indicator_type="sha256",
                indicator=sha256,
                sha256=sha256,
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
            await _sync_sha256_indexes(sha256, fallback_ts=now)

        await _release_queue_lease(key)
        return

    if resp.status_code == 404:
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
        await _sync_sha256_indexes(sha256, fallback_ts=now)
        await _release_queue_lease(key)
        return

    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            next_retry_at = now + int(retry_after)
        else:
            next_retry_at = now + retry_429

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
        await _sync_sha256_indexes(sha256, fallback_ts=now)

        await _release_queue_lease(key)
        await _stage_again(sha256)
        return

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
    await _sync_sha256_indexes(sha256, fallback_ts=now)
    await _release_queue_lease(key)
    await _stage_again(sha256)


async def worker_loop() -> None:
    while True:
        item = await r.brpop(VT_QUEUE, timeout=5)
        if not item:
            continue

        _, sha256 = item
        if not sha256:
            continue

        key = f"greycode:sha256:{sha256}"

        cfg = await _get_vt_runtime_config()
        vt_enabled = cfg["vt_enabled"]
        api_key = cfg["vt_api_key"]
        rate_per_min = cfg["rate_per_min"]
        retry_429 = cfg["retry_429"]

        sleep_seconds = 60.0 / max(1, rate_per_min)

        if not vt_enabled:
            await _stage_again(sha256)
            await _release_queue_lease(key)
            await _sync_sha256_indexes(sha256)
            continue

        if not api_key:
            now = time.time()
            await r.hset(
                key,
                mapping={
                    "status": "GREY",
                    "source": "vt",
                    "vt_state": "ERROR",
                    "vt_http_status": "NO_API_KEY",
                    "vt_last_checked": str(now),
                    "vt_next_retry_at": str(now + 300),
                },
            )
            await _sync_sha256_indexes(sha256, fallback_ts=now)
            await _release_queue_lease(key)
            await _stage_again(sha256)
            continue

        data = await r.hgetall(key)
        nra = data.get("vt_next_retry_at")
        if nra:
            try:
                if float(nra) > time.time():
                    await _stage_again(sha256)
                    await _release_queue_lease(key)
                    await _sync_sha256_indexes(sha256)
                    continue
            except ValueError:
                pass

        await query_virustotal(sha256, api_key=api_key, retry_429=retry_429)
        await asyncio.sleep(sleep_seconds)


async def main() -> None:
    await worker_loop()


if __name__ == "__main__":
    asyncio.run(main())