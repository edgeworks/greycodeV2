import asyncio
import logging
import os
import signal

import redis.asyncio as redis

from greycode_core.index_sync import (
    sync_sha256_indexes,
    sync_ip_indexes,
    sync_domain_indexes,
    sync_computer_indexes,
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("greycode.dirty_index_worker")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

INDEX_DIRTY_SHA256_SET = "greycode:index_dirty:sha256"
INDEX_DIRTY_IP_SET = "greycode:index_dirty:ip"
INDEX_DIRTY_DOMAIN_SET = "greycode:index_dirty:domain"
INDEX_DIRTY_COMPUTER_SET = "greycode:index_dirty:computer"

BATCH_SIZE = int(os.getenv("DIRTY_INDEX_BATCH_SIZE", "200"))
IDLE_SLEEP_SEC = float(os.getenv("DIRTY_INDEX_IDLE_SLEEP_SEC", "2"))
BUSY_SLEEP_SEC = float(os.getenv("DIRTY_INDEX_BUSY_SLEEP_SEC", "0.2"))
RARE_COMPUTER_THRESHOLD = int(os.getenv("GREYCODE_RARE_COMPUTER_THRESHOLD", "10"))

stop_event = asyncio.Event()


def _handle_signal(signum, frame):
    logger.warning("received signal=%s, shutting down", signum)
    stop_event.set()


async def drain_dirty_set(r: redis.Redis, set_key: str, kind: str, batch_size: int) -> int:
    pipe = r.pipeline()
    for _ in range(batch_size):
        pipe.spop(set_key)
    raw = await pipe.execute()

    indicators = [x for x in raw if x]
    if not indicators:
        return 0

    processed = 0

    for indicator in indicators:
        try:
            if kind == "sha256":
                await sync_sha256_indexes(r, indicator)
            elif kind == "ip":
                await sync_ip_indexes(r, indicator)
            elif kind == "domain":
                await sync_domain_indexes(r, indicator)
            elif kind == "computer":
                await sync_computer_indexes(
                    r,
                    indicator,
                    rare_threshold=RARE_COMPUTER_THRESHOLD,
                )
            else:
                logger.error("unknown kind=%s indicator=%s", kind, indicator)
                continue

            processed += 1

        except Exception:
            logger.exception("sync failed kind=%s indicator=%s", kind, indicator)
            await r.sadd(set_key, indicator)

    return processed


async def main():
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    logger.warning(
        "dirty-index-worker started redis=%s:%s batch_size=%d rare_threshold=%d idle_sleep=%.2f busy_sleep=%.2f",
        REDIS_HOST,
        REDIS_PORT,
        BATCH_SIZE,
        RARE_COMPUTER_THRESHOLD,
        IDLE_SLEEP_SEC,
        BUSY_SLEEP_SEC,
    )

    try:
        while not stop_event.is_set():
            ip_done = await drain_dirty_set(r, INDEX_DIRTY_IP_SET, "ip", BATCH_SIZE)
            domain_done = await drain_dirty_set(r, INDEX_DIRTY_DOMAIN_SET, "domain", BATCH_SIZE)
            sha_done = await drain_dirty_set(r, INDEX_DIRTY_SHA256_SET, "sha256", BATCH_SIZE)
            computer_done = await drain_dirty_set(r, INDEX_DIRTY_COMPUTER_SET, "computer", BATCH_SIZE)

            total = ip_done + domain_done + sha_done + computer_done

            if total > 0:
                logger.warning(
                    "dirty-index-worker processed total=%d ip=%d domain=%d sha256=%d computer=%d",
                    total,
                    ip_done,
                    domain_done,
                    sha_done,
                    computer_done,
                )
                await asyncio.sleep(BUSY_SLEEP_SEC)
            else:
                await asyncio.sleep(IDLE_SLEEP_SEC)
    finally:
        await r.aclose()
        logger.warning("dirty-index-worker stopped")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    asyncio.run(main())