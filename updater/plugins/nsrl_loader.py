# updater/plugins/nsrl_loader.py

import redis.asyncio as redis

# Dummy implementation — replace with real NSRL parser
NSRL_HASHES = [
    "d2d2d2...", "a1b2c3...", "deadbeef..."
]

async def update():
    r = redis.Redis(host="redis", port=6379, decode_responses=True)
    for sha256 in NSRL_HASHES:
        await r.hset(f"greycode:sha256:{sha256}", mapping={
            "status": "GREEN",
            "source": "nsrl"
        })
    print("[NSRL] Updated hashes.")
