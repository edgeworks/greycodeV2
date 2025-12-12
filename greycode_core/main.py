# greycode_core/main.py

from fastapi import FastAPI
from pydantic import BaseModel
import redis.asyncio as redis
import uuid
import datetime

app = FastAPI()
r = redis.Redis(host="redis", port=6379, decode_responses=True)

class ProcessEvent(BaseModel):
    sha256: str
    user: str

@app.post("/enrich/process")
async def enrich_process(event: ProcessEvent):
    key = f"greycode:sha256:{event.sha256}"
    rep = await r.hgetall(key)

    if rep:
        return {"status": rep.get("status"), "source": rep.get("source")}

    await r.hset(key, mapping={
        "status": "GREY",
        "source": "pending",
        "first_seen": str(datetime.datetime.utcnow()),
        "uuid": str(uuid.uuid4())
    })

    await r.lpush("greycode:queue:vt", event.sha256)

    return {"status": "GREY", "source": "pending"}
