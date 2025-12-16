from fastapi import FastAPI
from pydantic import BaseModel
import redis.asyncio as redis
import uuid
import datetime
from typing import Optional
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi import Request


templates = Jinja2Templates(directory="templates")

app = FastAPI(title="Greycode API")

r = redis.Redis(host="redis", port=6379, decode_responses=True)


class ProcessEvent(BaseModel):
    sha256: str
    computer: str
    image: str


@app.post("/enrich/process")
async def enrich_process(event: ProcessEvent):
    key = f"greycode:sha256:{event.sha256}"
    rep = await r.hgetall(key)

    if rep:
        return {
            "sha256": event.sha256,
            "status": rep.get("status"),
            "source": rep.get("source"),
            "computer": rep.get("computer"),
            "image": rep.get("image"),
        }

    await r.hset(
        key,
        mapping={
            "status": "GREY",
            "source": "pending",
            "first_seen": datetime.datetime.utcnow().isoformat(),
            "computer": event.computer,
            "image": event.image,
            "uuid": str(uuid.uuid4()),
        },
    )

    await r.lpush("greycode:queue:vt", event.sha256)

    return {
        "sha256": event.sha256,
        "status": "GREY",
        "source": "pending",
        "computer": event.computer,
        "image": event.image,
    }


@app.get("/status/{sha256}")
async def get_status(sha256: str):
    """
    Return the current status for a specific SHA-256 hash.
    """
    key = f"greycode:sha256:{sha256}"
    rep = await r.hgetall(key)

    if not rep:
        return {
            "sha256": sha256,
            "status": "UNKNOWN",
        }

    return {
        "sha256": sha256,
        **rep,
    }


@app.get("/hashes")
async def list_hashes(
    status: Optional[str] = None,
    limit: int = 100,
):
    """
    List known hashes.
    Optional filters:
      - status=GREY|GREEN|RED|ERROR
      - limit (default 100)
    """
    keys = await r.keys("greycode:sha256:*")
    results = []

    for key in keys:
        if len(results) >= limit:
            break

        rep = await r.hgetall(key)
        if status and rep.get("status") != status:
            continue

        results.append(
            {
                "sha256": key.split(":")[-1],
                **rep,
            }
        )

    return {
        "count": len(results),
        "results": results,
    }


@app.get("/ui", response_class=HTMLResponse)
async def ui_index(request: Request):
    keys = await r.keys("greycode:sha256:*")
    rows = []

    for key in keys:
        data = await r.hgetall(key)
        rows.append({
            "sha256": key.split(":")[-1],
            "status": data.get("status"),
            "computer": data.get("computer"),
            "image": data.get("image"),
        })

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "rows": rows},
    )


@app.get("/ui/hash/{sha256}", response_class=HTMLResponse)
async def ui_hash_detail(request: Request, sha256: str):
    key = f"greycode:sha256:{sha256}"
    data = await r.hgetall(key)

    if not data:
        return HTMLResponse("<h1>Hash not found</h1>", status_code=404)

    return templates.TemplateResponse(
        "hash_detail.html",
        {"request": request, "sha256": sha256, "data": data},
    )