from fastapi import FastAPI
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ValidationError
import redis.asyncio as redis
import uuid
import datetime
import json
import os
from typing import Optional



app = FastAPI(title="Greycode API")

r = redis.Redis(host="redis", port=6379, decode_responses=True)

templates = Jinja2Templates(directory="templates")

async def get_ui_metrics():
    vt_queue_len = await r.llen("greycode:queue:vt")
    staged_candidates = await r.scard("greycode:staged:vt_candidates")
    return {
        "vt_queue_len": vt_queue_len,
        "staged_candidates": staged_candidates
    }

def vt_enabled() -> bool:
    return os.getenv("VT_ENABLED", "0") == "1"

class ProcessEvent(BaseModel):
    sha256: str
    computer: str
    image: str


@app.post("/enrich/process")
async def enrich_process(event: ProcessEvent):
    key = f"greycode:sha256:{event.sha256}"
    rep = await r.hgetall(key)
    now = datetime.datetime.utcnow().isoformat()

    if rep:
        await r.hincrby(key, "count_total", 1)
        await r.hset(key, mapping={"last_seen": now})
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
            "first_seen": now,
            "last_seen": now,
            "computer": event.computer,
            "image": event.image,
            "count_total": "1",
            "uuid": str(uuid.uuid4()),
        },
    )

    if vt_enabled():
        await r.lpush("greycode:queue:vt", event.sha256)

    return {
        "sha256": event.sha256,
        "status": "GREY",
        "source": "pending",
        "computer": event.computer,
        "image": event.image,
    }

@app.post("/enrich/process/bulk")
async def enrich_process_bulk(request: Request):
    """
    Accept either:
      - application/x-ndjson (one JSON object per line)
      - application/json with a JSON array: [ {...}, {...} ]
      - application/json with a single object (also accepted)
    """
    ctype = (request.headers.get("content-type") or "").lower()
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace").strip()

    if not body_text:
        raise HTTPException(status_code=400, detail="Empty request body")

    events = []

    # NDJSON: one JSON object per line
    if "application/x-ndjson" in ctype:
        for line in body_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid NDJSON line: {e}")

    else:
        # application/json: could be object or array
        try:
            parsed = json.loads(body_text)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

        if isinstance(parsed, list):
            events = parsed
        elif isinstance(parsed, dict):
            events = [parsed]
        else:
            raise HTTPException(status_code=400, detail="JSON must be an object or an array of objects")

    accepted = 0
    rejected = 0
    errors = []

    for idx, obj in enumerate(events):
        try:
            event = ProcessEvent.model_validate(obj)  # Pydantic v2
        except ValidationError as e:
            rejected += 1
            errors.append({"index": idx, "error": e.errors()})
            continue

        # Reuse the same logic as /enrich/process
        key = f"greycode:sha256:{event.sha256}"
        rep = await r.hgetall(key)
        now = datetime.datetime.utcnow().isoformat()
        if rep:
            await r.hincrby(key, "count_total", 1)
            await r.hset(key, mapping={"last_seen": now})
        else:
            await r.hset(
                key,
                mapping={
                    "status": "GREY",
                    "source": "pending",
                    "first_seen": now,
                    "last_seen": now,
                    "computer": event.computer,
                    "image": event.image,
                    "count_total": "1",
                    "uuid": str(uuid.uuid4()),
                },
            )

        if vt_enabled() and not rep:
            await r.lpush("greycode:queue:vt", event.sha256)

        accepted += 1

    return JSONResponse(
        {
            "received": len(events),
            "accepted": accepted,
            "rejected": rejected,
            "errors": errors[:20],  # cap error list for safety
        }
    )

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
    total_hashes = len(keys)
    metrics = await get_ui_metrics()

    for key in keys:
        data = await r.hgetall(key)
        rows.append({
            "sha256": key.split(":")[-1],
            "status": data.get("status"),
            "computer": data.get("computer"),
            "image": data.get("image"),
            "count_total": int(data.get("count_total") or 0),
            "last_seen": data.get("last_seen"),
            "first_seen": data.get("first_seen"),
        })
        rows.sort(key=lambda x: x["count_total"])

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request, 
            "rows": rows, 
            "vt_enabled": vt_enabled(), 
            "total_hashes": total_hashes,
            **metrics
        },
    )


@app.get("/ui/hash/{sha256}", response_class=HTMLResponse)
async def ui_hash_detail(request: Request, sha256: str):
    key = f"greycode:sha256:{sha256}"
    data = await r.hgetall(key)
    metrics = await get_ui_metrics()

    if not data:
        return HTMLResponse("<h1>Hash not found</h1>", status_code=404)

    return templates.TemplateResponse(
        "hash_detail.html",
        {
            "request": request, 
            "sha256": sha256, 
            "data": data, 
            **metrics
        },
    )