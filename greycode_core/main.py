from fastapi import FastAPI
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi import Query
from pathlib import Path
from pydantic import BaseModel, ValidationError
import redis.asyncio as redis
import uuid
import datetime
import json
import os
from typing import Optional



app = FastAPI(title="Greycode API")
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

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
async def ui_index(
    request: Request,
    status: str = Query("ALL"),
    q: str = Query(""),
    sort: str = Query("last_seen"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=10, le=2000),
):
    # 1) Pull keys
    rows = []
    cursor = 0
    pattern = "greycode:sha256:*"
    q_lower = q.strip().lower()
    total_hashes = 0

    while True:
        cursor, keys = await r.scan(cursor=cursor, match=pattern, count=500)
        for key in keys:
            total_hashes += 1
            sha = key.split(":")[-1]
            data = await r.hgetall(key)

            row = {
                "sha256": sha,
                "status": (data.get("status") or "GREY").upper(),
                "vt_malicious": int(data.get("vt_malicious") or 0),
                "computer": data.get("computer") or "",
                "image": data.get("image") or "",
                "count_total": int(data.get("count_total") or 0),
                "first_seen": data.get("first_seen") or "",
                "last_seen": data.get("last_seen") or "",
                "source": data.get("source") or "",
            }

            # 2) Apply filters
            if status != "ALL" and row["status"] != status:
                continue

            if q_lower:
                hay = f'{row["sha256"]} {row["computer"]} {row["image"]}'.lower()
                if q_lower not in hay:
                    continue

            rows.append(row)

        if cursor == 0:
            break

    # 3) Sort
    reverse = (order.lower() != "asc")

    if sort == "count_total":
        rows.sort(key=lambda x: x["count_total"], reverse=reverse)
    elif sort == "status":
        # Custom status ordering (RED first is usually helpful)
        rank = {"RED": 0, "ERROR": 1, "GREY": 2, "GREEN": 3}
        rows.sort(key=lambda x: (rank.get(x["status"], 99), x["last_seen"]), reverse=False)
        if reverse:
            rows.reverse()
    else:
        # default: last_seen
        rows.sort(key=lambda x: x["last_seen"], reverse=reverse)

    # 4) Pagination
    total = len(rows)
    start = (page - 1) * page_size
    end = start + page_size
    page_rows = rows[start:end]

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "rows": page_rows,
            "total": total,
            "total_hashes": total_hashes,
            "page": page,
            "page_size": page_size,
            "status": status,
            "q": q,
            "sort": sort,
            "order": order,
            "vt_enabled": vt_enabled(),
            # if you already have metrics:
            **(await get_ui_metrics()),
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