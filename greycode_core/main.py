from hashlib import sha256
from fastapi import FastAPI
from fastapi import Path as ApiPath
from fastapi import Depends
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi import Query
from fastapi import Form
from pathlib import Path
from pydantic import BaseModel, ValidationError
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
import secrets
import redis.asyncio as redis
import uuid
import datetime
import ipaddress
import json
import os
import time
from typing import Optional



app = FastAPI(title="Greycode API")
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.mount("/site", StaticFiles(directory=str(BASE_DIR / "static_site")), name="site")
r = redis.Redis(host="redis", port=6379, decode_responses=True)
templates = Jinja2Templates(directory="templates")
STAGED_SET = "greycode:staged:vt_candidates"
VT_QUEUE = "greycode:queue:vt"
STAGED_SET_IP = "greycode:staged:ip_candidates"
STAGED_SET_DOMAIN = "greycode:staged:domain_candidates"

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("GREYCODE_SESSION_SECRET", ""),
    https_only=True,
    same_site="lax",
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

UI_USER = os.getenv("GREYCODE_UI_USER", "greycode")
UI_PASS_HASH = os.getenv("GREYCODE_UI_PASS_HASH", "")

def require_login(request: Request):
    if request.session.get("logged_in") is True:
        return True
    # Redirect to login page
    raise HTTPException(status_code=303, headers={"Location": "/login"})

async def get_ui_metrics():
    vt_queue_len = await r.llen(VT_QUEUE)
    staged_candidates = await r.scard(STAGED_SET)
    return {
        "vt_queue_len": vt_queue_len,
        "staged_candidates": staged_candidates
    }

def vt_enabled() -> bool:
    return os.getenv("VT_ENABLED", "0") == "1"

class ProcessEvent(BaseModel):
    # Sysmon ID 1 fields (Cribl passes sha256, Computer, Image)
    sha256: str
    computer: str
    image: str

class NetworkEvent(BaseModel):
    # Sysmon ID 3 fields (Cribl passes DestinationIp, Computer)
    DestinationIp: str
    Computer: str

class DnsEvent(BaseModel):
    # Sysmon ID 22 fields (Cribl passes QueryName, Computer)
    QueryName: str
    Computer: str

def normalize_ip(ip: str) -> str:
    """
    Canonicalize IPv4/IPv6 for keying:
      - IPv4 stays dotted-decimal
      - IPv6 becomes compressed lowercase
    Raises ValueError on invalid input.
    """
    ip = (ip or "").strip()
    if not ip:
        raise ValueError("empty ip")
    return str(ipaddress.ip_address(ip))

def normalize_domain(qname: str) -> str:
    """
    Normalize DNS query name:
      - lowercase
      - strip whitespace
      - strip trailing dot
    """
    d = (qname or "").strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d

def fmt_epoch(ts: Optional[str]) -> str:
    if not ts:
        return "-"
    try:
        f = float(ts)
    except (ValueError, TypeError):
        return "-"
    return datetime.datetime.utcfromtimestamp(f).strftime("%Y-%m-%d %H:%M:%S UTC")

def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()

async def recheck_vt_stage(sha256: str) -> None:
    """
    Recheck via staging (never directly queue) to avoid immediate VT storms.
    Clears VT-related fields that would block processing.
    """
    key = f"greycode:sha256:{sha256}"

    # Reset VT state so it is eligible again
    await r.hset(
        key,
        mapping={
            "status": "GREY",
            "source": "manual_recheck",
            "vt_state": "PENDING",
            "vt_http_status": "",
            "vt_next_retry_at": "",
            "vt_last_checked": "",
            "vt_malicious": "",
            "vt_suspicious": "",
            "manual_last_action": now_iso(),
        },
    )

    # Stage for later processing
    await r.sadd(STAGED_SET, sha256)

    # If it happens to be in the queue, remove it to avoid duplicates
    await r.lrem(VT_QUEUE, 0, sha256)

async def delete_hash_everywhere(sha256: str) -> None:
    """
    Deletes the hash record and removes it from staging/queue.
    """
    key = f"greycode:sha256:{sha256}"
    await r.delete(key)
    await r.srem(STAGED_SET, sha256)
    await r.lrem(VT_QUEUE, 0, sha256)

async def set_disposition(sha256: str, disposition: str, ticket_id: str = "", note: str = "", actor: str = "ui") -> None:
    key = f"greycode:sha256:{sha256}"
    mapping = {
        "disposition": disposition,
        "disposition_at": now_iso(),
        "disposition_by": actor,
        "disposition_note": note or "",
        "ticket_id": ticket_id or "",
    }
    await r.hset(key, mapping=mapping)

async def clear_disposition(sha256: str, actor: str = "ui") -> None:
    key = f"greycode:sha256:{sha256}"
    await r.hset(
        key,
        mapping={
            "disposition": "",
            "disposition_at": "",
            "disposition_by": actor,
            "disposition_note": "",
            "ticket_id": "",
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, err: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "err": err})


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not os.getenv("GREYCODE_SESSION_SECRET"):
        return JSONResponse({"detail": "GREYCODE_SESSION_SECRET not set"}, status_code=503)
    if not UI_PASS_HASH:
        return JSONResponse({"detail": "GREYCODE_UI_PASS_HASH not set"}, status_code=503)

    user_ok = secrets.compare_digest((username or "").strip(), UI_USER)
    pass_ok = pwd_context.verify(password or "", UI_PASS_HASH)

    if not (user_ok and pass_ok):
        return RedirectResponse(url="/login?err=1", status_code=303)

    request.session["logged_in"] = True
    request.session["user"] = UI_USER
    return RedirectResponse(url="/", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
async def portal(request: Request, _auth=Depends(require_login)):
    return templates.TemplateResponse("portal.html", {"request": request})


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
            "vt_state": "PENDING",
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
        await r.lpush(VT_QUEUE, event.sha256)

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
                    "vt_state": "PENDING",
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
            await r.lpush(VT_QUEUE, event.sha256)

        accepted += 1

    return JSONResponse(
        {
            "received": len(events),
            "accepted": accepted,
            "rejected": rejected,
            "errors": errors[:20],  # cap error list for safety
        }
    )

@app.post("/enrich/network")
async def enrich_network(event: NetworkEvent):
    """
    Sysmon ID 3 minimal ingest:
      - Computer
      - DestinationIp (IPv4/IPv6)
    """
    try:
        ip_norm = normalize_ip(event.DestinationIp)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid DestinationIp")

    key = f"greycode:ip:{ip_norm}"
    rep = await r.hgetall(key)
    now = datetime.datetime.utcnow().isoformat()

    if rep:
        await r.hincrby(key, "count_total", 1)
        await r.hset(key, mapping={"last_seen": now, "computer_last": event.Computer})
        return {
            "destination_ip": ip_norm,
            "status": rep.get("status"),
            "listing_state": rep.get("listing_state"),
            "source": rep.get("source"),
            "computer_last": event.Computer,
        }

    # New record: GREY + PENDING, stage for later blacklist checking
    await r.hset(
        key,
        mapping={
            "type": "ip",
            "status": "GREY",
            "listing_state": "PENDING",
            "source": "pending",
            "first_seen": now,
            "last_seen": now,
            "computer_first": event.Computer,
            "computer_last": event.Computer,
            "count_total": "1",
            "uuid": str(uuid.uuid4()),
        },
    )
    await r.sadd(STAGED_SET_IP, ip_norm)

    return {
        "destination_ip": ip_norm,
        "status": "GREY",
        "listing_state": "PENDING",
        "source": "pending",
        "computer_first": event.Computer,
    }


@app.post("/enrich/network/bulk")
async def enrich_network_bulk(request: Request):
    """
    Bulk Sysmon ID 3 ingest.
    Accept either:
      - application/x-ndjson (one JSON object per line)
      - application/json with a JSON array: [ {...}, {...} ]
      - application/json with a single object
    Expected fields per event (Cribl style):
      - Computer
      - DestinationIp
    """
    ctype = (request.headers.get("content-type") or "").lower()
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace").strip()

    if not body_text:
        raise HTTPException(status_code=400, detail="Empty request body")

    events = []
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
            event = NetworkEvent.model_validate(obj)  # Pydantic v2
        except ValidationError as e:
            rejected += 1
            errors.append({"index": idx, "error": e.errors()})
            continue

        try:
            ip_norm = normalize_ip(event.DestinationIp)
        except ValueError:
            rejected += 1
            errors.append({"index": idx, "error": "Invalid DestinationIp"})
            continue

        key = f"greycode:ip:{ip_norm}"
        rep = await r.hgetall(key)
        now = datetime.datetime.utcnow().isoformat()

        if rep:
            await r.hincrby(key, "count_total", 1)
            await r.hset(key, mapping={"last_seen": now, "computer_last": event.Computer})
        else:
            await r.hset(
                key,
                mapping={
                    "type": "ip",
                    "status": "GREY",
                    "listing_state": "PENDING",
                    "source": "pending",
                    "first_seen": now,
                    "last_seen": now,
                    "computer_first": event.Computer,
                    "computer_last": event.Computer,
                    "count_total": "1",
                    "uuid": str(uuid.uuid4()),
                },
            )
            await r.sadd(STAGED_SET_IP, ip_norm)

        accepted += 1

    return JSONResponse(
        {
            "received": len(events),
            "accepted": accepted,
            "rejected": rejected,
            "errors": errors[:20],
        }
    )

@app.post("/enrich/dns")
async def enrich_dns(event: DnsEvent):
    """
    Sysmon ID 22 minimal ingest:
      - Computer
      - QueryName (domain/hostname)
    """
    domain_norm = normalize_domain(event.QueryName)
    if not domain_norm:
        raise HTTPException(status_code=400, detail="Invalid QueryName")

    key = f"greycode:domain:{domain_norm}"
    rep = await r.hgetall(key)
    now = datetime.datetime.utcnow().isoformat()

    if rep:
        await r.hincrby(key, "count_total", 1)
        await r.hset(key, mapping={"last_seen": now, "computer_last": event.Computer})
        return {
            "query_name": domain_norm,
            "status": rep.get("status"),
            "listing_state": rep.get("listing_state"),
            "source": rep.get("source"),
            "computer_last": event.Computer,
        }

    await r.hset(
        key,
        mapping={
            "type": "domain",
            "status": "GREY",
            "listing_state": "PENDING",
            "source": "pending",
            "first_seen": now,
            "last_seen": now,
            "computer_first": event.Computer,
            "computer_last": event.Computer,
            "count_total": "1",
            "uuid": str(uuid.uuid4()),
        },
    )
    await r.sadd(STAGED_SET_DOMAIN, domain_norm)

    return {
        "query_name": domain_norm,
        "status": "GREY",
        "listing_state": "PENDING",
        "source": "pending",
        "computer_first": event.Computer,
    }


@app.post("/enrich/dns/bulk")
async def enrich_dns_bulk(request: Request):
    """
    Bulk Sysmon ID 22 ingest.
    Accept either:
      - application/x-ndjson (one JSON object per line)
      - application/json with a JSON array: [ {...}, {...} ]
      - application/json with a single object
    Expected fields per event (Cribl style):
      - Computer
      - QueryName
    """
    ctype = (request.headers.get("content-type") or "").lower()
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace").strip()

    if not body_text:
        raise HTTPException(status_code=400, detail="Empty request body")

    events = []
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
            event = DnsEvent.model_validate(obj)  # Pydantic v2
        except ValidationError as e:
            rejected += 1
            errors.append({"index": idx, "error": e.errors()})
            continue

        domain_norm = normalize_domain(event.QueryName)
        if not domain_norm:
            rejected += 1
            errors.append({"index": idx, "error": "Invalid QueryName"})
            continue

        key = f"greycode:domain:{domain_norm}"
        rep = await r.hgetall(key)
        now = datetime.datetime.utcnow().isoformat()

        if rep:
            await r.hincrby(key, "count_total", 1)
            await r.hset(key, mapping={"last_seen": now, "computer_last": event.Computer})
        else:
            await r.hset(
                key,
                mapping={
                    "type": "domain",
                    "status": "GREY",
                    "listing_state": "PENDING",
                    "source": "pending",
                    "first_seen": now,
                    "last_seen": now,
                    "computer_first": event.Computer,
                    "computer_last": event.Computer,
                    "count_total": "1",
                    "uuid": str(uuid.uuid4()),
                },
            )
            await r.sadd(STAGED_SET_DOMAIN, domain_norm)

        accepted += 1

    return JSONResponse(
        {
            "received": len(events),
            "accepted": accepted,
            "rejected": rejected,
            "errors": errors[:20],
        }
    )

@app.post("/ui/hash/{sha256}/accept")
async def ui_hash_accept(sha256: str, _auth=Depends(require_login)):
    await set_disposition(sha256, "ACCEPTED", actor="ui")
    return RedirectResponse(url=f"/ui/hash/{sha256}", status_code=303)

@app.post("/ui/hash/{sha256}/escalate")
async def ui_hash_escalate(sha256: str, ticket_id: str = Form(...), _auth=Depends(require_login)):
    ticket_id = (ticket_id or "").strip()
    if not ticket_id:
        # Redirect back if no ticket_id provided
        return RedirectResponse(url=f"/ui/hash/{sha256}", status_code=303)

    await set_disposition(sha256, "ESCALATED", ticket_id=ticket_id, actor="ui")
    return RedirectResponse(url=f"/ui/hash/{sha256}", status_code=303)

@app.post("/ui/hash/{sha256}/clear")
async def ui_hash_clear(sha256: str, _auth=Depends(require_login)):
    await clear_disposition(sha256, actor="ui")
    return RedirectResponse(url=f"/ui/hash/{sha256}", status_code=303)

@app.post("/ui/hash/{sha256}/recheck")
async def ui_hash_recheck(sha256: str, _auth=Depends(require_login)):
    await recheck_vt_stage(sha256)
    return RedirectResponse(url=f"/ui/hash/{sha256}", status_code=303)

@app.post("/ui/hash/{sha256}/delete")
async def ui_hash_delete(sha256: str, _auth=Depends(require_login)):
    await delete_hash_everywhere(sha256)
    return RedirectResponse(url="/ui", status_code=303)

@app.post("/ui/bulk_action")
async def ui_bulk_action(
    action: str = Form(...),
    selected: list[str] = Form(default=[]),
    ticket_id: str = Form(default=""),
    _auth=Depends(require_login),
):
    action = (action or "").strip().lower()
    ticket_id = (ticket_id or "").strip()
    hashes = [h.strip() for h in selected if h and h.strip()]

    if not hashes:
        return RedirectResponse(url="/ui", status_code=303)

    if action == "accept":
        for h in hashes:
            await set_disposition(h, "ACCEPTED", actor="ui")
        return RedirectResponse(url="/ui", status_code=303)

    if action == "escalate":
        if not ticket_id:
            # No ticket provided; do nothing for now
            return RedirectResponse(url="/ui", status_code=303)
        for h in hashes:
            await set_disposition(h, "ESCALATED", ticket_id=ticket_id, actor="ui")
        return RedirectResponse(url="/ui", status_code=303)

    if action == "clear":
        for h in hashes:
            await clear_disposition(h, actor="ui")
        return RedirectResponse(url="/ui", status_code=303)

    if action == "recheck":
        for h in hashes:
            await recheck_vt_stage(h)
        return RedirectResponse(url="/ui", status_code=303)

    if action == "delete":
        # Confirmation is enforced in the UI via confirm(), but server-side is still OK.
        for h in hashes:
            await delete_hash_everywhere(h)
        return RedirectResponse(url="/ui", status_code=303)

    return RedirectResponse(url="/ui", status_code=303)



@app.get("/status/{sha256}")
async def get_status(sha256: str, _auth=Depends(require_login)):
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

@app.get("/status/ip/{ip}")
async def get_status_ip(ip: str, _auth=Depends(require_login)):
    try:
        ip_norm = normalize_ip(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP")

    key = f"greycode:ip:{ip_norm}"
    rep = await r.hgetall(key)
    if not rep:
        return {"ip": ip_norm, "status": "UNKNOWN"}
    return {"ip": ip_norm, **rep}


@app.get("/status/domain/{domain}")
async def get_status_domain(domain: str, _auth=Depends(require_login)):
    dom = normalize_domain(domain)
    if not dom:
        raise HTTPException(status_code=400, detail="Invalid domain")

    key = f"greycode:domain:{dom}"
    rep = await r.hgetall(key)
    if not rep:
        return {"domain": dom, "status": "UNKNOWN"}
    return {"domain": dom, **rep}

@app.get("/hashes")
async def list_hashes(
    status: Optional[str] = None,
    limit: int = 100,
    _auth=Depends(require_login),
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

# ToDo: Replace or remove when other tabs are finished
async def ui_redirect():
    return RedirectResponse(url="/ui/sysmon/1", status_code=302)

async def ui_index(
    request: Request,
    status: str = Query("ALL"),
    triage: str = Query("ALL"),
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
                "vt_state": (data.get("vt_state") or "").upper(),
                "vt_malicious": int(data.get("vt_malicious") or 0),
                "disposition": (data.get("disposition") or "").upper(),
                "ticket_id": data.get("ticket_id") or "",
                "computer": data.get("computer") or "",
                "image": data.get("image") or "",
                "count_total": int(data.get("count_total") or 0),
                "first_seen": data.get("first_seen") or "",
                "last_seen": data.get("last_seen") or "",
                "source": data.get("source") or "",
                "vt_link": f"https://www.virustotal.com/gui/file/{sha}",
            }

            # 2) Apply filters
            if status != "ALL" and row["status"] != status:
                continue

            tri = (triage or "ALL").upper()
            if tri == "OPEN":
                # Open work queue: RED and no disposition
                if not (row["status"] == "RED" and row["disposition"] == ""):
                    continue
            elif tri == "TRIAGED":
                # Any disposition set (ACCEPTED/ESCALATED/whatever)
                if row["disposition"] == "":
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
    elif sort == "vt_state":
        rows.sort(key=lambda x: (x.get("vt_state") or "", x.get("last_seen") or ""), reverse=reverse)
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
            "triage": triage,
            "q": q,
            "sort": sort,
            "order": order,
            "vt_enabled": vt_enabled(),
            **(await get_ui_metrics()),
        },
    )

@app.get("/ui/sysmon/{event_id}", response_class=HTMLResponse)
async def ui_sysmon(
    request: Request,
    event_id: int = ApiPath(..., ge=1),
    # Common controls
    status: str = Query("ALL"),
    q: str = Query(""),
    sort: str = Query("last_seen"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=10, le=2000),

    # Sysmon 1 specific
    triage: str = Query("ALL"),  # ALL | OPEN | TRIAGED (only used for event_id=1)

    # Sysmon 3/22 specific
    listing_state: str = Query("ALL"),  # ALL | PENDING | NO_LISTING | LISTED (only used for 3/22)
    _auth=Depends(require_login),
):
    tab = int(event_id)

    # Map tab -> redis key pattern + primary field name
    if tab == 1:
        pattern = "greycode:sha256:*"
        indicator_label = "SHA256"
        indicator_field = "sha256"
        kind = "sha256"
        allowed_status = {"ALL", "RED", "ERROR", "GREY", "GREEN"}
    elif tab == 3:
        pattern = "greycode:ip:*"
        indicator_label = "DestinationIp"
        indicator_field = "ip"
        kind = "ip"
        allowed_status = {"ALL", "RED", "ERROR", "GREY"}
    elif tab == 22:
        pattern = "greycode:domain:*"
        indicator_label = "QueryName"
        indicator_field = "domain"
        kind = "domain"
        allowed_status = {"ALL", "RED", "ERROR", "GREY"}
    else:
        raise HTTPException(status_code=404, detail="Unknown Sysmon tab")

    status = (status or "ALL").upper()
    if status not in allowed_status:
        status = "ALL"

    q_lower = (q or "").strip().lower()

    rows = []
    cursor = 0
    total_seen = 0

    while True:
        cursor, keys = await r.scan(cursor=cursor, match=pattern, count=500)
        for key in keys:
            total_seen += 1
            data = await r.hgetall(key)

            # indicator value extracted from redis key
            indicator = key.split(":", 2)[-1]  # works for sha256/ip/domain patterns

            row = {
                "kind": kind,
                indicator_field: indicator,
                "status": (data.get("status") or "GREY").upper(),
                "listing_state": (data.get("listing_state") or "").upper(),
                "vt_state": (data.get("vt_state") or "").upper(),
                "vt_malicious": int(data.get("vt_malicious") or 0),
                "disposition": (data.get("disposition") or "").upper(),
                "ticket_id": data.get("ticket_id") or "",
                "count_total": int(data.get("count_total") or 0),
                "first_seen": data.get("first_seen") or "",
                "last_seen": data.get("last_seen") or "",
                "source": data.get("source") or "",
                # context fields differ by kind
                "computer": data.get("computer") or "",
                "computer_first": data.get("computer_first") or "",
                "computer_last": data.get("computer_last") or "",
                "image": data.get("image") or "",
                # links
                "vt_link": f"https://www.virustotal.com/gui/file/{indicator}" if tab == 1 else "",
            }

            # Filters
            if status != "ALL" and row["status"] != status:
                continue

            if tab == 1:
                tri = (triage or "ALL").upper()
                if tri == "OPEN":
                    if not (row["status"] == "RED" and row["disposition"] == ""):
                        continue
                elif tri == "TRIAGED":
                    if row["disposition"] == "":
                        continue

            if tab in (3, 22):
                ls = (listing_state or "ALL").upper()
                if ls != "ALL":
                    if row["listing_state"] != ls:
                        continue

            if q_lower:
                # search across relevant fields
                if tab == 1:
                    hay = f'{row.get("sha256","")} {row.get("computer","")} {row.get("image","")}'.lower()
                elif tab == 3:
                    hay = f'{row.get("ip","")} {row.get("computer_first","")} {row.get("computer_last","")}'.lower()
                else:
                    hay = f'{row.get("domain","")} {row.get("computer_first","")} {row.get("computer_last","")}'.lower()

                if q_lower not in hay:
                    continue

            rows.append(row)

        if cursor == 0:
            break

    # Sorting
    reverse = (order.lower() != "asc")

    if sort == "count_total":
        rows.sort(key=lambda x: x["count_total"], reverse=reverse)
    elif sort == "status":
        rank = {"RED": 0, "ERROR": 1, "GREY": 2, "GREEN": 3}
        rows.sort(key=lambda x: (rank.get(x["status"], 99), x.get("last_seen") or ""), reverse=False)
        if reverse:
            rows.reverse()
    elif sort == "listing_state":
        rows.sort(key=lambda x: (x.get("listing_state") or "", x.get("last_seen") or ""), reverse=reverse)
    elif sort == "vt_state":
        rows.sort(key=lambda x: (x.get("vt_state") or "", x.get("last_seen") or ""), reverse=reverse)
    else:
        rows.sort(key=lambda x: x.get("last_seen") or "", reverse=reverse)

    # Pagination
    total = len(rows)
    start = (page - 1) * page_size
    end = start + page_size
    page_rows = rows[start:end]

    return templates.TemplateResponse(
        "index_sysmon.html",
        {
            "request": request,
            "tab": tab,
            "rows": page_rows,
            "total": total,
            "page": page,
            "page_size": page_size,

            "status": status,
            "q": q,
            "sort": sort,
            "order": order,

            "triage": triage,
            "listing_state": listing_state,

            "indicator_label": indicator_label,
            "indicator_field": indicator_field,

            "vt_enabled": vt_enabled(),
            **(await get_ui_metrics()),
        },
    )



@app.get("/ui/hash/{sha256}", response_class=HTMLResponse)
async def ui_hash_detail(request: Request, sha256: str, _auth=Depends(require_login)):
    key = f"greycode:sha256:{sha256}"
    data = await r.hgetall(key)
    data["vt_last_checked_fmt"] = fmt_epoch(data.get("vt_last_checked"))
    data["vt_next_retry_at_fmt"] = fmt_epoch(data.get("vt_next_retry_at"))
    data["vt_link"] = f"https://www.virustotal.com/gui/file/{sha256}"
    metrics = await get_ui_metrics()

    if not data:
        return HTMLResponse("<h1>Hash not found</h1>", status_code=404)

    return templates.TemplateResponse(
        "hash_detail.html",
        {
            "request": request, 
            "sha256": sha256, 
            "data": data,
            "vt_enabled": vt_enabled(), 
            **(await get_ui_metrics()),
        },
    )