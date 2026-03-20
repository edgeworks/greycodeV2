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
import math
from pydantic import BaseModel, ValidationError
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import quote
import secrets
import redis.asyncio as redis
import uuid
import datetime
import ipaddress
import json
import os
import time
import base64
import hashlib
import hmac
from typing import Optional, Any
from cryptography.fernet import Fernet, InvalidToken
from config_store import cfg_get_bool, cfg_get, cfg_set
from blacklist_engine import (
    Vendor, 
    save_vendors, 
    load_vendors,
    fetch_vendor, 
    check_indicator_hits, 
    update_indicator_record, 
    SET_IP_PREFIX, 
    SET_DOMAIN_PREFIX, 
    CIDR_IP_PREFIX, 
    DEFAULT_VENDORS,
)
from alerts import AlertRouter
from audit_store import audit_log, get_recent_audit
from user_store import (
    get_user,
    list_users,
    create_user,
    update_user_profile,
    update_user_theme,
    update_user_role,
    set_user_active,
    update_user_password_hash,
    set_last_login,
    ensure_bootstrap_admin,
    count_active_admins,
)
from indexes import (
    idx_z_last_seen,
    idx_z_count,
    idx_z_rare,
    idx_s_status,
    idx_s_listing,
    idx_s_triage,
    update_sha256_indexes,
    update_listing_indexes,
    remove_from_all_indexes,
)
from index_sync import (
    sync_sha256_indexes,
    sync_ip_indexes,
    sync_domain_indexes,
)

import faulthandler
import signal
import sys
import logging

faulthandler.register(signal.SIGUSR1, file=sys.stderr, all_threads=True)
logger = logging.getLogger("greycode.debug")


app = FastAPI(title="Greycode API")
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
r = redis.Redis(host="redis", port=6379, decode_responses=True)
templates = Jinja2Templates(directory="templates")
alert_router = AlertRouter()

STAGED_SET = "greycode:staged:vt_candidates"
VT_QUEUE = "greycode:queue:vt"
STAGED_SET_IP = "greycode:staged:ip_candidates"
STAGED_SET_DOMAIN = "greycode:staged:domain_candidates"
CFG_KEY = "greycode:cfg"
KNOWN_SHA256_SET = "greycode:known:sha256"
KNOWN_IPS_SET = "greycode:known:ips"
KNOWN_DOMAINS_SET = "greycode:known:domains"
INDEX_DIRTY_IP_SET = "greycode:index_dirty:ip"
INDEX_DIRTY_DOMAIN_SET = "greycode:index_dirty:domain"
INDEX_DIRTY_SHA256_SET = "greycode:index_dirty:sha256"


#DEBUG RELATED ------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    dur = (time.perf_counter() - start) * 1000
    logger.warning("path=%s status=%s dur_ms=%.1f", request.url.path, response.status_code, dur)
    return response
#-------------------



if not os.getenv("GREYCODE_SESSION_SECRET"):
    raise RuntimeError("GREYCODE_SESSION_SECRET must be set")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("GREYCODE_SESSION_SECRET", ""),
    https_only=True,
    same_site="lax",
)

UI_USER = os.getenv("GREYCODE_UI_USER", "greycode")
UI_PASS = os.getenv("GREYCODE_UI_PASS", "")

@app.on_event("startup")
async def startup_bootstrap() -> None:
    await ensure_bootstrap_admin(
        r,
        bootstrap_username=UI_USER,
        bootstrap_password_hash=UI_PASS,
        bootstrap_email="",
    )

def require_login(request: Request):
    if request.session.get("logged_in") is True:
        return True
    nxt = quote(str(request.url.path), safe="/?=&")
    raise HTTPException(status_code=303, headers={"Location": f"/login?next={nxt}"})

def current_username(request: Request) -> str:
    return (request.session.get("user") or "").strip().lower()

def pbkdf2_hash(password: str, *, iterations: int = 310_000, salt_bytes: int = 16) -> str:
    """
    Returns: pbkdf2_sha256$<iterations>$<salt_b64>$<dk_b64>
    """
    salt = secrets.token_bytes(salt_bytes)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(dk).decode("ascii").rstrip("="),
    )

def pbkdf2_verify(password: str, encoded: str) -> bool:
    try:
        scheme, it_s, salt_b64, dk_b64 = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(it_s)

        # restore padding
        def unb64(s: str) -> bytes:
            pad = "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s + pad)

        salt = unb64(salt_b64)
        dk_expected = unb64(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, dk_expected)
    except Exception:
        return False

def current_role(request: Request) -> str:
    return (request.session.get("role") or "user").strip().lower()


async def current_user_theme(request: Request) -> str:
    uname = current_username(request)
    if not uname:
        return "light"
    user = await get_user(r, uname)
    theme = (user.get("theme") or "light").strip().lower()
    return theme if theme in {"dark", "light"} else "light"


def require_admin(request: Request):
    role = current_role(request)
    if role == "admin":
        return True
    raise HTTPException(status_code=403, detail="Admin role required")


def require_triage(request: Request):
    role = current_role(request)
    if role in {"admin", "analyst"}:
        return True
    raise HTTPException(status_code=403, detail="Triage permission required")


def require_delete(request: Request):
    role = current_role(request)
    if role == "admin":
        return True
    raise HTTPException(status_code=403, detail="Delete permission required")


def can_manage_settings(request: Request) -> bool:
    return current_role(request) == "admin"


def can_manage_users(request: Request) -> bool:
    return current_role(request) == "admin"


def can_triage(request: Request) -> bool:
    return current_role(request) in {"admin", "analyst"}


def can_delete(request: Request) -> bool:
    return current_role(request) == "admin"



async def get_ui_metrics():
    vt_queue_len = await r.llen(VT_QUEUE)
    staged_candidates = await r.scard(STAGED_SET)
    return {
        "vt_queue_len": vt_queue_len,
        "staged_candidates": staged_candidates
    }

async def vt_enabled_setting() -> bool:
    # Default disabled when not set
    return await cfg_get_bool(r, "vt_enabled", default=False)

VENDORS_KEY = "greycode:blacklist:vendors"

DEFAULT_SETTINGS: dict[str, Any] = {
    "blacklist_update_interval_min": "60",
    "blacklist_recheck_batch": "2000",
    "threatfox_api_key_enc": "",

    "vt_enabled": "0",
    "vt_budget_daily": "500",
    "vt_budget_per_min": "3",
    "vt_api_key_enc": "",

    "notify_email_enabled": "0",
    "notify_email_to": "",
    "notify_email_from": "greycode@localhost",
    "notify_email_subject_prefix": "[Greycode]",
    "notify_smtp_host": "",
    "notify_smtp_port": "25",
    "notify_smtp_user": "",
    "notify_smtp_pass_enc": "",
    "notify_smtp_starttls": "0",
}


def _fernet() -> Fernet:
    """
    Derive a stable Fernet key from GREYCODE_SESSION_SECRET.
    """
    secret = os.getenv("GREYCODE_SESSION_SECRET", "")
    if not secret:
        raise RuntimeError("GREYCODE_SESSION_SECRET not set (needed for settings encryption).")
    digest = hashlib.sha256(secret.encode("utf-8")).digest()  # 32 bytes
    key = base64.urlsafe_b64encode(digest)  # Fernet expects urlsafe b64
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        # If secret changed, we can't decrypt. Treat as unset.
        return ""


def mask_secret(s: str) -> str:
    if not s:
        return ""
    if len(s) <= 8:
        return s[0:2] + "…" + s[-2:]
    return s[:4] + "…" + s[-4:]


async def load_settings() -> dict[str, Any]:
    """
    Merge defaults + redis hash + vendor JSON.
    All stored values are strings; UI can cast where needed.
    """
    stored = await r.hgetall(CFG_KEY)
    s = {**DEFAULT_SETTINGS, **(stored or {})}

    vendors_json = await r.get(VENDORS_KEY)

    stored_vendors = []
    if vendors_json:
        try:
            parsed = json.loads(vendors_json)
            if isinstance(parsed, list):
                stored_vendors = parsed
        except Exception:
            stored_vendors = []

    default_by_key = {
        v["key"]: v
        for v in DEFAULT_VENDORS
        if isinstance(v, dict) and v.get("key")
    }

    stored_by_key = {
        v.get("key"): v
        for v in stored_vendors
        if isinstance(v, dict) and v.get("key")
    }

    merged_vendors = []

    # start with engine defaults, then overlay stored values
    for key, default_vendor in default_by_key.items():
        stored_vendor = stored_by_key.get(key, {})
        merged_vendors.append({**default_vendor, **stored_vendor})

    # preserve unknown/custom vendors already stored in redis
    for key, stored_vendor in stored_by_key.items():
        if key not in default_by_key:
            merged_vendors.append(stored_vendor)

    s["vendors"] = merged_vendors

    vt_key_plain = decrypt_secret(s.get("vt_api_key_enc") or "")
    s["vt_key_masked"] = mask_secret(vt_key_plain)

    tf_key_plain = decrypt_secret(s.get("threatfox_api_key_enc") or "")
    s["threatfox_api_key_masked"] = mask_secret(tf_key_plain)

    s["notify_smtp_pass_masked"] = "stored" if (s.get("notify_smtp_pass_enc") or "") else ""

    s["vt_enabled_bool"] = (s.get("vt_enabled", "0") == "1")
    s["notify_email_enabled_bool"] = (s.get("notify_email_enabled", "0") == "1")

    return s


async def save_settings(mapping: dict[str, str]) -> None:
    """
    Save only known keys into the settings hash.
    """
    allowed = set(DEFAULT_SETTINGS.keys())
    clean = {k: v for k, v in mapping.items() if k in allowed}
    if clean:
        await r.hset(CFG_KEY, mapping=clean)

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

def iso_to_epoch(ts: Optional[str]) -> float:
    if not ts:
        return time.time()
    try:
        # naive UTC ISO strings
        return datetime.datetime.fromisoformat(ts).timestamp()
    except Exception:
        return time.time()

def utcnow_iso() -> str:
    return datetime.datetime.utcnow().isoformat()

def record_key_for_kind(kind: str, indicator: str) -> str:
    if kind == "sha256":
        return f"greycode:sha256:{indicator}"
    if kind == "ip":
        return f"greycode:ip:{indicator}"
    if kind == "domain":
        return f"greycode:domain:{indicator}"
    raise ValueError(f"Unknown kind: {kind}")


def known_set_for_kind(kind: str) -> str:
    if kind == "sha256":
        return KNOWN_SHA256_SET
    if kind == "ip":
        return KNOWN_IPS_SET
    if kind == "domain":
        return KNOWN_DOMAINS_SET
    raise ValueError(f"Unknown kind: {kind}")

def should_refresh_index(last_sync_ts: Optional[str], now_ts: float, min_interval_sec: int = 30) -> bool:
    if not last_sync_ts:
        return True
    try:
        prev = float(last_sync_ts)
    except (TypeError, ValueError):
        return True
    return (now_ts - prev) >= min_interval_sec

def build_row_from_data(tab: int, kind: str, indicator_field: str, indicator: str, data: dict[str, str]) -> dict[str, Any]:
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
        "computer": data.get("computer") or "",
        "computer_first": data.get("computer_first") or "",
        "computer_last": data.get("computer_last") or "",
        "image": data.get("image") or "",
        "vt_link": f"https://www.virustotal.com/gui/file/{indicator}" if tab == 1 else "",
    }
    return row


def row_matches_q(tab: int, row: dict[str, Any], q_lower: str) -> bool:
    if not q_lower:
        return True

    if tab == 1:
        hay = f'{row.get("sha256","")} {row.get("computer","")} {row.get("image","")}'.lower()
    elif tab == 3:
        hay = f'{row.get("ip","")} {row.get("computer_first","")} {row.get("computer_last","")}'.lower()
    else:
        hay = f'{row.get("domain","")} {row.get("computer_first","")} {row.get("computer_last","")}'.lower()

    return q_lower in hay


def filter_set_keys_for(kind: str, status: str, triage: str, listing_state: str) -> list[str]:
    keys: list[str] = []

    if status != "ALL":
        keys.append(idx_s_status(kind, status))

    if kind == "sha256":
        tri = (triage or "ALL").upper()
        if tri in ("OPEN", "TRIAGED"):
            keys.append(idx_s_triage(kind, tri))
    else:
        ls = (listing_state or "ALL").upper()
        if ls in ("LISTED", "NO_LISTING", "PENDING", "ERROR"):
            keys.append(idx_s_listing(kind, ls))

    return keys


async def exact_count_for_filters(kind: str, filter_keys: list[str]) -> int:
    if not filter_keys:
        return int(await r.scard(known_set_for_kind(kind)))

    if len(filter_keys) == 1:
        return int(await r.scard(filter_keys[0]))

    try:
        return int(await r.execute_command("SINTERCARD", len(filter_keys), *filter_keys))
    except Exception:
        # fallback if SINTERCARD unavailable
        vals = await r.sinter(*filter_keys)
        return len(vals)


async def member_matches_filter_sets(indicator: str, filter_keys: list[str]) -> bool:
    if not filter_keys:
        return True

    for fk in filter_keys:
        if not await r.sismember(fk, indicator):
            return False
    return True


async def fetch_indexed_page(
    *,
    tab: int,
    kind: str,
    indicator_field: str,
    status: str,
    triage: str,
    listing_state: str,
    q: str,
    sort: str,
    order: str,
    page: int,
    page_size: int,
) -> tuple[list[dict[str, Any]], int]:
    if sort == "count_total":
        base_z = idx_z_count(kind)
    elif sort == "rare":
        base_z = idx_z_rare(kind)
    else:
        base_z = idx_z_last_seen(kind)

    reverse = (order.lower() != "asc")
    q_lower = (q or "").strip().lower()
    filter_keys = filter_set_keys_for(kind, status, triage, listing_state)

    page_start = (page - 1) * page_size
    total = 0 if q_lower else await exact_count_for_filters(kind, filter_keys)

    rows: list[dict[str, Any]] = []
    matched = 0
    chunk = max(500, page_size * 5)

    # Bound the iteration count to the size of the sorted index
    zcard = int(await r.zcard(base_z))
    if zcard <= 0:
        return [], 0

    num_chunks = math.ceil(zcard / chunk)

    for chunk_idx in range(num_chunks):
        start = chunk_idx * chunk
        end = start + chunk - 1

        if reverse:
            members = await r.zrevrange(base_z, start, end)
        else:
            members = await r.zrange(base_z, start, end)

        if not members:
            break

        if q_lower:
            pipe = r.pipeline()
            for m in members:
                for fk in filter_keys:
                    pipe.sismember(fk, m)
                pipe.hgetall(record_key_for_kind(kind, m))
            raw = await pipe.execute()

            width = len(filter_keys) + 1
            for i, m in enumerate(members):
                base = i * width
                membership_results = raw[base:base + len(filter_keys)]
                data = raw[base + len(filter_keys)] or {}

                if filter_keys and not all(bool(x) for x in membership_results):
                    continue

                row = build_row_from_data(tab, kind, indicator_field, m, data)
                if not row_matches_q(tab, row, q_lower):
                    continue

                total += 1
                if total > page_start and len(rows) < page_size:
                    rows.append(row)

            if len(rows) >= page_size and total > page_start:
                # keep scanning for exact total only when searching
                continue

        else:
            pipe = r.pipeline()
            members_kept: list[str] = []

            for m in members:
                include = True
                if filter_keys:
                    for fk in filter_keys:
                        pipe.sismember(fk, m)

            membership_raw = await pipe.execute() if filter_keys else []

            if filter_keys:
                idx = 0
                for m in members:
                    member_ok = True
                    for _ in filter_keys:
                        if not membership_raw[idx]:
                            member_ok = False
                        idx += 1
                    if member_ok:
                        members_kept.append(m)
            else:
                members_kept = members

            if not members_kept:
                continue

            need_members = members_kept[max(0, page_start - matched): max(0, page_start - matched) + (page_size - len(rows))]
            matched += len(members_kept)

            if need_members:
                pipe = r.pipeline()
                for m in need_members:
                    pipe.hgetall(record_key_for_kind(kind, m))
                data_list = await pipe.execute()

                for m, data in zip(need_members, data_list):
                    rows.append(build_row_from_data(tab, kind, indicator_field, m, data or {}))

            if len(rows) >= page_size:
                return rows, total

    return rows, total


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

async def set_disposition_ip(ip: str, disposition: str, ticket_id: str = "", note: str = "", actor: str = "ui") -> None:
    key = f"greycode:ip:{ip}"
    await r.hset(key, mapping={
        "disposition": disposition,
        "disposition_at": now_iso(),
        "disposition_by": actor,
        "disposition_note": note or "",
        "ticket_id": ticket_id or "",
    })

async def clear_disposition_ip(ip: str, actor: str = "ui") -> None:
    key = f"greycode:ip:{ip}"
    await r.hset(key, mapping={
        "disposition": "",
        "disposition_at": "",
        "disposition_by": actor,
        "disposition_note": "",
        "ticket_id": "",
    })

async def set_disposition_domain(domain: str, disposition: str, ticket_id: str = "", note: str = "", actor: str = "ui") -> None:
    key = f"greycode:domain:{domain}"
    await r.hset(key, mapping={
        "disposition": disposition,
        "disposition_at": now_iso(),
        "disposition_by": actor,
        "disposition_note": note or "",
        "ticket_id": ticket_id or "",
    })

async def clear_disposition_domain(domain: str, actor: str = "ui") -> None:
    key = f"greycode:domain:{domain}"
    await r.hset(key, mapping={
        "disposition": "",
        "disposition_at": "",
        "disposition_by": actor,
        "disposition_note": "",
        "ticket_id": "",
    })

async def render_sysmon_drawer(request: Request, tab: int, indicator: str) -> HTMLResponse:
    """
    Resolve redis key + normalize indicator, fetch record, and render the drawer partial.
    Returns an HTMLResponse (TemplateResponse is a subclass) suitable for HTMX swapping.
    """
    tab = int(tab)

    if tab == 1:
        key = f"greycode:sha256:{indicator}"
    elif tab == 3:
        try:
            indicator = normalize_ip(indicator)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IP")
        key = f"greycode:ip:{indicator}"
    elif tab == 22:
        indicator = normalize_domain(indicator)
        if not indicator:
            raise HTTPException(status_code=400, detail="Invalid domain")
        key = f"greycode:domain:{indicator}"
    else:
        raise HTTPException(status_code=404, detail="Unknown Sysmon tab")

    data = await r.hgetall(key)
    if not data:
        return HTMLResponse("<div class='card'><p class='muted'>Not found.</p></div>", status_code=404)

    return templates.TemplateResponse(
        "partials/sysmon_drawer.html",
        {
            "request": request,
            "tab": tab,
            "indicator": indicator,
            "data": data,
            "vt_link": f"https://www.virustotal.com/gui/file/{indicator}" if tab == 1 else "",
            "vt_last_checked_fmt": fmt_epoch(data.get("vt_last_checked")),
            "vt_next_retry_at_fmt": fmt_epoch(data.get("vt_next_retry_at")),
            "can_triage": can_triage(request),
            "can_delete": can_delete(request),
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, err: str = "", next: str = "/ui"):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "err": err,
            "next": next,
            "theme": "light",
        },
    )


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/ui"),
):
    uname = (username or "").strip().lower()

    user = await get_user(r, uname)
    if not user:
        return RedirectResponse(url="/login?err=1", status_code=303)

    if user.get("is_active", "1") != "1":
        return RedirectResponse(url="/login?err=1", status_code=303)

    stored_hash = user.get("password_hash") or ""
    if not pbkdf2_verify(password or "", stored_hash):
        return RedirectResponse(url="/login?err=1", status_code=303)

    request.session["logged_in"] = True
    request.session["user"] = uname
    request.session["role"] = user.get("role", "user")

    await set_last_login(r, uname)

    return RedirectResponse(url=next or "/ui", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

@app.get("/ui/settings", response_class=HTMLResponse)
async def ui_settings(request: Request, saved: str = "", _auth=Depends(require_login)):
    s = await load_settings()
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "tab": 0,
            "settings": s,
            "saved": saved,
            "theme": await current_user_theme(request),
            **(await get_ui_metrics()),
            "vt_enabled": await vt_enabled_setting(),
        },
    )

def settings_partial_for(tab: str) -> str:
    if tab == "notifications":
        return "partials/settings_tab_notifications.html"
    if tab == "users":
        return "partials/settings_tab_users.html"
    if tab == "audit":
        return "partials/settings_tab_audit.html"
    return "partials/settings_tab_blacklists_apis.html"


@app.get("/ui/settings/tab/{tab_name}", response_class=HTMLResponse)
async def ui_settings_tab(
    request: Request,
    tab_name: str,
    _auth=Depends(require_login),
):
    s = await load_settings()
    return templates.TemplateResponse(
        settings_partial_for(tab_name),
        {
            "request": request,
            "settings": s,
        },
    )

@app.post("/ui/settings/blacklist")
async def ui_settings_blacklist(request: Request, _auth=Depends(require_login)):
    require_admin(request)
    form = await request.form()

    def as_int_str(v: str, default: str, lo: int, hi: int) -> str:
        try:
            n = int((v or "").strip())
            return str(max(lo, min(hi, n)))
        except Exception:
            return default

    update_interval = as_int_str(
        form.get("blacklist_update_interval_min"),
        DEFAULT_SETTINGS["blacklist_update_interval_min"],
        5,
        1440,
    )
    recheck_batch = as_int_str(
        form.get("blacklist_recheck_batch"),
        DEFAULT_SETTINGS["blacklist_recheck_batch"],
        200,
        20000,
    )

    s = await load_settings()
    vendors = s.get("vendors") or DEFAULT_VENDORS

    # Rebuild vendors from the merged view so new defaults are not lost on save
    new_vendors = []
    seen_keys = set()

    for v in vendors:
        if not isinstance(v, dict):
            continue

        key = v.get("key")
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)

        enabled = form.get(f"vendor_enabled_{key}") is not None
        url = (form.get(f"vendor_url_{key}") or v.get("url") or "").strip()

        new_vendors.append({
            "key": key,
            "name": v.get("name") or key,
            "enabled": bool(enabled),
            "type": v.get("type") or "",
            "url": url,
            "requires_api_key": bool(v.get("requires_api_key")),
            "api_key_setting": v.get("api_key_setting") or "",
            "min_fetch_min": int(v.get("min_fetch_min") or 60),
            "etag": v.get("etag") or "",
            "last_modified": v.get("last_modified") or "",
            "last_fetch_at": float(v.get("last_fetch_at") or 0.0),
        })

    mapping = {
        "blacklist_update_interval_min": update_interval,
        "blacklist_recheck_batch": recheck_batch,
    }

    threatfox_api_key = (form.get("threatfox_api_key") or "").strip()
    if threatfox_api_key:
        mapping["threatfox_api_key_enc"] = encrypt_secret(threatfox_api_key)

    actor = current_username(request)
    actor_role = current_role(request)
    prev = await load_settings()

    await save_settings(mapping)
    await save_vendors(r, [Vendor(**v) for v in new_vendors])

    await audit_log(
        r,
        actor=actor,
        actor_role=actor_role,
        category="settings",
        action="update_blacklist",
        target_kind="settings",
        target="blacklist",
        details={
            "blacklist_update_interval_min": [
                prev.get("blacklist_update_interval_min"),
                update_interval,
            ],
            "blacklist_recheck_batch": [
                prev.get("blacklist_recheck_batch"),
                recheck_batch,
            ],
            "threatfox_api_key_changed": bool(threatfox_api_key),
            "vendor_count": len(new_vendors),
        },
    )

    s = await load_settings()
    return templates.TemplateResponse(
        "partials/settings_modal.html",
        {
            "request": request,
            "settings": s,
            "saved": "blacklist",
            "settings_tab": "blacklist",
            "settings_partial": settings_partial_for("blacklist"),
            "is_admin": can_manage_settings(request),
            **(await get_ui_metrics()),
        },
    )

@app.post("/ui/vendor/{vendor_key}/fetch")
async def ui_vendor_fetch_now(
    request: Request,
    vendor_key: str,
    _auth=Depends(require_login),
):
    require_admin(request)
    vendors = await load_vendors(r)
    vendor = next((v for v in vendors if v.key == vendor_key), None)
    if not vendor:
        return HTMLResponse("<div class='notice-banner error'><div>Vendor not found.</div></div>", status_code=404)

    changed, updated_vendor = await fetch_vendor(r, vendor, interval_min=0)

    new_vendors = []
    for v in vendors:
        if v.key == vendor_key:
            new_vendors.append(updated_vendor)
        else:
            new_vendors.append(v)

    await save_vendors(r, new_vendors)

    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="settings",
        action="vendor_fetch_now",
        target_kind="vendor",
        target=vendor_key,
        details={"changed": bool(changed)},
    )

    s = await load_settings()

    return templates.TemplateResponse(
        "partials/settings_modal.html",
        {
            "request": request,
            "settings": s,
            "saved": f"fetch:{vendor_key}",
            "settings_tab": "blacklist",
            "settings_partial": settings_partial_for("blacklist"),
            "is_admin": can_manage_settings(request),
            **(await get_ui_metrics()),
        },
    )

@app.get("/ui/vendor/{vendor_key}/preview", response_class=HTMLResponse)
async def ui_vendor_preview(
    request: Request,
    vendor_key: str,
    _auth=Depends(require_login),
):
    vendors = await load_vendors(r)
    vendor = next((v for v in vendors if v.key == vendor_key), None)
    if not vendor:
        return HTMLResponse(
            "<div class='settings-modal-shell'><div class='notice-banner error'><div>Vendor not found.</div></div></div>",
            status_code=404,
        )

    items: list[str] = []
    total = 0
    truncated = False
    preview_limit = 500

    if vendor.type in ("ip", "ip_port_json"):
        set_key = f"{SET_IP_PREFIX}{vendor.key}"
        total = int(await r.scard(set_key))
        cursor = 0
        while len(items) < preview_limit:
            cursor, batch = await r.sscan(set_key, cursor=cursor, count=200)
            items.extend(batch)
            if cursor == 0:
                break
        if len(items) > preview_limit:
            items = items[:preview_limit]
        truncated = total > len(items)

    elif vendor.type in ("domain", "domain_json"):
        set_key = f"{SET_DOMAIN_PREFIX}{vendor.key}"
        total = int(await r.scard(set_key))
        cursor = 0
        while len(items) < preview_limit:
            cursor, batch = await r.sscan(set_key, cursor=cursor, count=200)
            items.extend(batch)
            if cursor == 0:
                break
        if len(items) > preview_limit:
            items = items[:preview_limit]
        truncated = total > len(items)

    elif vendor.type == "ip_cidr":
        raw = await r.get(f"{CIDR_IP_PREFIX}{vendor.key}")
        cidrs = json.loads(raw or "[]")
        if not isinstance(cidrs, list):
            cidrs = []
        total = len(cidrs)
        items = [str(x) for x in cidrs[:preview_limit]]
        truncated = total > len(items)

    else:
        items = []
        total = 0

    items = sorted(items)

    return templates.TemplateResponse(
        "partials/vendor_preview_modal.html",
        {
            "request": request,
            "vendor": vendor,
            "items": items,
            "total": total,
            "truncated": truncated,
            "last_fetch_fmt": fmt_epoch(str(vendor.last_fetch_at)) if vendor.last_fetch_at else "-",
        },
    )

@app.get("/", include_in_schema=False)
async def root(_auth=Depends(require_login)):
    return RedirectResponse(url="/ui", status_code=302)

@app.post("/ui/settings/vt")
async def ui_settings_vt(request: Request, _auth=Depends(require_login)):
    require_admin(request)
    actor = current_username(request)
    actor_role = current_role(request)
    prev = await load_settings()
    form = await request.form()

    vt_enabled = "1" if (form.get("vt_enabled") == "1") else "0"

    # budgets
    def as_int_str(v: str, default: str) -> str:
        try:
            n = int((v or "").strip())
            if n < 0:
                return default
            return str(n)
        except Exception:
            return default

    daily = as_int_str(form.get("vt_budget_daily"), DEFAULT_SETTINGS["vt_budget_daily"])
    per_min = as_int_str(form.get("vt_budget_per_min"), DEFAULT_SETTINGS["vt_budget_per_min"])

    # API key: if empty => keep existing encrypted value
    new_key = (form.get("vt_api_key") or "").strip()
    mapping = {
        "vt_enabled": vt_enabled,
        "vt_budget_daily": daily,
        "vt_budget_per_min": per_min,
    }

    if new_key:
        mapping["vt_api_key_enc"] = encrypt_secret(new_key)

    await save_settings(mapping)

    await audit_log(
        r,
        actor=actor,
        actor_role=actor_role,
        category="settings",
        action="update_vt",
        target_kind="settings",
        target="vt",
        details={
            "vt_enabled": [prev.get("vt_enabled"), vt_enabled],
            "vt_budget_daily": [prev.get("vt_budget_daily"), daily],
            "vt_budget_per_min": [prev.get("vt_budget_per_min"), per_min],
            "vt_api_key_changed": bool(new_key),
        },
    )

    s = await load_settings()
    return templates.TemplateResponse(
        "partials/settings_modal.html",
        {
            "request": request,
            "settings": s,
            "saved": "vt",
            "settings_tab": "blacklist",
            "settings_partial": settings_partial_for("blacklist"),
            "is_admin": can_manage_settings(request),
            **(await get_ui_metrics()),
        },
    )

@app.post("/ui/users/create", response_class=HTMLResponse)
async def ui_users_create(
    request: Request,
    email: str = Form(""),
    first_name: str = Form(""),
    last_name: str = Form(""),
    role: str = Form("user"),
    temporary_password: str = Form(""),
    is_active: str = Form("1"),
    _auth=Depends(require_login),
):
    require_admin(request)

    err = ""
    email_norm = (email or "").strip().lower()
    role = (role or "user").strip().lower()
    active_bool = str(is_active) == "1"

    if not email_norm:
        err = "Email is required."
    elif "@" not in email_norm:
        err = "Email / username must look like an email address."
    elif len(temporary_password or "") < 10:
        err = "Temporary password must be at least 10 characters."
    elif await get_user(r, email_norm):
        err = "User already exists."
    else:
        await create_user(
            r,
            username=email_norm,
            email=email_norm,
            first_name=first_name,
            last_name=last_name,
            password_hash=pbkdf2_hash(temporary_password),
            role=role,
            is_active="1" if active_bool else "0",
            theme="dark",
            created_by=current_username(request),
        )

        await audit_log(
            r,
            actor=current_username(request),
            actor_role=current_role(request),
            category="settings",
            action="create_user",
            target_kind="user",
            target=email_norm,
            details={
                "role": role,
                "first_name": (first_name or "").strip(),
                "last_name": (last_name or "").strip(),
                "is_active": active_bool,
            },
        )

    users = await list_users(r)
    return templates.TemplateResponse(
        "partials/settings_tab_users.html",
        {
            "request": request,
            "users": users,
            "saved": "user_created" if not err else "",
            "err": err,
        },
    )

@app.post("/ui/users/{username}/role", response_class=HTMLResponse)
async def ui_users_update_role(
    request: Request,
    username: str,
    role: str = Form("user"),
    _auth=Depends(require_login),
):
    require_admin(request)

    username = username.strip().lower()
    target = await get_user(r, username)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = target.get("role", "user")
    new_role = (role or "user").strip().lower()

    await update_user_role(r, username, new_role)

    # keep session role in sync if admin edits self
    if current_username(request) == username:
        request.session["role"] = new_role

    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="settings",
        action="update_user_role",
        target_kind="user",
        target=username,
        details={"old_role": old_role, "new_role": new_role},
    )

    users = await list_users(r)
    return templates.TemplateResponse(
        "partials/settings_tab_users.html",
        {
            "request": request,
            "users": users,
            "saved": "role_updated",
            "err": "",
        },
    )

@app.post("/ui/users/{username}/active", response_class=HTMLResponse)
async def ui_users_update_active(
    request: Request,
    username: str,
    is_active: str = Form("0"),
    _auth=Depends(require_login),
):
    require_admin(request)

    username = username.strip().lower()
    actor = current_username(request)
    target = await get_user(r, username)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    new_active = str(is_active) == "1"
    old_active = target.get("is_active", "1") == "1"

    if actor == username and not new_active:
        err = "You cannot deactivate your own account."
    elif target.get("role") == "admin" and old_active and not new_active and await count_active_admins(r) <= 1:
        err = "Cannot deactivate the last active admin."
    else:
        err = ""
        await set_user_active(r, username, new_active, actor=actor)

        await audit_log(
            r,
            actor=actor,
            actor_role=current_role(request),
            category="settings",
            action="update_user_active",
            target_kind="user",
            target=username,
            details={"old_active": old_active, "new_active": new_active},
        )

    users = await list_users(r)
    return templates.TemplateResponse(
        "partials/settings_tab_users.html",
        {
            "request": request,
            "users": users,
            "saved": "active_updated" if not err else "",
            "err": err,
        },
    )

@app.post("/ui/users/{username}/password", response_class=HTMLResponse)
async def ui_users_reset_password(
    request: Request,
    username: str,
    new_password: str = Form(""),
    _auth=Depends(require_login),
):
    require_admin(request)

    username = username.strip().lower()
    target = await get_user(r, username)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    err = ""
    if len(new_password or "") < 10:
        err = "New password must be at least 10 characters."
    else:
        await update_user_password_hash(r, username, pbkdf2_hash(new_password))

        await audit_log(
            r,
            actor=current_username(request),
            actor_role=current_role(request),
            category="settings",
            action="reset_user_password",
            target_kind="user",
            target=username,
            details={"password_changed": True},
        )

    users = await list_users(r)
    return templates.TemplateResponse(
        "partials/settings_tab_users.html",
        {
            "request": request,
            "users": users,
            "saved": "password_reset" if not err else "",
            "err": err,
        },
    )

@app.post("/ui/settings/notifications")
async def ui_settings_notifications(request: Request, _auth=Depends(require_login)):
    require_admin(request)
    actor = current_username(request)
    actor_role = current_role(request)
    prev = await load_settings()    
    form = await request.form()

    enabled = "1" if (form.get("notify_email_enabled") == "1") else "0"
    email_to = (form.get("notify_email_to") or "").strip()
    email_from = (form.get("notify_email_from") or "").strip()
    subject_prefix = (form.get("notify_email_subject_prefix") or "[Greycode]").strip()

    smtp_host = (form.get("notify_smtp_host") or "").strip()
    smtp_port = (form.get("notify_smtp_port") or "25").strip()
    smtp_user = (form.get("notify_smtp_user") or "").strip()
    smtp_starttls = "1" if (form.get("notify_smtp_starttls") == "1") else "0"

    mapping = {
        "notify_email_enabled": enabled,
        "notify_email_to": email_to,
        "notify_email_from": email_from,
        "notify_email_subject_prefix": subject_prefix,
        "notify_smtp_host": smtp_host,
        "notify_smtp_port": smtp_port,
        "notify_smtp_user": smtp_user,
        "notify_smtp_starttls": smtp_starttls,
    }

    # Leave empty to keep existing password
    smtp_pass = (form.get("notify_smtp_pass") or "").strip()
    if smtp_pass:
        mapping["notify_smtp_pass_enc"] = encrypt_secret(smtp_pass)

    await save_settings(mapping)

    await audit_log(
        r,
        actor=actor,
        actor_role=actor_role,
        category="settings",
        action="update_notifications",
        target_kind="settings",
        target="notifications",
        details={
            "notify_email_enabled": [prev.get("notify_email_enabled"), enabled],
            "notify_email_to": [prev.get("notify_email_to"), email_to],
            "notify_email_from": [prev.get("notify_email_from"), email_from],
            "notify_email_subject_prefix": [prev.get("notify_email_subject_prefix"), subject_prefix],
            "notify_smtp_host": [prev.get("notify_smtp_host"), smtp_host],
            "notify_smtp_port": [prev.get("notify_smtp_port"), smtp_port],
            "notify_smtp_user": [prev.get("notify_smtp_user"), smtp_user],
            "notify_smtp_starttls": [prev.get("notify_smtp_starttls"), smtp_starttls],
            "notify_smtp_pass_changed": bool(smtp_pass),
        },
    )

    s = await load_settings()
    return templates.TemplateResponse(
        "partials/settings_modal.html",
        {
            "request": request,
            "settings": s,
            "saved": "notifications",
            "settings_tab": "notifications",
            "settings_partial": settings_partial_for("notifications"),
            "is_admin": can_manage_settings(request),
            **(await get_ui_metrics()),
        },
    )

@app.get("/ui/settings/modal", response_class=HTMLResponse)
async def ui_settings_modal(
    request: Request,
    saved: str = "",
    tab: str = "blacklist",
    _auth=Depends(require_login),
):
    s = await load_settings()
    users = await list_users(r) if tab == "users" else []
    audit_rows = await get_recent_audit(r, 100) if tab == "audit" else []

    return templates.TemplateResponse(
        "partials/settings_modal.html",
        {
            "request": request,
            "settings": s,
            "saved": saved,
            "settings_tab": tab,
            "settings_partial": settings_partial_for(tab),
            "users": users,
            "audit_rows": audit_rows,
            "is_admin": can_manage_settings(request),
            **(await get_ui_metrics()),
        },
    )


@app.get("/ui/profile/modal", response_class=HTMLResponse)
async def ui_profile_modal(request: Request, saved: str = "", err: str = "", _auth=Depends(require_login)):
    uname = current_username(request)
    user = await get_user(r, uname)

    return templates.TemplateResponse(
        "partials/profile_modal.html",
        {
            "request": request,
            "user_profile": user,
            "saved": saved,
            "err": err,
        },
    )


@app.post("/ui/profile/update", response_class=HTMLResponse)
async def ui_profile_update(
    request: Request,
    first_name: str = Form(""),
    last_name: str = Form(""),
    theme: str = Form("light"),
    _auth=Depends(require_login),
):
    uname = current_username(request)
    theme = (theme or "light").strip().lower()
    if theme not in {"dark", "light"}:
        theme = "light"

    user = await get_user(r, uname)
    current_email = user.get("email") or uname

    await update_user_profile(
        r,
        uname,
        email=current_email,
        first_name=first_name,
        last_name=last_name,
    )
    await update_user_theme(r, uname, theme)

    user = await get_user(r, uname)
    return templates.TemplateResponse(
        "partials/profile_modal.html",
        {
            "request": request,
            "user_profile": user,
            "saved": "profile",
            "err": "",
        },
    )


@app.post("/ui/profile/password", response_class=HTMLResponse)
async def ui_profile_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    new_password_confirm: str = Form(""),
    _auth=Depends(require_login),
):
    uname = current_username(request)
    user = await get_user(r, uname)

    err = ""

    stored_hash = user.get("password_hash") or ""
    if not pbkdf2_verify(current_password or "", stored_hash):
        err = "Current password is incorrect."
    elif len(new_password or "") < 10:
        err = "New password must be at least 10 characters."
    elif new_password != new_password_confirm:
        err = "New password confirmation does not match."
    else:
        new_hash = pbkdf2_hash(new_password)
        await update_user_password_hash(r, uname, new_hash)

    user = await get_user(r, uname)
    return templates.TemplateResponse(
        "partials/profile_modal.html",
        {
            "request": request,
            "user_profile": user,
            "saved": "password" if not err else "",
            "err": err,
        },
    )

@app.post("/enrich/process")
async def enrich_process(event: ProcessEvent):
    key = f"greycode:sha256:{event.sha256}"
    now = datetime.datetime.utcnow().isoformat()

    vals = await r.hmget(key, "status", "source", "computer", "image")
    exists = any(v is not None for v in vals)

    if exists:
        status, source, computer, image = vals

        pipe = r.pipeline()
        pipe.hincrby(key, "count_total", 1)
        pipe.hset(key, mapping={"last_seen": now})
        pipe.sadd(INDEX_DIRTY_SHA256_SET, event.sha256)
        await pipe.execute()

        return {
            "sha256": event.sha256,
            "status": status or "GREY",
            "source": source or "",
            "computer": computer or "",
            "image": image or "",
        }

    vt_enabled = await vt_enabled_setting()

    pipe = r.pipeline()
    pipe.hset(
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
    pipe.sadd(KNOWN_SHA256_SET, event.sha256)
    pipe.sadd(INDEX_DIRTY_SHA256_SET, event.sha256)

    if vt_enabled:
        pipe.lpush(VT_QUEUE, event.sha256)

    await pipe.execute()

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
    start_perf = time.perf_counter()
    new_count = 0
    existing_count = 0
    index_sync_count = 0

    vt_enabled = await vt_enabled_setting()

    # Aggregate by sha256
    aggregated: dict[str, dict[str, Any]] = {}

    for idx, obj in enumerate(events):
        try:
            event = ProcessEvent.model_validate(obj)
        except ValidationError as e:
            rejected += 1
            errors.append({"index": idx, "error": e.errors()})
            continue

        accepted += 1

        row = aggregated.get(event.sha256)
        if row is None:
            aggregated[event.sha256] = {
                "count": 1,
                "computer": event.computer,
                "image": event.image,
            }
        else:
            row["count"] += 1
            row["computer"] = event.computer
            row["image"] = event.image

    if not aggregated:
        logger.warning(
            "bulk kind=process received=%d accepted=%d rejected=%d unique=%d new=%d existing=%d index_sync=%d dur_ms=%.1f",
            len(events),
            accepted,
            rejected,
            0,
            new_count,
            existing_count,
            index_sync_count,
            (time.perf_counter() - start_perf) * 1000,
        )
        return JSONResponse(
            {
                "received": len(events),
                "accepted": accepted,
                "rejected": rejected,
                "errors": errors[:20],
            }
        )

    now = datetime.datetime.utcnow().isoformat()
    hashes = list(aggregated.keys())

    # Fetch only what we need, once per unique sha256
    pipe = r.pipeline()
    for sha256_value in hashes:
        key = f"greycode:sha256:{sha256_value}"
        pipe.exists(key)
    exists_raw = await pipe.execute()

    exists_by_hash = {
        sha256_value: bool(exists_raw[idx])
        for idx, sha256_value in enumerate(hashes)
    }

    pipe = r.pipeline()

    for sha256_value in hashes:
        key = f"greycode:sha256:{sha256_value}"
        agg = aggregated[sha256_value]
        count = int(agg["count"])
        computer = agg["computer"]
        image = agg["image"]

        if exists_by_hash[sha256_value]:
            existing_count += count
            index_sync_count += 1

            pipe.hincrby(key, "count_total", count)
            pipe.hset(key, mapping={"last_seen": now})
            pipe.sadd(INDEX_DIRTY_SHA256_SET, sha256_value)

        else:
            new_count += count
            index_sync_count += 1

            pipe.hset(
                key,
                mapping={
                    "status": "GREY",
                    "vt_state": "PENDING",
                    "source": "pending",
                    "first_seen": now,
                    "last_seen": now,
                    "computer": computer,
                    "image": image,
                    "count_total": str(count),
                    "uuid": str(uuid.uuid4()),
                },
            )
            pipe.sadd(KNOWN_SHA256_SET, sha256_value)
            pipe.sadd(INDEX_DIRTY_SHA256_SET, sha256_value)

            if vt_enabled:
                pipe.lpush(VT_QUEUE, sha256_value)

    await pipe.execute()

    logger.warning(
        "bulk kind=process received=%d accepted=%d rejected=%d unique=%d new=%d existing=%d index_sync=%d dur_ms=%.1f",
        len(events),
        accepted,
        rejected,
        len(hashes),
        new_count,
        existing_count,
        index_sync_count,
        (time.perf_counter() - start_perf) * 1000,
    )

    return JSONResponse(
        {
            "received": len(events),
            "accepted": accepted,
            "rejected": rejected,
            "errors": errors[:20],
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
    now = datetime.datetime.utcnow().isoformat()
    now_epoch = time.time()

    # Fetch only what we need
    vals = await r.hmget(key, "status", "listing_state", "source", "index_last_sync")
    exists = any(v is not None for v in vals)

    if exists:
        status, listing_state, source, index_last_sync = vals

        pipe = r.pipeline()
        pipe.hincrby(key, "count_total", 1)
        pipe.hset(
            key,
            mapping={
                "last_seen": now,
                "computer_last": event.Computer,
            },
        )

        if should_refresh_index(index_last_sync, now_epoch, min_interval_sec=30):
            pipe.sadd(INDEX_DIRTY_IP_SET, ip_norm)
            pipe.hset(key, mapping={"index_last_sync": str(now_epoch)})

        await pipe.execute()

        return {
            "destination_ip": ip_norm,
            "status": status or "GREY",
            "listing_state": listing_state or "",
            "source": source or "",
            "computer_last": event.Computer,
        }

    pipe = r.pipeline()
    pipe.hset(
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
            "index_last_sync": str(now_epoch),
        },
    )
    pipe.sadd(STAGED_SET_IP, ip_norm)
    pipe.sadd(KNOWN_IPS_SET, ip_norm)
    pipe.sadd(INDEX_DIRTY_IP_SET, ip_norm)
    await pipe.execute()

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
    start_perf = time.perf_counter()
    new_count = 0
    existing_count = 0
    index_sync_count = 0

    # Aggregate by normalized IP
    aggregated: dict[str, dict[str, Any]] = {}

    for idx, obj in enumerate(events):
        try:
            event = NetworkEvent.model_validate(obj)
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

        accepted += 1

        row = aggregated.get(ip_norm)
        if row is None:
            aggregated[ip_norm] = {
                "count": 1,
                "computer_first": event.Computer,
                "computer_last": event.Computer,
            }
        else:
            row["count"] += 1
            row["computer_last"] = event.Computer

    if not aggregated:
        logger.warning(
            "bulk kind=network received=%d accepted=%d rejected=%d new=%d existing=%d index_sync=%d unique=%d dur_ms=%.1f",
            len(events),
            accepted,
            rejected,
            new_count,
            existing_count,
            index_sync_count,
            0,
            (time.perf_counter() - start_perf) * 1000,
        )
        return JSONResponse(
            {
                "received": len(events),
                "accepted": accepted,
                "rejected": rejected,
                "errors": errors[:20],
            }
        )

    now = utcnow_iso()
    now_epoch = time.time()
    ips = list(aggregated.keys())

    # Fetch only what we actually need, once per unique indicator
    pipe = r.pipeline()
    for ip_norm in ips:
        key = f"greycode:ip:{ip_norm}"
        pipe.exists(key)
        pipe.hmget(key, "index_last_sync")
    existence_raw = await pipe.execute()

    meta_by_ip: dict[str, dict[str, Any]] = {}
    pos = 0
    for ip_norm in ips:
        exists_flag = bool(existence_raw[pos])
        index_last_sync_val = None
        pos += 1

        hmget_vals = existence_raw[pos]
        pos += 1
        if hmget_vals and len(hmget_vals) >= 1:
            index_last_sync_val = hmget_vals[0]

        meta_by_ip[ip_norm] = {
            "exists": exists_flag,
            "index_last_sync": index_last_sync_val,
        }

    pipe = r.pipeline()

    for ip_norm in ips:
        key = f"greycode:ip:{ip_norm}"
        agg = aggregated[ip_norm]
        meta = meta_by_ip[ip_norm]
        count = int(agg["count"])
        computer_first = agg["computer_first"]
        computer_last = agg["computer_last"]

        if meta["exists"]:
            existing_count += count

            pipe.hincrby(key, "count_total", count)
            pipe.hset(
                key,
                mapping={
                    "last_seen": now,
                    "computer_last": computer_last,
                },
            )

            if should_refresh_index(meta.get("index_last_sync"), now_epoch, min_interval_sec=30):
                index_sync_count += 1
                pipe.sadd(INDEX_DIRTY_IP_SET, ip_norm)
                pipe.hset(key, mapping={"index_last_sync": str(now_epoch)})
        else:
            new_count += count
            index_sync_count += 1

            pipe.hset(
                key,
                mapping={
                    "type": "ip",
                    "status": "GREY",
                    "listing_state": "PENDING",
                    "source": "pending",
                    "first_seen": now,
                    "last_seen": now,
                    "computer_first": computer_first,
                    "computer_last": computer_last,
                    "count_total": str(count),
                    "uuid": str(uuid.uuid4()),
                    "index_last_sync": str(now_epoch),
                },
            )
            pipe.sadd(STAGED_SET_IP, ip_norm)
            pipe.sadd(KNOWN_IPS_SET, ip_norm)
            pipe.sadd(INDEX_DIRTY_IP_SET, ip_norm)

    await pipe.execute()

    logger.warning(
        "bulk kind=network received=%d accepted=%d rejected=%d unique=%d new=%d existing=%d index_sync=%d dur_ms=%.1f",
        len(events),
        accepted,
        rejected,
        len(ips),
        new_count,
        existing_count,
        index_sync_count,
        (time.perf_counter() - start_perf) * 1000,
    )

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
    now = datetime.datetime.utcnow().isoformat()
    now_epoch = time.time()

    vals = await r.hmget(key, "status", "listing_state", "source", "index_last_sync")
    exists = any(v is not None for v in vals)

    if exists:
        status, listing_state, source, index_last_sync = vals

        pipe = r.pipeline()
        pipe.hincrby(key, "count_total", 1)
        pipe.hset(
            key,
            mapping={
                "last_seen": now,
                "computer_last": event.Computer,
            },
        )

        if should_refresh_index(index_last_sync, now_epoch, min_interval_sec=30):
            pipe.sadd(INDEX_DIRTY_DOMAIN_SET, domain_norm)
            pipe.hset(key, mapping={"index_last_sync": str(now_epoch)})

        await pipe.execute()

        return {
            "query_name": domain_norm,
            "status": status or "GREY",
            "listing_state": listing_state or "",
            "source": source or "",
            "computer_last": event.Computer,
        }

    pipe = r.pipeline()
    pipe.hset(
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
            "index_last_sync": str(now_epoch),
        },
    )
    pipe.sadd(STAGED_SET_DOMAIN, domain_norm)
    pipe.sadd(KNOWN_DOMAINS_SET, domain_norm)
    pipe.sadd(INDEX_DIRTY_DOMAIN_SET, domain_norm)
    await pipe.execute()

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
    start_perf = time.perf_counter()
    new_count = 0
    existing_count = 0
    index_sync_count = 0

    # Aggregate by normalized domain
    aggregated: dict[str, dict[str, Any]] = {}

    for idx, obj in enumerate(events):
        try:
            event = DnsEvent.model_validate(obj)
        except ValidationError as e:
            rejected += 1
            errors.append({"index": idx, "error": e.errors()})
            continue

        domain_norm = normalize_domain(event.QueryName)
        if not domain_norm:
            rejected += 1
            errors.append({"index": idx, "error": "Invalid QueryName"})
            continue

        accepted += 1

        row = aggregated.get(domain_norm)
        if row is None:
            aggregated[domain_norm] = {
                "count": 1,
                "computer_first": event.Computer,
                "computer_last": event.Computer,
            }
        else:
            row["count"] += 1
            row["computer_last"] = event.Computer

    if not aggregated:
        logger.warning(
            "bulk kind=dns received=%d accepted=%d rejected=%d new=%d existing=%d index_sync=%d unique=%d dur_ms=%.1f",
            len(events),
            accepted,
            rejected,
            new_count,
            existing_count,
            index_sync_count,
            0,
            (time.perf_counter() - start_perf) * 1000,
        )
        return JSONResponse(
            {
                "received": len(events),
                "accepted": accepted,
                "rejected": rejected,
                "errors": errors[:20],
            }
        )

    now = utcnow_iso()
    now_epoch = time.time()
    domains = list(aggregated.keys())

    # Fetch only what we need, once per unique indicator
    pipe = r.pipeline()
    for domain_norm in domains:
        key = f"greycode:domain:{domain_norm}"
        pipe.exists(key)
        pipe.hmget(key, "index_last_sync")
    existence_raw = await pipe.execute()

    meta_by_domain: dict[str, dict[str, Any]] = {}
    pos = 0
    for domain_norm in domains:
        exists_flag = bool(existence_raw[pos])
        pos += 1

        index_last_sync_val = None
        hmget_vals = existence_raw[pos]
        pos += 1
        if hmget_vals and len(hmget_vals) >= 1:
            index_last_sync_val = hmget_vals[0]

        meta_by_domain[domain_norm] = {
            "exists": exists_flag,
            "index_last_sync": index_last_sync_val,
        }

    pipe = r.pipeline()

    for domain_norm in domains:
        key = f"greycode:domain:{domain_norm}"
        agg = aggregated[domain_norm]
        meta = meta_by_domain[domain_norm]
        count = int(agg["count"])
        computer_first = agg["computer_first"]
        computer_last = agg["computer_last"]

        if meta["exists"]:
            existing_count += count

            pipe.hincrby(key, "count_total", count)
            pipe.hset(
                key,
                mapping={
                    "last_seen": now,
                    "computer_last": computer_last,
                },
            )

            if should_refresh_index(meta.get("index_last_sync"), now_epoch, min_interval_sec=30):
                index_sync_count += 1
                pipe.sadd(INDEX_DIRTY_DOMAIN_SET, domain_norm)
                pipe.hset(key, mapping={"index_last_sync": str(now_epoch)})
        else:
            new_count += count
            index_sync_count += 1

            pipe.hset(
                key,
                mapping={
                    "type": "domain",
                    "status": "GREY",
                    "listing_state": "PENDING",
                    "source": "pending",
                    "first_seen": now,
                    "last_seen": now,
                    "computer_first": computer_first,
                    "computer_last": computer_last,
                    "count_total": str(count),
                    "uuid": str(uuid.uuid4()),
                    "index_last_sync": str(now_epoch),
                },
            )
            pipe.sadd(STAGED_SET_DOMAIN, domain_norm)
            pipe.sadd(KNOWN_DOMAINS_SET, domain_norm)
            pipe.sadd(INDEX_DIRTY_DOMAIN_SET, domain_norm)

    await pipe.execute()

    logger.warning(
        "bulk kind=dns received=%d accepted=%d rejected=%d unique=%d new=%d existing=%d index_sync=%d dur_ms=%.1f",
        len(events),
        accepted,
        rejected,
        len(domains),
        new_count,
        existing_count,
        index_sync_count,
        (time.perf_counter() - start_perf) * 1000,
    )

    return JSONResponse(
        {
            "received": len(events),
            "accepted": accepted,
            "rejected": rejected,
            "errors": errors[:20],
        }
    )

@app.post("/ui/hash/{sha256}/accept")
async def ui_hash_accept(sha256: str, request: Request, _auth=Depends(require_login)):
    require_triage(request)
    await set_disposition(sha256, "ACCEPTED", actor="ui")
    await sync_sha256_indexes(r, sha256)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="accept",
        target_kind="sha256",
        target=sha256,
        details={},
    )
    return await render_sysmon_drawer(request, tab=1, indicator=sha256)

@app.post("/ui/hash/{sha256}/escalate")
async def ui_hash_escalate(sha256: str, request: Request, ticket_id: str = Form(...), _auth=Depends(require_login)):
    require_triage(request)
    ticket_id = (ticket_id or "").strip()
    if not ticket_id:
        # Redirect back if no ticket_id provided
        return await render_sysmon_drawer(request, tab=1, indicator=sha256)

    await set_disposition(sha256, "ESCALATED", ticket_id=ticket_id, actor="ui")
    await sync_sha256_indexes(r, sha256)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="escalate",
        target_kind="sha256",
        target=sha256,
        details={"ticket_id": ticket_id},
    )
    return await render_sysmon_drawer(request, tab=1, indicator=sha256)

@app.post("/ui/hash/{sha256}/clear")
async def ui_hash_clear(sha256: str, request: Request, _auth=Depends(require_login)):
    require_triage(request)
    await clear_disposition(sha256, actor="ui")
    await sync_sha256_indexes(r, sha256)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="clear",
        target_kind="sha256",
        target=sha256,
        details={},
    )
    return await render_sysmon_drawer(request, tab=1, indicator=sha256)

@app.post("/ui/hash/{sha256}/recheck")
async def ui_hash_recheck(sha256: str, request: Request, _auth=Depends(require_login)):
    require_triage(request)
    await recheck_vt_stage(sha256)
    await sync_sha256_indexes(r, sha256)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="recheck",
        target_kind="sha256",
        target=sha256,
        details={},
    )
    return await render_sysmon_drawer(request, tab=1, indicator=sha256)

@app.post("/ui/hash/{sha256}/delete")
async def ui_hash_delete(sha256: str, request: Request, _auth=Depends(require_login)):
    require_delete(request)
    await delete_hash_everywhere(sha256)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="delete",
        target_kind="sha256",
        target=sha256,
        details={},
    )
    gc = "<div class='card'><h2 style='margin-top:0;'>Details</h2><p class='muted'>Item deleted.</p></div>"
    return HTMLResponse(gc)

async def delete_hash_everywhere(sha256_value: str) -> None:
    key = f"greycode:sha256:{sha256_value}"
    await r.delete(key)
    await r.srem(STAGED_SET, sha256_value)
    await r.lrem(VT_QUEUE, 0, sha256_value)
    await remove_from_all_indexes(r, kind="sha256", indicator=sha256_value)
    await r.srem(KNOWN_SHA256_SET, sha256_value)

@app.post("/ui/ip/{ip}/accept")
async def ui_ip_accept(ip: str, request: Request, _auth=Depends(require_login)):
    require_triage(request)
    ip_norm = normalize_ip(ip)
    await set_disposition_ip(ip_norm, "ACCEPTED", actor="ui")
    await sync_ip_indexes(r, ip_norm)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="accept",
        target_kind="ip",
        target=ip_norm,
        details={},
    )
    return await render_sysmon_drawer(request, tab=3, indicator=ip_norm)

@app.post("/ui/ip/{ip}/escalate")
async def ui_ip_escalate(ip: str, request: Request, ticket_id: str = Form(...), _auth=Depends(require_login)):
    require_triage(request)
    ip_norm = normalize_ip(ip)
    ticket_id = (ticket_id or "").strip()
    if not ticket_id:
        raise HTTPException(status_code=400, detail="ticket_id required")
    await set_disposition_ip(ip_norm, "ESCALATED", ticket_id=ticket_id, actor="ui")
    await sync_ip_indexes(r, ip_norm)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="escalate",
        target_kind="ip",
        target=ip_norm,
        details={"ticket_id": ticket_id},
    )
    return await render_sysmon_drawer(request, tab=3, indicator=ip_norm)

@app.post("/ui/ip/{ip}/clear")
async def ui_ip_clear(ip: str, request: Request, _auth=Depends(require_login)):
    require_triage(request)
    ip_norm = normalize_ip(ip)
    await clear_disposition_ip(ip_norm, actor="ui")
    await sync_ip_indexes(r, ip_norm)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="clear",
        target_kind="ip",
        target=ip_norm,
        details={},
    )
    return await render_sysmon_drawer(request, tab=3, indicator=ip_norm)


@app.post("/ui/domain/{domain}/accept")
async def ui_domain_accept(domain: str, request: Request, _auth=Depends(require_login)):
    require_triage(request)
    dom = normalize_domain(domain)
    await set_disposition_domain(dom, "ACCEPTED", actor="ui")
    await sync_domain_indexes(r, dom)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="accept",
        target_kind="domain",
        target=dom,
        details={},
    )
    return await render_sysmon_drawer(request, tab=22, indicator=dom)

@app.post("/ui/domain/{domain}/escalate")
async def ui_domain_escalate(domain: str, request: Request, ticket_id: str = Form(...), _auth=Depends(require_login)):
    require_triage(request)
    dom = normalize_domain(domain)
    ticket_id = (ticket_id or "").strip()
    if not ticket_id:
        raise HTTPException(status_code=400, detail="ticket_id required")
    await set_disposition_domain(dom, "ESCALATED", ticket_id=ticket_id, actor="ui")
    await sync_domain_indexes(r, dom)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="escalate",
        target_kind="domain",
        target=dom,
        details={"ticket_id": ticket_id},
    )
    return await render_sysmon_drawer(request, tab=22, indicator=dom)

@app.post("/ui/domain/{domain}/clear")
async def ui_domain_clear(domain: str, request: Request, _auth=Depends(require_login)):
    require_triage(request)
    dom = normalize_domain(domain)
    await clear_disposition_domain(dom, actor="ui")
    await sync_domain_indexes(r, dom)
    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action="clear",
        target_kind="domain",
        target=dom,
        details={},
    )
    return await render_sysmon_drawer(request, tab=22, indicator=dom)


@app.post("/ui/bulk_action")
async def ui_bulk_action(
    request: Request,
    action: str = Form(...),
    selected: list[str] = Form(default=[]),
    ticket_id: str = Form(default=""),
    tab: int = Form(...),
    return_to: str = Form("/ui"),
    _auth=Depends(require_login),
):
    action = (action or "").strip().lower()
    ticket_id = (ticket_id or "").strip()
    values = [v.strip() for v in selected if v and v.strip()]
    redirect_to = return_to or "/ui"

    if action == "delete":
        require_delete(request)
    else:
        require_triage(request)

    if not values:
        return RedirectResponse(url=redirect_to, status_code=303)

    target_kind = {1: "sha256", 3: "ip", 22: "domain"}.get(tab, "unknown")

    if tab == 1:
        if action == "accept":
            for h in values:
                await set_disposition(h, "ACCEPTED", actor="ui")
                await sync_sha256_indexes(r, h)

        elif action == "escalate":
            if not ticket_id:
                return RedirectResponse(url=redirect_to, status_code=303)
            for h in values:
                await set_disposition(h, "ESCALATED", ticket_id=ticket_id, actor="ui")
                await sync_sha256_indexes(r, h)

        elif action == "clear":
            for h in values:
                await clear_disposition(h, actor="ui")
                await sync_sha256_indexes(r, h)

        elif action == "recheck":
            for h in values:
                await recheck_vt_stage(h)
                await sync_sha256_indexes(r, h)

        elif action == "delete":
            for h in values:
                await delete_hash_everywhere(h)

        else:
            return RedirectResponse(url=redirect_to, status_code=303)

    elif tab == 3:
        if action == "accept":
            for ip in values:
                ip_norm = normalize_ip(ip)
                await set_disposition_ip(ip_norm, "ACCEPTED", actor="ui")
                await sync_ip_indexes(r, ip_norm)

        elif action == "escalate":
            if not ticket_id:
                return RedirectResponse(url=redirect_to, status_code=303)
            for ip in values:
                ip_norm = normalize_ip(ip)
                await set_disposition_ip(ip_norm, "ESCALATED", ticket_id=ticket_id, actor="ui")
                await sync_ip_indexes(r, ip_norm)

        elif action == "clear":
            for ip in values:
                ip_norm = normalize_ip(ip)
                await clear_disposition_ip(ip_norm, actor="ui")
                await sync_ip_indexes(r, ip_norm)

        else:
            return RedirectResponse(url=redirect_to, status_code=303)

    elif tab == 22:
        if action == "accept":
            for domain in values:
                dom = normalize_domain(domain)
                await set_disposition_domain(dom, "ACCEPTED", actor="ui")
                await sync_domain_indexes(r, dom)

        elif action == "escalate":
            if not ticket_id:
                return RedirectResponse(url=redirect_to, status_code=303)
            for domain in values:
                dom = normalize_domain(domain)
                await set_disposition_domain(dom, "ESCALATED", ticket_id=ticket_id, actor="ui")
                await sync_domain_indexes(r, dom)

        elif action == "clear":
            for domain in values:
                dom = normalize_domain(domain)
                await clear_disposition_domain(dom, actor="ui")
                await sync_domain_indexes(r, dom)

        else:
            return RedirectResponse(url=redirect_to, status_code=303)

    else:
        return RedirectResponse(url=redirect_to, status_code=303)

    await audit_log(
        r,
        actor=current_username(request),
        actor_role=current_role(request),
        category="triage",
        action=f"bulk_{action}",
        target_kind=target_kind,
        target=f"{len(values)} items",
        details={
            "count": len(values),
            "ticket_id": ticket_id,
        },
    )

    return RedirectResponse(url=redirect_to, status_code=303)


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
async def ui_redirect(_auth=Depends(require_login)):
    return RedirectResponse(url="/ui/sysmon/1", status_code=302)

@app.get("/ui/sysmon/{event_id}", response_class=HTMLResponse)
async def ui_sysmon(
    request: Request,
    event_id: int = ApiPath(..., ge=1),
    status: str = Query("ALL"),
    q: str = Query(""),
    sort: str = Query("last_seen"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=10, le=2000),
    triage: str = Query("ALL"),
    listing_state: str = Query("ALL"),
    open: str = Query("", alias="open"),
    _auth=Depends(require_login),
):
    tab = int(event_id)

    if tab == 1:
        indicator_label = "SHA256"
        indicator_field = "sha256"
        allowed_status = {"ALL", "RED", "ERROR", "GREY", "GREEN"}
    elif tab == 3:
        indicator_label = "DestinationIp"
        indicator_field = "ip"
        allowed_status = {"ALL", "RED", "ERROR", "GREY"}
    elif tab == 22:
        indicator_label = "QueryName"
        indicator_field = "domain"
        allowed_status = {"ALL", "RED", "ERROR", "GREY"}
    else:
        raise HTTPException(status_code=404, detail="Unknown Sysmon tab")

    status = (status or "ALL").upper()
    if status not in allowed_status:
        status = "ALL"

    return templates.TemplateResponse(
        "index_sysmon.html",
        {
            "request": request,
            "tab": tab,
            "status": status,
            "triage": triage,
            "listing_state": listing_state,
            "q": q,
            "sort": sort,
            "order": order,
            "page": page,
            "page_size": page_size,
            "indicator_label": indicator_label,
            "indicator_field": indicator_field,
            "open": open,
            "vt_enabled": await vt_enabled_setting(),
            "can_triage": can_triage(request),
            "can_delete": can_delete(request),
            "theme": await current_user_theme(request),
            **(await get_ui_metrics()),
        },
    )

@app.get("/ui/sysmon/{event_id}/table", response_class=HTMLResponse)
async def ui_sysmon_table(
    request: Request,
    event_id: int = ApiPath(..., ge=1),
    status: str = Query("ALL"),
    q: str = Query(""),
    sort: str = Query("last_seen"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=10, le=2000),
    triage: str = Query("ALL"),
    listing_state: str = Query("ALL"),
    _auth=Depends(require_login),
):
    tab = int(event_id)

    if tab == 1:
        indicator_label = "SHA256"
        indicator_field = "sha256"
        kind = "sha256"
        allowed_status = {"ALL", "RED", "ERROR", "GREY", "GREEN"}
    elif tab == 3:
        indicator_label = "DestinationIp"
        indicator_field = "ip"
        kind = "ip"
        allowed_status = {"ALL", "RED", "ERROR", "GREY"}
    elif tab == 22:
        indicator_label = "QueryName"
        indicator_field = "domain"
        kind = "domain"
        allowed_status = {"ALL", "RED", "ERROR", "GREY"}
    else:
        raise HTTPException(status_code=404, detail="Unknown Sysmon tab")

    status = (status or "ALL").upper()
    if status not in allowed_status:
        status = "ALL"

    indexed_sorts = {"last_seen", "count_total", "rare"}

    if sort not in indexed_sorts:
        sort = "last_seen"

    rows, total = await fetch_indexed_page(
        tab=tab,
        kind=kind,
        indicator_field=indicator_field,
        status=status,
        triage=triage,
        listing_state=listing_state,
        q=q,
        sort=sort,
        order=order,
        page=page,
        page_size=page_size,
    )

    return templates.TemplateResponse(
        "partials/sysmon_table.html",
        {
            "request": request,
            "tab": tab,
            "rows": rows,
            "total": total,
            "page": page,
            "page_size": page_size,
            "status": status,
            "triage": triage,
            "listing_state": listing_state,
            "q": q,
            "sort": sort,
            "order": order,
            "indicator_label": indicator_label,
            "indicator_field": indicator_field,
            "can_triage": can_triage(request),
            "can_delete": can_delete(request),
        },
    )

@app.get("/ui/sysmon/{event_id}/row/{indicator}", response_class=HTMLResponse)
async def ui_sysmon_row(
    request: Request,
    event_id: int = ApiPath(..., ge=1),
    indicator: str = ApiPath(...),
    _auth=Depends(require_login),
):
    return await render_sysmon_drawer(request, int(event_id), indicator)

@app.get("/ui/hash/{sha256}", include_in_schema=False)
async def ui_hash_detail_redirect(sha256: str, _auth=Depends(require_login)):
    return RedirectResponse(url=f"/ui/sysmon/1?open={sha256}", status_code=302)