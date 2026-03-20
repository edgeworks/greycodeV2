from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import secrets


INVITE_KEY_PREFIX = "greycode:invite:"


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def invite_key(invite_id: str) -> str:
    return f"{INVITE_KEY_PREFIX}{invite_id}"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> tuple[str, str, str]:
    invite_id = secrets.token_urlsafe(12)
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    return invite_id, raw_token, token_hash


async def create_invite_token(
    r,
    *,
    username: str,
    created_by: str,
    ttl_seconds: int = 86400,
) -> str:
    invite_id, raw_token, token_hash = generate_token()
    key = invite_key(invite_id)

    now = datetime.datetime.utcnow()
    expires_at = now + datetime.timedelta(seconds=ttl_seconds)

    await r.hset(
        key,
        mapping={
            "username": (username or "").strip().lower(),
            "purpose": "set_initial_password",
            "token_hash": token_hash,
            "created_at": now.isoformat(),
            "created_by": (created_by or "").strip().lower(),
            "expires_at": expires_at.isoformat(),
            "used_at": "",
        },
    )
    await r.expire(key, ttl_seconds)

    return f"{invite_id}.{raw_token}"


async def validate_invite_token(r, token: str) -> dict[str, str]:
    token = (token or "").strip()
    if "." not in token:
        return {}

    invite_id, raw_token = token.split(".", 1)
    key = invite_key(invite_id)
    data = await r.hgetall(key)
    if not data:
        return {}

    if data.get("used_at"):
        return {}

    expires_at = data.get("expires_at") or ""
    if not expires_at:
        return {}

    try:
        exp = datetime.datetime.fromisoformat(expires_at)
    except Exception:
        return {}

    if datetime.datetime.utcnow() > exp:
        return {}

    expected = data.get("token_hash") or ""
    actual = hash_token(raw_token)
    if not expected or not hmac.compare_digest(expected, actual):
        return {}

    return data


async def mark_invite_used(r, token: str) -> None:
    token = (token or "").strip()
    if "." not in token:
        return
    invite_id, _ = token.split(".", 1)
    await r.hset(invite_key(invite_id), mapping={"used_at": now_iso()})