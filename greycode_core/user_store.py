from __future__ import annotations

import datetime
from typing import Optional

USERS_SET_KEY = "greycode:users"
USER_KEY_PREFIX = "greycode:user:"


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def user_key(username: str) -> str:
    return f"{USER_KEY_PREFIX}{(username or '').strip().lower()}"


async def user_exists(r, username: str) -> bool:
    if not username:
        return False
    return await r.exists(user_key(username)) == 1


async def get_user(r, username: str) -> dict[str, str]:
    if not username:
        return {}
    return await r.hgetall(user_key(username))


async def create_user(
    r,
    *,
    username: str,
    password_hash: str,
    role: str = "admin",
    email: str = "",
    is_active: str = "1",
) -> None:
    uname = (username or "").strip().lower()
    if not uname:
        raise ValueError("username required")

    ts = now_iso()
    key = user_key(uname)

    await r.hset(
        key,
        mapping={
            "username": uname,
            "password_hash": password_hash,
            "role": role,
            "email": email or "",
            "is_active": is_active,
            "created_at": ts,
            "updated_at": ts,
            "last_login_at": "",
        },
    )
    await r.sadd(USERS_SET_KEY, uname)


async def update_user_email(r, username: str, email: str) -> None:
    uname = (username or "").strip().lower()
    if not uname:
        raise ValueError("username required")

    await r.hset(
        user_key(uname),
        mapping={
            "email": (email or "").strip(),
            "updated_at": now_iso(),
        },
    )


async def update_user_password_hash(r, username: str, password_hash: str) -> None:
    uname = (username or "").strip().lower()
    if not uname:
        raise ValueError("username required")

    await r.hset(
        user_key(uname),
        mapping={
            "password_hash": password_hash,
            "updated_at": now_iso(),
        },
    )


async def set_last_login(r, username: str) -> None:
    uname = (username or "").strip().lower()
    if not uname:
        return

    await r.hset(
        user_key(uname),
        mapping={
            "last_login_at": now_iso(),
        },
    )


async def count_users(r) -> int:
    return await r.scard(USERS_SET_KEY)


async def ensure_bootstrap_admin(
    r,
    *,
    bootstrap_username: str,
    bootstrap_password_hash: str,
    bootstrap_email: str = "",
) -> None:
    """
    If no users exist yet, create the initial admin user from env/bootstrap values.
    Safe to call on every startup.
    """
    if await count_users(r) > 0:
        return

    if not bootstrap_username or not bootstrap_password_hash:
        return

    await create_user(
        r,
        username=bootstrap_username,
        password_hash=bootstrap_password_hash,
        role="admin",
        email=bootstrap_email,
        is_active="1",
    )