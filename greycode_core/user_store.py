from __future__ import annotations

import datetime

USERS_SET_KEY = "greycode:users"
USER_KEY_PREFIX = "greycode:user:"


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def user_key(username: str) -> str:
    return f"{USER_KEY_PREFIX}{(username or '').strip().lower()}"


def normalize_theme(theme: str | None) -> str:
    t = (theme or "dark").strip().lower()
    return t if t in {"dark", "light"} else "dark"


def normalize_role(role: str | None) -> str:
    r = (role or "user").strip().lower()
    return r if r in {"admin", "analyst", "user"} else "user"


def normalize_email_username(value: str | None) -> str:
    return (value or "").strip().lower()


async def user_exists(r, username: str) -> bool:
    if not username:
        return False
    return await r.exists(user_key(username)) == 1


async def get_user(r, username: str) -> dict[str, str]:
    if not username:
        return {}
    return await r.hgetall(user_key(username))


async def list_users(r) -> list[dict[str, str]]:
    usernames = sorted(await r.smembers(USERS_SET_KEY))
    if not usernames:
        return []

    pipe = r.pipeline()
    for uname in usernames:
        pipe.hgetall(user_key(uname))
    raw = await pipe.execute()

    users: list[dict[str, str]] = []
    for uname, data in zip(usernames, raw):
        row = data or {}
        if not row:
            continue
        row.setdefault("username", uname)
        row.setdefault("email", uname)
        row.setdefault("first_name", "")
        row.setdefault("last_name", "")
        row.setdefault("role", "user")
        row.setdefault("theme", "dark")
        row.setdefault("is_active", "1")
        users.append(row)

    return users


async def create_user(
    r,
    *,
    username: str,
    password_hash: str,
    role: str = "admin",
    email: str = "",
    first_name: str = "",
    last_name: str = "",
    is_active: str = "1",
    theme: str = "dark",
    created_by: str = "",
) -> None:
    uname = normalize_email_username(username or email)
    if not uname:
        raise ValueError("username required")

    ts = now_iso()
    key = user_key(uname)

    await r.hset(
        key,
        mapping={
            "username": uname,
            "email": normalize_email_username(email or uname),
            "first_name": (first_name or "").strip(),
            "last_name": (last_name or "").strip(),
            "password_hash": password_hash,
            "role": normalize_role(role),
            "theme": normalize_theme(theme),
            "is_active": "1" if str(is_active) == "1" else "0",
            "must_change_password": "1",
            "created_at": ts,
            "updated_at": ts,
            "last_login_at": "",
            "created_by": (created_by or "").strip().lower(),
            "invite_sent_at": "",
            "invited_by": (created_by or "").strip().lower(),
            "disabled_at": "",
            "disabled_by": "",
        },
    )
    await r.sadd(USERS_SET_KEY, uname)

async def set_user_invite_sent(r, username: str, actor: str = "") -> None:
    uname = normalize_email_username(username)
    if not uname:
        raise ValueError("username required")

    await r.hset(
        user_key(uname),
        mapping={
            "invite_sent_at": now_iso(),
            "invited_by": normalize_email_username(actor),
            "updated_at": now_iso(),
        },
    )


async def set_user_must_change_password(r, username: str, must_change: bool) -> None:
    uname = normalize_email_username(username)
    if not uname:
        raise ValueError("username required")

    await r.hset(
        user_key(uname),
        mapping={
            "must_change_password": "1" if must_change else "0",
            "updated_at": now_iso(),
        },
    )


async def delete_user(r, username: str) -> None:
    uname = normalize_email_username(username)
    if not uname:
        raise ValueError("username required")

    await r.delete(user_key(uname))
    await r.srem(USERS_SET_KEY, uname)


async def update_user_profile(
    r,
    username: str,
    *,
    email: str,
    first_name: str,
    last_name: str,
) -> None:
    uname = normalize_email_username(username)
    if not uname:
        raise ValueError("username required")

    await r.hset(
        user_key(uname),
        mapping={
            "email": normalize_email_username(email or uname),
            "first_name": (first_name or "").strip(),
            "last_name": (last_name or "").strip(),
            "updated_at": now_iso(),
        },
    )


async def update_user_theme(r, username: str, theme: str) -> None:
    uname = normalize_email_username(username)
    if not uname:
        raise ValueError("username required")

    await r.hset(
        user_key(uname),
        mapping={
            "theme": normalize_theme(theme),
            "updated_at": now_iso(),
        },
    )


async def update_user_role(r, username: str, role: str) -> None:
    uname = normalize_email_username(username)
    if not uname:
        raise ValueError("username required")

    await r.hset(
        user_key(uname),
        mapping={
            "role": normalize_role(role),
            "updated_at": now_iso(),
        },
    )


async def set_user_active(r, username: str, is_active: bool, actor: str = "") -> None:
    uname = normalize_email_username(username)
    if not uname:
        raise ValueError("username required")

    ts = now_iso()
    mapping = {
        "is_active": "1" if is_active else "0",
        "updated_at": ts,
    }

    if is_active:
        mapping["disabled_at"] = ""
        mapping["disabled_by"] = ""
    else:
        mapping["disabled_at"] = ts
        mapping["disabled_by"] = normalize_email_username(actor)

    await r.hset(user_key(uname), mapping=mapping)


async def update_user_password_hash(r, username: str, password_hash: str) -> None:
    uname = normalize_email_username(username)
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
    uname = normalize_email_username(username)
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


async def count_active_admins(r) -> int:
    users = await list_users(r)
    return sum(1 for u in users if u.get("role") == "admin" and u.get("is_active", "1") == "1")


async def ensure_bootstrap_admin(
    r,
    *,
    bootstrap_username: str,
    bootstrap_password_hash: str,
    bootstrap_email: str = "",
) -> None:
    if await count_users(r) > 0:
        return

    if not bootstrap_username or not bootstrap_password_hash:
        return

    await create_user(
        r,
        username=bootstrap_username,
        email=bootstrap_email or bootstrap_username,
        password_hash=bootstrap_password_hash,
        role="admin",
        first_name="",
        last_name="",
        is_active="1",
        theme="dark",
        created_by="bootstrap",
    )