# config_store.py
from __future__ import annotations
from typing import Optional

CFG_KEY = "greycode:cfg"

def _boolish(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "enabled")

def _intish(v: Optional[str], default: int) -> int:
    try:
        return int(v) if v is not None else default
    except Exception:
        return default

async def cfg_get(r, field: str, default: Optional[str] = None) -> Optional[str]:
    v = await r.hget(CFG_KEY, field)
    return default if v is None else v

async def cfg_set(r, field: str, value: str) -> None:
    await r.hset(CFG_KEY, field, value)

async def cfg_get_bool(r, field: str, default: bool = False) -> bool:
    v = await cfg_get(r, field, None)
    return _boolish(v, default=default)

async def cfg_get_int(r, field: str, default: int) -> int:
    v = await cfg_get(r, field, None)
    return _intish(v, default=default)