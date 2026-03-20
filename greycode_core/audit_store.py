from __future__ import annotations

import datetime
import json
from typing import Any

AUDIT_STREAM_KEY = "greycode:audit"


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


async def audit_log(
    r,
    *,
    actor: str,
    actor_role: str,
    category: str,
    action: str,
    result: str = "success",
    target_kind: str = "",
    target: str = "",
    details: dict[str, Any] | None = None,
) -> str:
    payload = {
        "ts": now_iso(),
        "actor": (actor or "").strip().lower(),
        "actor_role": (actor_role or "").strip().lower(),
        "category": (category or "").strip().lower(),
        "action": (action or "").strip().lower(),
        "result": (result or "success").strip().lower(),
        "target_kind": (target_kind or "").strip().lower(),
        "target": str(target or ""),
        "details": json.dumps(details or {}, ensure_ascii=False, sort_keys=True),
    }

    msg_id = await r.xadd(AUDIT_STREAM_KEY, payload, maxlen=100000, approximate=True)
    return str(msg_id)


async def get_recent_audit(r, limit: int = 100) -> list[dict[str, str]]:
    rows = await r.xrevrange(AUDIT_STREAM_KEY, count=max(1, min(limit, 500)))
    out: list[dict[str, str]] = []

    for msg_id, fields in rows:
        row = dict(fields)
        row["id"] = msg_id
        out.append(row)

    return out