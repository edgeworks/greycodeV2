from __future__ import annotations

import csv
import datetime
import io
import time
import httpx
import redis.asyncio as redis

CFG_KEY = "greycode:cfg"
KNOWN_DOMAINS_SET = "greycode:known:domains"
INDEX_DIRTY_COMPUTER_SET = "greycode:index_dirty:computer"
AKARANK_TOP1M_SET = "greycode:akarank:top1m"
AKARANK_META_KEY = "greycode:akarank:meta"

DEFAULT_URL = "https://www.akamai.com/pdata/akarank/prod/top1M.csv"


def normalize_akarank_domain(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


async def in_akarank_top1m(r: redis.Redis, domain: str) -> bool:
    dom = normalize_akarank_domain(domain)
    if not dom:
        return False
    if await r.sismember(AKARANK_TOP1M_SET, dom):
        return True
    parts = dom.split(".")
    if len(parts) >= 3:
        base = ".".join(parts[-2:])
        return bool(await r.sismember(AKARANK_TOP1M_SET, base))
    return False


async def sync_akarank_flags_for_known_domains(r: redis.Redis, batch_size: int = 1000) -> int:
    domains = list(await r.smembers(KNOWN_DOMAINS_SET))
    if not domains:
        return 0
    changed_domains: list[str] = []
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i + batch_size]
        pipe = r.pipeline()
        for dom in batch:
            pipe.hget(f"greycode:domain:{dom}", "is_top1m")
            pipe.sismember(AKARANK_TOP1M_SET, dom)
        raw = await pipe.execute()
        upd = r.pipeline()
        pos = 0
        for dom in batch:
            prev = "1" if str(raw[pos] or "0") == "1" else "0"
            pos += 1
            now = "1" if bool(raw[pos]) else "0"
            pos += 1
            if prev != now:
                upd.hset(f"greycode:domain:{dom}", "is_top1m", now)
                changed_domains.append(dom)
        await upd.execute()
    if changed_domains:
        p = r.pipeline()
        for dom in changed_domains:
            p.smembers(f"greycode:seen_by:domain:{dom}")
        comp_raw = await p.execute()
        dirty: set[str] = set()
        for comps in comp_raw:
            for c in (comps or []):
                dirty.add(c)
        if dirty:
            await r.sadd(INDEX_DIRTY_COMPUTER_SET, *dirty)
    await r.hset(AKARANK_META_KEY, mapping={"last_flag_sync_at": datetime.datetime.utcnow().isoformat(), "flag_changed_domains": str(len(changed_domains))})
    return len(changed_domains)


async def refresh_akarank_top1m(r: redis.Redis) -> int:
    cfg = await r.hgetall(CFG_KEY)
    if (cfg.get("akarank_enabled") or "1") != "1":
        return 0
    url = (cfg.get("akarank_url") or DEFAULT_URL).strip()
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0), follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
    reader = csv.DictReader(io.StringIO(resp.text))
    domains = sorted({normalize_akarank_domain((row or {}).get("domain_name") or "") for row in reader if normalize_akarank_domain((row or {}).get("domain_name") or "")})
    if not domains:
        return 0
    tmp = f"{AKARANK_TOP1M_SET}:tmp"
    p = r.pipeline()
    p.delete(tmp)
    p.sadd(tmp, *domains)
    p.rename(tmp, AKARANK_TOP1M_SET)
    p.hset(AKARANK_META_KEY, mapping={"last_success_at": datetime.datetime.utcnow().isoformat(), "size": str(len(domains)), "url": url})
    await p.execute()
    await sync_akarank_flags_for_known_domains(r)
    return len(domains)


async def refresh_akarank_if_due(r: redis.Redis, *, min_minutes: int = 15, max_minutes: int = 10080) -> bool:
    cfg = await r.hgetall(CFG_KEY)
    if (cfg.get("akarank_enabled") or "1") != "1":
        return False
    try:
        interval_min = int(cfg.get("akarank_update_interval_min") or 1440)
    except Exception:
        interval_min = 1440
    interval_min = max(min_minutes, min(max_minutes, interval_min))
    last_success_at = (await r.hget(AKARANK_META_KEY, "last_success_at")) or ""
    if last_success_at:
        try:
            last_epoch = datetime.datetime.fromisoformat(last_success_at).timestamp()
            if (time.time() - last_epoch) < (interval_min * 60):
                return False
        except Exception:
            pass
    await refresh_akarank_top1m(r)
    return True
