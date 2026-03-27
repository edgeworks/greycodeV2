from __future__ import annotations

from typing import Optional


def idx_z_last_seen(kind: str) -> str:
    return f"greycode:index:{kind}:last_seen"


def idx_z_count(kind: str) -> str:
    return f"greycode:index:{kind}:count_total"


def idx_z_rare(kind: str) -> str:
    # Same score as count_total, but UI uses ascending order for "rare"
    return f"greycode:index:{kind}:rare"


def idx_s_status(kind: str, status: str) -> str:
    return f"greycode:index:{kind}:status:{(status or '').upper()}"


def idx_s_listing(kind: str, listing_state: str) -> str:
    return f"greycode:index:{kind}:listing_state:{(listing_state or '').upper()}"


def idx_s_disposition(kind: str, disposition: str) -> str:
    return f"greycode:index:{kind}:disposition:{(disposition or '').upper()}"


def idx_s_triage(kind: str, triage: str) -> str:
    return f"greycode:index:{kind}:triage:{(triage or '').upper()}"

def idx_s_tag(kind: str, tag: str) -> str:
    return f"greycode:index:{kind}:tag:{(tag or '').strip().lower()}"


def idx_s_tags_catalog(kind: str) -> str:
    return f"greycode:index:{kind}:tags"


async def update_common_indexes(
    r,
    *,
    kind: str,                 # sha256 | ip | domain
    indicator: str,
    status: str,
    count_total: int,
    last_seen_epoch: float,
) -> None:
    await r.zadd(idx_z_last_seen(kind), {indicator: float(last_seen_epoch)})
    await r.zadd(idx_z_count(kind), {indicator: float(count_total)})
    await r.zadd(idx_z_rare(kind), {indicator: float(count_total)})  # ascending = rarer first

    for s in ("RED", "GREY", "GREEN", "ERROR"):
        await r.srem(idx_s_status(kind, s), indicator)
    await r.sadd(idx_s_status(kind, status), indicator)


async def update_sha256_indexes(
    r,
    *,
    sha256: str,
    status: str,
    count_total: int,
    last_seen_epoch: float,
    disposition: str = "",
) -> None:
    await update_common_indexes(
        r,
        kind="sha256",
        indicator=sha256,
        status=status,
        count_total=count_total,
        last_seen_epoch=last_seen_epoch,
    )

    for d in ("ACCEPTED", "ESCALATED"):
        await r.srem(idx_s_disposition("sha256", d), sha256)
    if disposition:
        await r.sadd(idx_s_disposition("sha256", disposition), sha256)

    for t in ("OPEN", "TRIAGED"):
        await r.srem(idx_s_triage("sha256", t), sha256)

    if status == "RED" and not disposition:
        await r.sadd(idx_s_triage("sha256", "OPEN"), sha256)
    elif disposition:
        await r.sadd(idx_s_triage("sha256", "TRIAGED"), sha256)


async def update_listing_indexes(
    r,
    *,
    kind: str,                 # ip | domain
    indicator: str,
    status: str,
    count_total: int,
    last_seen_epoch: float,
    listing_state: str = "",
) -> None:
    await update_common_indexes(
        r,
        kind=kind,
        indicator=indicator,
        status=status,
        count_total=count_total,
        last_seen_epoch=last_seen_epoch,
    )

    for ls in ("LISTED", "NO_LISTING", "PENDING", "ERROR"):
        await r.srem(idx_s_listing(kind, ls), indicator)
    if listing_state:
        await r.sadd(idx_s_listing(kind, listing_state), indicator)


async def remove_from_all_indexes(
    r,
    *,
    kind: str,                 # sha256 | ip | domain
    indicator: str,
) -> None:
    await r.zrem(idx_z_last_seen(kind), indicator)
    await r.zrem(idx_z_count(kind), indicator)
    await r.zrem(idx_z_rare(kind), indicator)

    for s in ("RED", "GREY", "GREEN", "ERROR"):
        await r.srem(idx_s_status(kind, s), indicator)

    if kind == "sha256":
        for t in ("OPEN", "TRIAGED"):
            await r.srem(idx_s_triage(kind, t), indicator)
        for d in ("ACCEPTED", "ESCALATED"):
            await r.srem(idx_s_disposition(kind, d), indicator)

    if kind in ("ip", "domain"):
        for ls in ("LISTED", "NO_LISTING", "PENDING", "ERROR"):
            await r.srem(idx_s_listing(kind, ls), indicator)

    await remove_from_all_tag_indexes(r, kind=kind, indicator=indicator)


async def update_tag_indexes(
    r,
    *,
    kind: str,                 # sha256 | ip | domain
    indicator: str,
    tags: list[str],
) -> None:
    tags = sorted({(t or "").strip().lower() for t in tags if (t or "").strip()})

    catalog_key = idx_s_tags_catalog(kind)

    # remove indicator from existing tag membership sets first
    existing_tags = await r.smembers(catalog_key)
    for t in existing_tags:
        await r.srem(idx_s_tag(kind, t), indicator)

    # add new memberships
    if tags:
        await r.sadd(catalog_key, *tags)
        for t in tags:
            await r.sadd(idx_s_tag(kind, t), indicator)


async def remove_from_all_tag_indexes(
    r,
    *,
    kind: str,
    indicator: str,
) -> None:
    catalog_key = idx_s_tags_catalog(kind)
    existing_tags = await r.smembers(catalog_key)
    for t in existing_tags:
        await r.srem(idx_s_tag(kind, t), indicator)