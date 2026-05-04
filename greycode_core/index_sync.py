import time
import fnmatch
import ipaddress
import json
from typing import Optional

import redis.asyncio as redis

try:
    from indexes import (
        update_sha256_indexes,
        update_listing_indexes,
        update_computer_indexes,
        remove_from_all_indexes,
        remove_computer_from_indexes,
    )
except ModuleNotFoundError:
    from greycode_core.indexes import (
        update_sha256_indexes,
        update_listing_indexes,
        update_computer_indexes,
        remove_from_all_indexes,
        remove_computer_from_indexes,
    )


KNOWN_SHA256_SET = "greycode:known:sha256"
KNOWN_IPS_SET = "greycode:known:ips"
KNOWN_DOMAINS_SET = "greycode:known:domains"
KNOWN_COMPUTERS_SET = "greycode:known:computers"

DEFAULT_RARE_COMPUTER_THRESHOLD = 10

CFG_KEY = "greycode:cfg"
MANUAL_FILTERS_KEY = "greycode:cfg:manual_filters"

SCORING_FALLBACKS = {
    "rare_computer_threshold": 10,
    "weight_rare_unknown_hash": 25,
    "weight_rare_sha256": 6,
    "weight_rare_ip": 5,
    "weight_rare_domain": 3,
    "weight_listed": 10,
    "weight_red": 5,
}

def iso_to_epoch(ts: Optional[str]) -> float:
    if not ts:
        return time.time()
    try:
        return __import__("datetime").datetime.fromisoformat(ts).timestamp()
    except Exception:
        return time.time()


def record_key_for_kind(kind: str, indicator: str) -> str:
    if kind == "sha256":
        return f"greycode:sha256:{indicator}"
    if kind == "ip":
        return f"greycode:ip:{indicator}"
    if kind == "domain":
        return f"greycode:domain:{indicator}"
    raise ValueError(f"Unknown kind: {kind}")


def normalize_computer(computer: str) -> str:
    return (computer or "").strip().lower().rstrip(".")


def computer_key(computer: str) -> str:
    return f"greycode:computer:{normalize_computer(computer)}"


def computer_sha256_set(computer: str) -> str:
    return f"greycode:computer:{normalize_computer(computer)}:sha256"


def computer_ip_set(computer: str) -> str:
    return f"greycode:computer:{normalize_computer(computer)}:ips"


def computer_domain_set(computer: str) -> str:
    return f"greycode:computer:{normalize_computer(computer)}:domains"


def seen_by_computers_key(kind: str, indicator: str) -> str:
    return f"greycode:seen_by:{kind}:{indicator}"

def computer_excluded_set(computer: str, kind: str) -> str:
    computer_norm = normalize_computer(computer)
    if kind == "sha256":
        return f"greycode:computer:{computer_norm}:excluded:sha256"
    if kind == "ip":
        return f"greycode:computer:{computer_norm}:excluded:ip"
    if kind == "domain":
        return f"greycode:computer:{computer_norm}:excluded:domain"
    raise ValueError(f"Unknown exclusion kind: {kind}")

def _safe_score_int(raw: str | None, default: int, lo: int = 0, hi: int = 100000) -> int:
    try:
        n = int(raw or default)
        return max(lo, min(hi, n))
    except Exception:
        return default


async def load_scoring_settings_from_redis(r: redis.Redis) -> dict[str, int]:
    cfg = await r.hgetall(CFG_KEY)

    return {
        "rare_computer_threshold": _safe_score_int(
            cfg.get("scoring_rare_computer_threshold"),
            SCORING_FALLBACKS["rare_computer_threshold"],
            1,
        ),
        "weight_rare_unknown_hash": _safe_score_int(
            cfg.get("scoring_weight_rare_unknown_hash"),
            SCORING_FALLBACKS["weight_rare_unknown_hash"],
        ),
        "weight_rare_sha256": _safe_score_int(
            cfg.get("scoring_weight_rare_sha256"),
            SCORING_FALLBACKS["weight_rare_sha256"],
        ),
        "weight_rare_ip": _safe_score_int(
            cfg.get("scoring_weight_rare_ip"),
            SCORING_FALLBACKS["weight_rare_ip"],
        ),
        "weight_rare_domain": _safe_score_int(
            cfg.get("scoring_weight_rare_domain"),
            SCORING_FALLBACKS["weight_rare_domain"],
        ),
        "weight_listed": _safe_score_int(
            cfg.get("scoring_weight_listed"),
            SCORING_FALLBACKS["weight_listed"],
        ),
        "weight_red": _safe_score_int(
            cfg.get("scoring_weight_red"),
            SCORING_FALLBACKS["weight_red"],
        ),
    }

async def sync_sha256_indexes(r: redis.Redis, sha256_value: str) -> None:
    key = f"greycode:sha256:{sha256_value}"
    data = await r.hgetall(key)

    if not data:
        await remove_from_all_indexes(r, kind="sha256", indicator=sha256_value)
        await r.srem(KNOWN_SHA256_SET, sha256_value)
        return

    await r.sadd(KNOWN_SHA256_SET, sha256_value)

    await update_sha256_indexes(
        r,
        sha256=sha256_value,
        status=(data.get("status") or "GREY").upper(),
        count_total=int(data.get("count_total") or 0),
        last_seen_epoch=iso_to_epoch(data.get("last_seen")),
        disposition=(data.get("disposition") or "").upper(),
    )


async def sync_ip_indexes(r: redis.Redis, ip_value: str) -> None:
    key = f"greycode:ip:{ip_value}"
    data = await r.hgetall(key)

    if not data:
        await remove_from_all_indexes(r, kind="ip", indicator=ip_value)
        await r.srem(KNOWN_IPS_SET, ip_value)
        return

    await r.sadd(KNOWN_IPS_SET, ip_value)

    await update_listing_indexes(
        r,
        kind="ip",
        indicator=ip_value,
        status=(data.get("status") or "GREY").upper(),
        count_total=int(data.get("count_total") or 0),
        last_seen_epoch=iso_to_epoch(data.get("last_seen")),
        listing_state=(data.get("listing_state") or "").upper(),
    )


async def sync_domain_indexes(r: redis.Redis, domain_value: str) -> None:
    key = f"greycode:domain:{domain_value}"
    data = await r.hgetall(key)

    if not data:
        await remove_from_all_indexes(r, kind="domain", indicator=domain_value)
        await r.srem(KNOWN_DOMAINS_SET, domain_value)
        return

    await r.sadd(KNOWN_DOMAINS_SET, domain_value)

    await update_listing_indexes(
        r,
        kind="domain",
        indicator=domain_value,
        status=(data.get("status") or "GREY").upper(),
        count_total=int(data.get("count_total") or 0),
        last_seen_epoch=iso_to_epoch(data.get("last_seen")),
        listing_state=(data.get("listing_state") or "").upper(),
    )


async def _fetch_indicator_meta(r: redis.Redis, kind: str, indicators: list[str]) -> list[dict]:
    if not indicators:
        return []

    pipe = r.pipeline()
    for indicator in indicators:
        pipe.hgetall(record_key_for_kind(kind, indicator))
        pipe.scard(seen_by_computers_key(kind, indicator))
    raw = await pipe.execute()

    out: list[dict] = []
    pos = 0
    for indicator in indicators:
        data = raw[pos] or {}
        pos += 1
        computer_count = int(raw[pos] or 0)
        pos += 1

        out.append(
            {
                "indicator": indicator,
                "data": data,
                "computer_count": computer_count,
            }
        )

    return out

def normalize_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if not ip:
        raise ValueError("empty ip")
    return str(ipaddress.ip_address(ip))


def normalize_domain(qname: str) -> str:
    d = (qname or "").strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


def normalize_filter_kind(kind: str) -> str:
    k = (kind or "").strip().lower()
    if k not in {"image", "ip", "domain"}:
        raise ValueError("Invalid filter kind")
    return k


def normalize_image_for_match(value: str) -> str:
    v = (value or "").strip().lower()
    return v.replace("/", "\\")


def normalize_filter_pattern(kind: str, pattern: str) -> str:
    p = (pattern or "").strip()
    if not p:
        raise ValueError("Pattern is required")

    kind = normalize_filter_kind(kind)

    if kind == "image":
        return normalize_image_for_match(p)

    if kind == "domain":
        return normalize_domain(p)

    if kind == "ip":
        return p.strip()

    return p


def manual_filter_matches(kind: str, pattern: str, value: str) -> bool:
    kind = normalize_filter_kind(kind)

    if kind == "image":
        return fnmatch.fnmatchcase(
            normalize_image_for_match(value),
            normalize_filter_pattern("image", pattern),
        )

    if kind == "domain":
        v = normalize_domain(value)
        if not v:
            return False
        return fnmatch.fnmatchcase(
            v,
            normalize_filter_pattern("domain", pattern),
        )

    if kind == "ip":
        try:
            ip_norm = normalize_ip(value)
        except ValueError:
            return False

        p = normalize_filter_pattern("ip", pattern)

        if "/" in p:
            try:
                net = ipaddress.ip_network(p, strict=False)
                return ipaddress.ip_address(ip_norm) in net
            except ValueError:
                return False

        return fnmatch.fnmatchcase(ip_norm, p)

    return False


async def load_manual_filters_from_redis(r: redis.Redis) -> list[dict[str, str]]:
    raw = await r.get(MANUAL_FILTERS_KEY)
    if not raw:
        return []

    try:
        parsed = json.loads(raw)
    except Exception:
        return []

    if not isinstance(parsed, list):
        return []

    out: list[dict[str, str]] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue

        kind = (item.get("kind") or "").strip().lower()
        pattern = (item.get("pattern") or "").strip()
        rule_id = (item.get("id") or "").strip()

        if kind not in {"image", "ip", "domain"} or not pattern or not rule_id:
            continue

        out.append({
            "id": rule_id,
            "kind": kind,
            "pattern": pattern,
        })

    return out


def is_single_label_domain(domain: str) -> bool:
    d = normalize_domain(domain)
    if not d:
        return True
    return "." not in d


async def drop_single_label_dns_setting_from_redis(r: redis.Redis) -> bool:
    val = await r.hget(CFG_KEY, "filter_drop_single_label_dns")
    return (val if val is not None else "1") == "1"


async def indicator_is_filtered_for_scoring(
    r: redis.Redis,
    *,
    kind: str,
    indicator: str,
    data: dict[str, str] | None,
    manual_filters: list[dict[str, str]],
) -> bool:
    if kind == "sha256":
        image = ""
        if data:
            image = data.get("image") or ""
        return bool(image and any(
            f.get("kind") == "image" and manual_filter_matches("image", f.get("pattern") or "", image)
            for f in manual_filters
        ))

    if kind == "ip":
        try:
            ip_norm = normalize_ip(indicator)
        except ValueError:
            return True

        return any(
            f.get("kind") == "ip" and manual_filter_matches("ip", f.get("pattern") or "", ip_norm)
            for f in manual_filters
        )

    if kind == "domain":
        dom = normalize_domain(indicator)
        if not dom:
            return True

        if await drop_single_label_dns_setting_from_redis(r) and is_single_label_domain(dom):
            return True

        return any(
            f.get("kind") == "domain" and manual_filter_matches("domain", f.get("pattern") or "", dom)
            for f in manual_filters
        )

    return False

async def sync_computer_indexes(
    r: redis.Redis,
    computer: str,
    rare_threshold: int = DEFAULT_RARE_COMPUTER_THRESHOLD,
) -> None:
    computer_norm = normalize_computer(computer)
    if not computer_norm:
        return

    key = computer_key(computer_norm)
    data = await r.hgetall(key)

    scoring = await load_scoring_settings_from_redis(r)
    rare_threshold = scoring["rare_computer_threshold"]

    if not data:
        await remove_computer_from_indexes(r, computer=computer_norm)
        await r.srem(KNOWN_COMPUTERS_SET, computer_norm)
        return

    sha256_values = sorted(await r.smembers(computer_sha256_set(computer_norm)))
    ip_values = sorted(await r.smembers(computer_ip_set(computer_norm)))
    domain_values = sorted(await r.smembers(computer_domain_set(computer_norm)))

    excluded_sha = set(await r.smembers(computer_excluded_set(computer_norm, "sha256")))
    excluded_ip = set(await r.smembers(computer_excluded_set(computer_norm, "ip")))
    excluded_domain = set(await r.smembers(computer_excluded_set(computer_norm, "domain")))

    manual_filters = await load_manual_filters_from_redis(r)

    rare_sha256 = 0
    rare_ip = 0
    rare_domain = 0
    rare_unknown_hash_count = 0
    red_count = 0
    listed_count = 0

    sha_meta = await _fetch_indicator_meta(r, "sha256", sha256_values)
    for item in sha_meta:
        indicator = item["indicator"]

        # Computer-scoped score exclusion:
        # keep the observation and global indicator state intact,
        # but do not let this indicator contribute to this computer's score.
        if indicator in excluded_sha:
            continue

        indicator_data = item["data"]
        prevalence = int(item["computer_count"] or 0)

        status = (indicator_data.get("status") or "GREY").upper()
        vt_state = (indicator_data.get("vt_state") or "").upper()

        is_rare = prevalence > 0 and prevalence <= rare_threshold

        if await indicator_is_filtered_for_scoring(
            r,
            kind="sha256",
            indicator=indicator,
            data=indicator_data,
            manual_filters=manual_filters,
        ):
            continue

        if is_rare:
            rare_sha256 += 1

        if is_rare and vt_state == "NOT_FOUND":
            rare_unknown_hash_count += 1

        if status == "RED":
            red_count += 1

    ip_meta = await _fetch_indicator_meta(r, "ip", ip_values)
    for item in ip_meta:
        indicator = item["indicator"]

        if indicator in excluded_ip:
            continue

        indicator_data = item["data"]
        prevalence = int(item["computer_count"] or 0)

        status = (indicator_data.get("status") or "GREY").upper()
        listing_state = (indicator_data.get("listing_state") or "").upper()

        if await indicator_is_filtered_for_scoring(
            r,
            kind="ip",
            indicator=indicator,
            data=indicator_data,
            manual_filters=manual_filters,
        ):
            continue

        if prevalence > 0 and prevalence <= rare_threshold:
            rare_ip += 1

        if status == "RED":
            red_count += 1

        if listing_state == "LISTED":
            listed_count += 1

    domain_meta = await _fetch_indicator_meta(r, "domain", domain_values)
    for item in domain_meta:
        indicator = item["indicator"]

        if indicator in excluded_domain:
            continue

        indicator_data = item["data"]
        prevalence = int(item["computer_count"] or 0)

        status = (indicator_data.get("status") or "GREY").upper()
        listing_state = (indicator_data.get("listing_state") or "").upper()

        if await indicator_is_filtered_for_scoring(
            r,
            kind="domain",
            indicator=indicator,
            data=indicator_data,
            manual_filters=manual_filters,
        ):
            continue
        if prevalence > 0 and prevalence <= rare_threshold:
            rare_domain += 1

        if status == "RED":
            red_count += 1

        if listing_state == "LISTED":
            listed_count += 1

    rare_total = rare_sha256 + rare_ip + rare_domain

    noticeable_score = (
        rare_unknown_hash_count * scoring["weight_rare_unknown_hash"]
        + rare_sha256 * scoring["weight_rare_sha256"]
        + rare_ip * scoring["weight_rare_ip"]
        + rare_domain * scoring["weight_rare_domain"]
        + listed_count * scoring["weight_listed"]
        + red_count * scoring["weight_red"]
    )

    mapping = {
        "type": "computer",
        "computer": computer_norm,
        "unique_sha256": str(len(sha256_values)),
        "unique_ip": str(len(ip_values)),
        "unique_domain": str(len(domain_values)),
        "rare_unknown_hash_count": str(rare_unknown_hash_count),
        "rare_sha256": str(rare_sha256),
        "rare_ip": str(rare_ip),
        "rare_domain": str(rare_domain),
        "rare_total": str(rare_total),
        "red_count": str(red_count),
        "listed_count": str(listed_count),
        "noticeable_score": str(noticeable_score),
        "index_last_sync": str(time.time()),
        "scoring_rare_computer_threshold": str(rare_threshold),
        "scoring_weight_rare_unknown_hash": str(scoring["weight_rare_unknown_hash"]),
        "scoring_weight_rare_sha256": str(scoring["weight_rare_sha256"]),
        "scoring_weight_rare_ip": str(scoring["weight_rare_ip"]),
        "scoring_weight_rare_domain": str(scoring["weight_rare_domain"]),
        "scoring_weight_listed": str(scoring["weight_listed"]),
        "scoring_weight_red": str(scoring["weight_red"]),
    }

    await r.hset(key, mapping=mapping)
    await r.sadd(KNOWN_COMPUTERS_SET, computer_norm)

    await update_computer_indexes(
        r,
        computer=computer_norm,
        noticeable_score=float(noticeable_score),
        last_seen_epoch=iso_to_epoch(data.get("last_seen")),
        rare_total=rare_total,
        rare_unknown_hash_count=rare_unknown_hash_count,
        red_count=red_count,
        listed_count=listed_count,
    )