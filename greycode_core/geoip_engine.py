# greycode_core/geoip_engine.py

from __future__ import annotations

import ipaddress
import os
import time
from typing import Any

try:
    import maxminddb
except Exception:
    maxminddb = None


GEOIP_DIR = os.getenv("GREYCODE_GEOIP_DIR", "/app/data/geoip")

ASN_DB_PATH = os.path.join(GEOIP_DIR, "GeoLite2-ASN.mmdb")
CITY_DB_PATH = os.path.join(GEOIP_DIR, "GeoLite2-City.mmdb")


_asn_reader = None
_city_reader = None
_asn_mtime = None
_city_mtime = None


def _safe_mtime(path: str) -> float | None:
    try:
        return os.path.getmtime(path)
    except Exception:
        return None


def _reload_reader_if_needed() -> None:
    """
    Lazy-load and hot-reload MMDB readers if files changed.
    Safe to call frequently.
    """
    global _asn_reader
    global _city_reader
    global _asn_mtime
    global _city_mtime

    if maxminddb is None:
        return

    asn_mtime = _safe_mtime(ASN_DB_PATH)
    city_mtime = _safe_mtime(CITY_DB_PATH)

    if asn_mtime != _asn_mtime:
        try:
            if _asn_reader:
                _asn_reader.close()
        except Exception:
            pass

        _asn_reader = None
        _asn_mtime = asn_mtime

        if asn_mtime:
            try:
                _asn_reader = maxminddb.open_database(ASN_DB_PATH)
            except Exception:
                _asn_reader = None

    if city_mtime != _city_mtime:
        try:
            if _city_reader:
                _city_reader.close()
        except Exception:
            pass

        _city_reader = None
        _city_mtime = city_mtime

        if city_mtime:
            try:
                _city_reader = maxminddb.open_database(CITY_DB_PATH)
            except Exception:
                _city_reader = None


def geoip_available() -> dict[str, Any]:
    """
    Status helper for UI/settings.
    """
    return {
        "library_available": maxminddb is not None,
        "asn": {
            "present": os.path.exists(ASN_DB_PATH),
            "path": ASN_DB_PATH,
            "mtime": _safe_mtime(ASN_DB_PATH),
        },
        "city": {
            "present": os.path.exists(CITY_DB_PATH),
            "path": CITY_DB_PATH,
            "mtime": _safe_mtime(CITY_DB_PATH),
        },
    }


def _is_private_or_reserved(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_multicast
            or obj.is_reserved
            or obj.is_link_local
        )
    except Exception:
        return True


def geoip_lookup_sync(ip: str) -> dict[str, str]:
    """
    Returns normalized GeoIP fields ready for Redis hset().
    Safe to call even if GeoIP is disabled/missing.
    """

    result: dict[str, str] = {}

    if not ip:
        return result

    if _is_private_or_reserved(ip):
        return result

    if maxminddb is None:
        return result

    _reload_reader_if_needed()

    asn_data = None
    city_data = None

    #
    # ASN
    #
    if _asn_reader:
        try:
            asn_data = _asn_reader.get(ip)
        except Exception:
            asn_data = None

    if asn_data:
        asn = asn_data.get("autonomous_system_number")
        as_org = asn_data.get("autonomous_system_organization")

        if asn is not None:
            result["geo_asn"] = str(asn)

        if as_org:
            result["geo_as_org"] = str(as_org)

    #
    # City / Country
    #
    if _city_reader:
        try:
            city_data = _city_reader.get(ip)
        except Exception:
            city_data = None

    if city_data:
        country = city_data.get("country") or {}
        continent = city_data.get("continent") or {}
        city = city_data.get("city") or {}
        location = city_data.get("location") or {}

        country_iso = country.get("iso_code")
        country_name = (country.get("names") or {}).get("en")

        continent_code = continent.get("code")
        continent_name = (continent.get("names") or {}).get("en")

        city_name = (city.get("names") or {}).get("en")

        lat = location.get("latitude")
        lon = location.get("longitude")

        if country_iso:
            result["geo_country_iso"] = str(country_iso)

        if country_name:
            result["geo_country_name"] = str(country_name)

        if continent_code:
            result["geo_continent_code"] = str(continent_code)

        if continent_name:
            result["geo_continent_name"] = str(continent_name)

        if city_name:
            result["geo_city"] = str(city_name)

        if lat is not None:
            result["geo_latitude"] = str(lat)

        if lon is not None:
            result["geo_longitude"] = str(lon)

    if result:
        result["geo_source"] = "maxmind"
        result["geo_last_checked"] = str(int(time.time()))

    return result