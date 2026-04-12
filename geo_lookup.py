#!/usr/bin/env python3
"""
geo_lookup.py
GeoIP lookup module for NetSniffer.

Requires:
    pip install geoip2
    Download GeoLite2-City.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    Place the .mmdb file in the same directory as this script, or set GEOIP_DB_PATH below.

Features:
    - Country + city for table column display
    - Full details (country, city, region, ISP/org, ASN, lat/lon) for tooltip
    - In-memory LRU-style cache so each IP is only looked up once
    - Graceful fallback if geoip2 is not installed or DB file is missing
    - Skips private/loopback IPs automatically (no pointless lookups)
"""

import ipaddress
import logging
import os

logger = logging.getLogger(__name__)

# ── Path to the GeoLite2-City database ──────────────────────────────────────
# Place GeoLite2-City.mmdb next to your scripts, or change this path.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GEOIP_DB_PATH = os.path.join(_SCRIPT_DIR, "GeoLite2-City.mmdb")

# Country code → flag emoji
def _flag(cc: str) -> str:
    """Convert a 2-letter country code to a flag emoji."""
    if not cc or len(cc) != 2:
        return "🌐"
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)


class GeoLookup:
    """
    Wraps geoip2 with a simple cache.
    All public methods return plain dicts — never raise exceptions to callers.
    """

    # Max IPs to cache (oldest entry dropped when full)
    CACHE_SIZE = 2000

    def __init__(self, db_path: str = GEOIP_DB_PATH):
        self._reader = None
        self._cache: dict = {}          # ip_str → full detail dict
        self._available = False

        try:
            import geoip2.database
            if os.path.exists(db_path):
                self._reader = geoip2.database.Reader(db_path)
                self._available = True
                logger.info(f"GeoIP database loaded: {db_path}")
            else:
                logger.warning(
                    f"GeoIP database not found at {db_path}. "
                    "Download GeoLite2-City.mmdb from https://dev.maxmind.com "
                    "and place it next to your scripts."
                )
        except ImportError:
            logger.warning("geoip2 not installed — GeoIP features disabled. "
                           "Run: pip install geoip2")

    @property
    def available(self) -> bool:
        return self._available

    # ── Private IPs to skip ─────────────────────────────────────────────────

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Return True for loopback, private, link-local, multicast IPs."""
        try:
            addr = ipaddress.ip_address(ip)
            return (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_multicast or
                    addr.is_unspecified)
        except ValueError:
            return True   # malformed → treat as private, skip

    # ── Core lookup ─────────────────────────────────────────────────────────

    def lookup(self, ip: str) -> dict:
        """
        Full GeoIP lookup for one IP address.

        Returns a dict with keys:
            ip, flag, country_code, country, city, region,
            org, asn, asn_org, latitude, longitude,
            summary       (short: "🇺🇸 United States, Oregon")
            tooltip_lines (list of strings for the hover tooltip)
            is_private    (bool)
        """
        # Private / local IPs
        if self._is_private(ip):
            return self._private_result(ip)

        # Cache hit
        if ip in self._cache:
            return self._cache[ip]

        # No DB available
        if not self._available:
            result = self._unknown_result(ip)
            self._store(ip, result)
            return result

        # DB lookup
        try:
            r = self._reader.city(ip)

            cc           = r.country.iso_code or ""
            country      = r.country.name or "Unknown"
            city         = r.city.name or ""
            region       = r.subdivisions.most_specific.name or ""
            latitude     = r.location.latitude
            longitude    = r.location.longitude
            org          = ""
            asn_num      = ""
            asn_org      = ""

            # Try ASN data if available in the same DB
            try:
                asn_rec  = self._reader.asn(ip)
                asn_num  = str(asn_rec.autonomous_system_number or "")
                asn_org  = asn_rec.autonomous_system_organization or ""
                org      = asn_org
            except Exception:
                pass

            flag = _flag(cc)

            # Short summary for the table column
            parts = [p for p in [country, city] if p]
            summary = f"{flag} {', '.join(parts)}" if parts else f"{flag} Unknown"

            # Full tooltip lines
            tooltip_lines = [
                f"  IP Address  :  {ip}",
                f"  Country     :  {flag} {country} ({cc})" if cc else f"  Country     :  {flag} {country}",
                f"  City        :  {city}"   if city   else "  City        :  —",
                f"  Region      :  {region}" if region else "  Region      :  —",
                f"  Org / ISP   :  {org}"    if org    else "  Org / ISP   :  —",
                f"  ASN         :  AS{asn_num} {asn_org}".rstrip() if asn_num else "  ASN         :  —",
                f"  Coordinates :  {latitude:.4f}, {longitude:.4f}"
                    if latitude is not None else "  Coordinates :  —",
            ]

            result = {
                "ip": ip, "flag": flag,
                "country_code": cc, "country": country,
                "city": city, "region": region,
                "org": org, "asn": asn_num, "asn_org": asn_org,
                "latitude": latitude, "longitude": longitude,
                "summary": summary,
                "tooltip_lines": tooltip_lines,
                "is_private": False,
            }

        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            result = self._unknown_result(ip)

        self._store(ip, result)
        return result

    # ── Convenience: summary string only ────────────────────────────────────

    def summary(self, ip: str) -> str:
        """Return short 'flag country, city' string for the table column."""
        return self.lookup(ip)["summary"]

    def tooltip_lines(self, ip: str) -> list:
        """Return list of detail strings for the hover tooltip."""
        return self.lookup(ip)["tooltip_lines"]

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _store(self, ip: str, result: dict):
        if len(self._cache) >= self.CACHE_SIZE:
            # Drop the oldest entry
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[ip] = result

    @staticmethod
    def _private_result(ip: str) -> dict:
        label = "Loopback" if ip.startswith("127.") or ip == "::1" else "Private / Local"
        lines = [f"  IP Address  :  {ip}",
                 f"  Type        :  {label}",
                 "  GeoIP       :  Not applicable for local addresses"]
        return {
            "ip": ip, "flag": "🏠", "country_code": "",
            "country": label, "city": "", "region": "",
            "org": "", "asn": "", "asn_org": "",
            "latitude": None, "longitude": None,
            "summary": f"🏠 {label}",
            "tooltip_lines": lines,
            "is_private": True,
        }

    @staticmethod
    def _unknown_result(ip: str) -> dict:
        lines = [f"  IP Address  :  {ip}",
                 "  GeoIP       :  Database unavailable"]
        return {
            "ip": ip, "flag": "🌐", "country_code": "",
            "country": "Unknown", "city": "", "region": "",
            "org": "", "asn": "", "asn_org": "",
            "latitude": None, "longitude": None,
            "summary": "🌐 Unknown",
            "tooltip_lines": lines,
            "is_private": False,
        }

    def close(self):
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass