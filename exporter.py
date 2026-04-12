#!/usr/bin/env python3
"""
exporter.py
Export captured packets to PCAP, CSV, or JSON.

CSV / JSON include both visible columns AND full GeoIP detail columns:
    timestamp, src, dst,
    src_country, src_city, src_region, src_org, src_asn, src_lat, src_lon,
    dst_country, dst_city, dst_region, dst_org, dst_asn, dst_lat, dst_lon,
    geo_summary (flag + country, city of src),
    protocol, length, info
"""

import csv
import json
import logging
import os
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def _geo_flat(geo_result: dict, prefix: str) -> dict:
    """
    Flatten a GeoLookup.lookup() result into prefixed CSV/JSON columns.
    e.g. prefix='src' → {'src_country': 'United States', 'src_city': 'Oregon', ...}
    """
    return {
        f"{prefix}_country":  geo_result.get("country", ""),
        f"{prefix}_city":     geo_result.get("city", ""),
        f"{prefix}_region":   geo_result.get("region", ""),
        f"{prefix}_org":      geo_result.get("org", ""),
        f"{prefix}_asn":      geo_result.get("asn", ""),
        f"{prefix}_lat":      geo_result.get("latitude", ""),
        f"{prefix}_lon":      geo_result.get("longitude", ""),
    }


def _build_rows(packets: list, geo) -> list[dict]:
    """
    Build a list of flat dicts from _all_packets + GeoLookup instance.
    Each dict has all visible + full GeoIP columns.
    """
    rows = []
    for pkt in packets:
        src = pkt.get("src", "")
        dst = pkt.get("dst", "")

        src_geo = geo.lookup(src)
        dst_geo = geo.lookup(dst)

        row = {
            "timestamp":   pkt.get("timestamp", ""),
            "src":         src,
            "dst":         dst,
            # Full GeoIP for src
            **_geo_flat(src_geo, "src"),
            # Full GeoIP for dst
            **_geo_flat(dst_geo, "dst"),
            # Short geo summary (flag + country, city)
            "geo_summary": pkt.get("geo_summary", src_geo.get("summary", "")),
            "protocol":    pkt.get("protocol", ""),
            "length":      pkt.get("length", ""),
            "info":        pkt.get("info", ""),
        }
        rows.append(row)
    return rows


# ── PCAP ─────────────────────────────────────────────────────────────────────

def export_pcap(packets: list, filename: str) -> tuple[bool, str, int]:
    """
    Save raw Scapy packets to a .pcap file.
    packets: list of packet_info dicts (each has a 'packet' key with raw Scapy pkt)
    """
    try:
        from scapy.all import wrpcap
        raw = [p["packet"] for p in packets if p.get("packet") is not None]
        if not raw:
            return False, "No raw packets available to save.", 0
        wrpcap(filename, raw)
        msg = f"Saved {len(raw)} packets to {os.path.basename(filename)}"
        logger.info(msg)
        return True, msg, len(raw)
    except Exception as e:
        msg = f"PCAP export failed: {e}"
        logger.error(msg)
        return False, msg, 0


# ── CSV ──────────────────────────────────────────────────────────────────────

def export_csv(packets: list, geo, filename: str) -> tuple[bool, str, int]:
    """
    Export packets to CSV with visible + full GeoIP columns.
    """
    try:
        rows = _build_rows(packets, geo)
        if not rows:
            return False, "No packets to export.", 0

        fieldnames = list(rows[0].keys())
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        msg = f"Exported {len(rows)} packets to {os.path.basename(filename)}"
        logger.info(msg)
        return True, msg, len(rows)
    except Exception as e:
        msg = f"CSV export failed: {e}"
        logger.error(msg)
        return False, msg, 0


# ── JSON ─────────────────────────────────────────────────────────────────────

def export_json(packets: list, geo, filename: str) -> tuple[bool, str, int]:
    """
    Export packets to JSON with visible + full GeoIP columns.
    Output structure:
    {
        "exported_at": "2026-04-12T17:30:00",
        "total_packets": 300,
        "packets": [ { ...row dict... }, ... ]
    }
    """
    try:
        rows = _build_rows(packets, geo)
        if not rows:
            return False, "No packets to export.", 0

        # Convert any non-serialisable values (e.g. None lat/lon) to strings
        clean_rows = []
        for row in rows:
            clean_rows.append({
                k: ("" if v is None else v)
                for k, v in row.items()
            })

        payload = {
            "exported_at":   datetime.now().isoformat(timespec="seconds"),
            "total_packets": len(clean_rows),
            "packets":       clean_rows,
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        msg = f"Exported {len(clean_rows)} packets to {os.path.basename(filename)}"
        logger.info(msg)
        return True, msg, len(clean_rows)
    except Exception as e:
        msg = f"JSON export failed: {e}"
        logger.error(msg)
        return False, msg, 0