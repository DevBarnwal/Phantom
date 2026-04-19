#!/usr/bin/env python3
"""
threat_detector.py
Security threat detection for NetSniffer.

Detectors:
  1. Port Scan   — one IP hits many distinct ports within a time window
  2. ARP Spoof   — same IP claimed by multiple MACs, or MAC/IP mapping changes

Each detector is stateful — feed packets one at a time via .analyze(pkt).
Returns a list of Alert dicts (may be empty) for every packet.

Alert dict keys:
    type        : "PORT_SCAN" | "ARP_SPOOF"
    severity    : "HIGH" | "MEDIUM"
    src         : attacker/suspect IP or MAC
    detail      : human-readable description
    timestamp   : time string
    packet_info : the triggering packet_info dict
"""

import time
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# ── TUNING CONSTANTS ─────────────────────────────────────────────────────────
# Port scan: alert if one IP hits this many distinct ports within the window
PORT_SCAN_THRESHOLD  = 15       # distinct ports
PORT_SCAN_WINDOW_SEC = 10       # seconds

# ARP spoof: alert if one IP is seen with more than this many distinct MACs
ARP_SPOOF_MAC_LIMIT  = 1        # 1 = any change triggers alert


class Alert:
    """Represents a single security alert."""
    SEVERITY_COLORS = {
        "HIGH":   ("#5c1a1a", "#ff6b6b"),   # dark red bg / bright red text
        "MEDIUM": ("#3d2800", "#ffaa55"),   # dark orange bg / orange text
    }

    def __init__(self, alert_type, severity, src, detail, timestamp, packet_info):
        self.type        = alert_type
        self.severity    = severity
        self.src         = src
        self.detail      = detail
        self.timestamp   = timestamp
        self.packet_info = packet_info

    def to_dict(self):
        return {
            "type":      self.type,
            "severity":  self.severity,
            "src":       self.src,
            "detail":    self.detail,
            "timestamp": self.timestamp,
        }


class PortScanDetector:
    """
    Tracks distinct destination ports per source IP within a rolling window.
    Fires once per attacker IP per window — resets after firing.
    """

    def __init__(self,
                 threshold=PORT_SCAN_THRESHOLD,
                 window_sec=PORT_SCAN_WINDOW_SEC):
        self.threshold  = threshold
        self.window_sec = window_sec
        # ip → list of (timestamp_float, dst_port)
        self._history: dict[str, list] = defaultdict(list)
        # IPs that already fired in the current window (avoid alert storm)
        self._alerted: dict[str, float] = {}

    def analyze(self, pkt: dict) -> Alert | None:
        """Feed one packet_info dict. Returns Alert or None."""
        proto = pkt.get("protocol", "")
        if proto not in ("TCP", "HTTPS", "HTTP"):
            return None

        raw = pkt.get("packet")
        if raw is None:
            return None

        try:
            from scapy.layers.inet import TCP
            if not raw.haslayer(TCP):
                return None
            dport = raw[TCP].dport
            src   = pkt.get("src", "")
            if not src:
                return None
        except Exception:
            return None

        now = time.time()

        # Prune old entries outside the window
        self._history[src] = [
            (t, p) for t, p in self._history[src]
            if now - t <= self.window_sec
        ]
        self._history[src].append((now, dport))

        # Count distinct ports in window
        distinct_ports = {p for _, p in self._history[src]}

        # Check if already alerted recently for this IP
        last_alert = self._alerted.get(src, 0)
        if now - last_alert < self.window_sec:
            return None

        if len(distinct_ports) >= self.threshold:
            self._alerted[src] = now
            self._history[src].clear()   # reset window after alert

            port_list = sorted(distinct_ports)[:10]
            ports_str = ", ".join(str(p) for p in port_list)
            if len(distinct_ports) > 10:
                ports_str += f" ... (+{len(distinct_ports)-10} more)"

            detail = (f"Port scan detected from {src} — "
                      f"{len(distinct_ports)} ports in {self.window_sec}s "
                      f"(e.g. {ports_str})")

            logger.warning(detail)
            return Alert(
                alert_type   = "PORT_SCAN",
                severity     = "HIGH",
                src          = src,
                detail       = detail,
                timestamp    = pkt.get("timestamp", ""),
                packet_info  = pkt,
            )

        return None


class ArpSpoofDetector:
    """
    Maintains an IP→MAC mapping table.
    Fires when an IP is claimed by a new/different MAC address.
    """

    def __init__(self):
        # ip → set of MACs seen
        self._ip_to_macs: dict[str, set] = defaultdict(set)
        # (ip, mac) pairs that already triggered alerts
        self._alerted: set = set()

    def analyze(self, pkt: dict) -> Alert | None:
        """Feed one packet_info dict. Returns Alert or None."""
        if pkt.get("protocol") != "ARP":
            return None

        raw = pkt.get("packet")
        if raw is None:
            return None

        try:
            from scapy.layers.l2 import ARP
            if not raw.haslayer(ARP):
                return None
            arp = raw[ARP]
            # op=1 is who-has (request), op=2 is is-at (reply) — both matter
            ip  = arp.psrc
            mac = arp.hwsrc
            if not ip or not mac or ip == "0.0.0.0":
                return None
        except Exception:
            return None

        known_macs = self._ip_to_macs[ip]

        if not known_macs:
            # First time seeing this IP — just record it
            known_macs.add(mac)
            return None

        if mac in known_macs:
            return None   # consistent — no alert

        # New MAC for a known IP — potential spoof
        alert_key = (ip, mac)
        if alert_key in self._alerted:
            return None   # already alerted for this exact pair

        self._alerted.add(alert_key)
        known_macs.add(mac)

        old_macs = ", ".join(known_macs - {mac})
        detail = (f"ARP spoofing suspected — IP {ip} "
                  f"now claims MAC {mac} "
                  f"(previously seen with: {old_macs})")

        logger.warning(detail)
        return Alert(
            alert_type  = "ARP_SPOOF",
            severity    = "HIGH",
            src         = ip,
            detail      = detail,
            timestamp   = pkt.get("timestamp", ""),
            packet_info = pkt,
        )


class ThreatDetector:
    """
    Aggregates all detectors.
    Call .analyze(pkt) for every packet — returns list of Alert objects.
    """

    def __init__(self):
        self._port_scan = PortScanDetector()
        self._arp_spoof = ArpSpoofDetector()
        self.alert_count = 0

    def analyze(self, pkt: dict) -> list:
        alerts = []
        for detector in (self._port_scan, self._arp_spoof):
            try:
                alert = detector.analyze(pkt)
                if alert:
                    alerts.append(alert)
                    self.alert_count += 1
            except Exception as e:
                logger.debug(f"Detector error: {e}")
        return alerts

    def reset(self):
        self._port_scan = PortScanDetector()
        self._arp_spoof = ArpSpoofDetector()
        self.alert_count = 0