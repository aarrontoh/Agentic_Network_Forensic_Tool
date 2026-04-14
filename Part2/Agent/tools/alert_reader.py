"""
Phase 1 – Suricata EVE alert ingestion.

Streams the sensor alert JSON file (Elastic-wrapped Suricata EVE format) and returns:
  - Categorised alert lists (C2, trojan, exfil, lateral, ransomware, policy, scan, other)
  - IOC sets: suspicious IPs (internal + external), community IDs
  - Summary statistics for reporting

The file can be hundreds of MB so we stream it line-by-line without loading into RAM.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

from tools.common import is_internal_ip

# Safety cap: collect at most this many alerts per category to avoid OOM
_MAX_PER_CAT = 500_000

# Internal IPs that appear in more than this fraction of alerts are likely
# infrastructure (DNS servers, domain controllers) and should NOT be sent
# to the Zeek grep filter — they match virtually every record and destroy
# signal.  They are still kept in internal_ips for reference, just excluded
# from the IOC set used for Zeek correlation.
_INFRA_IP_ALERT_FRACTION = 0.10


def _classify(rule_name: str, rule_category: str) -> str:
    """Return a coarse threat category string for a Suricata alert."""
    n = rule_name.lower()
    c = rule_category.lower()
    # Early exit: known false-positive patterns that should NOT be ransomware
    if "basic auth" in n or "password detected" in n:
        return "policy"
    if any(k in n for k in ("botnet", " c2 ", "command and control", "cnc", "cobalt", "empire", "beacon")):
        return "c2"
    if any(k in n for k in ("exfil", "data leak", "temp.sh", "upload", "transfer")):
        return "exfiltration"
    if any(k in n for k in ("ransomware", "lynx", "ransom", "encrypt", "file drop", "deployment")):
        return "ransomware"
    if any(k in n for k in ("lateral", "psexec", "wmi", "smb", "rdp", "pass the", "remote exec", "winrm")):
        return "lateral"
    if "trojan" in c or "malware" in c:
        return "trojan"
    if "policy" in c or "privacy" in c:
        return "policy"
    if "scan" in n or "scan" in c or "sweep" in n:
        return "scan"
    return "other"


def read_alerts(alert_json_path: str, internal_networks) -> Dict[str, Any]:
    """
    Parse the Suricata EVE alert JSON file and return a structured artifact dict.

    Keys returned
    -------------
    total_alerts          int
    external_ips          List[str]   – external IPs seen in alerts
    internal_ips          List[str]   – internal IPs seen in alerts
    all_ips               List[str]   – union of the above
    community_ids         List[str]   – community IDs for Zeek cross-reference
    categories            Dict[str,int] – per-category alert counts
    top_rules             List[{"name":str,"count":int}]
    alerts_by_category    Dict[str,List[dict]]
    """
    path = Path(alert_json_path)
    if not path.exists():
        return {
            "error": f"Alert file not found: {alert_json_path}",
            "total_alerts": 0,
            "external_ips": [],
            "internal_ips": [],
            "all_ips": [],
            "community_ids": [],
            "categories": {},
            "top_rules": [],
            "alerts_by_category": {},
        }

    _cats = ["c2", "exfiltration", "ransomware", "lateral", "trojan", "policy", "scan", "other"]
    # High-priority categories whose community IDs are worth sending to Zeek grep.
    # Low-signal categories (trojan, policy, other) generate too many community IDs.
    _HIGH_PRI_CATS = {"c2", "exfiltration", "ransomware", "lateral", "scan"}

    buckets: Dict[str, List[dict]] = {c: [] for c in _cats}
    cat_true_counts: Dict[str, int] = {c: 0 for c in _cats}  # true counts (not capped)
    external_ips: Set[str] = set()
    internal_ips: Set[str] = set()
    community_ids: Set[str] = set()          # all community IDs (for reference)
    highpri_community_ids: Set[str] = set()  # only from high-priority categories
    rule_counts: Dict[str, int] = {}
    ip_alert_freq: Dict[str, int] = defaultdict(int)  # per-IP alert count
    total = 0

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                rec = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            # Skip non-alert EVE records (stats, flow, dns, etc.)
            rule = rec.get("rule", {})
            if not rule or not rule.get("name"):
                continue

            total += 1

            src_ip = rec.get("source", {}).get("ip", "")
            dst_ip = rec.get("destination", {}).get("ip", "")

            rule_name = rule.get("name", "")
            rule_cat = rule.get("category", "")
            cid = rec.get("network", {}).get("community_id", "")

            if cid:
                community_ids.add(cid)
            for ip in (src_ip, dst_ip):
                if not ip:
                    continue
                ip_alert_freq[ip] += 1
                if is_internal_ip(ip, internal_networks):
                    internal_ips.add(ip)
                else:
                    external_ips.add(ip)

            rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
            cat = _classify(rule_name, rule_cat)
            cat_true_counts[cat] += 1

            # Only keep community IDs from high-priority categories for Zeek grep
            if cid and cat in _HIGH_PRI_CATS:
                highpri_community_ids.add(cid)

            if len(buckets[cat]) < _MAX_PER_CAT:
                buckets[cat].append({
                    "ts": rec.get("@timestamp", ""),
                    "src_ip": src_ip,
                    "src_port": rec.get("source", {}).get("port", 0),
                    "dst_ip": dst_ip,
                    "dst_port": rec.get("destination", {}).get("port", 0),
                    "protocol": rec.get("network", {}).get("protocol", ""),
                    "direction": rec.get("network", {}).get("direction", ""),
                    "community_id": cid,
                    "rule_name": rule_name,
                    "rule_id": rule.get("id", ""),
                    "category": rule_cat,
                    "severity": (
                        rec.get("suricata", {})
                        .get("eve", {})
                        .get("alert", {})
                        .get("severity", 0)
                    ),
                    # geo enrichment when available
                    "src_country": rec.get("source", {}).get("geo", {}).get("country_name", ""),
                    "dst_country": rec.get("destination", {}).get("geo", {}).get("country_name", ""),
                })

    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:25]

    # ── Filter out infrastructure IPs that would flood the Zeek grep ─────────
    # Internal IPs appearing in >10% of alerts are infrastructure (DNS, DC).
    # External IPs are always kept — they're specific threat indicators.
    infra_threshold = max(1, int(total * _INFRA_IP_ALERT_FRACTION))
    infra_ips = {
        ip for ip, cnt in ip_alert_freq.items()
        if cnt >= infra_threshold and ip in internal_ips
    }
    # IOC IPs = all external + non-infrastructure internal
    ioc_internal_ips = internal_ips - infra_ips
    ioc_all_ips = external_ips | ioc_internal_ips

    return {
        "total_alerts": total,
        "external_ips": sorted(external_ips),
        "internal_ips": sorted(internal_ips),
        "all_ips": sorted(ioc_all_ips),           # filtered for Zeek grep
        "all_ips_unfiltered": sorted(external_ips | internal_ips),  # full set for analysis tools
        "infra_ips": sorted(infra_ips),            # excluded from grep (for reporting)
        "community_ids": sorted(highpri_community_ids),  # only high-priority for Zeek grep
        "community_ids_all": sorted(community_ids),      # full set for reference
        "categories": cat_true_counts,
        "top_rules": [{"name": n, "count": cnt} for n, cnt in top_rules],
        "alerts_by_category": buckets,
    }
