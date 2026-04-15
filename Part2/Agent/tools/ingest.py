"""
Ingestion pipeline – replaces the old preprocess.py.

Four phases run in order:
  1. Alert ingestion      – stream Suricata EVE alerts → IOC lists
  2. Zeek correlation     – grep + stream Zeek JSON, keep only IOC-matching records
  3. PCAP targeting       – build time-range index, select minimum PCAP subset
  4. Deep PCAP analysis   – run targeted tshark on selected PCAPs only

Results are cached in <work_dir>/ingest/ so re-runs skip expensive I/O.

Dashboard compatibility
-----------------------
progress.json is written using keys that dashboard.html already understands:
  stage           → always "preprocessing" during phases 1-4, then "analyzing" etc.
  pcap_progress   → {done, total, current, phase}  drives the progress bar
  zeek_results    → [{segment, status}]  drives the Zeek chips panel
  tshark_results  → [{segment, status}]  drives the TShark chips panel
"""
from __future__ import annotations

import datetime
import glob
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from config import AgentConfig
from tools.alert_reader import read_alerts
from tools.common import ensure_dir
from tools.pcap_deep_analysis import analyze_targeted_pcaps
from tools.pcap_selector import build_pcap_index, select_pcaps
from tools.zeek_searcher import search_zeek


# --------------------------------------------------------------------------- #
# Auto-discovery helpers
# --------------------------------------------------------------------------- #

def _find_file(directory: str, pattern: str) -> Optional[str]:
    matches = glob.glob(str(Path(directory) / pattern))
    return matches[0] if matches else None


def discover_data_sources(network_dir: str) -> Dict[str, str]:
    """
    Auto-discover alert JSON, Zeek JSON, and PCAP directory from a network data folder.
    Expects:  *alert*.json,  *zeek*.json,  pcap/ sub-directory (or *.pcap files directly).
    """
    sources: Dict[str, str] = {}
    alert_path = _find_file(network_dir, "*alert*.json")
    if alert_path:
        sources["alert_json"] = alert_path
    zeek_path = _find_file(network_dir, "*zeek*.json")
    if zeek_path:
        sources["zeek_json"] = zeek_path
    pcap_subdir = Path(network_dir) / "pcap"
    if pcap_subdir.is_dir():
        sources["pcap_dir"] = str(pcap_subdir)
    elif list(Path(network_dir).glob("*.pcap")):
        sources["pcap_dir"] = network_dir
    return sources


# --------------------------------------------------------------------------- #
# Progress helpers  (writes dashboard-compatible progress.json)
# --------------------------------------------------------------------------- #

def _write_progress(
    work_dir: str,
    stage: str,               # use "preprocessing" during all ingest phases
    pcap_progress: Dict[str, Any],
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Merge progress data into <work_dir>/progress.json.
    Always writes keys the dashboard expects: stage, pcap_progress, updated_at.
    Optionally merges zeek_results / tshark_results via `extra`.
    """
    progress_path = Path(work_dir) / "progress.json"
    data: Dict[str, Any] = {}
    if progress_path.exists():
        try:
            data = json.loads(progress_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    data.update({
        "stage": stage,
        "updated_at": datetime.datetime.utcnow().isoformat(),
        "pcap_progress": pcap_progress,
    })
    if extra:
        data.update(extra)
    progress_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Cache helpers
# --------------------------------------------------------------------------- #

def _cache_path(ingest_dir: Path, name: str) -> Path:
    return ingest_dir / f"{name}.json"


def _load_cache(ingest_dir: Path, name: str) -> Optional[Any]:
    p = _cache_path(ingest_dir, name)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def _save_cache(ingest_dir: Path, name: str, data: Any) -> None:
    target = _cache_path(ingest_dir, name)
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(target)  # atomic rename on POSIX


# --------------------------------------------------------------------------- #
# Main ingest entry-point
# --------------------------------------------------------------------------- #

def run_ingest(
    network_dir: str,
    work_dir: str,
    config: AgentConfig,
    alert_json_override: Optional[str] = None,
    zeek_json_override: Optional[str] = None,
    pcap_dir_override: Optional[str] = None,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """
    Execute the four-phase ingest pipeline and return the artifacts dict
    consumed by all downstream analysis tools.
    """
    ingest_dir = ensure_dir(Path(work_dir) / "ingest")

    sources = discover_data_sources(network_dir)
    alert_json_path = alert_json_override or sources.get("alert_json", "")
    zeek_json_path  = zeek_json_override  or sources.get("zeek_json", "")
    pcap_dir        = pcap_dir_override   or sources.get("pcap_dir", "")

    artifacts: Dict[str, Any] = {
        "work_dir": work_dir,
        "network_dir": network_dir,
        "alert_json_path": alert_json_path,
        "zeek_json_path":  zeek_json_path,
        "pcap_dir":        pcap_dir,
    }

    # ── Phase 1: Alert ingestion ──────────────────────────────────────────────
    _write_progress(work_dir, "preprocessing", {
        "done": 0, "total": 0,
        "current": f"Reading alert JSON ({Path(alert_json_path).name if alert_json_path else 'not found'})...",
        "phase": "alerts",
    })

    cached_alerts = None if force_refresh else _load_cache(ingest_dir, "alerts")
    if cached_alerts:
        alert_result = cached_alerts
    else:
        if not alert_json_path:
            alert_result = {
                "error": "No alert JSON found", "total_alerts": 0,
                "external_ips": [], "internal_ips": [], "all_ips": [],
                "community_ids": [], "categories": {}, "top_rules": [],
                "alerts_by_category": {},
            }
        else:
            alert_result = read_alerts(alert_json_path, config.cached_networks)
        _save_cache(ingest_dir, "alerts", alert_result)

    # Flatten alert data into artifacts
    # "all_ips" is the *filtered* IOC set (infra IPs removed) for Zeek grep.
    # "all_ips_unfiltered" is the full set for analysis tools that need every IP.
    artifacts.update({
        "alert_total":            alert_result.get("total_alerts", 0),
        "alert_ioc_external_ips": alert_result.get("external_ips", []),
        "alert_ioc_internal_ips": alert_result.get("internal_ips", []),
        "alert_ioc_all_ips":      alert_result.get("all_ips", []),
        "alert_ioc_all_ips_unfiltered": alert_result.get("all_ips_unfiltered",
                                                          alert_result.get("all_ips", [])),
        "alert_infra_ips":        alert_result.get("infra_ips", []),
        "alert_community_ids":    alert_result.get("community_ids", []),
        "alert_categories":       alert_result.get("categories", {}),
        "alert_top_rules":        alert_result.get("top_rules", []),
    })
    for cat, alert_list in alert_result.get("alerts_by_category", {}).items():
        artifacts[f"alerts_{cat}"] = alert_list

    n_ioc = len(alert_result.get("all_ips", []))
    n_infra = len(alert_result.get("infra_ips", []))
    n_alerts = alert_result.get("total_alerts", 0)
    alert_chips = [
        {"segment": f"{cat}: {cnt:,}", "status": "ok"}
        for cat, cnt in sorted(alert_result.get("categories", {}).items(), key=lambda x: -x[1])
        if cnt > 0
    ]
    _write_progress(work_dir, "preprocessing", {
        "done": 1, "total": 4,
        "current": f"Phase 1 done — {n_alerts:,} alerts, {n_ioc} IOC IPs ({n_infra} infra excluded)",
        "phase": "alerts",
    }, extra={
        "alert_results": alert_chips,
    })

    # ── Phase 2: Zeek correlation ─────────────────────────────────────────────
    _write_progress(work_dir, "preprocessing", {
        "done": 1, "total": 4,
        "current": f"Phase 2 — scanning Zeek JSON with ripgrep ({n_ioc} IOC IPs)...",
        "phase": "zeek",
    })

    cached_zeek = None if force_refresh else _load_cache(ingest_dir, "zeek_records")
    if cached_zeek:
        zeek_result = cached_zeek
    else:
        ioc_ips  = set(alert_result.get("all_ips", []))
        # Community IDs disabled for grep — even high-priority CIDs produce
        # thousands of patterns that match nearly every Zeek line.
        # IP-based filtering alone is precise enough.
        ioc_cids = set()

        if not zeek_json_path:
            zeek_result = {
                "error": "No Zeek JSON found", "scanned": 0, "matched": 0,
                "records": {p: [] for p in ("conn", "dns", "ssl", "http", "dce_rpc", "other")},
            }
        else:
            def _zeek_progress(scanned: int, matched: int) -> None:
                _write_progress(work_dir, "preprocessing", {
                    "done": 0, "total": 0,
                    "current": f"Phase 2 — ripgrep output: {scanned:,} matched lines ({matched:,} verified)...",
                    "phase": "zeek",
                })

            zeek_result = search_zeek(zeek_json_path, ioc_ips, ioc_cids, progress_cb=_zeek_progress)
        _save_cache(ingest_dir, "zeek_records", zeek_result)

    artifacts.update({
        "zeek_scanned": zeek_result.get("scanned", 0),
        "zeek_matched": zeek_result.get("matched", 0),
    })
    # Merge Zeek protocol aliases into canonical names:
    #   "connection" → zeek_conn,  "smb_mapping"/"smb_files" → zeek_smb
    _PROTO_ALIASES = {
        "connection": "conn",
        "smb_mapping": "smb",
        "smb_files": "smb",
    }
    for protocol, recs in zeek_result.get("records", {}).items():
        canon = _PROTO_ALIASES.get(protocol, protocol)
        key = f"zeek_{canon}"
        if key in artifacts:
            artifacts[key].extend(recs)
        else:
            artifacts[key] = recs

    zeek_chips = [
        {"segment": f"{proto}: {len(recs):,}", "status": "ok" if recs else "error"}
        for proto, recs in zeek_result.get("records", {}).items()
        if proto != "other" or zeek_result.get("records", {}).get("other")
    ]
    _write_progress(work_dir, "preprocessing", {
        "done": 2, "total": 4,
        "current": f"Phase 2 done — {zeek_result.get('matched', 0):,} Zeek records matched",
        "phase": "zeek",
    }, extra={"zeek_results": zeek_chips})

    # ── Phase 3: PCAP targeting ───────────────────────────────────────────────
    _write_progress(work_dir, "preprocessing", {
        "done": 2, "total": 4,
        "current": "Phase 3 — building PCAP time-range index with capinfos...",
        "phase": "capinfos",
    })

    cached_pcap_index = None if force_refresh else _load_cache(ingest_dir, "pcap_index")
    if cached_pcap_index:
        pcap_index = cached_pcap_index
    else:
        if not pcap_dir:
            pcap_index = []
        else:
            total_pcaps = len(list(Path(pcap_dir).glob("*.pcap")))

            def _capinfos_progress(done: int, total: int, name: str) -> None:
                _write_progress(work_dir, "preprocessing", {
                    "done": done, "total": total,
                    "current": name,
                    "phase": "capinfos",
                })

            pcap_index = build_pcap_index(pcap_dir, progress_cb=_capinfos_progress)
        _save_cache(ingest_dir, "pcap_index", pcap_index)

    alert_timestamps: List[str] = []
    for cat_alerts in alert_result.get("alerts_by_category", {}).values():
        for a in cat_alerts:
            ts = a.get("ts", "")
            if ts:
                alert_timestamps.append(ts)

    # Select ALL PCAPs for Phase 4 — alert-based filtering was dropping PCAPs
    # containing temp.sh DNS/TLS, SMB file access, and exfil traffic that
    # occurred outside alert time windows.  The manual team processed all 129
    # PCAPs; with 8 tshark threads this is still manageable.
    targeted_pcaps = [e["path"] for e in pcap_index]
    artifacts.update({
        "pcap_index":     pcap_index,
        "pcap_count":     len(pcap_index),
        "targeted_pcaps": targeted_pcaps,
    })

    pcap_index_chips = [
        {"segment": f"Indexed: {len(pcap_index)} PCAPs", "status": "ok"},
        {"segment": f"Targeted: {len(targeted_pcaps)} PCAPs", "status": "ok" if targeted_pcaps else "error"},
    ]
    _write_progress(work_dir, "preprocessing", {
        "done": 3, "total": 4,
        "current": f"Phase 3 done — {len(targeted_pcaps)} of {len(pcap_index)} PCAPs selected",
        "phase": "capinfos",
    }, extra={"pcap_index_results": pcap_index_chips})

    # ── Phase 4: Deep PCAP analysis ───────────────────────────────────────────
    _write_progress(work_dir, "preprocessing", {
        "done": 3, "total": 4,
        "current": f"Phase 4 — tshark deep analysis on {len(targeted_pcaps)} PCAPs...",
        "phase": "tshark",
    })

    cached_pcap_analysis = None if force_refresh else _load_cache(ingest_dir, "pcap_analysis")
    if cached_pcap_analysis:
        pcap_analysis = cached_pcap_analysis
    else:
        target_ips = set(alert_result.get("all_ips_unfiltered",
                                         alert_result.get("all_ips", [])))
        # Dynamically discover exfil destination IPs from Zeek DNS answers.
        # Exfil services (temp.sh, file.io, etc.) are rarely in Suricata alerts,
        # but the beachhead host made DNS lookups before connecting — those answers
        # contain the actual server IPs.  Extract them here so conv,tcp and other
        # tshark extractors can target them without hardcoding any specific IP.
        from case_brief import EXFIL_SERVICE_DOMAINS
        exfil_ips_from_dns: set = set()
        for dns_rec in zeek_result.get("records", {}).get("dns", []):
            qname = ""
            answers = []
            zd = dns_rec.get("zeek_detail", {}).get("dns", {})
            qname = str(zd.get("query", "") or dns_rec.get("query", "")).lower()
            raw_answers = zd.get("answers", []) or []
            if isinstance(raw_answers, str):
                raw_answers = [raw_answers]
            answers = raw_answers
            if any(domain in qname for domain in EXFIL_SERVICE_DOMAINS):
                for ans in answers:
                    ans_str = str(ans).strip()
                    # Keep only IPv4 addresses (skip CNAME/MX strings)
                    import re as _re
                    if _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ans_str):
                        exfil_ips_from_dns.add(ans_str)
        if exfil_ips_from_dns:
            print(f"  [Phase 3] Discovered {len(exfil_ips_from_dns)} exfil IPs from Zeek DNS: {sorted(exfil_ips_from_dns)}")
        target_ips |= exfil_ips_from_dns
        tshark_chip_log: List[Dict[str, str]] = []

        if targeted_pcaps and target_ips:
            def _tshark_progress(done: int, total: int, name: str) -> None:
                if name != "done":
                    tshark_chip_log.append({"segment": name, "status": "ok"})
                # Include running extraction totals in progress
                extraction_counts = {
                    "dns": len(artifacts.get("pcap_dns_queries", [])),
                    "tls": len(artifacts.get("pcap_tls_sessions", [])),
                    "http": len(artifacts.get("pcap_http_requests", [])),
                    "smb": len(artifacts.get("pcap_smb_sessions", [])),
                    "rdp": len(artifacts.get("pcap_rdp_sessions", [])),
                    "tcp_conv": len(artifacts.get("pcap_tcp_conversations", [])),
                    "dns_srv": len(artifacts.get("pcap_dns_srv_records", [])),
                    "dcerpc": len(artifacts.get("pcap_dcerpc_calls", [])),
                    "smb_tree": len(artifacts.get("pcap_smb_tree_connects", [])),
                    "netbios": len(artifacts.get("pcap_netbios_records", [])),
                }
                pct = int(done / total * 100) if total else 0
                detail = f"[{pct}%] {name}" if name != "done" else "tshark analysis complete"
                _write_progress(work_dir, "preprocessing", {
                    "done": done, "total": total,
                    "current": detail,
                    "phase": "tshark",
                }, extra={
                    "alert_results":      alert_chips,
                    "zeek_results":       zeek_chips,
                    "pcap_index_results": pcap_index_chips,
                    "tshark_results":     list(tshark_chip_log),
                    "extraction_counts":  extraction_counts,
                })

            pcap_analysis = analyze_targeted_pcaps(
                targeted_pcaps, target_ips, work_dir,
                progress_cb=_tshark_progress,
            )
        else:
            pcap_analysis = {
                "pcaps_analyzed": [], "dns_queries": [], "http_requests": [],
                "tls_sessions": [], "smb_sessions": [], "rdp_sessions": [],
                "tcp_conversations": [], "dns_srv_records": [], "dcerpc_calls": [],
                "smb_tree_connects": [], "netbios_records": [], "errors": [],
            }
        _save_cache(ingest_dir, "pcap_analysis", pcap_analysis)

    artifacts.update({
        "pcap_dns_queries":       pcap_analysis.get("dns_queries", []),
        "pcap_http_requests":     pcap_analysis.get("http_requests", []),
        "pcap_tls_sessions":      pcap_analysis.get("tls_sessions", []),
        "pcap_smb_sessions":      pcap_analysis.get("smb_sessions", []),
        "pcap_rdp_sessions":      pcap_analysis.get("rdp_sessions", []),
        "pcap_tcp_conversations": pcap_analysis.get("tcp_conversations", []),
        "pcap_dns_srv_records":   pcap_analysis.get("dns_srv_records", []),
        "pcap_dcerpc_calls":      pcap_analysis.get("dcerpc_calls", []),
        "pcap_smb_tree_connects": pcap_analysis.get("smb_tree_connects", []),
        "pcap_netbios_records":   pcap_analysis.get("netbios_records", []),
        "pcap_analysis_errors":   pcap_analysis.get("errors", []),
        "pcaps_deeply_analyzed":  pcap_analysis.get("pcaps_analyzed", []),
    })

    # Final ingest progress — hand off to agent.py which will write "analyzing"
    tshark_final_chips = [
        {"segment": Path(p).name[:40], "status": "ok"}
        for p in pcap_analysis.get("pcaps_analyzed", [])
    ]
    _write_progress(work_dir, "preprocessing", {
        "done": 4, "total": 4,
        "current": "All ingest phases complete",
        "phase": "done",
    }, extra={
        "alert_results":      alert_chips,
        "zeek_results":       zeek_chips,
        "pcap_index_results": pcap_index_chips,
        "tshark_results":     tshark_final_chips,
    })

    # Persist human-readable summary
    summary = {
        "alert_json_path": alert_json_path,
        "zeek_json_path":  zeek_json_path,
        "pcap_dir":        pcap_dir,
        "alert_total":     artifacts["alert_total"],
        "alert_categories": artifacts["alert_categories"],
        "zeek_scanned":    artifacts["zeek_scanned"],
        "zeek_matched":    artifacts["zeek_matched"],
        "pcap_count":      artifacts["pcap_count"],
        "targeted_pcap_count": len(targeted_pcaps),
        "pcap_dns_queries":        len(artifacts["pcap_dns_queries"]),
        "pcap_http_requests":      len(artifacts["pcap_http_requests"]),
        "pcap_tls_sessions":       len(artifacts["pcap_tls_sessions"]),
        "pcap_smb_sessions":       len(artifacts["pcap_smb_sessions"]),
        "pcap_rdp_sessions":       len(artifacts["pcap_rdp_sessions"]),
        "pcap_tcp_conversations":  len(artifacts.get("pcap_tcp_conversations", [])),
        "pcap_dns_srv_records":    len(artifacts.get("pcap_dns_srv_records", [])),
        "pcap_dcerpc_calls":       len(artifacts.get("pcap_dcerpc_calls", [])),
        "pcap_smb_tree_connects":  len(artifacts.get("pcap_smb_tree_connects", [])),
        "pcap_netbios_records":    len(artifacts.get("pcap_netbios_records", [])),
    }
    (Path(work_dir) / "ingest_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    return artifacts
