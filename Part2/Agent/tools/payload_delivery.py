"""
Question D – Payload Deployment  (MITRE T1021.001 / T1021.002)

Evidence chain:
  1. Alert data:    Ransomware-specific or late-stage deployment alerts.
  2. Zeek SSL/conn: Late-stage RDP fan-out – a single internal host connects to
                    many others on port 3389 in the final hours of the capture.
  3. Zeek conn:     Late-stage SMB (445) fan-out from a high-value host.
  4. Deep PCAP:     RDP and SMB session records from the targeted PCAPs that
                    fall within the deployment window.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from case_brief import INVESTIGATION_DIRECTIVES
from config import AgentConfig
from models import EvidenceItem, Finding
from tools.common import is_internal_ip

# Last N seconds of the capture to consider as "late stage" (default 24 h)
_LATE_STAGE_WINDOW = 86_400


def _parse_ts(ts_str: str) -> float:
    """Parse ISO-8601 timestamp string to Unix float; return 0.0 on failure."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0


def analyze_payload_delivery(artifacts: Dict[str, Any], config: AgentConfig) -> Finding:
    networks = config.cached_networks
    evidence: List[EvidenceItem] = []
    limitations: List[str] = []

    # ── 1. Ransomware / deployment alerts ────────────────────────────────────
    ransomware_alerts = artifacts.get("alerts_ransomware", [])
    if ransomware_alerts:
        sample = ransomware_alerts[0]
        unique_targets: Set[str] = {
            a["dst_ip"] for a in ransomware_alerts
            if a.get("dst_ip") and is_internal_ip(a["dst_ip"], networks)
        }
        evidence.append(EvidenceItem(
            ts=sample.get("ts", ""),
            src_ip=sample.get("src_ip", ""),
            dst_ip=sample.get("dst_ip", ""),
            protocol=sample.get("protocol", ""),
            description=(
                f"{len(ransomware_alerts)} ransomware/deployment alert(s) fired. "
                f"Sample rule: \"{sample.get('rule_name', '')}\". "
                f"Internal targets observed: {len(unique_targets)}."
            ),
            artifact="alerts_ransomware",
        ))

    # ── 2. Identify the end-of-capture window ─────────────────────────────────
    # Use alert timestamps to determine the latest observed time, then define
    # "late stage" as the last 24 hours before that.
    all_alert_ts: List[float] = []
    for cat in ("alerts_c2", "alerts_trojan", "alerts_ransomware", "alerts_lateral"):
        for a in artifacts.get(cat, []):
            t = _parse_ts(a.get("ts", ""))
            if t > 0:
                all_alert_ts.append(t)
    # Also check Zeek records
    for rec in artifacts.get("zeek_ssl", []) + artifacts.get("zeek_conn", []):
        t = _parse_ts(rec.get("ts", ""))
        if t > 0:
            all_alert_ts.append(t)

    latest_ts = max(all_alert_ts, default=0.0)
    cutoff_ts = latest_ts - _LATE_STAGE_WINDOW if latest_ts > 0 else 0.0

    # ── 3. Late-stage RDP fan-out from Zeek SSL records ───────────────────────
    ssl_records = artifacts.get("zeek_ssl", [])
    # internal → internal on port 3389 after cutoff
    rdp_fanout: Dict[str, Set[str]] = defaultdict(set)
    rdp_sample: Dict[str, dict] = {}
    for rec in ssl_records:
        src = rec.get("src_ip", "")
        dst = rec.get("dst_ip", "")
        port = rec.get("dst_port", 0)
        t = _parse_ts(rec.get("ts", ""))
        if not (is_internal_ip(src, networks) and is_internal_ip(dst, networks)):
            continue
        if str(port) != "3389":
            continue
        if cutoff_ts > 0 and t < cutoff_ts:
            continue
        rdp_fanout[src].add(dst)
        if src not in rdp_sample:
            rdp_sample[src] = rec

    # ── 4. Late-stage SMB fan-out from Zeek conn records ─────────────────────
    conn_records = artifacts.get("zeek_conn", [])
    smb_fanout: Dict[str, Set[str]] = defaultdict(set)
    smb_sample: Dict[str, dict] = {}
    for rec in conn_records:
        src = rec.get("src_ip", "")
        dst = rec.get("dst_ip", "")
        port = str(rec.get("dst_port", ""))
        t = _parse_ts(rec.get("ts", ""))
        if not (is_internal_ip(src, networks) and is_internal_ip(dst, networks)):
            continue
        if port not in ("445", "3389"):
            continue
        if cutoff_ts > 0 and t < cutoff_ts:
            continue
        smb_fanout[src].add(dst)
        if src not in smb_sample:
            smb_sample[src] = rec

    # Merge RDP and SMB fan-out
    combined_fanout: Dict[str, Tuple[Set[str], str, dict]] = {}
    for src, targets in rdp_fanout.items():
        combined_fanout[src] = (targets, "3389", rdp_sample[src])
    for src, targets in smb_fanout.items():
        existing = combined_fanout.get(src)
        if existing:
            merged = existing[0] | targets
            port = existing[1] if len(existing[0]) >= len(targets) else "445"
            combined_fanout[src] = (merged, port, existing[2])
        else:
            combined_fanout[src] = (targets, "445", smb_sample[src])

    if combined_fanout:
        best_src = max(combined_fanout, key=lambda s: len(combined_fanout[s][0]))
        best_targets, best_port, best_rec = combined_fanout[best_src]
        evidence.append(EvidenceItem(
            ts=best_rec.get("ts", ""),
            src_ip=best_src,
            dst_ip="multiple_internal_hosts",
            protocol=f"tcp/{best_port}",
            description=(
                f"Late-stage fan-out: internal host {best_src} connected to "
                f"{len(best_targets)} unique internal targets on port {best_port} "
                f"within the last {_LATE_STAGE_WINDOW // 3600} hours of the capture. "
                "This is consistent with centralised ransomware staging or remote deployment."
            ),
            artifact="zeek_ssl / zeek_conn",
        ))
    else:
        limitations.append(
            "No late-stage internal RDP or SMB fan-out was found for IOC-matched IPs. "
            "Deployment may have used other protocols or occurred before the capture window."
        )

    # ── 5. Deep PCAP corroboration ─────────────────────────────────────────────
    pcap_rdp = artifacts.get("pcap_rdp_sessions", [])
    pcap_smb = artifacts.get("pcap_smb_sessions", [])
    internal_rdp_pairs: List[dict] = [
        s for s in pcap_rdp
        if is_internal_ip(s.get("src_ip", ""), networks)
        and is_internal_ip(s.get("dst_ip", ""), networks)
    ]
    if internal_rdp_pairs:
        # Count unique destination targets from internal sources
        rdp_int_sources: Dict[str, Set[str]] = defaultdict(set)
        for sess in internal_rdp_pairs:
            rdp_int_sources[sess.get("src_ip", "")].add(sess.get("dst_ip", ""))
        top_rdp_src = max(rdp_int_sources, key=lambda s: len(rdp_int_sources[s]))
        sample_rdp = next(s for s in internal_rdp_pairs if s.get("src_ip") == top_rdp_src)
        evidence.append(EvidenceItem(
            ts=sample_rdp.get("ts", ""),
            src_ip=top_rdp_src,
            dst_ip="multiple_internal_hosts",
            protocol="tcp/3389",
            description=(
                f"Deep PCAP analysis shows internal host {top_rdp_src} initiated RDP connections "
                f"to {len(rdp_int_sources[top_rdp_src])} unique internal targets. "
                f"Source PCAP: {sample_rdp.get('source_pcap', '')}."
            ),
            artifact=f"pcap/{sample_rdp.get('source_pcap', '')}",
        ))

    limitations.append(
        "RDP/SMB fan-out is consistent with ransomware deployment but does not itself "
        "prove which binary was executed – host telemetry or memory forensics would be needed."
    )

    if not evidence:
        return Finding(
            question_id="D",
            title=INVESTIGATION_DIRECTIVES["D"]["title"],
            status="no_clear_late_stage_fanout",
            confidence="LOW",
            summary=(
                "No clear late-stage deployment pattern was found. "
                "The final capture period does not show a strong RDP or SMB fan-out from a single host, "
                "and no ransomware deployment alerts were triggered."
            ),
            mitre=INVESTIGATION_DIRECTIVES["D"]["primary_mitre"],
            limitations=limitations,
            tool_name="payload_delivery",
        )

    # Confidence scoring
    has_alerts = bool(ransomware_alerts)
    has_fanout = any("multiple_internal_hosts" in e.dst_ip for e in evidence)
    has_pcap = any("pcap/" in e.artifact for e in evidence)
    if has_alerts and has_fanout:
        confidence = "HIGH"
    elif has_fanout and has_pcap:
        confidence = "MEDIUM"
    elif has_fanout or has_alerts:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # Identify the deployment host name
    deployment_host = (
        max(combined_fanout, key=lambda s: len(combined_fanout[s][0]))
        if combined_fanout else "unknown"
    )
    summary = (
        f"Host {deployment_host} exhibits the strongest late-stage internal fan-out pattern "
        f"consistent with ransomware deployment. "
        + ("Suricata raised deployment-specific alerts corroborating this. " if has_alerts else "")
        + (f"Deep PCAP analysis confirmed internal-to-internal RDP connections from this host. " if has_pcap else "")
        + "This aligns with the brief's guidance on late-stage RDP/SMB fan-out from a high-value system."
    )

    return Finding(
        question_id="D",
        title=INVESTIGATION_DIRECTIVES["D"]["title"],
        status="suspected_remote_deployment_path",
        confidence=confidence,
        summary=summary,
        mitre=INVESTIGATION_DIRECTIVES["D"]["primary_mitre"],
        evidence=evidence,
        limitations=limitations,
        next_steps=[
            f"Correlate {deployment_host} with domain-controller or admin jump-host roles.",
            "Inspect SMB write events in the same window for file-drop evidence.",
            "Check whether the deployment host also appears in earlier investigation stages.",
        ],
        tool_name="payload_delivery",
    )
