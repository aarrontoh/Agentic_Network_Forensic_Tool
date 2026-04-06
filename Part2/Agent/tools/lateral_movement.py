"""
Question B – Lateral Movement & Discovery  (MITRE T1046 / T1021.002)

Evidence chain:
  1. Zeek dce_rpc:  DCERPC operations (NetrLogon*, SAMR*, LSARPC*) identify
                    account enumeration and authentication flows.
  2. Alert data:    Scan or lateral-movement alerts flag SMB/RPC fan-out.
  3. Zeek conn:     Internal-to-internal fan-out on ports 135/445 within a
                    sliding time window identifies host-discovery scanning.
  4. Deep PCAP:     SMB session details from targeted PCAPs.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

from case_brief import INVESTIGATION_DIRECTIVES
from config import AgentConfig
from models import EvidenceItem, Finding
from tools.common import is_internal_ip


# DCERPC operation name keywords that indicate enumeration / account activity
_ENUM_KEYWORDS = (
    "netr", "samr", "lsar", "svcctl", "atsvc", "wkssvc",
    "srvsvc", "drsuapi", "epm", "logon", "user", "group",
    "enum", "query", "lookup",
)

# High-value DCERPC operations that are strong lateral-movement indicators
_HIGH_VALUE_OPS = {
    "SamrCreateUser2InDomain", "SamrAddMemberToGroup", "SamrAddMemberToAlias",
    "SamrEnumerateUsersInDomain", "SamrEnumerateAliasesInDomain",
    "SamrLookupNamesInDomain", "SamrQueryInformationUser",
    "DRSGetNCChanges", "DRSBind",               # DCSync
    "NetrShareEnum", "NetrShareGetInfo",         # Share enumeration
    "NetrLogonSamLogonEx", "NetrLogonSamLogon",  # NTLM relay
}

# Suspicious filenames in SMB sessions that indicate recon or deployment
_SUSPICIOUS_SMB_FILES = (
    "delete.me", ".7z", ".zip", ".rar",
    "how to back files", "readme", "ransom",
    "kkwlo", "hfs.exe", "psexec", "mimikatz", "cobalt",
)


def analyze_lateral_movement(artifacts: Dict[str, Any], config: AgentConfig) -> Finding:
    networks = config.cached_networks
    evidence: List[EvidenceItem] = []
    limitations: List[str] = []

    # ── 1. DCERPC enumeration from Zeek ───────────────────────────────────────
    dce_records = artifacts.get("zeek_dce_rpc", [])
    enum_hits: List[dict] = []
    for rec in dce_records:
        zeek_detail = rec.get("zeek_detail", {})
        dce = zeek_detail.get("dce_rpc", {})
        operation = str(dce.get("operation", "")).lower()
        endpoint = str(dce.get("endpoint", "")).lower()
        if any(kw in operation or kw in endpoint for kw in _ENUM_KEYWORDS):
            enum_hits.append(rec)

    if enum_hits:
        sample = enum_hits[0]
        dce_op = sample.get("zeek_detail", {}).get("dce_rpc", {}).get("operation", "")
        dce_ep = sample.get("zeek_detail", {}).get("dce_rpc", {}).get("endpoint", "")
        enum_sources: Set[str] = {r.get("src_ip", "") for r in enum_hits}
        evidence.append(EvidenceItem(
            ts=sample.get("ts", ""),
            src_ip=sample.get("src_ip", ""),
            dst_ip=sample.get("dst_ip", ""),
            protocol="dce_rpc",
            description=(
                f"Zeek captured {len(enum_hits)} DCERPC messages containing enumeration-related "
                f"operations (sample: endpoint={dce_ep!r}, operation={dce_op!r}). "
                f"{len(enum_sources)} unique internal host(s) sent such requests, "
                "which is consistent with Active Directory enumeration or credential abuse."
            ),
            artifact="zeek_dce_rpc",
        ))

    # ── 1b. High-value DCERPC operation breakdown ─────────────────────────────
    highval_ops: Dict[str, int] = defaultdict(int)
    highval_targets: Dict[str, Set[str]] = defaultdict(set)  # op → unique targets
    for rec in dce_records:
        dce = rec.get("zeek_detail", {}).get("dce_rpc", {})
        op = dce.get("operation", "")
        if op in _HIGH_VALUE_OPS:
            highval_ops[op] += 1
            highval_targets[op].add(rec.get("dst_ip", ""))

    if highval_ops:
        op_summary = ", ".join(
            f"{op}({cnt}, {len(highval_targets[op])} targets)"
            for op, cnt in sorted(highval_ops.items(), key=lambda x: -x[1])[:5]
        )
        # Find the most targeted operation for sample evidence
        top_op = max(highval_ops, key=highval_ops.get)
        top_op_sample = next(
            (r for r in dce_records
             if r.get("zeek_detail", {}).get("dce_rpc", {}).get("operation") == top_op),
            None,
        )
        if top_op_sample:
            evidence.append(EvidenceItem(
                ts=top_op_sample.get("ts", ""),
                src_ip=top_op_sample.get("src_ip", ""),
                dst_ip=top_op_sample.get("dst_ip", ""),
                protocol="dce_rpc",
                description=(
                    f"High-value DCERPC operations detected: {op_summary}. "
                    "SAMR operations indicate account enumeration/creation, "
                    "DRSUAPI indicates DCSync, NetrShareEnum indicates share discovery."
                ),
                artifact="zeek_dce_rpc",
            ))

    # ── 2. Lateral / scan alerts ───────────────────────────────────────────────
    lateral_alerts = artifacts.get("alerts_lateral", [])
    scan_alerts = artifacts.get("alerts_scan", [])
    if lateral_alerts or scan_alerts:
        all_lat = lateral_alerts + scan_alerts
        sample = all_lat[0]
        # Count unique internal source IPs in lateral/scan alerts
        lat_srcs: Set[str] = {
            a["src_ip"] for a in all_lat
            if a.get("src_ip") and is_internal_ip(a["src_ip"], networks)
        }
        evidence.append(EvidenceItem(
            ts=sample.get("ts", ""),
            src_ip=sample.get("src_ip", ""),
            dst_ip=sample.get("dst_ip", ""),
            protocol=sample.get("protocol", ""),
            description=(
                f"{len(all_lat)} lateral-movement or scan alerts were fired. "
                f"Rule: \"{sample.get('rule_name', '')}\" – "
                f"category: \"{sample.get('category', '')}\". "
                f"{len(lat_srcs)} unique internal source IP(s) involved."
            ),
            artifact="alerts_lateral/scan",
        ))

    # ── 2b. Zeek SMB records for internal-to-internal SMB activity ──────────
    zeek_smb = artifacts.get("zeek_smb", [])
    if zeek_smb:
        smb_int_pairs: Set[Tuple[str, str]] = set()
        for rec in zeek_smb:
            src = rec.get("src_ip", "")
            dst = rec.get("dst_ip", "")
            if is_internal_ip(src, networks) and is_internal_ip(dst, networks):
                smb_int_pairs.add((src, dst))
        if smb_int_pairs:
            smb_sources = {p[0] for p in smb_int_pairs}
            smb_targets = {p[1] for p in smb_int_pairs}
            sample_rec = zeek_smb[0]
            evidence.append(EvidenceItem(
                ts=sample_rec.get("ts", ""),
                src_ip=sample_rec.get("src_ip", ""),
                dst_ip=sample_rec.get("dst_ip", ""),
                protocol="smb",
                description=(
                    f"Zeek SMB logs show {len(zeek_smb)} records with "
                    f"{len(smb_int_pairs)} unique internal-to-internal pairs "
                    f"({len(smb_sources)} sources → {len(smb_targets)} targets). "
                    "This corroborates lateral SMB file access or share enumeration."
                ),
                artifact="zeek_smb",
            ))

    # ── 3. SMB/RPC fan-out from Zeek conn records ─────────────────────────────
    conn_records = artifacts.get("zeek_conn", [])
    lateral_ports = {str(p) for p in config.lateral_ports}   # "135", "445"
    # sliding-window fan-out: bucket by (src_ip, port, 15-min window)
    fan_buckets: Dict[Tuple[str, str, int], Set[str]] = defaultdict(set)
    sample_rows: Dict[Tuple[str, str, int], dict] = {}

    for rec in conn_records:
        src = rec.get("src_ip", "")
        dst = rec.get("dst_ip", "")
        port = str(rec.get("dst_port", ""))
        if not (is_internal_ip(src, networks) and is_internal_ip(dst, networks)):
            continue
        if port not in lateral_ports:
            continue
        # Parse timestamp
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(rec["ts"].replace("Z", "+00:00"))
            bucket_ts = int(dt.timestamp()) - (int(dt.timestamp()) % config.scan_window_seconds)
        except Exception:
            bucket_ts = 0
        key = (src, port, bucket_ts)
        fan_buckets[key].add(dst)
        if key not in sample_rows:
            sample_rows[key] = rec

    # Find the highest fan-out
    if fan_buckets:
        best_key = max(fan_buckets, key=lambda k: len(fan_buckets[k]))
        best_src, best_port, _ = best_key
        best_targets = fan_buckets[best_key]
        sample_rec = sample_rows[best_key]

        if len(best_targets) >= config.scan_unique_host_threshold:
            evidence.append(EvidenceItem(
                ts=sample_rec.get("ts", ""),
                src_ip=best_src,
                dst_ip="multiple_internal_hosts",
                protocol=f"tcp/{best_port}",
                description=(
                    f"Internal host {best_src} contacted {len(best_targets)} unique internal "
                    f"targets on port {best_port} within a {config.scan_window_seconds // 60}-minute "
                    "window. This is consistent with SMB/RPC host-discovery or lateral-movement preparation."
                ),
                artifact="zeek_conn",
            ))
        else:
            limitations.append(
                f"The highest internal fan-out found was {len(best_targets)} hosts on port {best_port}, "
                f"below the configured threshold of {config.scan_unique_host_threshold}."
            )
    else:
        limitations.append(
            "No internal-to-internal SMB/RPC connections found in the Zeek conn records for IOC IPs. "
            "The scanning may have used other ports or occurred outside the alert-matched time windows."
        )

    # ── 4. SMB session details from deep PCAP analysis ────────────────────────
    smb_sessions = artifacts.get("pcap_smb_sessions", [])
    if smb_sessions:
        smb_pairs: Set[Tuple[str, str]] = {
            (s.get("src_ip", ""), s.get("dst_ip", "")) for s in smb_sessions
        }
        sample_smb = smb_sessions[0]
        evidence.append(EvidenceItem(
            ts=sample_smb.get("ts", ""),
            src_ip=sample_smb.get("src_ip", ""),
            dst_ip=sample_smb.get("dst_ip", ""),
            protocol="smb",
            description=(
                f"Deep PCAP analysis found {len(smb_sessions)} SMB frames across "
                f"{len(smb_pairs)} unique source→destination pairs. "
                f"Sample: file={sample_smb.get('filename', 'N/A')!r}, "
                f"tree={sample_smb.get('tree', 'N/A')!r}. "
                f"Source PCAP: {sample_smb.get('source_pcap', '')}."
            ),
            artifact=f"pcap/{sample_smb.get('source_pcap', '')}",
        ))

    # ── 4b. Suspicious SMB filenames (recon / deployment indicators) ──────────
    suspicious_smb: List[dict] = []
    for sess in smb_sessions:
        fname = (sess.get("filename", "") or "").lower()
        if not fname:
            continue
        for indicator in _SUSPICIOUS_SMB_FILES:
            if indicator in fname:
                suspicious_smb.append({**sess, "_indicator": indicator})
                break

    if suspicious_smb:
        unique_files = sorted({s.get("filename", "") for s in suspicious_smb if s.get("filename")})[:10]
        unique_targets = {s.get("dst_ip", "") for s in suspicious_smb}
        sample_sus = suspicious_smb[0]
        evidence.append(EvidenceItem(
            ts=sample_sus.get("ts", ""),
            src_ip=sample_sus.get("src_ip", ""),
            dst_ip=sample_sus.get("dst_ip", ""),
            protocol="smb",
            description=(
                f"Suspicious SMB filenames detected across {len(unique_targets)} targets: "
                f"{unique_files}. "
                "These may indicate pre-deployment testing (delete.me), "
                "data staging (.7z/.zip), or ransomware artifacts."
            ),
            artifact=f"pcap/{sample_sus.get('source_pcap', '')}",
        ))

    limitations.append(
        "Network evidence can strongly suggest scanning and pivoting, but host telemetry "
        "would be needed to conclusively prove tool execution or account manipulation."
    )

    if not evidence:
        return Finding(
            question_id="B",
            title=INVESTIGATION_DIRECTIVES["B"]["title"],
            status="weak_or_noisy_pattern_not_found",
            confidence="LOW",
            summary="No strong lateral-movement signal was found in alert, Zeek, or PCAP data for the identified IOC addresses.",
            mitre=INVESTIGATION_DIRECTIVES["B"]["primary_mitre"],
            limitations=limitations + ["Attacker may have used slow/low enumeration or encrypted management channels."],
            tool_name="lateral_movement",
        )

    # Determine confidence
    has_dcerpc = any("dce_rpc" in e.artifact for e in evidence)
    has_fanout = any("multiple_internal_hosts" in e.dst_ip for e in evidence)
    has_highval_ops = bool(highval_ops)
    has_suspicious_files = bool(suspicious_smb)
    if (has_dcerpc and has_fanout) or (has_highval_ops and has_fanout):
        confidence = "HIGH"
    elif has_dcerpc or has_fanout or has_highval_ops:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    summary_parts = []
    if enum_hits:
        top_src = max(
            {r.get("src_ip", "") for r in enum_hits} - {""},
            key=lambda ip: sum(1 for r in enum_hits if r.get("src_ip") == ip),
            default="unknown",
        )
        summary_parts.append(
            f"DCERPC enumeration activity was observed from host {top_src} "
            f"({len(enum_hits)} matching records)"
        )
    if fan_buckets and evidence:
        for e in evidence:
            if "multiple_internal_hosts" in e.dst_ip:
                summary_parts.append(f"SMB/RPC fan-out from {e.src_ip}")
                break
    if not summary_parts:
        summary_parts.append("Lateral-movement indicators were found in alert and PCAP data")

    summary = ". ".join(summary_parts) + ". " + (
        "These patterns are consistent with Active Directory enumeration, "
        "host discovery, and SMB-based lateral movement as described in the case brief."
    )

    return Finding(
        question_id="B",
        title=INVESTIGATION_DIRECTIVES["B"]["title"],
        status="strong_scan_pattern" if confidence in ("HIGH", "MEDIUM") else "weak_or_noisy_pattern_not_found",
        confidence=confidence,
        summary=summary,
        mitre=INVESTIGATION_DIRECTIVES["B"]["primary_mitre"],
        evidence=evidence,
        limitations=limitations,
        next_steps=[
            "Check whether the DCERPC source host overlaps with the patient-zero or domain-controller candidate.",
            "Use tshark on targeted PCAPs to reconstruct full SMB session trees.",
            "Look for SAMR CreateUser / AddMember operations in dce_rpc records.",
        ],
        tool_name="lateral_movement",
    )
