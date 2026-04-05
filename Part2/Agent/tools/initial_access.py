"""
Question A – Initial Access  (MITRE T1133)

Evidence chain:
  1. Alert data:  C2 / trojan alerts originating from internal hosts identify
                  compromised candidates.
  2. Zeek SSL:    External → internal TLS sessions on port 3389 (RDP) or other
                  remote-access ports reveal the inbound attack path.
  3. Zeek conn:   After the initial external connection, the destination host's
                  subsequent internal traffic is measured (behaviour shift).
  4. Deep PCAP:   RDP session records from targeted PCAPs corroborate the finding.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Set

from case_brief import INVESTIGATION_DIRECTIVES
from config import AgentConfig
from models import EvidenceItem, Finding
from tools.common import is_internal_ip


def analyze_initial_access(artifacts: Dict[str, Any], config: AgentConfig) -> Finding:
    networks = config.cached_networks
    evidence: List[EvidenceItem] = []
    limitations: List[str] = []

    # ── 1. Find compromised internal hosts via alert intelligence ─────────────
    # Internal IPs that generated outbound C2 or trojan alerts are strong
    # candidates – they were already communicating with threat infrastructure.
    c2_alerts = artifacts.get("alerts_c2", [])
    trojan_alerts = artifacts.get("alerts_trojan", [])
    ransomware_alerts = artifacts.get("alerts_ransomware", [])

    # Map: internal IP → list of alerting events
    internal_alert_map: Dict[str, List[dict]] = defaultdict(list)
    for alert in c2_alerts + trojan_alerts + ransomware_alerts:
        src = alert.get("src_ip", "")
        dst = alert.get("dst_ip", "")
        for ip in (src, dst):
            if ip and is_internal_ip(ip, networks):
                internal_alert_map[ip].append(alert)

    # ── 2. Find external→internal remote-access sessions in Zeek SSL/conn ─────
    # Look for connections where an external IP connects TO an internal host on
    # a known remote-access port (RDP 3389, VPN 443/8443/1194, IPsec 500/4500).
    remote_access_ports = set(str(p) for p in config.remote_access_ports)
    # Zeek SSL has external→internal RDP with geo info
    ssl_records = artifacts.get("zeek_ssl", [])

    candidates: List[Dict[str, Any]] = []
    for rec in ssl_records:
        src_ip = rec.get("src_ip", "")
        dst_ip = rec.get("dst_ip", "")
        dst_port = str(rec.get("dst_port", ""))
        if not src_ip or not dst_ip:
            continue
        # External source, internal destination, on a remote-access port
        if is_internal_ip(src_ip, networks):
            continue
        if not is_internal_ip(dst_ip, networks):
            continue
        if dst_port not in remote_access_ports:
            continue
        candidates.append(rec)

    # Also check PCAP-derived RDP sessions
    rdp_sessions = artifacts.get("pcap_rdp_sessions", [])
    for sess in rdp_sessions:
        src_ip = sess.get("src_ip", "")
        dst_ip = sess.get("dst_ip", "")
        if not src_ip or not dst_ip:
            continue
        if is_internal_ip(src_ip, networks):
            continue
        if not is_internal_ip(dst_ip, networks):
            continue
        candidates.append({
            "ts": sess.get("ts", ""),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": sess.get("dst_port", "3389"),
            "src_geo": {},
            "dst_geo": {},
            "_source": "pcap_rdp",
        })

    if not candidates and not internal_alert_map:
        return Finding(
            question_id="A",
            title=INVESTIGATION_DIRECTIVES["A"]["title"],
            status="insufficient_evidence",
            confidence="LOW",
            summary=(
                "No external-to-internal remote-access sessions were found in the Zeek records "
                "and no internal hosts generated C2 or trojan alerts. "
                "Consider expanding the remote-access port list or checking if traffic is encrypted."
            ),
            mitre=INVESTIGATION_DIRECTIVES["A"]["primary_mitre"],
            limitations=[
                "Alert JSON or Zeek JSON may not have been discovered correctly. "
                "Verify network_dir contains the expected files."
            ],
            tool_name="initial_access",
        )

    # ── 3. Score candidates by post-access internal activity ──────────────────
    # The destination of the external access who later contacts the most internal
    # hosts is the strongest patient-zero candidate.
    conn_records = artifacts.get("zeek_conn", [])
    # Build: internal IP → set of unique internal IPs it contacted
    internal_fanout: Dict[str, Set[str]] = defaultdict(set)
    for rec in conn_records:
        src = rec.get("src_ip", "")
        dst = rec.get("dst_ip", "")
        if is_internal_ip(src, networks) and is_internal_ip(dst, networks):
            internal_fanout[src].add(dst)

    # Score each remote-access candidate
    scored: List[tuple] = []
    for rec in candidates:
        dst_ip = rec.get("dst_ip", "")
        alert_score = len(internal_alert_map.get(dst_ip, []))
        fanout_score = len(internal_fanout.get(dst_ip, set()))
        scored.append((alert_score + fanout_score * 2, rec))

    scored.sort(key=lambda x: x[0], reverse=True)

    if not scored:
        # Fallback: use highest-alert internal host as patient zero
        if internal_alert_map:
            best_ip = max(internal_alert_map, key=lambda ip: len(internal_alert_map[ip]))
            sample = internal_alert_map[best_ip][0]
            evidence.append(EvidenceItem(
                ts=sample.get("ts", ""),
                src_ip=sample.get("src_ip", ""),
                dst_ip=sample.get("dst_ip", ""),
                protocol=sample.get("protocol", ""),
                description=(
                    f"Internal host {best_ip} generated {len(internal_alert_map[best_ip])} "
                    "C2/trojan/ransomware alerts, making it the strongest compromised host candidate. "
                    "No matching inbound remote-access session was found in Zeek data."
                ),
                artifact="alerts/c2+trojan+ransomware",
            ))
            return Finding(
                question_id="A",
                title=INVESTIGATION_DIRECTIVES["A"]["title"],
                status="suspected_compromise_path",
                confidence="MEDIUM",
                summary=f"Host {best_ip} is the most likely patient zero based on outbound C2 alert activity, though the inbound access path was not directly observed in Zeek data.",
                mitre=INVESTIGATION_DIRECTIVES["A"]["primary_mitre"],
                evidence=evidence,
                limitations=["The inbound access session was not captured in Zeek logs; it may predate the capture window or have used an encrypted/unrecognised protocol."],
                next_steps=["Check whether this host appears as a lateral-movement source.", "Look for VPN or firewall logs outside the PCAP evidence."],
                tool_name="initial_access",
            )
        return Finding(
            question_id="A",
            title=INVESTIGATION_DIRECTIVES["A"]["title"],
            status="no_clear_candidate",
            confidence="LOW",
            summary="No viable patient-zero candidate was identified from alert or Zeek evidence.",
            mitre=INVESTIGATION_DIRECTIVES["A"]["primary_mitre"],
            limitations=["The capture may have begun after initial access occurred."],
            tool_name="initial_access",
        )

    _, best = scored[0]
    src_ip = best.get("src_ip", "")
    dst_ip = best.get("dst_ip", "")
    dst_port = str(best.get("dst_port", ""))
    ts = best.get("ts", "")
    src_country = best.get("src_geo", {}).get("country_name", "") or best.get("src_country", "")
    src_asn_org = best.get("src_as", {}).get("organization", {}).get("name", "")
    fanout_count = len(internal_fanout.get(dst_ip, set()))
    alert_count = len(internal_alert_map.get(dst_ip, []))

    geo_note = ""
    if src_country:
        geo_note = f" (source country: {src_country}"
        if src_asn_org:
            geo_note += f", ASN org: {src_asn_org}"
        geo_note += ")"

    evidence.append(EvidenceItem(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=f"tcp/{dst_port}",
        description=(
            f"External host {src_ip}{geo_note} connected to internal host {dst_ip} "
            f"on port {dst_port} (remote-access service). "
            f"Post-access: {dst_ip} communicated with {fanout_count} unique internal hosts "
            f"and generated {alert_count} threat alerts."
        ),
        artifact="zeek_ssl / alert_data",
    ))

    # Also add an alert-corroboration evidence item if available
    if alert_count > 0 and internal_alert_map.get(dst_ip):
        sample_alert = internal_alert_map[dst_ip][0]
        evidence.append(EvidenceItem(
            ts=sample_alert.get("ts", ""),
            src_ip=sample_alert.get("src_ip", ""),
            dst_ip=sample_alert.get("dst_ip", ""),
            protocol=sample_alert.get("protocol", ""),
            description=(
                f"After initial access, host {dst_ip} triggered a threat alert: "
                f"\"{sample_alert.get('rule_name', '')}\" "
                f"(category: {sample_alert.get('category', '')}). "
                "This corroborates active compromise of the host."
            ),
            artifact="alerts_c2/trojan",
        ))

    if dst_port != "3389":
        limitations.append(
            "The candidate is not on RDP port 3389; it may represent VPN or another remote-access path – validate manually."
        )
    limitations.append(
        "Network evidence can suggest but not conclusively prove successful authentication."
    )
    if not src_country:
        limitations.append("Geo information was not available for the source IP.")

    confidence = "HIGH" if (fanout_count >= 5 and alert_count >= 1) else "MEDIUM" if (fanout_count >= 2 or alert_count >= 1) else "LOW"
    summary = (
        f"The strongest patient-zero candidate is internal host {dst_ip}, which received an inbound "
        f"remote-access connection from {src_ip}{geo_note} on port {dst_port}. "
        f"The host subsequently contacted {fanout_count} unique internal hosts and generated "
        f"{alert_count} threat-intelligence alerts, consistent with post-compromise activity."
    )

    return Finding(
        question_id="A",
        title=INVESTIGATION_DIRECTIVES["A"]["title"],
        status="suspected_compromise_path",
        confidence=confidence,
        summary=summary,
        mitre=INVESTIGATION_DIRECTIVES["A"]["primary_mitre"],
        evidence=evidence,
        limitations=limitations,
        next_steps=[
            "Validate whether the destination host appears as a lateral-movement source.",
            "Review VPN or firewall logs to strengthen login attribution.",
            f"Inspect targeted PCAPs for the exact session: filter for 'ip.addr=={src_ip} && ip.addr=={dst_ip}'.",
        ],
        tool_name="initial_access",
    )
