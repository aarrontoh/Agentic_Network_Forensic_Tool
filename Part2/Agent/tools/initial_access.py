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
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from case_brief import INVESTIGATION_DIRECTIVES
from config import AgentConfig
from models import EvidenceItem, Finding
from tools.common import is_internal_ip


def _parse_ts_iso(ts: str) -> Optional[datetime]:
    if not ts or not isinstance(ts, str):
        return None
    t = ts.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(t)
    except ValueError:
        return None


def _first_privileged_activity_ts(artifacts: Dict[str, Any]) -> Optional[datetime]:
    """Earliest DC-style RPC that indicates post-access AD abuse (manual PIVOT_TIME proxy)."""
    pivot: Optional[datetime] = None
    for rec in artifacts.get("zeek_dce_rpc", []):
        dce = (rec.get("zeek_detail") or {}).get("dce_rpc") or {}
        op = (dce.get("operation") or "").lower()
        if not op:
            continue
        if any(k in op for k in ("samr", "drsgetncchanges", "drsbind", "getncchanges", "netrlogon")):
            dt = _parse_ts_iso(rec.get("ts", ""))
            if dt and (pivot is None or dt < pivot):
                pivot = dt
    return pivot


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

    # ── 2. Find external→internal remote-access sessions in Zeek SSL/conn/rdp ──
    # Look for connections where an external IP connects TO an internal host on
    # a known remote-access port (RDP 3389, VPN 443/8443/1194, IPsec 500/4500).
    remote_access_ports = set(str(p) for p in config.remote_access_ports)

    # Check Zeek SSL records
    ssl_records = artifacts.get("zeek_ssl", [])
    candidates: List[Dict[str, Any]] = []
    for rec in ssl_records:
        src_ip = rec.get("src_ip", "")
        dst_ip = rec.get("dst_ip", "")
        dst_port = str(rec.get("dst_port", ""))
        if not src_ip or not dst_ip:
            continue
        if is_internal_ip(src_ip, networks):
            continue
        if not is_internal_ip(dst_ip, networks):
            continue
        if dst_port not in remote_access_ports:
            continue
        candidates.append(rec)

    # Check Zeek conn records for external→internal on remote-access ports
    # This captures sessions that don't appear in SSL (plain RDP, etc.)
    # and provides byte/duration metrics for session quality scoring.
    conn_records = artifacts.get("zeek_conn", [])
    ext_conn_quality: Dict[str, Dict[str, Any]] = {}  # (src,dst) → quality metrics
    for rec in conn_records:
        src_ip = rec.get("src_ip", "")
        dst_ip = rec.get("dst_ip", "")
        dst_port = str(rec.get("dst_port", ""))
        if not src_ip or not dst_ip:
            continue
        if is_internal_ip(src_ip, networks):
            continue
        if not is_internal_ip(dst_ip, networks):
            continue
        if dst_port not in remote_access_ports:
            continue
        # Track session quality: bytes transferred + duration
        zeek_conn = rec.get("zeek_detail", {}).get("conn", {})
        try:
            orig_bytes = int(zeek_conn.get("orig_bytes", 0) or 0)
        except (TypeError, ValueError):
            orig_bytes = 0
        try:
            resp_bytes = int(zeek_conn.get("resp_bytes", 0) or 0)
        except (TypeError, ValueError):
            resp_bytes = 0
        try:
            duration = float(zeek_conn.get("duration", 0) or 0)
        except (TypeError, ValueError):
            duration = 0.0
        pair_key = f"{src_ip}->{dst_ip}"
        existing = ext_conn_quality.get(pair_key, {"bytes": 0, "duration": 0.0, "count": 0})
        ext_conn_quality[pair_key] = {
            "bytes": existing["bytes"] + orig_bytes + resp_bytes,
            "duration": max(existing["duration"], duration),
            "count": existing["count"] + 1,
            "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
            "rec": rec,
        }
        # Also add as a candidate if not already from SSL
        if not any(c.get("src_ip") == src_ip and c.get("dst_ip") == dst_ip for c in candidates):
            candidates.append(rec)

    # Check Zeek RDP records for cookie/username information
    rdp_zeek_records = artifacts.get("zeek_rdp", [])
    rdp_cookies: Dict[str, List[str]] = defaultdict(list)  # dst_ip → [cookies]
    for rec in rdp_zeek_records:
        src_ip = rec.get("src_ip", "")
        dst_ip = rec.get("dst_ip", "")
        if is_internal_ip(src_ip, networks):
            continue
        cookie = rec.get("zeek_detail", {}).get("rdp", {}).get("cookie", "")
        if cookie:
            rdp_cookies[dst_ip].append(cookie)

    # Also check PCAP-derived RDP sessions (includes cookie field now)
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
        cookie = sess.get("cookie", "")
        if cookie:
            rdp_cookies[dst_ip].append(cookie)
        if not any(c.get("src_ip") == src_ip and c.get("dst_ip") == dst_ip for c in candidates):
            candidates.append({
                "ts": sess.get("ts", ""),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": sess.get("dst_port", "3389"),
                "src_geo": {},
                "dst_geo": {},
                "_source": "pcap_rdp",
            })

    # Prefer inbound remote-access sessions in the ~30 minutes BEFORE the first
    # heavy AD/RPC abuse (manual methodology), and drop very-late noise (e.g. weeks after pivot).
    pivot_dt = _first_privileged_activity_ts(artifacts)
    if pivot_dt and candidates:
        window_start = pivot_dt - timedelta(minutes=30)
        late_cutoff = pivot_dt + timedelta(days=3)
        in_window = []
        for rec in candidates:
            dt = _parse_ts_iso(rec.get("ts", ""))
            if dt is None:
                in_window.append(rec)
                continue
            if dt > late_cutoff:
                continue
            if window_start <= dt <= pivot_dt + timedelta(minutes=15):
                in_window.append(rec)
        if in_window:
            candidates = in_window
        else:
            before = [c for c in candidates if (t := _parse_ts_iso(c.get("ts", ""))) is None or t <= pivot_dt + timedelta(hours=2)]
            if before:
                candidates = before

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

    # ── 3. Score candidates by session quality + post-access activity ──────────
    # Build: internal IP → set of unique internal IPs it contacted
    internal_fanout: Dict[str, Set[str]] = defaultdict(set)
    for rec in conn_records:
        src = rec.get("src_ip", "")
        dst = rec.get("dst_ip", "")
        if is_internal_ip(src, networks) and is_internal_ip(dst, networks):
            internal_fanout[src].add(dst)

    # Score each candidate using multiple signals:
    #   - alert_score: threat alerts from this host
    #   - fanout_score: internal hosts contacted post-access
    #   - quality_score: session bytes + duration (distinguishes operator from scanner)
    scored: List[tuple] = []
    for rec in candidates:
        src_ip = rec.get("src_ip", "")
        dst_ip = rec.get("dst_ip", "")
        alert_score = len(internal_alert_map.get(dst_ip, []))
        fanout_score = len(internal_fanout.get(dst_ip, set()))

        # Session quality from Zeek conn
        pair_key = f"{src_ip}->{dst_ip}"
        quality = ext_conn_quality.get(pair_key, {"bytes": 0, "duration": 0.0, "count": 0})
        # Normalize: >100KB bytes = meaningful session, >5s duration = interactive
        bytes_score = min(quality["bytes"] / 100_000, 10)   # cap at 10
        duration_score = min(quality["duration"] / 5.0, 10)  # cap at 10
        session_count = quality["count"]

        total_score = (alert_score * 3
                       + fanout_score * 2
                       + bytes_score * 2
                       + duration_score * 2
                       + min(session_count, 5))
        scored.append((total_score, rec, quality))

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

    _, best, best_quality = scored[0]
    src_ip = best.get("src_ip", "")
    dst_ip = best.get("dst_ip", "")
    dst_port = str(best.get("dst_port", ""))
    ts = best.get("ts", "")
    src_country = best.get("src_geo", {}).get("country_name", "") or best.get("src_country", "")
    src_asn_org = best.get("src_as", {}).get("organization", {}).get("name", "")
    fanout_count = len(internal_fanout.get(dst_ip, set()))
    alert_count = len(internal_alert_map.get(dst_ip, []))
    session_bytes = best_quality.get("bytes", 0)
    session_duration = best_quality.get("duration", 0.0)
    session_count = best_quality.get("count", 0)

    geo_note = ""
    if src_country:
        geo_note = f" (source country: {src_country}"
        if src_asn_org:
            geo_note += f", ASN org: {src_asn_org}"
        geo_note += ")"

    # Build a rich description including session quality metrics
    quality_note = ""
    if session_bytes > 0 or session_duration > 0:
        quality_note = (
            f" Session metrics: {session_bytes:,} bytes transferred, "
            f"{session_duration:.1f}s max duration, {session_count} connection(s)."
        )

    evidence.append(EvidenceItem(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=f"tcp/{dst_port}",
        description=(
            f"External host {src_ip}{geo_note} connected to internal host {dst_ip} "
            f"on port {dst_port} (remote-access service). "
            f"Post-access: {dst_ip} communicated with {fanout_count} unique internal hosts "
            f"and generated {alert_count} threat alerts.{quality_note}"
        ),
        artifact="zeek_ssl / zeek_conn / alert_data",
    ))

    # Add RDP cookie evidence if available (reveals attempted usernames)
    dst_cookies = rdp_cookies.get(dst_ip, [])
    if dst_cookies:
        unique_cookies = sorted(set(dst_cookies))[:10]
        evidence.append(EvidenceItem(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="rdp",
            description=(
                f"RDP cookie values observed targeting {dst_ip}: {unique_cookies}. "
                "These reveal attempted usernames during the RDP handshake, "
                "consistent with credential spraying or targeted login attempts."
            ),
            artifact="zeek_rdp / pcap_rdp",
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
    if pivot_dt:
        limitations.append(
            f"Initial-access candidates were time-bounded using earliest SAMR/DRS-style RPC at "
            f"{pivot_dt.isoformat()} (±30 min inbound RDP window where possible)."
        )
    if not src_country:
        limitations.append("Geo information was not available for the source IP.")

    # Session quality: large byte count + interactive duration = strong indicator
    has_quality_session = session_bytes >= 100_000 and session_duration >= 5.0
    confidence = (
        "HIGH" if ((fanout_count >= 5 and alert_count >= 1) or (has_quality_session and alert_count >= 1))
        else "MEDIUM" if (fanout_count >= 2 or alert_count >= 1 or has_quality_session)
        else "LOW"
    )
    summary = (
        f"The strongest patient-zero candidate is internal host {dst_ip}, which received an inbound "
        f"remote-access connection from {src_ip}{geo_note} on port {dst_port}. "
        f"The host subsequently contacted {fanout_count} unique internal hosts and generated "
        f"{alert_count} threat-intelligence alerts, consistent with post-compromise activity."
    )
    if has_quality_session:
        summary += (
            f" Session analysis shows {session_bytes:,} bytes and {session_duration:.1f}s duration, "
            "indicating an interactive operator session rather than a brief scan."
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
