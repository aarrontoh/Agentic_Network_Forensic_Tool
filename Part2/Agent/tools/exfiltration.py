"""
Question C – Exfiltration  (MITRE T1567)

Evidence chain:
  1. Alert data:    Direct exfiltration alerts and C2 alerts with outbound direction.
  2. Zeek SSL:      TLS sessions where SNI contains "temp.sh" or other exfil domains.
  3. Zeek HTTP:     HTTP metadata with temp.sh hostnames or large POST request bodies.
  4. Zeek conn:     Large outbound transfers (≥ exfil_large_bytes_threshold).
  5. Deep PCAP:     HTTP request details and TLS SNI from targeted PCAPs.
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

from case_brief import INVESTIGATION_DIRECTIVES
from config import AgentConfig
from models import EvidenceItem, Finding
from tools.common import is_internal_ip

# Known exfiltration-associated domains / keywords
_EXFIL_DOMAINS = ("temp.sh", "file.io", "transfer.sh", "anonfiles", "gofile", "we.tl", "filetransfer.io")
_ARCHIVE_MAGIC = bytes.fromhex("377ABCAF271C")   # 7-Zip magic bytes


def _matches_exfil_domain(value: str) -> str:
    """Return the matched exfil domain keyword, or empty string."""
    v = value.lower()
    for d in _EXFIL_DOMAINS:
        if d in v:
            return d
    return ""


def analyze_exfiltration(artifacts: Dict[str, Any], config: AgentConfig) -> Finding:
    networks = config.cached_networks
    evidence: List[EvidenceItem] = []
    limitations: List[str] = []
    exfil_confidence_boost = False

    # ── 1. Direct exfiltration and C2 outbound alerts ─────────────────────────
    exfil_alerts = artifacts.get("alerts_exfiltration", [])
    c2_alerts_outbound = [
        a for a in artifacts.get("alerts_c2", [])
        if a.get("direction", "") in ("outbound", "egress")
    ]
    all_exfil_alerts = exfil_alerts + c2_alerts_outbound

    if all_exfil_alerts:
        sample = all_exfil_alerts[0]
        unique_srcs: Set[str] = {
            a["src_ip"] for a in all_exfil_alerts
            if a.get("src_ip") and is_internal_ip(a["src_ip"], networks)
        }
        evidence.append(EvidenceItem(
            ts=sample.get("ts", ""),
            src_ip=sample.get("src_ip", ""),
            dst_ip=sample.get("dst_ip", ""),
            protocol=sample.get("protocol", ""),
            description=(
                f"{len(all_exfil_alerts)} exfiltration/outbound-C2 alerts fired. "
                f"Sample rule: \"{sample.get('rule_name', '')}\". "
                f"{len(unique_srcs)} unique internal source IP(s): {', '.join(sorted(unique_srcs)[:5])}."
            ),
            artifact="alerts_exfiltration/c2",
        ))
        exfil_confidence_boost = True

    # ── 2. Zeek SSL – temp.sh and known exfil domains in SNI ──────────────────
    ssl_records = artifacts.get("zeek_ssl", [])
    ssl_exfil_hits: List[dict] = []
    for rec in ssl_records:
        zeek_ssl = rec.get("zeek_detail", {}).get("ssl", {})
        sni = zeek_ssl.get("server_name", "") or ""
        # Also check ECS tls field
        sni = sni or rec.get("tls", {}).get("server_name", "") or ""
        if not sni:
            continue
        match = _matches_exfil_domain(sni)
        if match:
            ssl_exfil_hits.append({**rec, "_matched_domain": match, "_sni": sni})

    if ssl_exfil_hits:
        sample = ssl_exfil_hits[0]
        evidence.append(EvidenceItem(
            ts=sample.get("ts", ""),
            src_ip=sample.get("src_ip", ""),
            dst_ip=sample.get("dst_ip", ""),
            protocol="tls",
            description=(
                f"TLS SNI field references known exfiltration service "
                f"\"{sample['_sni']}\" ({sample['_matched_domain']}). "
                f"{len(ssl_exfil_hits)} matching TLS session(s) found in Zeek data."
            ),
            artifact="zeek_ssl",
        ))
        exfil_confidence_boost = True

    # ── 3. Zeek HTTP – temp.sh in host/URI or large POST ──────────────────────
    http_records = artifacts.get("zeek_http", [])
    http_exfil_hits: List[dict] = []
    for rec in http_records:
        url_info = rec.get("url", {})
        host = str(url_info.get("domain", "") or "").lower()
        uri = str(url_info.get("original", "") or "").lower()
        match = _matches_exfil_domain(host) or _matches_exfil_domain(uri)
        if match:
            http_exfil_hits.append({**rec, "_matched_domain": match})
            continue
        # Large HTTP POST (body size in content_length or from zeek_detail)
        zeek_http = rec.get("zeek_detail", {}).get("http", {})
        try:
            body_len = int(zeek_http.get("request_body_len", 0) or 0)
        except (TypeError, ValueError):
            body_len = 0
        if body_len >= config.exfil_large_bytes_threshold:
            http_exfil_hits.append({**rec, "_matched_domain": "large_post"})

    if http_exfil_hits:
        sample = http_exfil_hits[0]
        url_host = sample.get("url", {}).get("domain", "")
        evidence.append(EvidenceItem(
            ts=sample.get("ts", ""),
            src_ip=sample.get("src_ip", ""),
            dst_ip=sample.get("dst_ip", ""),
            protocol="http",
            description=(
                f"HTTP metadata references exfiltration indicator: host={url_host!r}, "
                f"match={sample['_matched_domain']!r}. "
                f"{len(http_exfil_hits)} suspicious HTTP record(s) in Zeek data."
            ),
            artifact="zeek_http",
        ))
        exfil_confidence_boost = True

    # ── 4. Zeek conn – large outbound transfers ───────────────────────────────
    conn_records = artifacts.get("zeek_conn", [])
    large_outbound: List[dict] = []
    for rec in conn_records:
        src = rec.get("src_ip", "")
        dst = rec.get("dst_ip", "")
        if not is_internal_ip(src, networks):
            continue
        if is_internal_ip(dst, networks):
            continue
        # orig_bytes in Zeek conn
        zeek_conn = rec.get("zeek_detail", {}).get("conn", {})
        try:
            orig_bytes = int(zeek_conn.get("orig_bytes", 0) or 0)
        except (TypeError, ValueError):
            orig_bytes = 0
        if orig_bytes >= config.exfil_large_bytes_threshold:
            large_outbound.append({**rec, "_bytes": orig_bytes})

    if large_outbound:
        biggest = max(large_outbound, key=lambda r: r["_bytes"])
        evidence.append(EvidenceItem(
            ts=biggest.get("ts", ""),
            src_ip=biggest.get("src_ip", ""),
            dst_ip=biggest.get("dst_ip", ""),
            protocol=f"tcp/{biggest.get('dst_port', '')}",
            description=(
                f"Large outbound transfer of {biggest['_bytes']:,} bytes "
                f"from internal host {biggest.get('src_ip', '')} to external {biggest.get('dst_ip', '')}. "
                f"{len(large_outbound)} connection(s) exceeded the {config.exfil_large_bytes_threshold:,}-byte threshold."
            ),
            artifact="zeek_conn",
        ))

    # ── 5. Deep PCAP – HTTP requests to exfil domains ────────────────────────
    pcap_http = artifacts.get("pcap_http_requests", [])
    pcap_exfil_http: List[dict] = []
    for req in pcap_http:
        host = (req.get("host", "") or "").lower()
        uri = (req.get("uri", "") or "").lower()
        match = _matches_exfil_domain(host) or _matches_exfil_domain(uri)
        if match:
            pcap_exfil_http.append({**req, "_match": match})

    if pcap_exfil_http:
        sample = pcap_exfil_http[0]
        evidence.append(EvidenceItem(
            ts=sample.get("ts", ""),
            src_ip=sample.get("src_ip", ""),
            dst_ip=sample.get("dst_ip", ""),
            protocol="http",
            description=(
                f"Deep PCAP analysis confirmed HTTP request to exfil-associated host "
                f"\"{sample.get('host', '')}\" (URI: {sample.get('uri', '')!r}), "
                f"method={sample.get('method', '')}, status={sample.get('status_code', '')}, "
                f"content-length={sample.get('content_length', 'N/A')}. "
                f"Source PCAP: {sample.get('source_pcap', '')}."
            ),
            artifact=f"pcap/{sample.get('source_pcap', '')}",
        ))
        exfil_confidence_boost = True

    # ── 6. Deep PCAP – TLS SNI to exfil domains ───────────────────────────────
    pcap_tls = artifacts.get("pcap_tls_sessions", [])
    for sess in pcap_tls:
        sni = (sess.get("sni", "") or "").lower()
        match = _matches_exfil_domain(sni)
        if match:
            evidence.append(EvidenceItem(
                ts=sess.get("ts", ""),
                src_ip=sess.get("src_ip", ""),
                dst_ip=sess.get("dst_ip", ""),
                protocol="tls",
                description=(
                    f"Deep PCAP TLS ClientHello SNI={sni!r} references exfil-associated domain ({match}). "
                    f"TLS version: {sess.get('tls_version', 'N/A')}, dst_port: {sess.get('dst_port', '')}. "
                    f"Source PCAP: {sess.get('source_pcap', '')}."
                ),
                artifact=f"pcap/{sess.get('source_pcap', '')}",
            ))
            exfil_confidence_boost = True
            break   # one representative item is enough

    limitations.append(
        "Hostnames and large transfer sizes strongly suggest exfiltration, but payload content "
        "confirmation requires TLS decryption or endpoint telemetry."
    )
    if not ssl_exfil_hits and not http_exfil_hits:
        limitations.append(
            "No temp.sh or other known exfil domain was observed in Zeek SNI/HTTP metadata. "
            "Exfiltration may have used a less-known domain or a direct IP connection."
        )

    if not evidence:
        return Finding(
            question_id="C",
            title=INVESTIGATION_DIRECTIVES["C"]["title"],
            status="weak_or_no_exfil_signal",
            confidence="LOW",
            summary="No strong exfiltration indicators were found in alert, Zeek, or PCAP data for the identified IOC addresses.",
            mitre=INVESTIGATION_DIRECTIVES["C"]["primary_mitre"],
            limitations=limitations + ["Exfil may have occurred over encrypted/unrecognised channels."],
            tool_name="exfiltration",
        )

    confidence = "HIGH" if exfil_confidence_boost and len(evidence) >= 2 else "MEDIUM"
    summary = (
        "Multiple exfiltration indicators were identified across alert, Zeek, and PCAP evidence. "
        "These include "
        + (f"TLS connections to known exfil services, " if ssl_exfil_hits or any("tls" in e.protocol for e in evidence) else "")
        + (f"HTTP requests to temp.sh or similar, " if http_exfil_hits or pcap_exfil_http else "")
        + (f"large outbound data transfers, " if large_outbound else "")
        + (f"direct Suricata exfiltration alerts, " if exfil_alerts else "")
        + "supporting the double-extortion hypothesis in the case brief."
    )
    summary = summary.replace(", supporting", " supporting").strip()

    return Finding(
        question_id="C",
        title=INVESTIGATION_DIRECTIVES["C"]["title"],
        status="supported_exfiltration_hypothesis",
        confidence=confidence,
        summary=summary,
        mitre=INVESTIGATION_DIRECTIVES["C"]["primary_mitre"],
        evidence=evidence,
        limitations=limitations,
        next_steps=[
            "Correlate the exfil source IP with the patient-zero and lateral-movement host set.",
            "Inspect SNI certificate fingerprints and byte-count evidence in the final narrative.",
            "Search for 7-Zip or other archive tool activity in SMB sessions preceding the exfil event.",
        ],
        tool_name="exfiltration",
    )
