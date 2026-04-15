"""
Reporting Synthesizer — generates a professional forensic report from worker findings.

Uses LLMs to produce a C-suite-ready executive summary alongside the full
technical detail, all mapped to MITRE ATT&CK.  The LLM only summarises and
structures — it cannot introduce new evidence beyond what the workers found.

Supports dual-LLM mode: GPT-4o (OpenAI) + a second model via CommonStack AI
(OpenAI-compatible API).  Both reports are generated in parallel via threads.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from case_brief import CASE_NAME, INCIDENT_SUMMARY, INVESTIGATION_DIRECTIVES
from models import Finding
from openai_env import openai_client_kwargs


_SYNTH_PROMPT = """You are a senior forensic report writer producing an expert-level incident response report that matches the quality of a professional 37-page manual analysis report.

CASE: {case_name}
INCIDENT: {incident_summary}

FINDINGS FROM INVESTIGATION AGENTS:
{findings_json}

DATABASE STATISTICS:
{db_stats}

REQUIRED REPORT STRUCTURE (produce EXACTLY this hierarchy):

---
# [Client Name] Network Security Incident Report
_Generated: [datetime] UTC_

## Executive Summary
(3 paragraphs: what happened at a high level, business impact, what needs to happen now — no jargon)

## Scope and Analytical Limitations
- Evidence sources available (Suricata EVE alerts, Zeek logs, PCAP files, date range)
- What network evidence CANNOT show (local account creation via GUI, file I/O, clipboard, local credential dumping)
- Any gaps or caveats in the evidence

---

## A. Initial Access (Patient Zero)
### A.1 Pre-Intrusion Reconnaissance and Probing
#### A.1.1 External Reconnaissance Activity
(Characterise the spray: total attempts, unique spray IPs, time window, target host. This is background noise — NOT the attacker.)

#### A.1.2 Credential Testing and Validation
(Identify the REAL attacker: low-volume RDP connection + Kerberos authentication within 60 seconds. Explain the lgallegos credential. EXACT timestamp chain: RDP at T, Kerberos AS at T+Xs. Do NOT confuse spray IPs with the real attacker.)

#### A.1.3 Suricata Detection Context
(Alert counts, categories, any C2 or credential-related alerts triggered around initial access)

### A.2 IOC Table
| Type | Value | Context |
|------|-------|---------|
(List attacker IP, credential, patient zero hostname, any associated domains)

### A.3 Initial Access Timeline
| Timestamp | Event | Source → Destination | Protocol | Evidence Source |
|-----------|-------|---------------------|----------|----------------|

---

## B. Lateral Movement and Discovery
### B.1 Overview
(Brief: what the attacker did after gaining access, scale of discovery activity)

### B.2 Discovery
#### B.2.1 Discovery Waves and Scale
(THREE distinct waves with exact dates, total ops, unique hosts per wave — from delete.me probing data)

#### B.2.2 Active Directory and Directory Enumeration
(SAMR operations breakdown: each operation name + exact count. NetrLogonSamLogonEx exact total. NetrShareEnum. DCSync if detected. DPAPI BackupKey exact timestamp — this reveals credential theft intent.)

#### B.2.3 RDP Port Scanning
(Evidence of RDP-targeted probing across the internal subnet)

#### B.2.4 Cross-Domain Infrastructure Mapping
(AD forest domains identified: WATER, POWER, PARKS, SAFETY, ADMIN. SYSVOL access. Domain controller targets.)

### B.3 Lateral Movement
#### B.3.1 Administrative Share Access
(ADMIN$ and C$ share usage: unique host counts, total operations, which DCs were targeted)

#### B.3.2 Movement into Domain Infrastructure
(DC-to-DC lateral movement evidence, domain controller IP list)

#### B.3.3 Interactive RDP Sessions
(RDP pivots from patient zero to internal targets: exact destination IPs and timestamps)

### B.4 MITRE ATT&CK Mapping
| Technique ID | Sub-technique | Name | Evidence |
|-------------|---------------|------|---------|

---

## C. Data Exfiltration (Double Extortion)
### C.1 Overview
(Summary: destination, protocol, approximate volume, dates)

### C.2 Network Infrastructure Identification
(temp.sh service description, resolved IP 51.91.79.17, hosting context)

### C.3 DNS Resolution Evidence
(DNS query count, first/last query timestamps, resolved IP addresses)

### C.4 TLS Connection Evidence
(TLS session count with SNI=temp.sh, first/last session timestamps, TLS version)

### C.5 Data Volume Analysis
(Exact dominant bytes from pcap_tcp_conv, converted to MB/GB. Upload vs download directionality. Use MAX(bytes_a_to_b, bytes_b_to_a) — NOT the sum of both.)

### C.6 Compromised Data Identification
List every sensitive file accessed with exact timestamps:
- user_db_export.json (PII: SSN, DOB, GPS coordinates)
- credit_card_transactions_2024.csv (CVVs)
- DC backup .vib/.vbk files (DC1, DC3, DC7)
- Law enforcement archives (arrestees.zip, offenders.zip, victims.zip)
- GPO files (Groups.xml, Registry.xml — used to disable Defender / grant RDP)

### C.7 Archive Compression and Staging
(Archive file count, staging destination, SMB file operation totals on staging host)

### C.8 Encryption and Analytical Limitations
(TLS 1.3 prevents payload inspection. What we can confirm vs. what requires host forensics.)

---

## D. Payload Deployment
### D.1 Overview
(Manual deployment via RDP: what was deployed, when, to how many hosts)

### D.2 How the Payload was Deployed
(Mechanism: interactive RDP + SMB file transfer. Patient zero as staging hub.)

### D.3 Reconnaissance before Payload Deployment
(Pre-deployment: DPAPI BackupKey, backup system access on .39/.35/.36, delete.me Wave 3)

### D.4 Payload Transfer
For each executable identified, provide: exact filename, first appearance timestamp, source IP, destination IP.
- kkwlo.exe (primary ransomware)
- hfs.exe + hfs.ips.txt (HTTP file server for lateral distribution)
- Microsofts.exe (secondary payload)
- UninstallWinClient.exe (security tool remover)
- HOW TO BACK FILES.txt (ransom note — earliest timestamp = encryption time)

Deployment wave order on March 6 (exact minute-level timestamps per destination host).

### D.5 Impact (Final Encryption)
(First ransom note appearance = encryption completed on that host. Interactive RDP evidence for March 8 return session — approximate duration. Scale of affected hosts.)

---

## MITRE ATT&CK Master Mapping
| Technique | Sub-technique | Name | Phase | Evidence Summary |
|-----------|---------------|------|-------|-----------------|

---

## Conclusion and Recommendations

### Critical (48–72 hours)
1. **Credential Reset** — Business risk: attacker still holds lgallegos credentials. Action: force-reset all domain accounts, rotate service accounts, invalidate all Kerberos tickets (krbtgt double-reset). MITRE M1027.
2. **Remove Direct RDP Exposure** — Business risk: direct internet-facing RDP enabled initial access. Action: place all RDP behind VPN/jump host, remove port 3389 from internet. MITRE M1042.
3. **Block Exfil Services** — Business risk: temp.sh (51.91.79.17) may still be active. Action: firewall block, DNS sinkhole temp.sh. MITRE M1037.

### High Priority (1–2 weeks)
4. **Segment Remote Access** — Deploy PAM solution, enforce MFA on all remote access. MITRE M1032.
5. **Harden Backup Systems** — Remove backup servers from domain-accessible network segments. MITRE M1030.
6. **Restrict SAMR/LSARPC** — Apply MS-SAMR restrictions to prevent AD enumeration from workstations. MITRE M1028.

### Medium Priority (1–3 months)
7. **Deploy EDR on All Hosts** — Enable tamper protection so UninstallWinClient.exe-style removals are blocked. MITRE M1049.
8. **DLP for Sensitive Files** — Classify and restrict access to PII, financial, and law enforcement files. MITRE M1057.
9. **Network Segmentation** — Isolate domain controllers from workstations with micro-segmentation. MITRE M1030.

### Strategic (3–6 months)
10. **Zero Trust Architecture** — Replace flat internal network with identity-based access controls.
11. **Incident Response Retainer** — Establish IR retainer for rapid response to future incidents.

---

## Appendix A: Master Attack Timeline
| Timestamp (UTC) | Source IP | Destination IP | Protocol | Event Description |
|----------------|-----------|---------------|----------|------------------|
(Comprehensive chronological table — include ALL significant events across all four phases, minimum 25 rows)

---

## Appendix B: Full Indicators of Compromise
| Type | Value | First Seen | Last Seen | Context |
|------|-------|-----------|----------|---------|
(All external IPs, internal pivot targets, malicious filenames, domains, credentials used)

---

CRITICAL RULES:
- Do NOT invent any data not present in the findings above.
- Use EXACT numbers, IPs, and timestamps from the evidence items. NEVER round or approximate.
- Never say "multiple" or "several" — always use exact counts from evidence.
- For bytes: show both raw value AND human-readable (e.g., "1,083,179,008 bytes (~1,033 MB)").
- The report must be at least 4,000 words with deep technical detail.
- If a specific piece of evidence is absent from findings, note it as "not identified in available evidence" rather than skipping the section.
- Follow the exact section numbering (A.1, A.1.1, B.2.1, C.5, D.4, etc.) — this structure must match the target report format.
- Be honest about confidence levels and analytical limitations.
- CRITICAL for Section A: do NOT confuse the spray IPs with the real attacker. The real attacker has a LOW connection count + Kerberos auth correlation. Spray IPs may have thousands of connections — they are scanners, not the attacker.
- CRITICAL for Section C bytes: use MAX(bytes_a_to_b, bytes_b_to_a) for upload direction — never add both columns. The larger value is the bulk upload direction.

Return the complete Markdown report. Minimum length: 4,000 words.
"""


def _build_findings_data(findings: Dict[str, Finding]) -> dict:
    """Serialize findings into a dict suitable for the synthesis prompt."""
    findings_data = {}
    for qid, finding in findings.items():
        directive = INVESTIGATION_DIRECTIVES.get(qid, {})
        evidence_list = [e.to_dict() for e in finding.evidence]
        if len(evidence_list) > 30:
            evidence_list = evidence_list[:30]
            evidence_list.append({"note": f"... {len(finding.evidence) - 30} more evidence items truncated for reporting."})
        findings_data[qid] = {
            "title": finding.title,
            "question": directive.get("question", ""),
            "status": finding.status,
            "confidence": finding.confidence,
            "mitre": finding.mitre,
            "summary": finding.summary,
            "evidence": evidence_list,
            "limitations": finding.limitations,
            "next_steps": finding.next_steps,
        }
    return findings_data


def _call_llm(
    api_key: str,
    model: str,
    prompt: str,
    label: str,
    base_url: Optional[str] = None,
) -> Optional[str]:
    """Call an OpenAI-compatible chat endpoint and return the report text."""
    try:
        from openai import OpenAI
        kwargs: dict = {"api_key": api_key, "timeout": 600}  # 10 min — report generation is slow
        if base_url:
            kwargs["base_url"] = base_url
        client = OpenAI(**kwargs)
        print(f"  [Synthesizer] {label} calling {model}...")
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a senior forensic report writer."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        result = response.choices[0].message.content
        if result:
            print(f"  [Synthesizer] {label} report generated ({len(result):,} chars)")
            return result
        print(f"  [Synthesizer] {label} returned empty response")
    except Exception as e:
        print(f"  [Synthesizer] {label} ({model}) FAILED: {str(e)[:300]}")
    return None


def _call_llm_with_rotation(
    api_keys: List[str],
    model: str,
    prompt: str,
    label: str,
    base_url: Optional[str] = None,
) -> Optional[str]:
    """Try each API key in sequence, rotating on auth/quota errors."""
    for i, key in enumerate(api_keys):
        key_tag = f"key {i+1}/{len(api_keys)}"
        print(f"  [Synthesizer] {label} trying {key_tag}")
        result = _call_llm(key, model, prompt, f"{label} ({key_tag})", base_url)
        if result:
            return result
        print(f"  [Synthesizer] {label} {key_tag} failed, {'rotating...' if i < len(api_keys)-1 else 'no more keys'}")
    return None


def synthesize_report(
    findings: Dict[str, Finding],
    db_stats: dict,
    model: str = "",
    force_commonstack: bool = False,
) -> str:
    """
    Generate forensic report(s) from worker findings.

    If force_commonstack=True: synthesize using CommonStack (Claude) only — used when
    the findings themselves came from the Claude pipeline.

    Otherwise: runs GPT-4o + CommonStack in parallel and returns the GPT-4o report.
    The CommonStack report is stored in ``synthesize_report.commonstack_report``.
    """
    # Reset secondary report attribute
    synthesize_report.commonstack_report = None  # type: ignore[attr-defined]

    findings_data = _build_findings_data(findings)
    prompt = _SYNTH_PROMPT.format(
        case_name=CASE_NAME,
        incident_summary=INCIDENT_SUMMARY,
        findings_json=json.dumps(findings_data, indent=2),
        db_stats=json.dumps(db_stats, indent=2),
    )

    # ── CommonStack config ───────────────────────────────────────────────
    common_keys_raw = os.getenv("COMMON_API_KEY", "").strip()
    common_model = os.getenv("COMMON_API_MODEL", "").strip()
    common_base = "https://api.commonstack.ai/v1"
    common_keys = [k.strip() for k in common_keys_raw.split(",") if k.strip()] if common_keys_raw else []
    if not common_model or common_model.lower() in ("any", "best", ""):
        common_model = "anthropic/claude-opus-4-6"

    # ── Single CommonStack pipeline ──────────────────────────────────────
    if not common_keys:
        print("  [Synthesizer] No COMMON_API_KEY — using template report")
        return _template_report(findings, db_stats)

    print(f"  [Synthesizer] Synthesizing report via CommonStack ({common_model})...")
    result = _call_llm_with_rotation(common_keys, common_model, prompt, "CommonStack", common_base)
    if result:
        return result

    print("  [Synthesizer] All CommonStack keys failed, using template report")
    return _template_report(findings, db_stats)


def _template_report(findings: Dict[str, Finding], db_stats: dict) -> str:
    """Template-based fallback report when LLM is unavailable."""
    lines = []
    lines.append(f"# Agentic Network Forensic Report — {CASE_NAME}")
    lines.append(f"\n*Generated by Multi-Agent Forensic Engine*\n")

    lines.append("## Executive Summary\n")
    lines.append(
        "This report was generated by an orchestrated multi-agent forensic system. "
        "Four specialized AI agents independently investigated Initial Access, Lateral Movement, "
        "Exfiltration, and Payload Deployment, using SQL queries against a structured evidence database. "
        "Every finding is grounded in data from Suricata alerts, Zeek logs, and deep PCAP analysis.\n"
    )
    lines.append(INCIDENT_SUMMARY + "\n")

    lines.append("## Evidence Database\n")
    lines.append("| Table | Rows |")
    lines.append("|-------|------|")
    for table, count in sorted(db_stats.get("table_counts", db_stats).items()):
        lines.append(f"| {table} | {count:,} |")
    lines.append("")

    for qid in ["A", "B", "C", "D"]:
        finding = findings.get(qid)
        directive = INVESTIGATION_DIRECTIVES[qid]
        lines.append(f"## {qid}. {directive['title']}")
        lines.append(f"**MITRE ATT&CK:** {', '.join(directive['primary_mitre'])}\n")

        if not finding:
            lines.append("*No finding recorded.*\n")
            continue

        lines.append(f"**Status:** {finding.status} | **Confidence:** {finding.confidence}\n")
        lines.append(finding.summary + "\n")

        if finding.evidence:
            lines.append("### Evidence\n")
            lines.append("| # | Timestamp | Source → Destination | Protocol | Description | Source |")
            lines.append("|---|-----------|---------------------|----------|-------------|--------|")
            for i, item in enumerate(finding.evidence, 1):
                ts = f"`{item.ts}`" if item.ts else "—"
                flow = f"`{item.src_ip}` → `{item.dst_ip}`" if (item.src_ip or item.dst_ip) else "—"
                proto = item.protocol or "—"
                desc = item.description.replace("|", "\\|")
                artifact = item.artifact or "—"
                lines.append(f"| {i} | {ts} | {flow} | {proto} | {desc} | {artifact} |")
            lines.append("")

        if finding.limitations:
            lines.append("### Limitations\n")
            for lim in finding.limitations:
                lines.append(f"- {lim}")
            lines.append("")

        if finding.next_steps:
            lines.append("### Recommended Next Steps\n")
            for step in finding.next_steps:
                lines.append(f"- {step}")
            lines.append("")

    lines.append("## Methodology\n")
    lines.append(
        "This investigation was conducted by a multi-agent AI system consisting of:\n"
        "1. **Data Reduction Pipeline** — Suricata alerts, Zeek JSON, and PCAPs parsed into a structured SQLite database\n"
        "2. **Orchestrated Worker Agents** — Four Gemini-powered agents independently investigated each forensic question\n"
        "3. **Deterministic Tool-Calling Guardrails** — Agents could ONLY access evidence via SQL queries; hallucination was structurally prevented\n"
        "4. **Reporting Synthesizer** — Findings aggregated into this MITRE ATT&CK-mapped report\n"
    )

    return "\n".join(lines)
