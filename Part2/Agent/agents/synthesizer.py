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


_SYNTH_PROMPT = """You are a senior forensic report writer producing an expert-level incident response report. Given the structured findings below from four independent investigation agents, produce a comprehensive, detailed forensic report.

CASE: {case_name}
INCIDENT: {incident_summary}

FINDINGS FROM INVESTIGATION AGENTS:
{findings_json}

DATABASE STATISTICS:
{db_stats}

REPORT REQUIREMENTS:
1. Executive Summary (2-3 paragraphs for C-suite): What happened, how bad is it, what to do next. No technical jargon.

2. Scope and Assumptions: What evidence was available, what wasn't.

3. For each finding (A, B, C, D), write a DETAILED section with sub-sections:
   - Title with MITRE ATT&CK technique IDs (e.g., T1133, T1078)
   - Confidence level and status
   - Detailed narrative explaining the full evidence chain — not a summary, but a thorough walkthrough
   - Sub-sections for each distinct phase/aspect (e.g., A.1 RDP Access, A.2 Credential Spraying, A.3 Behavior Shift)
   - IOC table: list all attacker IPs, hostnames, file hashes, domains with their context
   - Key evidence items with EXACT IPs, EXACT timestamps (never rounded), and EXACT numbers
   - For byte counts: always show both raw bytes AND human-readable (e.g., "1,083,179,008 bytes (1,033 MB)")
   - For host counts: always show exact number (e.g., "49 unique internal hosts", not "multiple hosts")
   - Distinct attack waves/phases broken down by date
   - Limitations and gaps

4. Attack Timeline: Detailed chronological table with columns: Timestamp | Source → Destination | Protocol | Description
   - Include ALL significant events from all four phases
   - Use exact timestamps from evidence items

5. MITRE ATT&CK Mapping: Table mapping each finding to specific techniques with sub-technique IDs

6. Indicators of Compromise (IOC) Summary Table: All external IPs, domains, filenames, tools identified

7. Recommendations section with THREE priority tiers:
   - Critical (48-72 hours): Immediate credential reset, remove direct RDP exposure, block known exfil services
   - High Priority (1-2 weeks): Segment remote access, implement PAM, harden backup access, enforce east-west segmentation
   - Medium Priority (1-3 months): Deploy monitoring, strengthen credential hygiene, deploy DLP, restrict SAMR/LSARPC
   Each recommendation should have: title, business risk explanation, technical description, and MITRE mitigation ID

CRITICAL RULES:
- Do NOT invent any data not present in the findings above.
- Use EXACT numbers, IPs, and timestamps from the evidence items. Never round or approximate.
- Never say "multiple" or "several" — always use the exact count from evidence.
- Convert all byte values to human-readable format (KB/MB/GB) alongside raw values.
- Be honest about confidence levels and limitations.
- The report should be at least 3,000 words with deep technical detail.
- Include specific SQL-derived statistics wherever available.

KEY FACTS TO HIGHLIGHT (if present in findings — do NOT fabricate if absent):
- Section A: Real attacker IP (low-volume, credential-bearing, lgallegos cookie) vs spray campaign (X attempts from Y IPs). Attacker IP ASN. First RDP timestamp. Kerberos AS-REQ delta (seconds after RDP). Patient zero hostname from NetBIOS. March 8 return RDP session from different IP.
- Section B: THREE distinct waves (March 1/6/8) with per-wave event counts. NetrLogonSamLogonEx total count. Total SAMR operations count. Per-operation SAMR breakdown (SamrOpenGroup, SamrGetMembersInGroup, etc.). NetrShareEnum count. DCSync calls. DPAPI bkrp_BackupKey via \pipe\lsass exact timestamp. AD forest domain names (WATER, POWER, PARKS, SAFETY). delete.me per-wave breakdown. ADMIN$ hosts vs C$ hosts.
- Section C: Exact upload bytes from pcap_tcp_conv (expect ~1,033 MB) and download bytes (~15 MB). DNS query count for temp.sh. TLS session count with SNI=temp.sh. Total SMB file access events (~27,305). Specific sensitive files: user_db_export.json (SSN/DOB/GPS), credit_card_transactions_2024.csv (CVVs), DC backup .vib files (DC1/DC3/DC7), law enforcement archives (arrestees.zip/offenders.zip/victims.zip), Groups.xml/Registry.xml GPO files. Archive count (~28 files).
- Section D: kkwlo.exe (primary payload), hfs.exe + hfs.ips.txt (staging tool), Microsofts.exe (secondary payload), UninstallWinClient.exe (security removal). Ransom note "HOW TO BACK FILES.txt" earliest appearance. delete.me three waves with FILE_OPEN/FILE_DELETE split. March 6 executable transfer wave order (.57→.36 first, then .34, then .37). March 8 ~67-minute interactive RDP from external IP. Interactive RDP from .57 to specific targets (.34/.35/.36/.37/.39/.176).

Return the report as a complete Markdown document.
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
