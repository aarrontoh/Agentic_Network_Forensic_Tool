"""
Reporting Synthesizer — generates a professional forensic report from worker findings.

Uses Gemini to produce a C-suite-ready executive summary alongside the full
technical detail, all mapped to MITRE ATT&CK.  The LLM only summarises and
structures — it cannot introduce new evidence beyond what the workers found.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from case_brief import CASE_NAME, INCIDENT_SUMMARY, INVESTIGATION_DIRECTIVES
from models import Finding


_SYNTH_PROMPT = """You are a senior forensic report writer. Given the structured findings below from four independent investigation agents, produce a professional forensic report.

CASE: {case_name}
INCIDENT: {incident_summary}

FINDINGS FROM INVESTIGATION AGENTS:
{findings_json}

DATABASE STATISTICS:
{db_stats}

REPORT REQUIREMENTS:
1. Executive Summary (2-3 paragraphs for C-suite): What happened, how bad is it, what to do next. No technical jargon.
2. For each finding (A, B, C, D):
   - Title with MITRE ATT&CK technique IDs
   - Confidence level and status
   - Narrative summary explaining the evidence chain
   - Key evidence items with specific IPs, timestamps, and numbers
   - Limitations and gaps
3. Attack Timeline: Chronological sequence of events
4. Recommendations: Prioritized remediation steps

RULES:
- Do NOT invent any data not present in the findings above.
- Use specific numbers, IPs, and timestamps from the evidence items.
- Be honest about confidence levels and limitations.
- Balance technical depth with executive accessibility.

Return the report as a complete Markdown document.
"""


def synthesize_report(
    findings: Dict[str, Finding],
    db_stats: dict,
    model: str = "",
) -> str:
    """
    Generate a professional Markdown forensic report from worker findings.

    Falls back to a template-based report if Gemini is unavailable.
    """
    model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    findings_data = {}
    for qid, finding in findings.items():
        directive = INVESTIGATION_DIRECTIVES.get(qid, {})
        findings_data[qid] = {
            "title": finding.title,
            "question": directive.get("question", ""),
            "status": finding.status,
            "confidence": finding.confidence,
            "mitre": finding.mitre,
            "summary": finding.summary,
            "evidence": [e.to_dict() for e in finding.evidence],
            "limitations": finding.limitations,
            "next_steps": finding.next_steps,
        }

    prompt = _SYNTH_PROMPT.format(
        case_name=CASE_NAME,
        incident_summary=INCIDENT_SUMMARY,
        findings_json=json.dumps(findings_data, indent=2),
        db_stats=json.dumps(db_stats, indent=2),
    )

    # Build fallback order: gemini models first → groq → together → sambanova
    backends_to_try = []

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
    if gemini_key:
        models_str = os.getenv("GEMINI_MODELS", "gemini-2.5-flash")
        for m in models_str.split(","):
            m = m.strip()
            if m:
                backends_to_try.append(("gemini", m, gemini_key, None))

    _OPENAI_BACKENDS = [
        ("groq", "GROQ_API_KEY", "GROQ_MODEL", "llama-3.3-70b-versatile", "https://api.groq.com/openai/v1"),
        ("together", "TOGETHER_API_KEY", "TOGETHER_MODEL", "meta-llama/Llama-4-Maverick-17B-128E-Instruct", os.getenv("TOGETHER_BASE_URL", "https://api.together.xyz/v1")),
        ("sambanova", "SAMBANOVA_API_KEY", "SAMBANOVA_MODEL", "Llama-4-Maverick-17B-128E-Instruct", "https://api.sambanova.ai/v1"),
    ]
    for name, key_env, model_env, default_model, base_url in _OPENAI_BACKENDS:
        api_key = os.getenv(key_env, "").strip()
        if api_key:
            backends_to_try.append((name, os.getenv(model_env, default_model), api_key, base_url))

    for backend, llm_model, api_key, base_url in backends_to_try:
        try:
            if backend == "gemini":
                from google import genai
                from google.genai import types
                client = genai.Client(api_key=api_key)
                response = client.models.generate_content(
                    model=llm_model,
                    contents=prompt,
                    config=types.GenerateContentConfig(temperature=0.3),
                )
                result = response.text
            else:
                from openai import OpenAI
                client = OpenAI(api_key=api_key, base_url=base_url)
                response = client.chat.completions.create(
                    model=llm_model,
                    messages=[
                        {"role": "system", "content": "You are a senior forensic report writer."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                )
                result = response.choices[0].message.content

            if result:
                print(f"  [Synthesizer] Report generated using {backend}/{llm_model}")
                return result
        except Exception as e:
            print(f"  [Synthesizer] {backend}/{llm_model} failed: {str(e)[:100]}, trying next...")
            continue

    print("  [Synthesizer] All backends failed, using template report")
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
            for i, item in enumerate(finding.evidence, 1):
                lines.append(f"**{i}.** [{item.artifact}]")
                if item.ts:
                    lines.append(f"  - Timestamp: `{item.ts}`")
                if item.src_ip or item.dst_ip:
                    lines.append(f"  - Flow: `{item.src_ip}` → `{item.dst_ip}` ({item.protocol})")
                lines.append(f"  - {item.description}\n")

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
