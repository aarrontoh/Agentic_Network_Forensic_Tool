"""
Manager agent — orchestrates the multi-agent investigation.

The manager:
  1. Receives the case brief and database statistics.
  2. Dispatches specialized worker agents in sequence (A → B → C → D).
  3. After each worker completes, reviews findings and passes context to the next.
  4. Hands all findings to the reporting synthesizer.

The manager uses Gemini to generate a brief investigation plan, but the actual
evidence gathering is done entirely by the workers via SQL queries.
"""
from __future__ import annotations

import datetime
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from case_brief import INCIDENT_SUMMARY, INVESTIGATION_DIRECTIVES
from db.schema import get_table_stats
from models import AnalysisState, Finding
from agents.worker import run_worker
from agents.worker_prompts import WORKER_PROMPTS


def _build_manager_context(conn: sqlite3.Connection) -> str:
    """Build context string showing what data is available."""
    stats = get_table_stats(conn)
    lines = ["Evidence Database Overview:"]
    for table, count in sorted(stats.items()):
        lines.append(f"  {table}: {count:,} rows")
    return "\n".join(lines)


def run_multi_agent(
    conn: sqlite3.Connection,
    state: AnalysisState,
    progress_callback: Optional[Callable] = None,
) -> Dict[str, Finding]:
    """
    Execute the full multi-agent investigation pipeline.

    Returns a dict mapping question_id to Finding.
    """
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    db_context = _build_manager_context(conn)
    findings: Dict[str, Finding] = {}

    # Investigation order: A → B → C → D
    question_order = ["A", "B", "C", "D"]

    for i, qid in enumerate(question_order):
        worker_config = WORKER_PROMPTS[qid]
        directive = INVESTIGATION_DIRECTIVES[qid]

        # Build worker prompt with accumulated context from prior findings
        prior_context = ""
        if findings:
            prior_summaries = []
            for prev_qid, prev_finding in findings.items():
                prior_summaries.append(
                    f"  Question {prev_qid} ({prev_finding.title}): "
                    f"{prev_finding.confidence} confidence — {prev_finding.summary[:300]}"
                )
            prior_context = (
                "\n\nPRIOR FINDINGS FROM OTHER AGENTS:\n"
                + "\n".join(prior_summaries)
                + "\n\nUse these to inform your investigation (e.g., correlate IPs across stages)."
            )

        full_prompt = (
            worker_config["prompt"]
            + f"\n\n{db_context}"
            + prior_context
            + f"\n\nBegin your investigation now. Start by examining the database to understand the available evidence."
        )

        if progress_callback:
            progress_callback(
                stage="multi_agent",
                detail=f"Worker {qid}: {worker_config['title']} ({i+1}/{len(question_order)})",
                worker_id=qid,
                status="running",
            )

        state.log("worker_dispatched", {
            "question_id": qid,
            "title": worker_config["title"],
        })

        # Run the worker agent
        finding = run_worker(
            conn=conn,
            question_id=qid,
            title=worker_config["title"],
            mitre=worker_config["mitre"],
            system_prompt=full_prompt,
            model=model,
            log_callback=lambda event, data: state.log(event, data),
        )

        findings[qid] = finding
        state.add_finding(f"agent_{worker_config['title'].lower().replace(' ', '_')}", finding)

        # Cooldown between workers to avoid rate-limit bursts on free tier
        if i < len(question_order) - 1:
            cooldown = int(os.getenv("WORKER_COOLDOWN_SECONDS", "15"))
            if cooldown > 0:
                print(f"  [Manager] Cooldown {cooldown}s before next worker...")
                time.sleep(cooldown)

        state.log("worker_completed", {
            "question_id": qid,
            "confidence": finding.confidence,
            "evidence_count": len(finding.evidence),
            "summary": finding.summary[:200],
        })

        if progress_callback:
            progress_callback(
                stage="multi_agent",
                detail=f"Worker {qid}: {worker_config['title']} — {finding.confidence}",
                worker_id=qid,
                status="completed",
            )

    return findings
