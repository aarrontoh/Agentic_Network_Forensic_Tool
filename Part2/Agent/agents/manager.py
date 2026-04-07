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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    db_context = _build_manager_context(conn)
    findings: Dict[str, Finding] = {}

    # ── Parallel execution strategy ──────────────────────────────────────────
    # Workers A (Initial Access) and B (Lateral Movement) are independent —
    # run them in parallel. C (Exfiltration) benefits from A+B context.
    # D (Payload Deployment) benefits from all prior findings.
    #
    # Batch 1: A + B in parallel
    # Batch 2: C (with A+B context)
    # Batch 3: D (with A+B+C context)
    parallel_batches = [
        ["A", "B"],   # independent — run in parallel
        ["C"],        # depends on A + B
        ["D"],        # depends on A + B + C
    ]

    def _build_prompt(qid: str) -> str:
        """Build worker prompt with accumulated prior findings context."""
        worker_config = WORKER_PROMPTS[qid]
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
        return (
            worker_config["prompt"]
            + f"\n\n{db_context}"
            + prior_context
            + "\n\nBegin your investigation now. Start by examining the database to understand the available evidence."
        )

    def _run_one_worker(qid: str) -> tuple:
        """Run a single worker and return (qid, finding)."""
        worker_config = WORKER_PROMPTS[qid]
        full_prompt = _build_prompt(qid)

        state.log("worker_dispatched", {"question_id": qid, "title": worker_config["title"]})

        if progress_callback:
            progress_callback(
                stage="multi_agent",
                detail=f"Worker {qid}: {worker_config['title']}",
                worker_id=qid,
                status="running",
            )

        finding = run_worker(
            conn=conn,
            question_id=qid,
            title=worker_config["title"],
            mitre=worker_config["mitre"],
            system_prompt=full_prompt,
            log_callback=lambda event, data: state.log(event, data),
        )
        return qid, finding

    total_dispatched = 0
    total_workers = sum(len(b) for b in parallel_batches)

    for batch_idx, batch in enumerate(parallel_batches):
        if len(batch) > 1:
            # Parallel batch
            print(f"  [Manager] Batch {batch_idx + 1}: Running workers {', '.join(batch)} in parallel...")
            with ThreadPoolExecutor(max_workers=len(batch)) as pool:
                futures = {pool.submit(_run_one_worker, qid): qid for qid in batch}
                for future in as_completed(futures):
                    qid, finding = future.result()
                    findings[qid] = finding
                    worker_config = WORKER_PROMPTS[qid]
                    state.add_finding(f"agent_{worker_config['title'].lower().replace(' ', '_')}", finding)
                    total_dispatched += 1

                    state.log("worker_completed", {
                        "question_id": qid,
                        "confidence": finding.confidence,
                        "evidence_count": len(finding.evidence),
                        "summary": finding.summary[:200],
                    })

                    if progress_callback:
                        progress_callback(
                            stage="multi_agent",
                            detail=f"Worker {qid}: {worker_config['title']} — {finding.confidence} ({total_dispatched}/{total_workers})",
                            worker_id=qid,
                            status="completed",
                        )
        else:
            # Sequential single worker
            qid = batch[0]
            print(f"  [Manager] Batch {batch_idx + 1}: Running worker {qid}...")
            qid, finding = _run_one_worker(qid)
            findings[qid] = finding
            worker_config = WORKER_PROMPTS[qid]
            state.add_finding(f"agent_{worker_config['title'].lower().replace(' ', '_')}", finding)
            total_dispatched += 1

            state.log("worker_completed", {
                "question_id": qid,
                "confidence": finding.confidence,
                "evidence_count": len(finding.evidence),
                "summary": finding.summary[:200],
            })

            if progress_callback:
                progress_callback(
                    stage="multi_agent",
                    detail=f"Worker {qid}: {worker_config['title']} — {finding.confidence} ({total_dispatched}/{total_workers})",
                    worker_id=qid,
                    status="completed",
                )

        # Cooldown between batches (not between parallel workers in same batch)
        if batch_idx < len(parallel_batches) - 1:
            cooldown = int(os.getenv("WORKER_COOLDOWN_SECONDS", "5"))
            if cooldown > 0:
                print(f"  [Manager] Cooldown {cooldown}s before next batch...")
                time.sleep(cooldown)

    return findings
