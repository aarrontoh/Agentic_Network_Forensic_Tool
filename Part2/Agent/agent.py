"""
Network Forensics Agent — SC4063
================================
4-phase pipeline targeting ~1 hour total runtime:

  Phase 1  JSON Analysis     (~15 min)  Stream Alerts + Zeek JSON → IOCs + evidence
  Phase 2  PCAP Sampling     (~20 min)  Parallel tshark on targeted PCAPs (capped)
  Phase 3  Worker Agents     (~20 min)  4 × Claude Opus 4.6 workers via CommonStack
  Phase 4  Report Synthesis  (~5  min)  Claude synthesises findings → Markdown report

Design principles:
  - JSON is the primary source of truth (faster, richer timeline)
  - PCAPs supplement JSON — never replace it
  - No assumption that initial access occurred within the capture window
  - Single LLM backend (CommonStack / Claude Opus 4.6)
  - All phases are independently re-runnable (--from-phase N)
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_progress_lock = threading.Lock()

# ── Load .env ────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    _env = Path(__file__).parent / ".env"
    if _env.exists():
        for _line in _env.read_text().splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

from models import AnalysisState


# ─────────────────────────────────────────────────────────────────────────────
# Progress helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write_progress(work_dir: str, stage: str, extra: Optional[Dict] = None) -> None:
    path = Path(work_dir) / "progress.json"
    data: dict = {}
    if path.exists():
        try:
            data = json.loads(path.read_text())
        except Exception:
            pass
    data["stage"] = stage
    data["updated_at"] = datetime.datetime.utcnow().isoformat()
    if extra:
        data.update(extra)
    try:
        path.write_text(json.dumps(data, indent=2, default=str))
    except Exception:
        pass


def _clean_work_dir(work_dir: Path, wipe_ingest_cache: bool, preserve_db: bool, preserve_findings: bool) -> None:
    """Remove stale outputs; preserve ingest cache and (optionally) DB/findings."""
    stale = [
        "report_commonstack.md", "agent_log.json", "timeline_commonstack.json",
        "findings_commonstack.json", "ingest_summary.json", "progress.json",
    ]
    if not preserve_db:
        stale.append("forensic_evidence.db")
    if not preserve_findings:
        pass  # findings already in stale list above unless preserve_findings

    for name in stale:
        p = work_dir / name
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass

    if wipe_ingest_cache:
        cache_dir = work_dir / "ingest"
        if cache_dir.exists():
            import shutil
            shutil.rmtree(cache_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Main run command
# ─────────────────────────────────────────────────────────────────────────────

def run_case(args: argparse.Namespace) -> None:
    from config import AgentConfig
    from tools.ingest import run_ingest

    config = AgentConfig()
    network_dir = getattr(args, "network_dir", None) or config.network_dir
    if not network_dir:
        raise SystemExit("ERROR: --network-dir is required (or set NF_NETWORK_DIR)")

    alert_override  = getattr(args, "alert_json", None) or config.alert_json_path or None
    zeek_override   = getattr(args, "zeek_json",  None) or config.zeek_json_path  or None
    pcap_override   = getattr(args, "pcap_dir",   None) or config.pcap_dir        or None

    from_phase  = getattr(args, "from_phase",  1)  or 1
    stop_phase  = getattr(args, "stop_phase",  99) or 99
    force_refresh = getattr(args, "force_refresh", False)

    work_dir = Path(args.output_root).resolve() / args.case
    _clean_work_dir(
        work_dir,
        wipe_ingest_cache=force_refresh,
        preserve_db=(from_phase >= 6),
        preserve_findings=(from_phase >= 8),
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    started_at = datetime.datetime.utcnow().isoformat()

    state = AnalysisState(
        case_id=args.case,
        pcap_path=pcap_override or network_dir,
        work_dir=str(work_dir),
    )

    _write_progress(str(work_dir), "starting", {
        "case_id": args.case,
        "started_at": started_at,
        "from_phase": from_phase,
    })

    # ── Phases 1-4: JSON + PCAP ingest (with cache) ─────────────────────────
    _write_progress(str(work_dir), "ingesting")
    print(f"\n{'='*60}")
    print(f"  SC4063 Network Forensics Agent")
    print(f"  Case: {args.case}  |  From phase: {from_phase}")
    print(f"{'='*60}")

    artifacts = run_ingest(
        network_dir=network_dir,
        work_dir=str(work_dir),
        config=config,
        alert_json_override=alert_override,
        zeek_json_override=zeek_override,
        pcap_dir_override=pcap_override,
        force_refresh=force_refresh,
    )
    state.artifacts = artifacts

    # Write ingest summary
    summary = {
        "alert_total":     artifacts.get("alert_total", 0),
        "zeek_matched":    artifacts.get("zeek_matched", 0),
        "targeted_pcaps":  len(artifacts.get("targeted_pcaps", [])),
        "pcap_dns":        len(artifacts.get("pcap_dns_queries", [])),
        "pcap_tls":        len(artifacts.get("pcap_tls_sessions", [])),
        "pcap_smb":        len(artifacts.get("pcap_smb_sessions", [])),
        "pcap_rdp":        len(artifacts.get("pcap_rdp_sessions", [])),
    }
    (work_dir / "ingest_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"  Ingest: {summary['alert_total']:,} alerts | {summary['zeek_matched']:,} Zeek records | {summary['targeted_pcaps']} PCAPs")

    # ── Phases 5-8: multi-agent analysis ────────────────────────────────────
    _run_multi_agent_analysis(state, artifacts, str(work_dir), started_at, from_phase, stop_phase)


# ─────────────────────────────────────────────────────────────────────────────
# DB verification (--stop-phase 5)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_notes_summary(notes_path: str, max_chars: int = 4000) -> str:
    """
    Extract a concise summary from phase2_notes.md for injection into worker prompts.

    Pulls only the most actionable sections:
      - Section 3 (RDP spray + attacker Kerberos correlation)
      - Section 12 (exfil volume)
      - Section 14 (key event timeline)

    Capped at max_chars to avoid bloating worker prompts.
    """
    try:
        content = Path(notes_path).read_text(encoding="utf-8")
    except Exception:
        return ""

    # Extract specific sections by header
    target_headers = [
        "## 3. RDP Spray Analysis",
        "## 12. Exfiltration Volume",
        "## 14. Key Event Timeline",
    ]
    extracted = []
    lines = content.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        is_target = any(line.startswith(h) for h in target_headers)
        if is_target:
            section_lines = [line]
            i += 1
            # Collect until next ## section
            while i < len(lines) and not (lines[i].startswith("## ") and not any(lines[i].startswith(h) for h in target_headers)):
                if lines[i].startswith("---"):
                    break
                section_lines.append(lines[i])
                i += 1
            extracted.append("\n".join(section_lines))
        else:
            i += 1

    summary = "\n\n".join(extracted)
    if len(summary) > max_chars:
        summary = summary[:max_chars] + "\n...[truncated — see phase2_notes.md for full details]"
    return summary


def _verify_db_and_exit(conn, db_path: str) -> None:
    """Print a DB health report and exit. Called when --stop-phase 5 is set."""
    from db.schema import get_table_stats
    stats = get_table_stats(conn)
    table_counts = stats.get("table_counts", stats)

    print("\n" + "=" * 70)
    print("  DB VERIFICATION REPORT")
    print(f"  {db_path}")
    print("=" * 70)
    print("\n  TABLE ROW COUNTS:")
    for table, count in sorted(table_counts.items()):
        flag = "  ⚠  EMPTY" if count == 0 else ""
        print(f"    {table:<35} {count:>10,}{flag}")

    print("\n  ATTACKER IP CHECK (zeek_rdp — external→.57, low volume = real attacker):")
    try:
        rows = conn.execute("""
            SELECT src_ip, COUNT(*) cnt, MIN(ts) first_ts, GROUP_CONCAT(DISTINCT cookie) cookies
            FROM zeek_rdp
            WHERE dst_ip='10.128.239.57'
              AND src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '172.%' AND src_ip NOT LIKE '192.168.%'
            GROUP BY src_ip ORDER BY cnt ASC LIMIT 10
        """).fetchall()
        for r in rows:
            marker = "  ← LIKELY ATTACKER (low volume)" if r[1] <= 5 else ""
            print(f"    {r[0]:<20} {r[1]:>6} connections  first={r[2]}  cookie={r[3]}{marker}")
    except Exception as e:
        print(f"    Error: {e}")

    print("\n  KERBEROS CORRELATION CHECK (auth from .57 within 60s of external RDP):")
    try:
        rows = conn.execute("""
            SELECT r.src_ip, r.ts rdp_ts, r.cookie, k.ts kerberos_ts, k.client_name,
                   CAST((julianday(k.ts)-julianday(r.ts))*86400 AS INTEGER) delta_s
            FROM zeek_rdp r
            JOIN zeek_kerberos k ON k.src_ip='10.128.239.57'
              AND julianday(k.ts) >= julianday(r.ts)
              AND (julianday(k.ts)-julianday(r.ts))*86400 <= 60
            WHERE r.dst_ip='10.128.239.57'
              AND r.src_ip NOT LIKE '10.%'
            ORDER BY delta_s LIMIT 10
        """).fetchall()
        if rows:
            print(f"    ✓ {len(rows)} correlations found")
            for r in rows:
                print(f"    {r[0]} → Kerberos '{r[4]}' delta={r[5]}s  rdp_cookie={r[2]}")
        else:
            print("    ✗ No Kerberos correlations — check zeek_kerberos table")
    except Exception as e:
        print(f"    Error (zeek_kerberos may not exist yet): {e}")

    print("\n  EXFIL CHECK (pcap_tcp_conv to 51.91.79.17):")
    try:
        rows = conn.execute("""
            SELECT src_ip, dst_ip, bytes_a_to_b, bytes_b_to_a,
                   MAX(bytes_a_to_b, bytes_b_to_a) dominant_bytes
            FROM pcap_tcp_conv WHERE dst_ip='51.91.79.17' OR src_ip='51.91.79.17'
            ORDER BY dominant_bytes DESC LIMIT 5
        """).fetchall()
        for r in rows:
            print(f"    {r[0]}→{r[1]}  a_to_b={r[2]:,}  b_to_a={r[3]:,}  dominant={r[4]:,} ({r[4]//1024//1024} MB)")
        if not rows:
            print("    No rows for 51.91.79.17")
    except Exception as e:
        print(f"    Error: {e}")

    print("\n  PAYLOAD CHECK (kkwlo.exe / hfs.exe in zeek_smb):")
    try:
        for fname in ("kkwlo.exe", "hfs.exe", "Microsofts.exe", "HOW TO BACK FILES.txt", "UninstallWinClient.exe"):
            n = conn.execute("SELECT COUNT(*) FROM zeek_smb WHERE filename LIKE ?", (f"%{fname}%",)).fetchone()[0]
            print(f"    {fname:<35} zeek_smb={n}")
    except Exception as e:
        print(f"    Error: {e}")

    conn.close()
    print("\n" + "=" * 70)
    print("  Phase 5 complete. Review the above before running phase 6.")
    print("  To continue: python3 agent.py run ... --from-phase 6")
    print("=" * 70 + "\n")
    raise SystemExit(0)


# ─────────────────────────────────────────────────────────────────────────────
# Multi-agent analysis (phases 5 → 8)
# ─────────────────────────────────────────────────────────────────────────────

def _run_multi_agent_analysis(
    state: AnalysisState,
    artifacts: Dict[str, Any],
    work_dir: str,
    started_at: str,
    from_phase: int = 1,
    stop_phase: int = 99,
) -> None:
    from db.schema import init_db, get_table_stats
    from db.ingest_db import load_all
    from agents.manager import run_multi_agent
    from agents.synthesizer import synthesize_report

    db_path = str(Path(work_dir) / "forensic_evidence.db")

    # ── Phase 5: Load evidence into SQLite ───────────────────────────────────
    if from_phase <= 5:
        print(f"\n  [Phase 5] Building forensic database...")
        _write_progress(work_dir, "loading_database")
        if Path(db_path).exists():
            Path(db_path).unlink()

        conn = init_db(db_path)

        def _db_cb(step, total, table, count):
            print(f"  [Phase 5] {table:<25} {count:>10,} rows  ({step}/{total})")
            _write_progress(work_dir, "loading_database", {
                "db_loading": {"step": step, "total": total, "current_table": table}
            })

        counts = load_all(conn, artifacts, progress_cb=_db_cb)
        state.log("db_loaded", counts)
        print(f"  [Phase 5] Database ready: {sum(v for v in counts.values() if isinstance(v, int)):,} total rows")

        # Generate Phase 2 investigation notes
        try:
            from tools.phase2_notes import generate_phase2_notes
            notes_path = str(Path(work_dir) / "phase2_notes.md")
            print(f"  [Phase 5] Generating investigation notes → phase2_notes.md")
            notes_content = generate_phase2_notes(conn, notes_path)
            state.log("phase2_notes_generated", {"path": notes_path, "size": len(notes_content)})
        except Exception as _e:
            print(f"  [Phase 5] Notes generation failed (non-fatal): {_e}")
            notes_content = ""

        if stop_phase <= 5:
            _verify_db_and_exit(conn, db_path)
    else:
        print(f"  [Phase skip] Reusing existing database: {db_path}")
        if not Path(db_path).exists():
            raise SystemExit(f"ERROR: DB not found at {db_path}. Run from phase 5 first.")
        conn = init_db(db_path)

    db_stats = get_table_stats(conn)

    # ── CommonStack config ───────────────────────────────────────────────────
    _cs_raw  = os.getenv("COMMON_API_KEY", "").strip()
    cs_keys  = [k.strip() for k in _cs_raw.split(",") if k.strip()] if _cs_raw else []
    cs_model = os.getenv("COMMON_API_MODEL", "anthropic/claude-opus-4-6").strip()
    if cs_model.lower() in ("any", "best", "", "any available model"):
        cs_model = "anthropic/claude-opus-4-6"
    cs_base  = "https://api.commonstack.ai/v1"

    if not cs_keys:
        raise SystemExit("ERROR: COMMON_API_KEY not set in .env")

    print(f"\n  [Config] Model: {cs_model}  |  Keys available: {len(cs_keys)}")

    # ── Finding serialisation helpers ────────────────────────────────────────
    def _findings_to_json(f_dict):
        return {qid: {
            "question_id": f.question_id, "title": f.title,
            "status": f.status, "confidence": f.confidence,
            "summary": f.summary, "mitre_techniques": list(f.mitre or []),
            "evidence": [vars(e) for e in f.evidence],
            "limitations": list(f.limitations or []),
        } for qid, f in f_dict.items()}

    def _load_findings_json(path: Path) -> dict:
        from models import Finding, EvidenceItem
        if not path.exists():
            return {}
        raw = json.loads(path.read_text())
        result = {}
        for qid, fd in raw.items():
            evidence = [
                EvidenceItem(**{k: v for k, v in e.items() if k in EvidenceItem.__dataclass_fields__})
                for e in fd.get("evidence", [])
            ]
            result[qid] = Finding(
                question_id=fd.get("question_id", qid),
                title=fd.get("title", ""),
                status=fd.get("status", ""),
                confidence=fd.get("confidence", ""),
                summary=fd.get("summary", ""),
                mitre=fd.get("mitre_techniques", []),
                evidence=evidence,
                limitations=fd.get("limitations", []),
            )
        return result

    # ── Phase 8 shortcut ─────────────────────────────────────────────────────
    if from_phase >= 8:
        print("\n  [Phase 8] Re-synthesizing from existing findings...")
        _write_progress(work_dir, "synthesizing")
        findings_path = Path(work_dir) / "findings_commonstack.json"
        findings = _load_findings_json(findings_path)
        if not findings:
            raise SystemExit("ERROR: findings_commonstack.json not found. Run phase 6 first.")
        report = synthesize_report(findings, db_stats)
        (Path(work_dir) / "report_commonstack.md").write_text(report)
        print("  [Phase 8] Report → report_commonstack.md")
        _write_progress(work_dir, "complete")
        conn.close()
        return

    _write_progress(work_dir, "multi_agent")

    # ── Load notes summary for worker context injection ──────────────────────
    notes_summary = _extract_notes_summary(str(Path(work_dir) / "phase2_notes.md"))

    # ── Phase 6: Worker agents ───────────────────────────────────────────────
    print(f"\n  [Phase 6] Running workers A → B → C → D  ({cs_model})")
    print(f"  [Phase 6] {len(cs_keys)} key(s) available, rotating on credit exhaustion")

    # ── Phase 6 live state — written to progress.json after every worker event ──
    import datetime as _dt
    _p6: dict = {
        "workers": {qid: {"status": "queued", "iteration": 0, "max_iter": 12,
                          "sql_count": 0, "last_sql": "", "evidence_count": 0,
                          "confidence": "", "key_idx": 1, "error": ""}
                   for qid in ("A", "B", "C", "D")},
        "activity": [],          # rolling last-30 events shown in dashboard
        "keys": [{"idx": i+1, "status": "ok"} for i in range(len(cs_keys))],
        "model": cs_model,
        "total_keys": len(cs_keys),
    }

    def _p6_flush():
        _write_progress(work_dir, "multi_agent", {
            "agent_status": {
                "worker_id": next((q for q,w in _p6["workers"].items() if w["status"]=="running"), ""),
                "status": "running",
                "detail": "",
            },
            "phase6": _p6,
        })

    def _p6_activity(wid: str, typ: str, msg: str):
        ts = _dt.datetime.utcnow().strftime("%H:%M:%S")
        _p6["activity"].append({"ts": ts, "wid": wid, "type": typ, "msg": msg})
        if len(_p6["activity"]) > 40:
            _p6["activity"] = _p6["activity"][-40:]

    def _phase6_log(event: str, data: dict):
        """Rich log_callback passed to workers — updates phase6 live state."""
        qid = data.get("question_id", "?")
        w = _p6["workers"].get(qid, {})

        if event == "worker_started":
            w["status"] = "running"
            w["iteration"] = 0
            w["sql_count"] = 0
            w["last_sql"] = ""
            w["key_idx"] = data.get("key_idx", shared_key_idx[0] + 1)
            _p6_activity(qid, "start", f"Worker {qid} started — {data.get('backend','')}")

        elif event == "tool_call":
            sql = (data.get("args") or {}).get("sql", "")
            w["iteration"] = data.get("iteration", w.get("iteration", 0))
            w["sql_count"] = w.get("sql_count", 0) + 1
            w["last_sql"] = sql[:200] if sql else data.get("tool_name", "")
            _p6_activity(qid, "sql", f"[iter {w['iteration']}] {sql[:100]}" if sql else f"[iter {w['iteration']}] {w['last_sql']}")

        elif event == "worker_completed":
            w["status"] = "done"
            w["iteration"] = data.get("iterations", w.get("iteration", 0))
            w["evidence_count"] = data.get("evidence_count", 0)
            w["confidence"] = data.get("confidence", "")
            _p6_activity(qid, "done", f"Worker {qid} done — {data.get('iterations',0)} iters, {data.get('evidence_count',0)} evidence, {data.get('confidence','')}")

        elif event == "backend_failed":
            _p6_activity(qid, "error", f"Worker {qid} backend failed: {data.get('error','')[:80]}")

        elif event == "key_rotated":
            new_idx = data.get("new_key_idx", shared_key_idx[0])
            w["key_idx"] = new_idx + 1
            # Mark old key as exhausted/rate-limited
            old_idx = data.get("old_key_idx", new_idx - 1)
            if 0 <= old_idx < len(_p6["keys"]):
                _p6["keys"][old_idx]["status"] = data.get("reason", "rotated")
            _p6_activity(qid, "key", f"Key rotated → key {new_idx+1}/{len(cs_keys)}: {data.get('reason','')}")

        elif event == "rate_limit":
            _p6_activity(qid, "warn", f"Rate limited — waiting {data.get('backoff_seconds','?')}s")

        elif event == "all_backends_failed":
            w["status"] = "error"
            w["error"] = "; ".join(f['error'] for f in data.get("failed_backends", []))
            _p6_activity(qid, "error", f"All backends failed for Worker {qid}")

        _p6_flush()

    def _agent_cb(stage, detail, worker_id, status, **kw):
        if worker_id and status == "running":
            _p6["workers"][worker_id]["status"] = "running"
        elif worker_id and status == "completed":
            _p6["workers"][worker_id]["status"] = "done"
        _p6_flush()

    findings: dict = {}
    last_error = None

    # Shared mutable key index — persists across all 4 workers so if Worker A
    # rotates from key 1 to key 2, Worker B starts on key 2 (not key 1 again).
    shared_key_idx = [0]

    cs_backend = {
        "backend": "openai",
        "api_key": cs_keys[0],
        "model": cs_model,
        "base_url": cs_base,
        "all_keys": cs_keys,
        "shared_key_idx": shared_key_idx,  # mutable — updated by workers mid-run
        "fallback_models": ["google/gemini-2.5-pro", "anthropic/claude-opus-4-6"],  # tried if primary 404s
    }
    try:
        findings = run_multi_agent(
            conn, state,
            progress_callback=_agent_cb,
            log_callback_override=_phase6_log,
            backend_config=cs_backend,
            sequential=True,
            inter_worker_cooldown=60,
            investigation_notes=notes_summary,
        )
        if findings:
            print(f"  [Phase 6] All workers done (key {shared_key_idx[0] + 1}/{len(cs_keys)} used)")
        else:
            raise SystemExit("ERROR: Workers completed but returned no findings. Check agent_log.json.")
    except SystemExit:
        raise
    except Exception as exc:
        raise SystemExit(f"ERROR: Workers failed — {exc}")

    if not findings:
        raise SystemExit("ERROR: No findings produced. All keys may be exhausted.")

    for qid, f in findings.items():
        state.findings[qid] = f

    # Save findings
    findings_path = Path(work_dir) / "findings_commonstack.json"
    findings_path.write_text(json.dumps(_findings_to_json(findings), indent=2, default=str))
    print(f"  [Phase 6] Findings → findings_commonstack.json")

    # Save agent log
    log_path = Path(work_dir) / "agent_log.json"
    log_path.write_text(json.dumps(state.agent_log, indent=2, default=str))

    # Update progress findings summary
    _write_progress(work_dir, "workers_done", {
        "findings": {
            qid: {"title": f.title, "confidence": f.confidence, "status": f.status}
            for qid, f in findings.items()
        }
    })

    # ── Phase 7: Timeline ────────────────────────────────────────────────────
    print(f"\n  [Phase 7] Building timeline...")
    _write_progress(work_dir, "building_timeline")
    try:
        from tools.timeline import build_timeline
        timeline = build_timeline(state)
        tl_path = Path(work_dir) / "timeline_commonstack.json"
        tl_path.write_text(json.dumps(timeline, indent=2, default=str))
        print(f"  [Phase 7] Timeline → {len(timeline)} events")
    except Exception as e:
        print(f"  [Phase 7] Timeline failed (non-fatal): {e}")

    # ── Phase 8: Report synthesis ────────────────────────────────────────────
    print(f"\n  [Phase 8] Synthesising report via Claude Opus 4.6...")
    _write_progress(work_dir, "synthesizing")
    report = synthesize_report(findings, db_stats)
    report_path = Path(work_dir) / "report_commonstack.md"
    report_path.write_text(report)
    print(f"  [Phase 8] Report ({len(report):,} chars) → report_commonstack.md")

    conn.close()

    elapsed = (datetime.datetime.utcnow() - datetime.datetime.fromisoformat(started_at)).seconds // 60
    _write_progress(work_dir, "complete", {"elapsed_minutes": elapsed})

    print(f"\n{'='*60}")
    print(f"  DONE — {elapsed} minutes elapsed")
    print(f"  Output: {work_dir}/")
    print(f"{'='*60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent", description="SC4063 Network Forensics Agent")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="Run the forensic analysis pipeline")
    run.add_argument("--network-dir", dest="network_dir", default="",
                     help="Root folder containing alert JSON, zeek JSON, and pcap/ subfolder")
    run.add_argument("--case", default="SC4063_Network_Security",
                     help="Case name (used as output subfolder)")
    run.add_argument("--output-root", dest="output_root", default="data/output",
                     help="Root output directory")
    run.add_argument("--reasoner", default="multi-agent",
                     choices=["multi-agent"],
                     help="Analysis mode (only multi-agent is supported)")
    run.add_argument("--from-phase", dest="from_phase", type=int,
                     choices=[1, 5, 6, 8], default=1,
                     help="Start from phase: 1=full ingest+DB+analysis, 5=reload DB only, 6=reuse existing DB, 8=re-synthesize only")
    run.add_argument("--stop-phase", dest="stop_phase", type=int,
                     choices=[5, 6], default=99,
                     help="Stop after this phase (5=load DB then print verification; 6=run workers but skip synthesis)")
    run.add_argument("--force-refresh", dest="force_refresh", action="store_true",
                     help="Ignore ingest cache and re-run phases 1-4")
    run.add_argument("--alert-json", dest="alert_json", default="")
    run.add_argument("--zeek-json",  dest="zeek_json",  default="")
    run.add_argument("--pcap-dir",   dest="pcap_dir",   default="")
    run.set_defaults(func=run_case)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
