from __future__ import annotations

import argparse
import datetime
import json
import shutil
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_progress_lock = threading.Lock()

from config import AgentConfig
from llm import build_reasoner
from openai_env import openai_client_kwargs
from models import AnalysisState
from tools.exfiltration import analyze_exfiltration
from tools.ingest import run_ingest
from tools.initial_access import analyze_initial_access
from tools.lateral_movement import analyze_lateral_movement
from tools.payload_delivery import analyze_payload_delivery
from tools.reporting import write_outputs
from tools.timeline import build_timeline

# Load .env file if present (for GEMINI_API_KEY etc.)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed — fall back to manual .env loading
    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        import os
        for line in _env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())


ACTION_MAP = {
    "initial_access": analyze_initial_access,
    "lateral_movement": analyze_lateral_movement,
    "exfiltration": analyze_exfiltration,
    "payload_delivery": analyze_payload_delivery,
}


def _write_progress(
    work_dir: str,
    stage: str,
    state: AnalysisState,
    started_at: str,
    timeline_events: Optional[List[Dict[str, Any]]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    progress_path = Path(work_dir) / "progress.json"
    data: Dict[str, Any] = {}
    if progress_path.exists():
        try:
            data = json.loads(progress_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    all_tools = list(ACTION_MAP.keys())
    data.update({
        "case_id": state.case_id,
        "started_at": started_at,
        "updated_at": datetime.datetime.utcnow().isoformat(),
        "stage": stage,
        "completed_tools": [t for t in state.completed_actions if t in all_tools],
        "pending_tools": [t for t in all_tools if t not in state.completed_actions],
        "findings": {
            qid: {
                "question_id": f.question_id,
                "title": f.title,
                "confidence": f.confidence,
                "status": f.status,
                "summary": f.summary,
                "evidence_count": len(f.evidence),
                "model": getattr(f, "tool_name", ""),
                "limitations": getattr(f, "limitations", []) or [],
            }
            for qid, f in state.findings.items()
        },
        "llm_log": [
            entry for entry in state.agent_log
            if isinstance(entry, dict) and entry.get("event_type") in (
                "worker_started", "worker_completed", "backend_failed",
                "all_backends_failed", "rate_limit", "tool_call",
                "worker_dispatched", "key_rotated",
            )
        ][-200:],  # last 200 LLM-related log entries
    })
    if timeline_events is not None:
        data["timeline"] = timeline_events
    if extra:
        data.update(extra)

    with _progress_lock:
        progress_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _clean_work_dir(work_dir: Path, wipe_ingest_cache: bool = False, preserve_db: bool = False, preserve_findings: bool = False) -> None:
    """Remove stale output so every run starts from a clean slate.

    Preserves the ``ingest/`` cache directory (expensive Zeek/PCAP results)
    unless *wipe_ingest_cache* is True (i.e. --force-refresh).
    Everything else — progress.json, findings.json, report.md, agent_log.json,
    timeline.json, ingest_summary.json, and any legacy directories like
    preprocessing/ — is deleted.
    """
    if not work_dir.exists():
        return

    # Files that must be wiped every run
    _STALE_FILES = [
        "progress.json",
        "findings.json",
        "findings_openai.json",
        "findings_commonstack.json",
        "report.md",
        "report_synthesized.md",
        "report_commonstack.md",
        "agent_log.json",
        "timeline.json",
        "timeline_commonstack.json",
        "ingest_summary.json",
        "preprocessing_summary.json",
        "forensic_evidence.db",
    ]
    if preserve_db and "forensic_evidence.db" in _STALE_FILES:
        _STALE_FILES.remove("forensic_evidence.db")
    if preserve_findings:
        for _f in ("findings_openai.json", "findings_commonstack.json", "timeline.json", "timeline_commonstack.json"):
            if _f in _STALE_FILES:
                _STALE_FILES.remove(_f)
    for name in _STALE_FILES:
        p = work_dir / name
        if p.exists():
            p.unlink()

    # Legacy directories from the old preprocess.py pipeline
    _STALE_DIRS = ["preprocessing"]
    for name in _STALE_DIRS:
        d = work_dir / name
        if d.is_dir():
            shutil.rmtree(d)

    # Optionally wipe the ingest cache too
    if wipe_ingest_cache:
        ingest_dir = work_dir / "ingest"
        if ingest_dir.is_dir():
            shutil.rmtree(ingest_dir)


def run_case(args: argparse.Namespace) -> None:
    config = AgentConfig.from_env()

    # Resolve network_dir from args or env
    network_dir = getattr(args, "network_dir", None) or config.network_dir
    if not network_dir:
        raise SystemExit(
            "ERROR: --network-dir is required (or set NF_NETWORK_DIR env var)."
        )

    # Optional per-component overrides
    alert_json_override = getattr(args, "alert_json", None) or config.alert_json_path or None
    zeek_json_override = getattr(args, "zeek_json", None) or config.zeek_json_path or None
    pcap_dir_override = getattr(args, "pcap_dir", None) or config.pcap_dir or None

    work_dir = Path(args.output_root).resolve() / args.case

    # ── Clean slate: wipe stale output from previous runs ─────────────────────
    # The ingest/ cache is preserved unless --force-refresh is used, but all
    # other output files and legacy directories are removed so the dashboard
    # never shows data from a prior run.
    force_refresh = getattr(args, "force_refresh", False)
    from_phase_early = getattr(args, "from_phase", 1) or 1
    _clean_work_dir(work_dir, wipe_ingest_cache=force_refresh,
                    preserve_db=(from_phase_early >= 6),
                    preserve_findings=(from_phase_early >= 8))

    work_dir.mkdir(parents=True, exist_ok=True)
    started_at = datetime.datetime.utcnow().isoformat()

    state = AnalysisState(
        case_id=args.case,
        pcap_path=pcap_dir_override or network_dir,
        work_dir=str(work_dir),
    )
    state.log("run_started", {
        "case_id": args.case,
        "network_dir": network_dir,
        "reasoner": args.reasoner,
    })
    _write_progress(str(work_dir), "starting", state, started_at)

    # ── Ingest pipeline (phases 1-4) ──────────────────────────────────────────
    artifacts = run_ingest(
        network_dir=network_dir,
        work_dir=str(work_dir),
        config=config,
        alert_json_override=alert_json_override,
        zeek_json_override=zeek_json_override,
        pcap_dir_override=pcap_dir_override,
        force_refresh=force_refresh,
    )
    state.artifacts = artifacts
    state.log("ingest_completed", {
        "alert_total": artifacts.get("alert_total", 0),
        "zeek_matched": artifacts.get("zeek_matched", 0),
        "targeted_pcaps": len(artifacts.get("targeted_pcaps", [])),
        "pcap_dns_queries": len(artifacts.get("pcap_dns_queries", [])),
        "pcap_tls_sessions": len(artifacts.get("pcap_tls_sessions", [])),
    })
    _write_progress(str(work_dir), "analyzing", state, started_at)

    # ── Analysis: choose between deterministic/LLM planner or multi-agent ────
    from_phase = getattr(args, "from_phase", 1) or 1
    stop_phase = getattr(args, "stop_phase", 99) or 99
    if args.reasoner == "multi-agent":
        _run_multi_agent_analysis(state, artifacts, str(work_dir), started_at, from_phase=from_phase, stop_phase=stop_phase)
    else:
        _run_planner_analysis(state, artifacts, config, args, str(work_dir), started_at)


def _run_planner_analysis(
    state: AnalysisState,
    artifacts: Dict[str, Any],
    config: AgentConfig,
    args: argparse.Namespace,
    work_dir: str,
    started_at: str,
) -> None:
    """Original deterministic / LLM-planner analysis loop."""
    reasoner = build_reasoner(args.reasoner, config.openai_model, config.gemini_model)

    for _ in range(config.max_agent_steps):
        available_actions = [name for name in ACTION_MAP if name not in state.completed_actions]
        if not available_actions:
            break

        decision = reasoner.choose_next_action(state, available_actions)
        if decision.next_action not in ACTION_MAP:
            raise RuntimeError(f"Reasoner returned unknown action: {decision.next_action}")
        state.log("decision", {"next_action": decision.next_action, "reason": decision.reason})

        finding = ACTION_MAP[decision.next_action](state.artifacts, config)
        state.add_finding(decision.next_action, finding)
        state.log("finding_recorded", {"question_id": finding.question_id, "summary": finding.summary})
        _write_progress(work_dir, "analyzing", state, started_at)

    # ── Timeline + reporting ──────────────────────────────────────────────────
    timeline_payload = build_timeline(state)
    state.completed_actions.append("timeline")
    state.log("timeline_built", {
        "timeline_path": timeline_payload["path"],
        "event_count": len(timeline_payload["events"]),
    })
    _write_progress(work_dir, "reporting", state, started_at, timeline_events=timeline_payload["events"])

    write_outputs(state)
    _write_progress(work_dir, "complete", state, started_at, timeline_events=timeline_payload["events"])
    print(json.dumps({"status": "ok", "output_dir": state.work_dir}, indent=2))


def _test_llm_connection() -> None:
    """Pre-flight test: verify OpenAI gpt-4o works before ingest.

    Tests OpenAI with a realistic function-calling round trip (~4 KB tool response).
    """
    import os
    import json

    _FAKE_DB_RESULT = {
        "columns": ["src_ip", "dst_ip", "dst_port", "protocol", "count"],
        "rows": [
            ["10.128.239.57", "10.128.239.29", 49668, "dce_rpc", 72670],
            ["10.128.239.57", "10.128.239.23", 49668, "dce_rpc", 3977],
            ["10.128.239.57", "10.128.239.34", 3389, "rdp", 1245],
        ] * 10,
        "row_count": 30,
        "truncated": False,
    }

    _TEST_TOOL = {
        "type": "function",
        "function": {
            "name": "query_db",
            "description": "Execute a read-only SQL SELECT query.",
            "parameters": {
                "type": "object",
                "properties": {"sql": {"type": "string", "description": "SQL SELECT query."}},
                "required": ["sql"],
            },
        },
    }

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    model = os.getenv("OPENAI_MODEL", "gpt-4o")

    if not api_key:
        raise RuntimeError("OPENAI_API_KEY missing in .env")

    print(f"  [Pre-flight] Testing OpenAI {model}...")

    try:
        from openai import OpenAI
        client = OpenAI(**openai_client_kwargs(api_key))

        # Step 1: function calling
        print(f"  [OPENAI] Step 1/2: Function calling...")
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a forensic analyst. Use the query_db tool."},
                {"role": "user", "content": "Query the database to count all alerts."},
            ],
            tools=[_TEST_TOOL], tool_choice="auto", temperature=0.1,
        )
        msg = resp.choices[0].message
        if not msg.tool_calls:
            raise RuntimeError("No function call returned")
        tc = msg.tool_calls[0]
        print(f"  [OPENAI]   Called: {tc.function.name}")

        # Step 2: large tool response
        print(f"  [OPENAI] Step 2/2: Large tool response (~4 KB)...")
        assistant_msg = {k: v for k, v in msg.model_dump().items() if k in ("role", "content", "tool_calls")}
        resp2 = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "Summarize briefly."},
                {"role": "user", "content": "Query the database to count all alerts."},
                assistant_msg,
                {"role": "tool", "tool_call_id": tc.id, "content": json.dumps(_FAKE_DB_RESULT)},
            ],
            tools=[_TEST_TOOL], temperature=0.1, max_tokens=100,
        )
        reply = resp2.choices[0].message.content or "(ok)"
        print(f"  [OPENAI]   Response: {reply[:80]}...")
        print(f"  [Pre-flight] Result: PASS")

    except Exception as e:
        print(f"  [Pre-flight] Result: FAIL — {str(e)[:200]}")
        raise RuntimeError(f"OpenAI pre-flight test failed: {e}")


def _verify_db_and_exit(conn, db_path: str) -> None:
    """Print a DB verification report and exit cleanly. Called after phase 5 with --stop-phase 5."""
    from db.schema import get_table_stats

    print("\n" + "="*70)
    print("  DB VERIFICATION REPORT")
    print(f"  DB path: {db_path}")
    print("="*70)

    stats = get_table_stats(conn)
    table_counts = stats.get("table_counts", stats)
    print("\n  TABLE ROW COUNTS:")
    for table, count in sorted(table_counts.items()):
        flag = "  ⚠  EMPTY" if count == 0 else ""
        print(f"    {table:<35} {count:>10,}{flag}")

    # ── Critical: pcap_credentials check ─────────────────────────────────────
    print("\n  CRITICAL — pcap_credentials (attacker IP identification):")
    try:
        rows = conn.execute(
            "SELECT attacker_ip, target_ip, credential, real_ts_rdp, delta_secs, evidence_note, source_pcap "
            "FROM pcap_credentials ORDER BY real_ts_rdp LIMIT 20"
        ).fetchall()
        if rows:
            print(f"    ✓  {len(rows)} credential record(s) found — attacker IP identification WORKING")
            for r in rows:
                print(f"    attacker={r[0]}  target={r[1]}  cred={r[2]}  rdp_ts={r[3]}  delta={r[4]:.1f}s")
                print(f"      note: {r[5]}")
                print(f"      pcap: {r[6]}")
        else:
            print("    ✗  pcap_credentials is EMPTY — attacker IP identification WILL FAIL")
            print("       Worker A will report wrong IP (58.97.5.203 instead of 195.211.190.189)")
            print("       DO NOT proceed to phase 6 until this is fixed.")
    except Exception as e:
        print(f"    ✗  Error querying pcap_credentials: {e}")

    # ── pcap_rdp check ────────────────────────────────────────────────────────
    print("\n  pcap_rdp (RDP sessions from PCAPs):")
    try:
        total = conn.execute("SELECT COUNT(*) FROM pcap_rdp").fetchone()[0]
        external = conn.execute(
            "SELECT COUNT(*) FROM pcap_rdp WHERE src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '172.%' AND src_ip NOT LIKE '192.168.%'"
        ).fetchone()[0]
        sample = conn.execute(
            "SELECT src_ip, dst_ip, real_ts, cookie FROM pcap_rdp WHERE src_ip NOT LIKE '10.%' LIMIT 5"
        ).fetchall()
        print(f"    Total RDP rows: {total:,}  |  External-source rows: {external:,}")
        for r in sample:
            print(f"    {r[0]} → {r[1]}  ts={r[2]}  cookie={r[3]!r}")
    except Exception as e:
        print(f"    Error: {e}")

    # ── zeek_conn check for attacker IP ───────────────────────────────────────
    print("\n  zeek_conn rows for 195.211.190.189 (expected: 0 — not in Zeek):")
    try:
        n = conn.execute("SELECT COUNT(*) FROM zeek_conn WHERE src_ip='195.211.190.189' OR dst_ip='195.211.190.189'").fetchone()[0]
        print(f"    {n} rows  {'(confirmed absent from Zeek — normal)' if n == 0 else '(unexpected!)'}")
    except Exception as e:
        print(f"    Error: {e}")

    # ── temp.sh exfil check ───────────────────────────────────────────────────
    print("\n  Exfil — pcap_tcp_conv bytes to 51.91.79.17 (expect ~1,033 MB upload):")
    try:
        rows = conn.execute(
            "SELECT src_ip, dst_ip, bytes_a_to_b, bytes_b_to_a FROM pcap_tcp_conv "
            "WHERE dst_ip='51.91.79.17' OR src_ip='51.91.79.17' ORDER BY bytes_a_to_b DESC LIMIT 5"
        ).fetchall()
        for r in rows:
            dominant = max(r[2], r[3])
            print(f"    {r[0]} → {r[1]}  a_to_b={r[2]:,}  b_to_a={r[3]:,}  dominant={dominant:,} ({dominant/1024/1024:.0f} MB)")
        if not rows:
            print("    No rows found for 51.91.79.17")
    except Exception as e:
        print(f"    Error: {e}")

    # ── Ransomware payloads check ─────────────────────────────────────────────
    print("\n  Payload — kkwlo.exe / hfs.exe in zeek_smb or pcap_smb:")
    try:
        for fname in ("kkwlo.exe", "hfs.exe", "Microsofts.exe", "HOW TO BACK FILES.txt"):
            n_zeek = conn.execute("SELECT COUNT(*) FROM zeek_smb WHERE filename LIKE ?", (f"%{fname}%",)).fetchone()[0]
            try:
                n_pcap = conn.execute("SELECT COUNT(*) FROM pcap_smb WHERE filename LIKE ?", (f"%{fname}%",)).fetchone()[0]
            except Exception:
                n_pcap = "n/a"
            print(f"    {fname:<35} zeek_smb={n_zeek}  pcap_smb={n_pcap}")
    except Exception as e:
        print(f"    Error: {e}")

    conn.close()
    print("\n" + "="*70)
    print("  Phase 5 complete. Review above before running phase 6.")
    print("  If pcap_credentials is EMPTY, do NOT proceed — fix the extractor first.")
    print("  To continue: re-run with --from-phase 6")
    print("="*70 + "\n")
    raise SystemExit(0)


def _run_multi_agent_analysis(
    state: AnalysisState,
    artifacts: Dict[str, Any],
    work_dir: str,
    started_at: str,
    from_phase: int = 1,
    stop_phase: int = 99,
) -> None:
    """Multi-agent investigation: DB ingestion → Worker agents → Synthesizer."""
    from db.schema import init_db, get_table_stats
    from db.ingest_db import load_all
    from agents.manager import run_multi_agent
    from agents.synthesizer import synthesize_report

    db_path = str(Path(work_dir) / "forensic_evidence.db")

    if from_phase <= 5:
        # ── Phase 5: Load evidence into SQLite database ──────────────────────
        # Remove old DB so we get a fresh load
        if Path(db_path).exists():
            Path(db_path).unlink()
        state.log("db_init", {"db_path": db_path})
        _write_progress(work_dir, "loading_database", state, started_at)

        conn = init_db(db_path)

        def _db_progress(step, total, table_name, row_count):
            _write_progress(work_dir, "loading_database", state, started_at,
                            extra={"db_loading": {
                                "step": step, "total": total,
                                "current_table": table_name,
                                "rows_loaded": row_count,
                            }})
            print(f"  [Phase 5] Loading {table_name}... ({step}/{total}) — {row_count:,} rows")

        counts = load_all(conn, artifacts, progress_cb=_db_progress)
        state.log("db_loaded", counts)

        # ── Stop-phase 5: verify DB then exit ─────────────────────────────────
        if stop_phase <= 5:
            _verify_db_and_exit(conn, db_path)
    else:
        # Phase 6+: reuse existing DB
        print(f"  [Phase skip] Reusing existing database: {db_path}")
        if not Path(db_path).exists():
            raise SystemExit(f"ERROR: --from-phase {from_phase} requires existing DB at {db_path}")
        conn = init_db(db_path)  # opens existing DB, creates missing tables

    db_stats = get_table_stats(conn)

    import os

    # ── CommonStack config — single pipeline ─────────────────────────────────
    _cs_raw     = os.getenv("COMMON_API_KEY", "").strip()
    cs_keys     = [k.strip() for k in _cs_raw.split(",") if k.strip()] if _cs_raw else []
    cs_model    = os.getenv("COMMON_API_MODEL", "anthropic/claude-opus-4-6").strip()
    # "any available model" → use claude-opus-4-6 as default
    if cs_model.lower() in ("any", "best", "", "any available model"):
        cs_model = "anthropic/claude-opus-4-6"
    cs_base_url = "https://api.commonstack.ai/v1"

    if not cs_keys:
        raise SystemExit("ERROR: COMMON_API_KEY not set in .env — required for multi-agent mode")

    def _findings_to_json(f_dict):
        return {qid: {
            "question_id": f.question_id,
            "title": f.title,
            "status": f.status,
            "confidence": f.confidence,
            "summary": f.summary,
            "mitre_techniques": list(f.mitre or []),
            "evidence": [vars(e) for e in f.evidence],
            "limitations": list(f.limitations or []),
        } for qid, f in f_dict.items()}

    def _load_findings_json(path: Path) -> dict:
        """Deserialize findings_commonstack.json back into Finding objects."""
        from models import Finding, EvidenceItem
        if not path.exists():
            return {}
        raw = json.loads(path.read_text(encoding="utf-8"))
        result = {}
        for qid, fd in raw.items():
            evidence = [
                EvidenceItem(**{k: v for k, v in e.items() if k in EvidenceItem.__dataclass_fields__})
                for e in fd.get("evidence", [])
            ]
            f = Finding(
                question_id=fd.get("question_id", qid),
                title=fd.get("title", ""),
                status=fd.get("status", ""),
                confidence=fd.get("confidence", ""),
                summary=fd.get("summary", ""),
                mitre=fd.get("mitre_techniques", []),
                evidence=evidence,
                limitations=fd.get("limitations", []),
            )
            result[qid] = f
        return result

    # ── Phase 8 shortcut: re-synthesize report from existing findings ─────────
    if from_phase >= 8:
        print("  [Phase skip] Re-synthesizing report from existing findings...")
        _write_progress(work_dir, "synthesizing", state, started_at)

        cs_findings_path = Path(work_dir) / "findings_commonstack.json"
        findings = _load_findings_json(cs_findings_path)

        if not findings:
            raise SystemExit("ERROR: --from-phase 8 requires findings_commonstack.json (run phase 6 first)")

        print("  [Phase 8] Synthesizing report via CommonStack...")
        cs_report = synthesize_report(findings, db_stats, force_commonstack=True)
        (Path(work_dir) / "report_commonstack.md").write_text(cs_report, encoding="utf-8")
        print("  [Phase 8] Report written → report_commonstack.md")

        _write_progress(work_dir, "complete", state, started_at)
        conn.close()
        print(json.dumps({"status": "ok", "mode": "re-synthesize", "output_dir": state.work_dir}, indent=2))
        return

    _write_progress(work_dir, "multi_agent", state, started_at)

    def _agent_progress(stage, detail, worker_id, status, **kw):
        _write_progress(work_dir, stage, state, started_at,
                        extra={"agent_status": {
                            "worker_id": worker_id,
                            "status": status,
                            "detail": detail,
                        }})

    # ── Phase 6: CommonStack workers with API key rotation ────────────────────
    print(f"  [Phase 6] Running CommonStack workers A→B→C→D ({cs_model})...")
    print(f"  [Phase 6] {len(cs_keys)} API key(s) available for rotation")

    findings: dict = {}
    last_error = None

    for key_idx, api_key in enumerate(cs_keys):
        cs_backend = {
            "backend": "openai",
            "api_key": api_key,
            "model": cs_model,
            "base_url": cs_base_url,
            "all_keys": cs_keys,  # full list for mid-worker key rotation
        }
        try:
            findings = run_multi_agent(
                conn, state,
                progress_callback=_agent_progress,
                backend_config=cs_backend,
                sequential=True,
                inter_worker_cooldown=120,
            )
            if findings:
                print(f"  [Phase 6] Workers completed with key {key_idx + 1}/{len(cs_keys)}")
                break
        except Exception as exc:
            last_error = str(exc)
            print(f"  [Phase 6] Key {key_idx + 1}/{len(cs_keys)} exhausted/failed: {last_error[:120]}")
            if key_idx < len(cs_keys) - 1:
                print(f"  [Phase 6] Rotating to key {key_idx + 2}...")
            continue

    if not findings:
        raise SystemExit(f"ERROR: All CommonStack keys exhausted. Last error: {last_error}")

    for qid, finding in findings.items():
        state.findings[qid] = finding

    # ── Phase 7: Timeline ──────────────────────────────────────────────────────
    timeline_payload = build_timeline(state)
    state.completed_actions.append("timeline")
    state.log("timeline_built", {"event_count": len(timeline_payload["events"])})

    findings_path = Path(work_dir) / "findings_commonstack.json"
    findings_path.write_text(json.dumps(_findings_to_json(findings), indent=2), encoding="utf-8")
    timeline_path = Path(work_dir) / "timeline_commonstack.json"
    timeline_path.write_text(json.dumps({"events": timeline_payload.get("events", [])}, indent=2), encoding="utf-8")

    # ── Phase 8: Synthesis ─────────────────────────────────────────────────────
    _write_progress(work_dir, "synthesizing", state, started_at)
    state.log("synthesizer_started", {})
    print(f"  [Phase 8] Synthesizing report via CommonStack ({cs_model})...")

    report_md = synthesize_report(findings, db_stats, force_commonstack=True)
    report_path = Path(work_dir) / "report_commonstack.md"
    report_path.write_text(report_md, encoding="utf-8")
    state.log("synthesizer_completed", {"report_path": str(report_path)})
    print("  [Phase 8] Report written → report_commonstack.md")

    agent_log_path = Path(work_dir) / "agent_log.json"
    agent_log_path.write_text(json.dumps(state.agent_log, indent=2), encoding="utf-8")
    _write_progress(work_dir, "complete", state, started_at, timeline_events=timeline_payload["events"])

    conn.close()
    print(json.dumps({
        "status": "ok",
        "mode": "multi-agent-commonstack",
        "output_dir": state.work_dir,
        "db_path": db_path,
        "db_stats": db_stats,
    }, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agentic network forensic workflow for SC4063 Part 2."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="Run the agent against the network evidence directory.",
    )

    # Primary input
    run_parser.add_argument(
        "--network-dir",
        required=False,
        default="",
        help=(
            "Root directory containing the Suricata alert JSON, Zeek JSON, "
            "and a 'pcap/' sub-directory. "
            "Example: /path/to/network  (auto-discovers *alert*.json, *zeek*.json, pcap/)"
        ),
    )

    # Optional per-component overrides
    run_parser.add_argument(
        "--alert-json",
        default="",
        help="Explicit path to the Suricata EVE alert JSON file (overrides auto-discovery).",
    )
    run_parser.add_argument(
        "--zeek-json",
        default="",
        help="Explicit path to the Zeek JSON file (overrides auto-discovery).",
    )
    run_parser.add_argument(
        "--pcap-dir",
        default="",
        help="Explicit path to the PCAP directory (overrides auto-discovery).",
    )

    run_parser.add_argument(
        "--case",
        required=True,
        help="Case identifier used for the output directory.",
    )
    run_parser.add_argument(
        "--output-root",
        default="data/output",
        help="Root directory for run artefacts. Defaults to data/output.",
    )
    run_parser.add_argument(
        "--reasoner",
        choices=["deterministic", "openai", "gemini", "multi-agent"],
        default="deterministic",
        help=(
            "Analysis engine: 'deterministic' (no LLM), 'openai'/'gemini' (LLM planner), "
            "or 'multi-agent' (full Gemini-powered multi-agent with SQL tool-calling)."
        ),
    )
    run_parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Ignore cached ingest results and re-run all four phases.",
    )
    run_parser.add_argument(
        "--from-phase",
        type=int,
        choices=[1, 5, 6, 8],
        default=1,
        help=(
            "Start from a specific phase: 1=full run (default), "
            "5=skip ingest (reuse cache) reload DB + re-run agents, "
            "6=reuse existing DB re-run agents only, "
            "8=re-synthesize reports from existing findings_commonstack.json."
        ),
    )
    run_parser.add_argument(
        "--stop-phase",
        type=int,
        choices=[5],
        default=99,
        help=(
            "Stop after this phase and print a verification report. "
            "5=load DB then print table counts + pcap_credentials check, then exit. "
            "Useful to verify the DB before spending API credits on workers."
        ),
    )

    # Legacy alias: --pcap accepted but treated as --network-dir
    run_parser.add_argument(
        "--pcap",
        default="",
        help=argparse.SUPPRESS,   # hidden; kept for backwards compatibility
    )

    run_parser.set_defaults(func=run_case)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Legacy --pcap compat: treat as --network-dir if --network-dir not set
    if getattr(args, "pcap", "") and not getattr(args, "network_dir", ""):
        args.network_dir = args.pcap

    args.func(args)


if __name__ == "__main__":
    main()
