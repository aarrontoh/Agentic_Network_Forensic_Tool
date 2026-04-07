from __future__ import annotations

import argparse
import datetime
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import AgentConfig
from llm import build_reasoner
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
    })
    if timeline_events is not None:
        data["timeline"] = timeline_events

    progress_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _clean_work_dir(work_dir: Path, wipe_ingest_cache: bool = False) -> None:
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
        "report.md",
        "agent_log.json",
        "timeline.json",
        "ingest_summary.json",
        "preprocessing_summary.json",
        "forensic_evidence.db",
    ]
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
    _clean_work_dir(work_dir, wipe_ingest_cache=force_refresh)

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
    if args.reasoner == "multi-agent":
        _run_multi_agent_analysis(state, artifacts, str(work_dir), started_at)
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
    """Pre-flight test: verify at least one LLM backend works before ingest.

    Tests ALL configured backends with a realistic function-calling round trip
    (~4 KB tool response). Reports which passed/failed so the resilient fallback
    has at least one working backend before we spend hours on ingest.
    """
    import os

    _FAKE_DB_RESULT = {
        "columns": ["src_ip", "dst_ip", "dst_port", "protocol", "count"],
        "rows": [
            ["10.128.239.57", "10.128.239.29", 49668, "dce_rpc", 72670],
            ["10.128.239.57", "10.128.239.23", 49668, "dce_rpc", 3977],
            ["10.128.239.57", "10.128.239.34", 3389, "rdp", 1245],
            ["10.128.239.57", "10.128.239.35", 3389, "rdp", 892],
            ["10.128.239.57", "10.128.239.36", 445, "smb", 567],
            ["10.128.239.57", "10.128.239.37", 445, "smb", 2341],
            ["10.128.239.57", "51.91.79.17", 443, "tls", 11],
            ["194.0.234.17", "10.128.239.57", 3389, "rdp", 48],
            ["96.126.120.149", "10.128.239.57", 3389, "rdp", 12],
            ["206.189.231.47", "10.128.239.57", 3389, "rdp", 3],
        ] * 3,
        "row_count": 30,
        "truncated": False,
    }

    _TEST_TOOL = {
        "type": "function",
        "function": {
            "name": "query_db",
            "description": "Execute a read-only SQL SELECT query against the forensic evidence database.",
            "parameters": {
                "type": "object",
                "properties": {"sql": {"type": "string", "description": "SQL SELECT query."}},
                "required": ["sql"],
            },
        },
    }

    # Discover all configured backends
    backends_to_test = []
    primary = os.getenv("LLM_BACKEND", "gemini").strip().lower()
    for name in [primary] + [b for b in ["groq", "deepseek", "gemini"] if b != primary]:
        if name == "groq" and os.getenv("GROQ_API_KEY", "").strip():
            backends_to_test.append(("groq", os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
                                     os.getenv("GROQ_API_KEY", "").strip(), "https://api.groq.com/openai/v1"))
        elif name == "deepseek" and os.getenv("DEEPSEEK_API_KEY", "").strip():
            backends_to_test.append(("deepseek", os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
                                     os.getenv("DEEPSEEK_API_KEY", "").strip(),
                                     os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")))
        elif name == "gemini" and (os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()):
            backends_to_test.append(("gemini", os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
                                     os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip(),
                                     None))

    if not backends_to_test:
        raise RuntimeError("No LLM API keys configured in .env! Set at least one of: GROQ_API_KEY, DEEPSEEK_API_KEY, GEMINI_API_KEY")

    print(f"  [Pre-flight] Testing {len(backends_to_test)} configured backend(s): {', '.join(b[0] for b in backends_to_test)}")
    print(f"  [Pre-flight] Primary backend: {primary}")

    passed = []
    failed = []

    for backend_name, model, api_key, base_url in backends_to_test:
        print(f"\n  [{backend_name.upper()}] Testing {model}...")
        try:
            if backend_name in ("groq", "deepseek"):
                from openai import OpenAI
                client = OpenAI(api_key=api_key, base_url=base_url)

                # Step 1: function calling
                print(f"  [{backend_name.upper()}] Step 1/2: Function calling...")
                resp = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "You are a forensic analyst. Use the query_db tool to investigate."},
                        {"role": "user", "content": "Query the database to count all alerts."},
                    ],
                    tools=[_TEST_TOOL], tool_choice="auto", temperature=0.1,
                )
                msg = resp.choices[0].message
                if not msg.tool_calls:
                    raise RuntimeError("No function call returned")
                tc = msg.tool_calls[0]
                print(f"  [{backend_name.upper()}]   Called: {tc.function.name}({tc.function.arguments[:60]})")

                # Step 2: large tool response
                print(f"  [{backend_name.upper()}] Step 2/2: Large tool response (~4 KB)...")
                # Strip unsupported fields (e.g. 'annotations') that some providers reject
                assistant_msg = {k: v for k, v in msg.model_dump().items() if k in ("role", "content", "tool_calls")}
                resp2 = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "Summarize the query results briefly."},
                        {"role": "user", "content": "Query the database to count all alerts."},
                        assistant_msg,
                        {"role": "tool", "tool_call_id": tc.id, "content": json.dumps(_FAKE_DB_RESULT)},
                    ],
                    tools=[_TEST_TOOL], temperature=0.1, max_tokens=100,
                )
                reply = resp2.choices[0].message.content or "(ok)"
                print(f"  [{backend_name.upper()}]   Response: {reply[:80]}...")

            else:  # gemini
                from google import genai
                from google.genai import types
                client = genai.Client(api_key=api_key)
                gemini_tool_decl = {
                    "name": "query_db", "description": "Execute a read-only SQL SELECT query.",
                    "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]},
                }

                print(f"  [{backend_name.upper()}] Step 1/2: Function calling...")
                resp = client.models.generate_content(
                    model=model,
                    contents=[{"role": "user", "parts": [types.Part.from_text(text="Query the database to count all alerts.")]}],
                    config=types.GenerateContentConfig(
                        tools=[types.Tool(function_declarations=[gemini_tool_decl])],
                        system_instruction="You are a forensic analyst. Use the query_db tool.",
                        temperature=0.1,
                    ),
                )
                parts = resp.candidates[0].content.parts if resp.candidates and resp.candidates[0].content else []
                fc_found = any(getattr(p, "function_call", None) for p in parts)
                if not fc_found:
                    raise RuntimeError("No function call returned")
                print(f"  [{backend_name.upper()}]   Function call OK")

                print(f"  [{backend_name.upper()}] Step 2/2: Large tool response (~4 KB)...")
                fc_part = next(p for p in parts if getattr(p, "function_call", None))
                resp2 = client.models.generate_content(
                    model=model,
                    contents=[
                        {"role": "user", "parts": [types.Part.from_text(text="Query the database to count all alerts.")]},
                        {"role": "model", "parts": [fc_part]},
                        {"role": "user", "parts": [types.Part.from_function_response(name="query_db", response=_FAKE_DB_RESULT)]},
                    ],
                    config=types.GenerateContentConfig(
                        tools=[types.Tool(function_declarations=[gemini_tool_decl])],
                        system_instruction="Summarize briefly.", temperature=0.1, max_output_tokens=100,
                    ),
                )
                reply = resp2.text or "(ok)"
                print(f"  [{backend_name.upper()}]   Response: {reply[:80]}...")

            passed.append(f"{backend_name}/{model}")
            print(f"  [{backend_name.upper()}] PASSED")

        except Exception as e:
            err = str(e)[:120]
            failed.append(f"{backend_name}/{model}: {err}")
            print(f"  [{backend_name.upper()}] FAILED — {err}")

    # Summary
    print(f"\n  [Pre-flight] Results: {len(passed)} passed, {len(failed)} failed")
    for p in passed:
        print(f"    PASS: {p}")
    for f in failed:
        print(f"    FAIL: {f}")

    if not passed:
        raise RuntimeError(
            f"ALL backends failed pre-flight test! Cannot proceed.\n"
            + "\n".join(f"  - {f}" for f in failed)
        )
    print(f"  [Pre-flight] At least one backend ready — investigation can proceed with fallback.\n")


def _run_multi_agent_analysis(
    state: AnalysisState,
    artifacts: Dict[str, Any],
    work_dir: str,
    started_at: str,
) -> None:
    """Multi-agent investigation: DB ingestion → Worker agents → Synthesizer."""
    from db.schema import init_db, get_table_stats
    from db.ingest_db import load_all
    from agents.manager import run_multi_agent
    from agents.synthesizer import synthesize_report

    # ── Phase 5: Load evidence into SQLite database ──────────────────────────
    db_path = str(Path(work_dir) / "forensic_evidence.db")
    state.log("db_init", {"db_path": db_path})
    _write_progress(work_dir, "loading_database", state, started_at)

    conn = init_db(db_path)
    counts = load_all(conn, artifacts)
    state.log("db_loaded", counts)

    db_stats = get_table_stats(conn)
    _write_progress(work_dir, "multi_agent", state, started_at)

    # ── Phase 6: Run multi-agent investigation ───────────────────────────────
    def _agent_progress(stage, detail, worker_id, status):
        _write_progress(work_dir, stage, state, started_at)

    findings = run_multi_agent(conn, state, progress_callback=_agent_progress)

    # Map agent findings into state
    for qid, finding in findings.items():
        state.findings[qid] = finding
    _write_progress(work_dir, "synthesizing", state, started_at)

    # ── Phase 7: Timeline ────────────────────────────────────────────────────
    timeline_payload = build_timeline(state)
    state.completed_actions.append("timeline")
    state.log("timeline_built", {
        "timeline_path": timeline_payload["path"],
        "event_count": len(timeline_payload["events"]),
    })

    # ── Phase 8: Synthesize report ───────────────────────────────────────────
    state.log("synthesizer_started", {})
    report_md = synthesize_report(findings, db_stats)
    report_path = Path(work_dir) / "report.md"
    report_path.write_text(report_md, encoding="utf-8")
    state.log("synthesizer_completed", {"report_path": str(report_path)})

    # Also write standard outputs (findings.json, agent_log.json)
    write_outputs(state)
    _write_progress(work_dir, "complete", state, started_at, timeline_events=timeline_payload["events"])

    conn.close()
    print(json.dumps({
        "status": "ok",
        "mode": "multi-agent",
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
