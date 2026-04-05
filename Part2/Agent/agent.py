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

    # ── Analysis loop ─────────────────────────────────────────────────────────
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
        _write_progress(str(work_dir), "analyzing", state, started_at)

    # ── Timeline + reporting ──────────────────────────────────────────────────
    timeline_payload = build_timeline(state)
    state.completed_actions.append("timeline")
    state.log("timeline_built", {
        "timeline_path": timeline_payload["path"],
        "event_count": len(timeline_payload["events"]),
    })
    _write_progress(str(work_dir), "reporting", state, started_at, timeline_events=timeline_payload["events"])

    write_outputs(state)
    _write_progress(str(work_dir), "complete", state, started_at, timeline_events=timeline_payload["events"])
    print(json.dumps({"status": "ok", "output_dir": state.work_dir}, indent=2))


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
        choices=["deterministic", "openai", "gemini"],
        default="deterministic",
        help="Autonomous decision engine to use.",
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
