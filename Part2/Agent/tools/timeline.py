from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from models import AnalysisState


def build_timeline(state: AnalysisState) -> Dict[str, List[Dict[str, str]]]:
    events: List[Dict[str, str]] = []
    for question_id, finding in state.findings.items():
        for item in finding.evidence:
            events.append(
                {
                    "ts": item.ts,
                    "category": question_id,
                    "title": finding.title,
                    "summary": item.description,
                    "src_ip": item.src_ip,
                    "dst_ip": item.dst_ip,
                    "artifact": item.artifact,
                }
            )

    events.sort(key=lambda row: row["ts"] or "9999")
    timeline_path = Path(state.work_dir) / "timeline.json"
    timeline_path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    return {"events": events, "path": str(timeline_path)}
