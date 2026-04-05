from __future__ import annotations

import json
from typing import Iterable

from case_brief import INCIDENT_SUMMARY, INVESTIGATION_DIRECTIVES
from models import AnalysisState


def build_planner_prompt(state: AnalysisState, available_actions: Iterable[str]) -> str:
    directive_summary = {
        key: {"title": value["title"], "question": value["question"]}
        for key, value in INVESTIGATION_DIRECTIVES.items()
    }
    return f"""
You are a constrained network forensic planning agent.

Case summary:
{INCIDENT_SUMMARY}

Investigation directives:
{json.dumps(directive_summary, indent=2)}

Available actions:
{json.dumps(list(available_actions), indent=2)}

Current findings:
{json.dumps(state.findings_for_reasoner(), indent=2)}

Rules:
- Choose exactly one next action from the available list.
- Base your choice only on the current findings and the investigation directives.
- Prefer the next action that reduces uncertainty the most.
- If a finding is weak, pick the action that most directly validates or refutes it.
- Do not invent artifacts that do not exist.

Return JSON only in this format:
{{"next_action":"action_name","reason":"one short sentence"}}
""".strip()
