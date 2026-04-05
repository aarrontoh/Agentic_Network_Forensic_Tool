from __future__ import annotations

import json
import os
from typing import Iterable

from case_brief import INVESTIGATION_DIRECTIVES
from models import AnalysisState, Decision
from prompts import build_planner_prompt


class DeterministicReasoner:
    PRIORITY = [
        "initial_access",
        "lateral_movement",
        "exfiltration",
        "payload_delivery",
        "timeline",
    ]

    def choose_next_action(self, state: AnalysisState, available_actions: Iterable[str]) -> Decision:
        available = list(available_actions)
        findings = state.findings

        if "A" not in findings and "initial_access" in available:
            return Decision("initial_access", "Establish patient zero before deeper pivot analysis.")
        if "B" not in findings and "lateral_movement" in available:
            return Decision("lateral_movement", "The brief explicitly asks how the actor moved after entry.")
        if "C" not in findings and "exfiltration" in available:
            return Decision("exfiltration", "Exfiltration evidence directly answers the double-extortion question.")
        if "D" not in findings and "payload_delivery" in available:
            return Decision("payload_delivery", "Late-stage deployment patterns should be evaluated after earlier stages.")
        if "timeline" in available:
            return Decision("timeline", "All investigative stages are complete enough to build the timeline.")

        # Fallback keeps the agent autonomous even if the available action set changes.
        return Decision(available[0], "Default fallback because no higher-priority action is outstanding.")


class OpenAIReasoner:
    def __init__(self, model: str) -> None:
        self.model = model

    def choose_next_action(self, state: AnalysisState, available_actions: Iterable[str]) -> Decision:
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required for the OpenAI reasoner.")

        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "The OpenAI SDK is not installed. Run 'python3 -m pip install openai' first."
            ) from exc

        client = OpenAI(api_key=api_key)
        prompt = build_planner_prompt(state, available_actions)
        response = client.responses.create(
            model=self.model,
            input=prompt,
        )
        text = response.output_text.strip()
        payload = json.loads(text)
        return Decision(payload["next_action"], payload["reason"])


class GeminiReasoner:
    def __init__(self, model: str) -> None:
        self.model = model

    def choose_next_action(self, state: AnalysisState, available_actions: Iterable[str]) -> Decision:
        api_key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY or GOOGLE_API_KEY is required for the Gemini reasoner.")

        try:
            from google import genai
        except ImportError as exc:
            raise RuntimeError(
                "The Google GenAI SDK is not installed. Run 'python3 -m pip install google-genai' first."
            ) from exc

        client = genai.Client(api_key=api_key)
        prompt = build_planner_prompt(state, available_actions)
        response = client.models.generate_content(
            model=self.model,
            contents=prompt,
        )
        text = (response.text or "").strip()
        payload = json.loads(text)
        return Decision(payload["next_action"], payload["reason"])


def build_reasoner(name: str, openai_model: str | None, gemini_model: str | None):
    if name == "openai":
        if not openai_model:
            raise RuntimeError("OPENAI_MODEL must be set when using the OpenAI reasoner.")
        return OpenAIReasoner(openai_model)
    if name == "gemini":
        if not gemini_model:
            raise RuntimeError("GEMINI_MODEL must be set when using the Gemini reasoner.")
        return GeminiReasoner(gemini_model)
    return DeterministicReasoner()
