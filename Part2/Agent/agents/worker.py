"""
Base worker agent with LLM function-calling loop.

Supports two backends:
  - Gemini (google-genai SDK)   — set LLM_BACKEND=gemini  (default)
  - DeepSeek (OpenAI-compatible) — set LLM_BACKEND=deepseek

Each worker runs an autonomous investigation loop:
  1. Receives a system prompt with its mission + database schema overview.
  2. Calls tools (SQL queries) to gather evidence.
  3. Must ground every finding in tool results — hallucination is blocked.
  4. Returns a structured Finding when done.

The function-calling loop continues until the agent calls the `submit_finding`
tool, which signals it has gathered enough evidence and is ready to report.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import traceback
from typing import Any, Dict, List, Optional

from models import EvidenceItem, Finding
from agents.tool_registry import TOOL_DECLARATIONS, dispatch_tool

# Maximum tool-calling iterations before forcing the agent to conclude
_MAX_ITERATIONS = 15

# Retry settings for rate-limit (429) errors
_MAX_RETRIES = 5
_INITIAL_BACKOFF = 15  # seconds
_BACKOFF_MULTIPLIER = 2


# The submit_finding tool declaration — agents call this to return results
_SUBMIT_FINDING_DECL = {
    "name": "submit_finding",
    "description": (
        "Submit your final finding for this investigation question. "
        "Call this ONLY after you have gathered sufficient evidence via query_db. "
        "Every claim in your summary MUST be supported by data from your queries."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "description": "Finding status: 'confirmed', 'suspected', 'insufficient_evidence'.",
            },
            "confidence": {
                "type": "string",
                "description": "Confidence level: 'HIGH', 'MEDIUM', 'LOW'.",
            },
            "summary": {
                "type": "string",
                "description": (
                    "Detailed summary of findings. MUST reference specific IPs, timestamps, "
                    "counts, and byte values from your queries. No unsupported claims."
                ),
            },
            "evidence_items": {
                "type": "array",
                "description": "List of evidence items supporting this finding.",
                "items": {
                    "type": "object",
                    "properties": {
                        "ts": {"type": "string", "description": "Timestamp of the evidence."},
                        "src_ip": {"type": "string"},
                        "dst_ip": {"type": "string"},
                        "protocol": {"type": "string"},
                        "description": {"type": "string", "description": "What this evidence shows. Reference query results."},
                        "artifact": {"type": "string", "description": "Source table or data source."},
                    },
                    "required": ["description", "artifact"],
                },
            },
            "limitations": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Known limitations or gaps in the evidence.",
            },
            "next_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Recommended follow-up actions.",
            },
        },
        "required": ["status", "confidence", "summary", "evidence_items"],
    },
}


def _get_backend() -> str:
    """Return the active LLM backend: 'gemini' or 'deepseek'."""
    return os.getenv("LLM_BACKEND", "gemini").strip().lower()


# ─────────────────────────────────────────────────────────────────────────────
# Gemini backend
# ─────────────────────────────────────────────────────────────────────────────

def _get_gemini_client():
    """Lazily import and create Gemini client."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is required for Gemini backend.")
    try:
        from google import genai
        from google.genai import types
        return genai.Client(api_key=api_key), types
    except ImportError:
        raise RuntimeError("google-genai is required. Run: pip install google-genai")


def _run_gemini_worker(conn, question_id, title, mitre, system_prompt, model, log_callback):
    """Gemini function-calling loop."""
    model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    client, types = _get_gemini_client()

    all_tools = TOOL_DECLARATIONS + [_SUBMIT_FINDING_DECL]
    tools = [types.Tool(function_declarations=all_tools)]

    messages = []
    finding_result = None

    for iteration in range(1, _MAX_ITERATIONS + 1):
        if not messages:
            messages.append({
                "role": "user",
                "parts": [types.Part.from_text(text="Begin your investigation. Start by calling summarize_db to see what data is available, then use query_db to investigate.")],
            })

        # Retry loop for rate-limit errors
        response = None
        backoff = _INITIAL_BACKOFF
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=messages,
                    config=types.GenerateContentConfig(
                        tools=tools,
                        system_instruction=system_prompt,
                        temperature=0.1,
                    ),
                )
                break
            except Exception as api_err:
                err_str = str(api_err).lower()
                is_rate_limit = "429" in err_str or "resource_exhausted" in err_str or "rate" in err_str
                if is_rate_limit and attempt < _MAX_RETRIES:
                    if log_callback:
                        log_callback("rate_limit", {"question_id": question_id, "attempt": attempt + 1, "backoff_seconds": backoff})
                    print(f"    [Worker {question_id}] Rate limited — waiting {backoff}s before retry {attempt + 2}/{_MAX_RETRIES + 1}...")
                    time.sleep(backoff)
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, 120)
                    continue
                raise

        if response is None:
            raise RuntimeError("All retries exhausted due to rate limiting")

        if not response.candidates:
            break

        candidate = response.candidates[0]
        parts = candidate.content.parts if candidate.content else []

        function_calls = []
        text_parts = []
        for p in parts:
            fc = getattr(p, "function_call", None)
            if fc and getattr(fc, "name", None):
                function_calls.append(fc)
            txt = getattr(p, "text", None)
            is_thought = getattr(p, "thought", False)
            if txt and not is_thought:
                text_parts.append(txt)

        if not function_calls:
            if text_parts:
                messages.append({"role": "model", "parts": [types.Part.from_text(text=t) for t in text_parts]})
                messages.append({"role": "user", "parts": [types.Part.from_text(text="Continue your investigation. Use the tools to gather evidence, then call submit_finding when ready.")]})
            else:
                messages.append({"role": "user", "parts": [types.Part.from_text(text="Continue. Use the database tools to investigate, then call submit_finding.")]})
            continue

        safe_parts = [p for p in parts if not getattr(p, "thought", False)]
        if safe_parts:
            messages.append({"role": "model", "parts": safe_parts})

        fn_responses = []
        for fc in function_calls:
            tool_name = fc.name
            tool_args = dict(fc.args) if fc.args else {}

            if log_callback:
                log_callback("tool_call", {"question_id": question_id, "iteration": iteration, "tool": tool_name, "args": _truncate_args(tool_args)})

            if tool_name == "submit_finding":
                finding_result = tool_args
                fn_responses.append(types.Part.from_function_response(name="submit_finding", response={"status": "accepted"}))
                break
            else:
                result = dispatch_tool(conn, tool_name, tool_args)
                result_str = json.dumps(result, default=str)
                if len(result_str) > 8000:
                    if isinstance(result.get("rows"), list) and len(result["rows"]) > 30:
                        result["rows"] = result["rows"][:30]
                        result["truncated"] = True
                        result["note"] = "Showing first 30 rows. Use LIMIT in SQL for precise control."
                fn_responses.append(types.Part.from_function_response(name=tool_name, response=result))

        messages.append({"role": "user", "parts": fn_responses})

        if finding_result:
            break

    return finding_result, iteration


# ─────────────────────────────────────────────────────────────────────────────
# DeepSeek backend (OpenAI-compatible)
# ─────────────────────────────────────────────────────────────────────────────

def _get_deepseek_client():
    """Create an OpenAI-compatible client for DeepSeek."""
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY is required for DeepSeek backend.")
    base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    try:
        from openai import OpenAI
        return OpenAI(api_key=api_key, base_url=base_url)
    except ImportError:
        raise RuntimeError("openai package is required for DeepSeek backend. Run: pip install openai")


def _build_openai_tools():
    """Convert tool declarations to OpenAI function-calling format."""
    tools = []
    for decl in TOOL_DECLARATIONS + [_SUBMIT_FINDING_DECL]:
        tools.append({
            "type": "function",
            "function": {
                "name": decl["name"],
                "description": decl["description"],
                "parameters": decl["parameters"],
            },
        })
    return tools


def _run_deepseek_worker(conn, question_id, title, mitre, system_prompt, model, log_callback):
    """DeepSeek/OpenAI-compatible function-calling loop."""
    model = model or os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    client = _get_deepseek_client()
    tools = _build_openai_tools()

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Begin your investigation. Start by calling summarize_db to see what data is available, then use query_db to investigate."},
    ]
    finding_result = None

    for iteration in range(1, _MAX_ITERATIONS + 1):
        # Retry loop for rate-limit errors
        response = None
        backoff = _INITIAL_BACKOFF
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=0.1,
                )
                break
            except Exception as api_err:
                err_str = str(api_err).lower()
                is_rate_limit = "429" in err_str or "rate" in err_str or "too many" in err_str
                if is_rate_limit and attempt < _MAX_RETRIES:
                    if log_callback:
                        log_callback("rate_limit", {"question_id": question_id, "attempt": attempt + 1, "backoff_seconds": backoff})
                    print(f"    [Worker {question_id}] Rate limited — waiting {backoff}s before retry {attempt + 2}/{_MAX_RETRIES + 1}...")
                    time.sleep(backoff)
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, 120)
                    continue
                raise

        if response is None:
            raise RuntimeError("All retries exhausted due to rate limiting")

        choice = response.choices[0]
        msg = choice.message

        # Add assistant message to history
        messages.append(msg.model_dump())

        # Check for tool calls
        if not msg.tool_calls:
            # No tool calls — model returned text
            if choice.finish_reason == "stop":
                # Model finished without submitting — nudge it
                messages.append({"role": "user", "content": "Continue your investigation. Use the tools to gather evidence, then call submit_finding when ready."})
            continue

        # Process tool calls
        for tc in msg.tool_calls:
            tool_name = tc.function.name
            try:
                tool_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            except json.JSONDecodeError:
                tool_args = {}

            if log_callback:
                log_callback("tool_call", {"question_id": question_id, "iteration": iteration, "tool": tool_name, "args": _truncate_args(tool_args)})

            if tool_name == "submit_finding":
                finding_result = tool_args
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps({"status": "accepted"}),
                })
                break
            else:
                result = dispatch_tool(conn, tool_name, tool_args)
                result_str = json.dumps(result, default=str)
                if len(result_str) > 8000:
                    if isinstance(result.get("rows"), list) and len(result["rows"]) > 30:
                        result["rows"] = result["rows"][:30]
                        result["truncated"] = True
                        result["note"] = "Showing first 30 rows. Use LIMIT in SQL for precise control."
                    result_str = json.dumps(result, default=str)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_str,
                })

        if finding_result:
            break

    return finding_result, iteration


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_worker(
    conn: sqlite3.Connection,
    question_id: str,
    title: str,
    mitre: List[str],
    system_prompt: str,
    model: str = "",
    log_callback=None,
) -> Finding:
    """
    Run a single worker agent investigation loop.

    Uses the backend specified by LLM_BACKEND env var ('gemini' or 'deepseek').
    """
    backend = _get_backend()

    if log_callback:
        log_callback("worker_started", {"question_id": question_id, "title": title, "backend": backend})

    try:
        if backend == "deepseek":
            finding_result, iteration = _run_deepseek_worker(conn, question_id, title, mitre, system_prompt, model, log_callback)
        else:
            finding_result, iteration = _run_gemini_worker(conn, question_id, title, mitre, system_prompt, model, log_callback)
    except Exception as e:
        if log_callback:
            log_callback("worker_error", {"question_id": question_id, "error": str(e)})
        return _fallback_finding(question_id, title, mitre, str(e))

    if log_callback:
        log_callback("worker_completed", {
            "question_id": question_id,
            "iterations": iteration,
            "has_finding": finding_result is not None,
        })

    if not finding_result:
        return _fallback_finding(question_id, title, mitre, "Agent reached maximum iterations without submitting.")

    return _parse_finding(question_id, title, mitre, finding_result)


def _parse_finding(question_id: str, title: str, mitre: List[str], result: Dict[str, Any]) -> Finding:
    """Convert the agent's submit_finding args into a Finding dataclass."""
    evidence = []
    for item in result.get("evidence_items", []):
        evidence.append(EvidenceItem(
            ts=item.get("ts", ""),
            src_ip=item.get("src_ip", ""),
            dst_ip=item.get("dst_ip", ""),
            protocol=item.get("protocol", ""),
            description=item.get("description", ""),
            artifact=item.get("artifact", ""),
        ))

    return Finding(
        question_id=question_id,
        title=title,
        status=result.get("status", "suspected"),
        confidence=result.get("confidence", "MEDIUM"),
        summary=result.get("summary", ""),
        mitre=mitre,
        evidence=evidence,
        limitations=result.get("limitations", []),
        next_steps=result.get("next_steps", []),
        tool_name=f"agent_{question_id.lower()}",
    )


def _fallback_finding(question_id: str, title: str, mitre: List[str], error: str) -> Finding:
    """Return a minimal finding when the agent fails."""
    return Finding(
        question_id=question_id,
        title=title,
        status="agent_error",
        confidence="LOW",
        summary=f"The agent was unable to complete its investigation: {error}",
        mitre=mitre,
        limitations=[f"Agent error: {error}"],
        tool_name=f"agent_{question_id.lower()}",
    )


def _truncate_args(args: dict) -> dict:
    """Truncate long values in tool args for logging."""
    out = {}
    for k, v in args.items():
        s = str(v)
        out[k] = s[:200] + "..." if len(s) > 200 else s
    return out
