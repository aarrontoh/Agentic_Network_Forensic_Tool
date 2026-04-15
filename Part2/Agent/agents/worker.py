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
from openai_env import openai_client_kwargs
from agents.tool_registry import TOOL_DECLARATIONS, dispatch_tool

# ── Cost caps ────────────────────────────────────────────────────────────────
# Each iteration = 1 API call. Workers receive pre-computed notes context from
# phase2_notes.md so they don't need many turns to re-discover basics.
#
# Budget math (CommonStack Claude Opus pricing):
#   12 turns × 4 workers = 48 calls
#   ~15K input tokens/call (system + history) × $15/1M ≈ $0.72 input
#   ~1.2K output tokens/call × $75/1M ≈ $0.29 output
#   Synthesis (1 call, ~30K in + 6K out) ≈ $0.90
#   Total estimate per full run: ~$2 — adjust _MAX_ITERATIONS to tune cost
_MAX_ITERATIONS = 12
_MIN_ITERATIONS = 5

# Retry settings for rate-limit (429) errors
_MAX_RETRIES = 10
_INITIAL_BACKOFF = 20  # seconds
_BACKOFF_MULTIPLIER = 2
_MAX_BACKOFF = 300  # seconds — wait up to 5 min per retry for persistent rate limits


# Minimum evidence items required before a finding is accepted
_MIN_EVIDENCE_ITEMS = 10

# The submit_finding tool declaration — agents call this to return results
_SUBMIT_FINDING_DECL = {
    "name": "submit_finding",
    "description": (
        f"Submit your final structured finding. "
        f"REQUIREMENTS BEFORE CALLING THIS: "
        f"(1) You must have completed ALL investigation steps in your prompt — do not skip any. "
        f"(2) evidence_items MUST contain at least {_MIN_EVIDENCE_ITEMS} items, each with a real exact timestamp from SQL results. "
        f"(3) Every IP, count, byte value, and timestamp in summary MUST come from a tool query result — no estimates. "
        f"(4) summary must be at least 300 words covering all steps. "
        f"If you have not met these requirements, keep querying instead of calling this."
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
                        "ts": {"type": "string", "description": "Exact timestamp from query results (e.g. '2025-03-01T18:20:01.130Z'). MUST be a real timestamp from your SQL results, never empty or rounded."},
                        "src_ip": {"type": "string", "description": "Source IP address from query results. MUST be filled."},
                        "dst_ip": {"type": "string", "description": "Destination IP address from query results. MUST be filled."},
                        "protocol": {"type": "string", "description": "Protocol (e.g. 'RDP', 'SMB', 'DCERPC', 'TLS', 'DNS')."},
                        "description": {"type": "string", "description": "What this evidence shows. Reference specific query results with exact numbers."},
                        "artifact": {"type": "string", "description": "Source table or data source."},
                    },
                    "required": ["ts", "src_ip", "dst_ip", "description", "artifact"],
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


def _deadline_nudge_openai(messages, iteration):
    """Inject deadline warnings into OpenAI-compatible message lists."""
    if iteration == _MAX_ITERATIONS - 4:
        messages.append({"role": "user", "content": (
            "IMPORTANT: You are running low on remaining iterations. "
            "You MUST call submit_finding within the next 3-4 tool calls. "
            "Summarize what you have found so far and submit your finding now, "
            "even if your investigation is not fully complete. "
            "Include ALL evidence items with exact timestamps, src_ip, and dst_ip from your queries. "
            "An incomplete finding is better than no finding at all."
        )})
    elif iteration == _MAX_ITERATIONS - 1:
        messages.append({"role": "user", "content": (
            "FINAL WARNING: This is your LAST iteration. You MUST call submit_finding RIGHT NOW "
            "with whatever evidence you have gathered. Do NOT make any more query_db calls. "
            "Call submit_finding immediately."
        )})


def _tool_choice_for_iteration(iteration):
    """Force submit_finding on the last iteration."""
    if iteration >= _MAX_ITERATIONS:
        return {"type": "function", "function": {"name": "submit_finding"}}
    return "auto"


def _get_backend() -> str:
    """Return the active LLM backend."""
    return os.getenv("LLM_BACKEND", "openai").strip().lower()


# ─────────────────────────────────────────────────────────────────────────────
# OpenAI backend (gpt-4o)
# ─────────────────────────────────────────────────────────────────────────────

def _get_openai_client():
    """Create a client for OpenAI."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for OpenAI backend.")
    try:
        from openai import OpenAI
        return OpenAI(**openai_client_kwargs(api_key))
    except ImportError:
        raise RuntimeError("openai package is required. Run: pip install openai")


def _prune_openai_messages(messages: list, keep_recent: int = 20) -> list:
    """
    Trim conversation history to keep token count manageable.
    Always preserves messages[0] (system) and messages[1] (initial user prompt).
    Keeps the most recent `keep_recent` messages after that.
    Pruning at message boundaries prevents orphaned tool_call/tool_result pairs.
    """
    anchor = messages[:2]
    tail = messages[2:]
    if len(tail) <= keep_recent:
        return messages
    # Drop from the front of tail, but never leave an orphaned assistant message
    # (assistant with tool_calls must be followed by its tool results)
    trimmed = tail[-keep_recent:]
    # If first message in trimmed is a tool result (not system/user/assistant), drop it
    while trimmed and trimmed[0].get("role") == "tool":
        trimmed = trimmed[1:]
    return anchor + trimmed


def _run_openai_worker(conn, question_id, title, mitre, system_prompt, model, log_callback,
                       api_key: str = "", base_url: str = "",
                       all_cs_keys: list = None, cs_key_idx: list = None):
    """OpenAI-compatible function-calling loop. Works for OpenAI and any compatible API (e.g. CommonStack).

    all_cs_keys: full list of CommonStack API keys for mid-worker rotation on credit exhaustion.
    cs_key_idx:  mutable single-element list [int] tracking current key index (shared state).
    """
    model = model or os.getenv("OPENAI_MODEL", "gpt-4o")
    all_cs_keys = all_cs_keys or []
    cs_key_idx = cs_key_idx if cs_key_idx is not None else [0]
    # Build client — use explicit params if provided, else fall back to env
    from openai import OpenAI
    if api_key or base_url:
        _key = api_key or os.getenv("OPENAI_API_KEY", "")
        _kwargs: dict = {"api_key": _key, "timeout": 300}
        if base_url:
            _kwargs["base_url"] = base_url
        client = OpenAI(**_kwargs)
    else:
        client = _get_openai_client()
    tools = _build_openai_tools()

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Begin your investigation. Start by calling summarize_db to see what data is available, then use query_db to investigate."},
    ]
    finding_result = None

    for iteration in range(1, _MAX_ITERATIONS + 1):
        # Inject deadline nudge when approaching iteration limit
        if iteration == _MAX_ITERATIONS - 4:
            messages.append({"role": "user", "content": (
                "IMPORTANT: You are running low on remaining iterations. "
                "You MUST call submit_finding within the next 3-4 tool calls. "
                "Summarize what you have found so far and submit your finding now, "
                "even if your investigation is not fully complete. "
                "Include ALL evidence items with exact timestamps, src_ip, and dst_ip from your queries. "
                "An incomplete finding is better than no finding at all."
            )})
        elif iteration == _MAX_ITERATIONS - 1:
            messages.append({"role": "user", "content": (
                "FINAL WARNING: This is your LAST iteration. You MUST call submit_finding RIGHT NOW "
                "with whatever evidence you have gathered. Do NOT make any more query_db calls. "
                "Call submit_finding immediately."
            )})

        # Prune old context to stay within TPM limits
        # keep_recent=14: system (1) + initial user (1) + last 12 exchanges
        # More aggressive pruning = cheaper calls without losing current focus
        messages = _prune_openai_messages(messages, keep_recent=14)

        # Throttle: small inter-request delay to stay under CommonStack RPM limits.
        # CommonStack enforces per-key request-rate limits; without this, back-to-back
        # iterations within a single worker trigger 429s even with valid credits.
        _inter_request_delay = float(os.getenv("NF_REQUEST_DELAY", "3"))
        if iteration > 1:
            time.sleep(_inter_request_delay)

        # Implementation with robust truncation handling + API key rotation
        response = None
        backoff = _INITIAL_BACKOFF
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    tool_choice=_tool_choice_for_iteration(iteration),
                    temperature=0.1,
                    max_tokens=1500,  # caps cost; tool calls are short
                )
                break
            except Exception as api_err:
                err_str = str(api_err).lower()
                is_rate_limit = "429" in err_str or "rate" in err_str or "too many" in err_str
                is_exhausted = "402" in err_str or "insufficient balance" in err_str or "credit" in err_str or "quota" in err_str

                if is_exhausted or is_rate_limit:
                    # Rotate to next key immediately on either credit exhaustion or rate limit.
                    # We have 6 keys — cycling is far faster than waiting out a 429 backoff.
                    if all_cs_keys and cs_key_idx[0] + 1 < len(all_cs_keys):
                        cs_key_idx[0] += 1
                        new_key = all_cs_keys[cs_key_idx[0]]
                        reason = "credits exhausted" if is_exhausted else "rate limited"
                        print(f"    [Worker {question_id}] Key {reason} — rotating to key {cs_key_idx[0] + 1}/{len(all_cs_keys)}")
                        from openai import OpenAI as _OAI
                        client = _OAI(api_key=new_key, base_url=base_url or None, timeout=300)
                        backoff = _INITIAL_BACKOFF
                        continue
                    elif is_rate_limit and attempt < _MAX_RETRIES:
                        # No more keys to rotate to — fall back to waiting
                        if log_callback:
                            log_callback("rate_limit", {"question_id": question_id, "attempt": attempt + 1, "backoff_seconds": backoff})
                        print(f"    [Worker {question_id}] All keys rate limited — waiting {backoff}s before retry {attempt + 2}/{_MAX_RETRIES + 1}...")
                        time.sleep(backoff)
                        backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF)
                        # Wrap back to first key after waiting
                        cs_key_idx[0] = 0
                        client = _OAI(api_key=all_cs_keys[0], base_url=base_url or None, timeout=300)
                        continue
                    else:
                        raise RuntimeError(f"All CommonStack API keys exhausted: {err_str[:200]}")
                raise

        if response is None:
            raise RuntimeError("All retries exhausted due to rate limiting")

        choice = response.choices[0]
        msg = choice.message
        messages.append({k: v for k, v in msg.model_dump().items() if k in ("role", "content", "tool_calls")})

        if not msg.tool_calls:
            if choice.finish_reason == "stop":
                messages.append({"role": "user", "content": "Continue your investigation. Use the tools to gather evidence, then call submit_finding when ready."})
            continue

        for tc in msg.tool_calls:
            tool_name = tc.function.name
            try:
                tool_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                if not isinstance(tool_args, dict):
                    tool_args = {}
            except json.JSONDecodeError:
                tool_args = {}

            if log_callback:
                log_callback("tool_call", {"question_id": question_id, "iteration": iteration, "tool": tool_name, "args": _truncate_args(tool_args)})

            if tool_name == "submit_finding":
                evidence_items = tool_args.get("evidence_items", [])
                n_evidence = len(evidence_items) if isinstance(evidence_items, list) else 0
                rejection_reasons = []
                if iteration < _MIN_ITERATIONS:
                    rejection_reasons.append(
                        f"Only {iteration}/{_MIN_ITERATIONS} minimum investigation steps completed — keep querying."
                    )
                if n_evidence < _MIN_EVIDENCE_ITEMS:
                    rejection_reasons.append(
                        f"Only {n_evidence}/{_MIN_EVIDENCE_ITEMS} required evidence items provided. "
                        f"You need {_MIN_EVIDENCE_ITEMS - n_evidence} more items. Each must have a real exact timestamp, src_ip, dst_ip, and description from your SQL results."
                    )
                if rejection_reasons:
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps({
                        "status": "rejected",
                        "reasons": rejection_reasons,
                        "instruction": (
                            "Do NOT retry submit_finding yet. Continue your investigation: "
                            "query tables you haven't checked, drill into specific IPs and timestamps, "
                            "quantify byte volumes, map each attack phase with exact timestamps. "
                            "Every evidence item must be a distinct event with a real timestamp from SQL."
                        ),
                    })})
                else:
                    finding_result = tool_args
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps({"status": "accepted"})})
                    break
            else:
                result = dispatch_tool(conn, tool_name, tool_args)
                # Progressively truncate rows to fit within token limits
                if isinstance(result.get("rows"), list):
                    for max_rows in (50, 30, 15):
                        if len(result["rows"]) > max_rows:
                            result["rows"] = result["rows"][:max_rows]
                            result["truncated"] = True
                            result["note"] = f"Showing first {max_rows} rows. Use LIMIT/WHERE for specifics."
                        result_str = json.dumps(result, default=str)
                        if len(result_str) <= 6000:
                            break
                    else:
                        result_str = json.dumps(result, default=str)
                else:
                    result_str = json.dumps(result, default=str)
                # Final safety truncation — keep valid JSON by summarizing
                if len(result_str) > 6000:
                    result["rows"] = result.get("rows", [])[:5]
                    result["truncated"] = True
                    result["note"] = "Response too large. Only 5 rows shown. Use more specific queries."
                    result_str = json.dumps(result, default=str)[:6000]

                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result_str})

        if finding_result:
            break

    return finding_result, iteration


# ─────────────────────────────────────────────────────────────────────────────
# Gemini backend
# ─────────────────────────────────────────────────────────────────────────────

def _get_gemini_client(api_key: str = ""):
    """Lazily import and create Gemini client with a specific API key."""
    api_key = api_key or os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is required for Gemini backend.")
    try:
        from google import genai
        from google.genai import types
        return genai.Client(api_key=api_key), types
    except ImportError:
        raise RuntimeError("google-genai is required. Run: pip install google-genai")


# Thread-local storage for passing the API key to the Gemini runner
import threading
_gemini_key_local = threading.local()


def _run_gemini_worker(conn, question_id, title, mitre, system_prompt, model, log_callback):
    """Gemini function-calling loop with inline API key rotation.

    When a key hits its daily quota mid-conversation, the runner swaps to the
    next available Gemini key WITHOUT losing the conversation history.  This
    preserves context across all 15 investigation iterations.
    """
    initial_key = getattr(_gemini_key_local, "api_key", "")
    model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    # Build a queue of Gemini keys to try — start from the requested key
    all_keys = _get_gemini_keys()
    if initial_key in all_keys:
        start_idx = all_keys.index(initial_key)
        key_queue = all_keys[start_idx:] + all_keys[:start_idx]
    else:
        key_queue = all_keys if all_keys else [initial_key]

    current_key_idx = 0
    client, types = _get_gemini_client(key_queue[current_key_idx])

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

        # Inject deadline nudge when approaching iteration limit
        if iteration == _MAX_ITERATIONS - 4:
            messages.append({
                "role": "user",
                "parts": [types.Part.from_text(text=(
                    "IMPORTANT: You are running low on remaining iterations. "
                    "You MUST call submit_finding within the next 3-4 tool calls. "
                    "Summarize what you have found so far and submit your finding now, "
                    "even if your investigation is not fully complete. "
                    "Include ALL evidence items with exact timestamps, src_ip, and dst_ip from your queries. "
                    "An incomplete finding is better than no finding at all."
                ))],
            })
        elif iteration == _MAX_ITERATIONS - 1:
            messages.append({
                "role": "user",
                "parts": [types.Part.from_text(text=(
                    "FINAL WARNING: This is your LAST iteration. You MUST call submit_finding RIGHT NOW "
                    "with whatever evidence you have gathered. Do NOT make any more query_db calls. "
                    "Call submit_finding immediately."
                ))],
            })

        # Retry loop with inline key rotation on ANY rate limit (429)
        # Strategy: retry once on same key (short wait), then rotate key.
        # This avoids wasting minutes retrying a key that's exhausted.
        response = None
        max_attempts_per_key = 2  # try twice on same key, then rotate
        attempt_on_current_key = 0

        while True:
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

                if not is_rate_limit:
                    raise  # Non-rate-limit error — bail out

                attempt_on_current_key += 1

                if attempt_on_current_key < max_attempts_per_key:
                    # First retry: short wait on same key
                    wait = 10
                    print(f"    [Worker {question_id}] Rate limited — waiting {wait}s then retry on same key...")
                    if log_callback:
                        log_callback("rate_limit", {"question_id": question_id, "attempt": attempt_on_current_key, "backoff_seconds": wait, "key": f"...{key_queue[current_key_idx][-6:]}"})
                    time.sleep(wait)
                    continue

                # Exhausted retries on this key — rotate to next key
                current_key_idx += 1
                if current_key_idx < len(key_queue):
                    new_key = key_queue[current_key_idx]
                    print(f"    [Worker {question_id}] Key rate-limited — rotating to key#{current_key_idx + 1} (...{new_key[-6:]}) [context preserved, iteration {iteration}]")
                    if log_callback:
                        log_callback("key_rotated", {
                            "question_id": question_id,
                            "iteration": iteration,
                            "old_key": f"...{key_queue[current_key_idx - 1][-6:]}",
                            "new_key": f"...{new_key[-6:]}",
                            "context_preserved": True,
                        })
                    client, types = _get_gemini_client(new_key)
                    tools = [types.Tool(function_declarations=all_tools)]
                    attempt_on_current_key = 0  # Reset for new key
                    time.sleep(2)  # Brief pause before trying new key
                    continue
                else:
                    raise RuntimeError("All Gemini API keys exhausted (rate limited)")

        if response is None:
            raise RuntimeError("All retries exhausted due to rate limiting")

        if not response.candidates:
            break

        candidate = response.candidates[0]
        parts = (candidate.content.parts if candidate.content and candidate.content.parts else []) or []

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
                if iteration < _MIN_ITERATIONS:
                    fn_responses.append(types.Part.from_function_response(name="submit_finding", response={
                        "status": "rejected",
                        "reason": (
                            f"You have only completed {iteration} of a minimum {_MIN_ITERATIONS} investigation steps. "
                            "You MUST continue investigating before submitting. "
                            "Go back to your investigation strategy and complete the remaining steps — "
                            "check tables you haven't queried yet, drill into specifics, quantify byte counts, "
                            "map timestamps precisely, and aim for 15-20 evidence items with exact timestamps."
                        ),
                    }))
                else:
                    finding_result = tool_args
                    fn_responses.append(types.Part.from_function_response(name="submit_finding", response={"status": "accepted"}))
                    break
            else:
                result = dispatch_tool(conn, tool_name, tool_args)
                # Progressively truncate to fit Gemini context limits
                if isinstance(result.get("rows"), list):
                    for max_rows in (50, 30, 15, 5):
                        result_str = json.dumps(result, default=str)
                        if len(result_str) <= 8000:
                            break
                        result["rows"] = result["rows"][:max_rows]
                        result["truncated"] = True
                        result["note"] = f"Showing first {max_rows} rows. Use LIMIT in SQL for precise control."
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
        _deadline_nudge_openai(messages, iteration)

        # Retry loop for rate-limit errors
        response = None
        backoff = _INITIAL_BACKOFF
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    tool_choice=_tool_choice_for_iteration(iteration),
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
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF)
                    continue
                raise

        if response is None:
            raise RuntimeError("All retries exhausted due to rate limiting")

        choice = response.choices[0]
        msg = choice.message

        # Add assistant message to history
        # Strip unsupported fields (e.g. 'annotations') that some providers reject
        messages.append({k: v for k, v in msg.model_dump().items() if k in ("role", "content", "tool_calls")})

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
                if not isinstance(tool_args, dict):
                    tool_args = {}
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
# Groq backend (OpenAI-compatible, free 30 RPM)
# ─────────────────────────────────────────────────────────────────────────────

def _get_groq_client():
    """Create an OpenAI-compatible client for Groq."""
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is required for Groq backend. Get one free at https://console.groq.com")
    try:
        from openai import OpenAI
        return OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
    except ImportError:
        raise RuntimeError("openai package is required for Groq backend. Run: pip install openai")


def _run_groq_worker(conn, question_id, title, mitre, system_prompt, model, log_callback):
    """Groq function-calling loop (OpenAI-compatible)."""
    model = model or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    client = _get_groq_client()
    tools = _build_openai_tools()

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Begin your investigation. Start by calling summarize_db to see what data is available, then use query_db to investigate."},
    ]
    finding_result = None

    for iteration in range(1, _MAX_ITERATIONS + 1):
        _deadline_nudge_openai(messages, iteration)

        response = None
        backoff = _INITIAL_BACKOFF
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    tool_choice=_tool_choice_for_iteration(iteration),
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
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF)
                    continue
                raise

        if response is None:
            raise RuntimeError("All retries exhausted due to rate limiting")

        choice = response.choices[0]
        msg = choice.message
        # Strip unsupported fields (e.g. 'annotations') that some providers reject
        messages.append({k: v for k, v in msg.model_dump().items() if k in ("role", "content", "tool_calls")})

        if not msg.tool_calls:
            if choice.finish_reason == "stop":
                messages.append({"role": "user", "content": "Continue your investigation. Use the tools to gather evidence, then call submit_finding when ready."})
            continue

        for tc in msg.tool_calls:
            tool_name = tc.function.name
            try:
                tool_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                if not isinstance(tool_args, dict):
                    tool_args = {}
            except json.JSONDecodeError:
                tool_args = {}

            if log_callback:
                log_callback("tool_call", {"question_id": question_id, "iteration": iteration, "tool": tool_name, "args": _truncate_args(tool_args)})

            if tool_name == "submit_finding":
                finding_result = tool_args
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps({"status": "accepted"})})
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
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result_str})

        if finding_result:
            break

    return finding_result, iteration


# ─────────────────────────────────────────────────────────────────────────────
# Together AI backend (OpenAI-compatible)
# ─────────────────────────────────────────────────────────────────────────────

def _get_together_client():
    """Create an OpenAI-compatible client for Together AI."""
    api_key = os.getenv("TOGETHER_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("TOGETHER_API_KEY is required for Together AI backend.")
    base_url = os.getenv("TOGETHER_BASE_URL", "https://api.together.xyz/v1")
    from openai import OpenAI
    return OpenAI(api_key=api_key, base_url=base_url)


def _run_together_worker(conn, question_id, title, mitre, system_prompt, model, log_callback):
    """Together AI function-calling loop (OpenAI-compatible)."""
    model = model or os.getenv("TOGETHER_MODEL", "meta-llama/Llama-4-Maverick-17B-128E-Instruct")
    client = _get_together_client()
    tools = _build_openai_tools()

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Begin your investigation. Start by calling summarize_db to see what data is available, then use query_db to investigate."},
    ]
    finding_result = None

    for iteration in range(1, _MAX_ITERATIONS + 1):
        _deadline_nudge_openai(messages, iteration)

        response = None
        backoff = _INITIAL_BACKOFF
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    tool_choice=_tool_choice_for_iteration(iteration),
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
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF)
                    continue
                raise

        if response is None:
            raise RuntimeError("All retries exhausted due to rate limiting")

        choice = response.choices[0]
        msg = choice.message
        messages.append({k: v for k, v in msg.model_dump().items() if k in ("role", "content", "tool_calls")})

        if not msg.tool_calls:
            if choice.finish_reason == "stop":
                messages.append({"role": "user", "content": "Continue your investigation. Use the tools to gather evidence, then call submit_finding when ready."})
            continue

        for tc in msg.tool_calls:
            tool_name = tc.function.name
            try:
                tool_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                if not isinstance(tool_args, dict):
                    tool_args = {}
            except json.JSONDecodeError:
                tool_args = {}

            if log_callback:
                log_callback("tool_call", {"question_id": question_id, "iteration": iteration, "tool": tool_name, "args": _truncate_args(tool_args)})

            if tool_name == "submit_finding":
                finding_result = tool_args
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps({"status": "accepted"})})
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
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result_str})

        if finding_result:
            break

    return finding_result, iteration


# ─────────────────────────────────────────────────────────────────────────────
# SambaNova backend (OpenAI-compatible, free tier)
# ─────────────────────────────────────────────────────────────────────────────

def _get_sambanova_client():
    """Create an OpenAI-compatible client for SambaNova."""
    api_key = os.getenv("SAMBANOVA_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("SAMBANOVA_API_KEY is required for SambaNova backend.")
    from openai import OpenAI
    return OpenAI(api_key=api_key, base_url="https://api.sambanova.ai/v1")


def _run_sambanova_worker(conn, question_id, title, mitre, system_prompt, model, log_callback):
    """SambaNova function-calling loop (OpenAI-compatible)."""
    model = model or os.getenv("SAMBANOVA_MODEL", "Llama-4-Maverick-17B-128E-Instruct")
    client = _get_sambanova_client()
    tools = _build_openai_tools()

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Begin your investigation. Start by calling summarize_db to see what data is available, then use query_db to investigate."},
    ]
    finding_result = None

    for iteration in range(1, _MAX_ITERATIONS + 1):
        _deadline_nudge_openai(messages, iteration)

        response = None
        backoff = _INITIAL_BACKOFF
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    tool_choice=_tool_choice_for_iteration(iteration),
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
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF)
                    continue
                raise

        if response is None:
            raise RuntimeError("All retries exhausted due to rate limiting")

        choice = response.choices[0]
        msg = choice.message
        messages.append({k: v for k, v in msg.model_dump().items() if k in ("role", "content", "tool_calls")})

        if not msg.tool_calls:
            if choice.finish_reason == "stop":
                messages.append({"role": "user", "content": "Continue your investigation. Use the tools to gather evidence, then call submit_finding when ready."})
            continue

        for tc in msg.tool_calls:
            tool_name = tc.function.name
            try:
                tool_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                if not isinstance(tool_args, dict):
                    tool_args = {}
            except json.JSONDecodeError:
                tool_args = {}

            if log_callback:
                log_callback("tool_call", {"question_id": question_id, "iteration": iteration, "tool": tool_name, "args": _truncate_args(tool_args)})

            if tool_name == "submit_finding":
                finding_result = tool_args
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps({"status": "accepted"})})
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
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result_str})

        if finding_result:
            break

    return finding_result, iteration


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def _get_gemini_keys() -> List[str]:
    """Return all configured Gemini API keys (supports multi-key rotation)."""
    # GEMINI_API_KEYS (comma-separated) takes priority over single GEMINI_API_KEY
    multi = os.getenv("GEMINI_API_KEYS", "").strip()
    if multi:
        return [k.strip() for k in multi.split(",") if k.strip()]
    single = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
    return [single] if single else []


def _get_fallback_order() -> List[tuple]:
    """
    Return the backend fallback order. Only openai/gpt-4o is allowed
    as per current configuration.
    """
    primary = _get_backend()
    available: List[tuple] = []

    def _add_openai():
        available.append(("openai", os.getenv("OPENAI_MODEL", "gpt-4o"), os.getenv("OPENAI_API_KEY", ""), 0))

    # Gemini and Groq disabled by user request
    # def _add_gemini(): ...
    # def _add_groq(): ...

    adders = {
        "openai": _add_openai,
    }
    
    # We only allow openai now
    order = ["openai"]
    for name in order:
        if name in adders:
            adders[name]()

    return available if available else [("openai", "gpt-4o", "", 0)]


_BACKEND_RUNNERS = {
    "openai": lambda *a: _run_openai_worker(*a),
    "gemini": lambda *a: _run_gemini_worker(*a),
}


def run_worker(
    conn: sqlite3.Connection,
    question_id: str,
    title: str,
    mitre: List[str],
    system_prompt: str,
    model: str = "",
    log_callback=None,
    backend_config: Optional[Dict[str, str]] = None,
) -> Finding:
    """
    Run a single worker agent investigation loop.

    backend_config overrides env-based backend selection:
        {"backend": "openai", "api_key": "sk-...", "model": "gpt-4o", "base_url": "https://..."}
    If backend_config is None, falls back to env-based _get_fallback_order().
    """
    if backend_config:
        # Explicit backend override — build a single-entry fallback list
        fallback_order = [(
            backend_config.get("backend", "openai"),
            backend_config.get("model", os.getenv("OPENAI_MODEL", "gpt-4o")),
            backend_config.get("api_key", ""),
            0,
        )]
        # Temporarily patch the openai client factory for this call if base_url is set
        _override_base_url = backend_config.get("base_url", "")
    else:
        fallback_order = _get_fallback_order()
        _override_base_url = ""

    failed_backends = []

    for i, (backend, backend_model, api_key, key_idx) in enumerate(fallback_order):
        is_fallback = i > 0

        # Set the API key for Gemini multi-key rotation (thread-safe)
        # Offset starting key by question_id so parallel workers (A+B) don't
        # collide on the same key and trigger rate limits.
        if backend == "gemini" and api_key:
            all_keys = _get_gemini_keys()
            qid_offset = ord(question_id) - ord('A')  # A=0, B=1, C=2, D=3
            if all_keys and len(all_keys) > 1:
                offset_key = all_keys[qid_offset % len(all_keys)]
                _gemini_key_local.api_key = offset_key
                key_label = f"key#{(qid_offset % len(all_keys)) + 1}"
            else:
                _gemini_key_local.api_key = api_key
                key_label = f"key#{key_idx}"
        else:
            _gemini_key_local.api_key = ""
            key_label = ""

        display_name = f"{backend}/{backend_model}" + (f" ({key_label})" if key_label else "")

        if is_fallback:
            print(f"    [Worker {question_id}] Falling back to {display_name}...")

        if log_callback:
            log_callback("worker_started", {
                "question_id": question_id,
                "title": title,
                "backend": display_name,
                "model": backend_model,
                "api_key": f"...{api_key[-6:]}" if api_key else "env",
                "is_fallback": is_fallback,
                "failed_backends": [f["backend"] for f in failed_backends],
            })

        try:
            runner = _BACKEND_RUNNERS.get(backend, _BACKEND_RUNNERS["openai"])
            if _override_base_url and backend == "openai":
                # Inject custom base_url (e.g. CommonStack) into the openai runner
                # Pass full key list + mutable index for mid-worker key rotation
                _all_cs_keys = backend_config.get("all_keys", []) if backend_config else []
                _cs_key_idx = [0]
                # Find current key's index in all_keys so rotation starts from right place
                if _all_cs_keys and api_key in _all_cs_keys:
                    _cs_key_idx = [_all_cs_keys.index(api_key)]
                finding_result, iteration = _run_openai_worker(
                    conn, question_id, title, mitre, system_prompt, backend_model, log_callback,
                    api_key=api_key, base_url=_override_base_url,
                    all_cs_keys=_all_cs_keys, cs_key_idx=_cs_key_idx,
                )
            else:
                finding_result, iteration = runner(conn, question_id, title, mitre, system_prompt, backend_model, log_callback)
        except Exception as e:
            error_msg = str(e)
            # Shorten common error messages for display
            if "Insufficient Balance" in error_msg:
                short_err = "Insufficient Balance (credits exhausted)"
            elif "RESOURCE_EXHAUSTED" in error_msg or "429" in error_msg:
                short_err = "Rate limit exceeded (429)"
            elif "invalid_api_key" in error_msg.lower() or "401" in error_msg:
                short_err = "Invalid API key (401)"
            else:
                short_err = error_msg[:120]

            failed_backends.append({"backend": display_name, "model": backend_model, "error": short_err})
            print(f"    [Worker {question_id}] {display_name} FAILED: {short_err}")

            if log_callback:
                log_callback("backend_failed", {
                    "question_id": question_id,
                    "backend": display_name,
                    "model": backend_model,
                    "error": short_err,
                    "remaining_backends": [f"{b}/{m}" for b, m, *_ in fallback_order[i+1:]],
                })
            continue  # Try next backend

        # Success
        if log_callback:
            log_callback("worker_completed", {
                "question_id": question_id,
                "iterations": iteration,
                "has_finding": finding_result is not None,
                "backend": display_name,
                "model": backend_model,
                "api_key": f"...{api_key[-6:]}" if api_key else "env",
                "failed_backends": [f["backend"] for f in failed_backends],
            })

        if not finding_result:
            return _fallback_finding(question_id, title, mitre, "Agent reached maximum iterations without submitting.")

        finding = _parse_finding(question_id, title, mitre, finding_result)
        # Attach backend metadata to the finding summary
        finding.tool_name = f"agent_{question_id.lower()} [{display_name}]"
        if failed_backends:
            finding.limitations = list(finding.limitations or [])
            finding.limitations.insert(0, f"Backends tried before success: {', '.join(f['backend'] + ' (' + f['error'] + ')' for f in failed_backends)}")
        return finding

    # All backends failed
    all_errors = "; ".join(f"{f['backend']}: {f['error']}" for f in failed_backends)
    if log_callback:
        log_callback("all_backends_failed", {
            "question_id": question_id,
            "failed_backends": failed_backends,
        })
    return _fallback_finding(question_id, title, mitre, f"All backends failed — {all_errors}")


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
