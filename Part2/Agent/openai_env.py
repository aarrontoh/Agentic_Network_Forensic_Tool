"""Shared OpenAI SDK client options from environment variables."""

from __future__ import annotations

import os
from typing import Any


def openai_client_kwargs(api_key: str) -> dict[str, Any]:
    """
    Build kwargs for ``OpenAI(**openai_client_kwargs(key))``.

    Set ``OPENAI_BASE_URL`` for OpenAI-compatible gateways (e.g. Commonstack:
    ``https://api.commonstack.ai/v1``).
    """
    kwargs: dict[str, Any] = {"api_key": api_key}
    base = os.getenv("OPENAI_BASE_URL", "").strip()
    if base:
        kwargs["base_url"] = base
    return kwargs


def openai_uses_custom_base_url() -> bool:
    return bool(os.getenv("OPENAI_BASE_URL", "").strip())
