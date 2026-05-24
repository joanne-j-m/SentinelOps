"""
core/llm.py
────────────
Phase 5: Added exponential backoff retry, robust JSON cleaning,
         rate-limit handling, and startup key validation.
"""

from __future__ import annotations
import os
import re
import json
import time
import logging
from typing import Any, Dict
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

_client: Groq | None = None

PRIMARY_MODEL  = "llama-3.3-70b-versatile"
FALLBACK_MODEL = "llama-3.1-8b-instant"

MAX_RETRIES    = 3
BACKOFF_BASE   = 3   # seconds


def _get_client() -> Groq:
    global _client
    if _client is None:
        api_key = os.getenv("GROQ_API_KEY", "").strip()
        if not api_key:
            raise EnvironmentError("GROQ_API_KEY not set. Add it to your .env file.")
        _client = Groq(api_key=api_key)
    return _client


def validate_keys() -> Dict[str, bool]:
    """
    Called at startup. Returns status of all configured API keys.
    Used by the /health endpoint.
    """
    return {
        "groq":    bool(os.getenv("GROQ_API_KEY", "").strip()),
        "tavily":  bool(os.getenv("TAVILY_API_KEY", "").strip()),
        "discord": bool(os.getenv("DISCORD_WEBHOOK_URL", "").strip()),
        "omium":   bool(os.getenv("OMIUM_API_KEY", "").strip()),    # ← was noveum/NOVEUM_API_KEY
    }


def clean_json(raw: str) -> str:
    """
    Phase 7: Robust JSON extraction from LLM output.
    Handles:
      - Markdown code fences (```json ... ```)
      - Leading/trailing prose before/after the JSON object
      - Trailing commas (common LLM mistake)
    Uses bracket-balanced extraction instead of greedy regex to avoid
    grabbing prose between two separate JSON-like fragments.
    """
    # Strip markdown fences
    text = raw.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'```\s*$', '', text, flags=re.MULTILINE)
    text = text.strip()

    # Extract the first balanced JSON object using bracket counting.
    # This avoids the greedy regex problem where `{a} prose {b}` would
    # match from the first `{` to the last `}`.
    start = text.find('{')
    if start != -1:
        depth = 0
        in_string = False
        escape_next = False
        for i in range(start, len(text)):
            c = text[i]
            if escape_next:
                escape_next = False
                continue
            if c == '\\' and in_string:
                escape_next = True
                continue
            if c == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    text = text[start:i + 1]
                    break

    # Fix trailing commas before } or ]  (common LLM mistake)
    text = re.sub(r',\s*([}\]])', r'\1', text)

    return text.strip()


def call_llm(
    system: str,
    user: str,
    temperature: float = 0.1,
    max_tokens: int = 1024,
) -> str:
    """
    Call Groq API with exponential backoff retry on rate limits.
    Falls back to smaller model if primary is unavailable.
    """
    client = _get_client()

    for model in (PRIMARY_MODEL, FALLBACK_MODEL):
        for attempt in range(MAX_RETRIES):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user},
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                content = response.choices[0].message.content
                return (content or "").strip()

            except Exception as exc:
                err = str(exc).lower()

                # Rate limit → backoff and retry same model
                if "rate" in err or "429" in err:
                    wait = BACKOFF_BASE ** (attempt + 1)
                    logger.warning(f"Rate limit on {model}, waiting {wait:.1f}s (attempt {attempt+1})")
                    time.sleep(wait)
                    continue

                # Decommissioned/bad model → try fallback
                if "decommission" in err or "model" in err or "400" in err:
                    logger.warning(f"Model {model} unavailable, trying fallback.")
                    break  # break inner loop → try next model

                # Auth error or unknown → raise immediately
                raise

    raise RuntimeError(f"All Groq models failed after {MAX_RETRIES} retries.")


def call_llm_json(
    system: str,
    user: str,
    temperature: float = 0.1,
    max_tokens: int = 1024,
) -> Dict[str, Any]:
    """
    Phase 5: LLM call that guarantees a parsed dict back.
    Retries up to MAX_RETRIES times if JSON parsing fails.
    Raises ValueError only if all attempts fail.
    """
    last_err = None
    for attempt in range(MAX_RETRIES):
        try:
            raw    = call_llm(system, user, temperature, max_tokens)
            clean  = clean_json(raw)
            return json.loads(clean)
        except json.JSONDecodeError as exc:
            last_err = exc
            logger.warning(f"JSON parse failed (attempt {attempt+1}): {exc}. Retrying with stricter prompt.")
            # On retry, append a stronger instruction
            user = user + "\n\nIMPORTANT: Your previous response was not valid JSON. Respond with ONLY a raw JSON object. No prose, no markdown, no code fences."

    raise ValueError(f"LLM returned invalid JSON after {MAX_RETRIES} attempts: {last_err}")