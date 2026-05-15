"""
core/llm.py
────────────
Centralised Groq/Llama 3 client.

All agents import `call_llm()` from here — no agent touches the Groq SDK directly.
This makes it trivial to swap models or providers in one place.

Model: llama3-70b-8192  (fast, free tier, strong reasoning)
Fallback: llama3-8b-8192 (if 70b quota is hit)

Usage:
    from backend.core.llm import call_llm

    response = call_llm(
        system="You are a threat analyst.",
        user="Analyse this log: ...",
        temperature=0.1,   # low = deterministic, good for structured extraction
    )
    # response is a plain string
"""

from __future__ import annotations
import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# ── Client (singleton) ────────────────────────────────────────────────────
_client: Groq | None = None


def _get_client() -> Groq:
    global _client
    if _client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "GROQ_API_KEY not set. Add it to your .env file."
            )
        _client = Groq(api_key=api_key)
    return _client


# ── Primary model + fallback ──────────────────────────────────────────────
PRIMARY_MODEL  = "llama-3.3-70b-versatile"
FALLBACK_MODEL = "llama-3.1-8b-instant"


def call_llm(
    system: str,
    user: str,
    temperature: float = 0.1,
    max_tokens: int = 1024,
) -> str:
    """
    Call Groq API with system + user prompt.
    Automatically falls back to smaller model on rate-limit errors.
    Returns the response text as a plain string.
    """
    client = _get_client()

    for model in (PRIMARY_MODEL, FALLBACK_MODEL):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system",  "content": system},
                    {"role": "user",    "content": user},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content.strip()
        except Exception as exc:
            err = str(exc).lower()
            # Only retry on rate limit / model errors, not auth errors
            if model == FALLBACK_MODEL or ("rate" not in err and "model" not in err):
                raise
            continue

    raise RuntimeError("Both Groq models failed.")
