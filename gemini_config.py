#!/usr/bin/env python3
"""
BSI Central Gemini Configuration
==================================
Single source of truth for:
  - Gemini model name  (change GEMINI_MODEL to update all phases at once)
  - 22 API keys        (loaded from .env, never hardcoded in any phase file)
  - Auto key rotation  (on quota / 429, silently moves to next key)

Usage in any phase file:
    from gemini_config import call_gemini, GEMINI_MODEL, GEMINI_API_KEYS
"""

import os
from datetime import datetime
from pathlib import Path

# Load .env from same directory as this file
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).parent / '.env')
except ImportError:
    pass  # dotenv optional — keys can be set in OS environment directly

# ============================================================================
# MODEL NAME — change this ONE line to update the model across all BSI phases
# ============================================================================
GEMINI_MODEL = "gemini-2.5-flash"

# ============================================================================
# API KEYS — loaded from .env (GEMINI_API_KEY_1 … GEMINI_API_KEY_22)
# ============================================================================
GEMINI_API_KEYS = [os.getenv(f"GEMINI_API_KEY_{i}") for i in range(1, 23)]
GEMINI_API_KEYS = [k for k in GEMINI_API_KEYS if k]  # drop empty/missing

if not GEMINI_API_KEYS:
    # Hard fallback: check legacy single-key env var
    _legacy = os.getenv("GEMINI_API_KEY")
    if _legacy:
        GEMINI_API_KEYS = [_legacy]

# ── Rotation state (module-level, shared across all callers in one process) ──
_current_idx = 0
_key_status   = {
    i: {"status": "active", "usage_count": 0, "exhausted_at": None}
    for i in range(len(GEMINI_API_KEYS))
}


def get_current_key() -> str | None:
    """Return the currently active API key, or None if all exhausted."""
    if not GEMINI_API_KEYS:
        return None
    return GEMINI_API_KEYS[_current_idx]


def rotate_key() -> bool:
    """
    Mark current key as exhausted and move to the next active one.
    Returns True if a new key is available, False if all keys are exhausted.
    """
    global _current_idx
    if not GEMINI_API_KEYS:
        return False

    _key_status[_current_idx]["status"]       = "exhausted"
    _key_status[_current_idx]["exhausted_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"  ⚠️  Gemini Key {_current_idx + 1} quota exceeded — rotating...")

    next_idx = _current_idx + 1
    while next_idx < len(GEMINI_API_KEYS):
        if _key_status[next_idx]["status"] == "active":
            _current_idx = next_idx
            print(f"  ✅ Now using Gemini Key {_current_idx + 1} / {len(GEMINI_API_KEYS)}")
            return True
        next_idx += 1

    print(f"  ❌ All {len(GEMINI_API_KEYS)} Gemini keys exhausted!")
    return False


def call_gemini(prompt: str, max_tokens: int = 65536, temperature: float = 0.7) -> str | None:
    """
    Call Gemini AI with automatic key rotation on quota / 429 errors.
    Returns the response text, or None if all keys failed.

    This is the ONLY function all BSI phases should use for Gemini calls.
    """
    global _current_idx

    try:
        import google.generativeai as genai
    except ImportError:
        print("  ❌ google-generativeai not installed")
        return None

    if not GEMINI_API_KEYS:
        print("  ❌ No Gemini API keys available")
        return None

    attempts = 0
    max_attempts = len(GEMINI_API_KEYS)

    while attempts < max_attempts:
        key = GEMINI_API_KEYS[_current_idx]
        _key_status[_current_idx]["usage_count"] += 1

        try:
            genai.configure(api_key=key)
            model = genai.GenerativeModel(GEMINI_MODEL)

            generation_config = genai.types.GenerationConfig(
                temperature=temperature,
                top_p=0.95,
                top_k=40,
                max_output_tokens=max_tokens,
            )
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT",        "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH",       "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ]

            response = model.generate_content(
                prompt,
                generation_config=generation_config,
                safety_settings=safety_settings,
            )

            if hasattr(response, 'prompt_feedback') and response.prompt_feedback.block_reason:
                print(f"  ⚠️  Response blocked: {response.prompt_feedback.block_reason}")
                return None

            if response.text:
                return response.text
            return None

        except Exception as e:
            err = str(e).lower()
            is_quota = any(x in err for x in ['quota', '429', 'resource_exhausted', 'rate_limit', 'rateerror'])
            if is_quota:
                if not rotate_key():
                    return None   # all keys exhausted
                attempts += 1
                continue
            else:
                print(f"  ⚠️  Gemini error (Key {_current_idx + 1}): {str(e)[:120]}")
                return None

    return None


def key_summary() -> str:
    """Return a one-line summary of key pool status."""
    active    = sum(1 for s in _key_status.values() if s["status"] == "active")
    exhausted = sum(1 for s in _key_status.values() if s["status"] == "exhausted")
    total     = len(GEMINI_API_KEYS)
    return f"Gemini keys: {active} active / {exhausted} exhausted / {total} total | Model: {GEMINI_MODEL}"


# Print status on import so every phase shows key pool at startup
if GEMINI_API_KEYS:
    print(f"  ✅ gemini_config loaded — {len(GEMINI_API_KEYS)} keys available | Model: {GEMINI_MODEL}")
else:
    print("  ❌ gemini_config: NO Gemini API keys found in .env!")
