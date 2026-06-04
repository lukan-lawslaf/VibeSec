"""
patch_agent.py — Patch generation agent for VibeSec.

Uses InferenceClient from huggingface_hub to call DeepSeek-V3-0324.
Takes the original source code and the vulnerability report produced by
``vuln_agent``, then returns patched source code together with a unified diff.

Environment variables
---------------------
HF_API_KEY : str
    Your Hugging Face API token (required at runtime).
PATCH_MODEL : str  (optional)
    Override the patch model at runtime.
    Supported values:
      (unset / default)  → deepseek-ai/DeepSeek-V3-0324
      'qwen-securecode'  → NotImplementedError (coming soon)
"""

import difflib
import json
import os
import re
from typing import Any

from huggingface_hub import InferenceClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_MODEL_ID  = "deepseek-ai/DeepSeek-V3-0324"

# ---------------------------------------------------------------------------
# Model routing — extend here as new patch models are integrated
# ---------------------------------------------------------------------------

def _resolve_patch_model() -> str:
    """
    Return the model ID to use for patch generation.

    Reads the ``PATCH_MODEL`` environment variable and routes accordingly.
    Raises ``NotImplementedError`` for models that are planned but not yet live.
    """
    selector = os.environ.get("PATCH_MODEL", "").strip().lower()

    if selector == "qwen-securecode":
        raise NotImplementedError(
            "Qwen-SecureCode is coming soon and is not yet integrated. "
            "Leave PATCH_MODEL unset to use the default DeepSeek-Coder model."
        )

    # Default: DeepSeek-V3-0324
    return _MODEL_ID

_SYSTEM_PROMPT = {
    "role": "system",
    "content": (
        "You are an expert Python security engineer performing minimal, surgical security patches.\n\n"

        "ABSOLUTE RULES — NEVER BREAK THESE:\n"
        "1. DO NOT change any import statements. Preserve every 'import X' and 'from X import Y' exactly.\n"
        "2. DO NOT rename, replace, or swap any third-party library, API client, or SDK. "
        "   If the code uses 'InferenceClient', keep 'InferenceClient'. "
        "   If it uses 'openai.ChatCompletion', keep 'openai.ChatCompletion'. Never substitute alternatives.\n"
        "3. DO NOT change any external API method names, argument names, or call signatures "
        "   (e.g. '.chat.completions.create()', '.run()', '.predict()'). Keep them exactly.\n"
        "4. DO NOT refactor or reorganise code structure. Only change the minimum lines needed "
        "   to fix the exact vulnerabilities listed.\n"
        "5. DO NOT add new dependencies that are not already imported in the original code.\n\n"

        "WHAT YOU SHOULD FIX:\n"
        "- Replace hardcoded credential strings with os.getenv() calls.\n"
        "- Add input validation / sanitisation before dangerous calls.\n"
        "- Use parameterised queries instead of f-string SQL.\n"
        "- Replace eval()/exec() with safe alternatives.\n"
        "- Add shell=False to subprocess calls.\n\n"

        "Return ONLY the complete, fixed Python source code inside a single "
        "```python ... ``` code block — no explanations outside the block."
    ),
}

# Client is lazily initialised so the module can be imported without the
# env-var present (tests, linting, etc.).
_client: InferenceClient | None = None


def _get_client() -> InferenceClient:
    """Return (or lazily create) the shared InferenceClient."""
    global _client
    if _client is None:
        _client = InferenceClient(
            api_key=os.environ["HF_API_KEY"],
            model=_MODEL_ID,
        )
    return _client


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def run_patch_agent(
    source_code: str,
    vuln_report: list[dict[str, Any]],
) -> dict[str, str]:
    """
    Generate a patched version of *source_code* fixing the issues in
    *vuln_report*.

    Parameters
    ----------
    source_code:
        The original raw Python source code.
    vuln_report:
        Output of ``vuln_agent.run_vuln_agent()`` — list of vuln dicts.

    Returns
    -------
    dict with keys:
        ``patched_code`` : str   — the fixed source code
        ``diff``         : str   — unified diff between original and patched
    """
    user_message = _build_user_message(source_code, vuln_report)
    raw_response = _call_model(user_message)
    patched_code = _extract_code(raw_response, source_code)
    diff = _generate_diff(source_code, patched_code)

    return {
        "patched_code": patched_code,
        "diff":         diff,
    }


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _build_user_message(source_code: str, vuln_report: list[dict[str, Any]]) -> str:
    """Compose the patch-generation user-turn message for DeepSeek-Coder."""
    vulns_json = json.dumps(vuln_report, indent=2)

    return f"""Fix the security vulnerabilities listed below. Make MINIMAL, SURGICAL changes only.

## Vulnerability Report
{vulns_json}

## Original Code
```python
{source_code}
```

## Critical Instructions
- Fix ONLY the vulnerabilities listed. Do not touch anything else.
- PRESERVE every import statement exactly as-is.
- PRESERVE all third-party library names and API method calls exactly as-is.
  Example: if original uses `InferenceClient`, keep `InferenceClient` — do NOT change to another client.
- Return ONLY the complete fixed source code inside a single ```python ... ``` block.

Fixed code:"""


# ---------------------------------------------------------------------------
# InferenceClient call  (same pattern as vuln_agent)
# ---------------------------------------------------------------------------

def _call_model(user_message: str) -> str:
    """
    Send *user_message* to the active patch model via InferenceClient and
    return the raw reply string.

    Uses the same ``client.chat.completions.create`` pattern as vuln_agent,
    with a security-engineering system prompt.
    """
    messages = [
        _SYSTEM_PROMPT,
        {"role": "user", "content": user_message},
    ]

    try:
        comp = _get_client().chat.completions.create(
            messages=messages,
            max_tokens=2048,
            temperature=0.05,  # near-zero temperature → deterministic code output
        )
        return comp.choices[0].message.content
    except Exception as exc:  # noqa: BLE001
        print(f"[patch_agent] InferenceClient error: {exc}")
        return ""


# ---------------------------------------------------------------------------
# Response parsing helpers
# ---------------------------------------------------------------------------

def _extract_code(raw: str, fallback: str) -> str:
    """
    Pull the first ```python ... ``` block from the model output.
    Returns *fallback* (original code) if no code block is found.
    """
    match = re.search(r"```(?:python)?\s*\n(.*?)```", raw, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Sometimes the model omits fences — return everything after the prompt
    stripped = raw.strip()
    if stripped:
        return stripped

    return fallback


def _generate_diff(original: str, patched: str) -> str:
    """Return a unified diff string between *original* and *patched*."""
    original_lines = original.splitlines(keepends=True)
    patched_lines  = patched.splitlines(keepends=True)

    diff_lines = list(
        difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile="original.py",
            tofile="patched.py",
        )
    )
    return "".join(diff_lines)
