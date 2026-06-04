"""
vuln_agent.py — Vulnerability detection agent for VibeSec.
Calls DeepHat V1 (featherless-ai) via HuggingFace InferenceClient.
Requires HF_API_KEY in environment.
"""

import ast
import json
import os
import re
from typing import Any

from huggingface_hub import InferenceClient

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_MODEL_ID = "DeepHat/DeepHat-V1-7B"
_PROVIDER  = "featherless-ai"

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Lines matching these patterns are never real secrets
_SAFE_PATTERNS = [
    re.compile(r"os\.getenv\s*\("),
    re.compile(r"os\.environ(?:\.get)?\s*[([]"),
    re.compile(r"load_dotenv\s*\("),
    re.compile(r"=\s*\{\s*\}"),   # empty dict
    re.compile(r"=\s*\[\s*\]"),   # empty list
]

# Known tech-stack comment patterns that are never vulnerabilities
# (e.g. "# TODO: add auth", "# FIXME: sanitize later", or framework boilerplate comments)
_COMMENT_SAFE_RE = re.compile(
    r"#\s*(?:TODO|FIXME|NOTE|HACK|XXX|type:\s*ignore|noqa)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Lazy client
# ---------------------------------------------------------------------------

_client: InferenceClient | None = None

def _get_client() -> InferenceClient:
    global _client
    if _client is None:
        _client = InferenceClient(
            api_key=os.environ["HF_API_KEY"],
            model=_MODEL_ID,
            provider=_PROVIDER,
        )
    return _client


# ---------------------------------------------------------------------------
# AST pre-analysis (flat, simple)
# ---------------------------------------------------------------------------

def _extract_safe_names(source: str) -> dict[str, Any]:
    """
    Return names assigned from os.getenv/os.environ (safe vars) and
    string literals that look like model/resource IDs (contain '/').
    Falls back gracefully on SyntaxError.
    """
    safe_vars: list[str] = []
    model_ids: list[str] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {"safe_vars": [], "model_ids": []}

    for node in ast.walk(tree):
        # VAR = os.getenv(...) or os.environ.get(...)
        if isinstance(node, ast.Assign):
            val = node.value
            if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute):
                attr = val.func
                parent = attr.value
                is_getenv = (
                    isinstance(parent, ast.Name)
                    and parent.id == "os"
                    and attr.attr == "getenv"
                )
                is_environ_get = (
                    isinstance(parent, ast.Attribute)
                    and isinstance(parent.value, ast.Name)
                    and parent.value.id == "os"
                    and parent.attr == "environ"
                    and attr.attr == "get"
                )
                if is_getenv or is_environ_get:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            safe_vars.append(t.id)

        # String literals that look like "org/model-name"
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and "/" in node.value
            and " " not in node.value
        ):
            model_ids.append(node.value)

    return {"safe_vars": list(set(safe_vars)), "model_ids": model_ids[:5]}


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

def _build_system_prompt(safe_meta: dict[str, Any]) -> str:
    safe_note = ""
    if safe_meta["safe_vars"]:
        names = ", ".join(f'"{v}"' for v in safe_meta["safe_vars"])
        safe_note = (
            f"\n\nSAFE VARIABLES (from os.getenv / os.environ) — DO NOT FLAG:\n{names}"
        )

    model_note = ""
    if safe_meta["model_ids"]:
        ids = ", ".join(f'"{m}"' for m in safe_meta["model_ids"])
        model_note = (
            f"\n\nMODEL / RESOURCE IDENTIFIERS — NOT SECRETS:\n{ids}"
        )

    return (
        "You are an expert cybersecurity analyst. Find REAL, EXPLOITABLE vulnerabilities only.\n\n"

        "TECH STACK AWARENESS:\n"
        "This codebase may use FastAPI, React/Vite, Supabase, LangChain, HuggingFace, and "
        "similar modern frameworks. Understand their idioms:\n"
        "  - FastAPI dependency injection, Pydantic models, and router declarations are NOT vulnerabilities.\n"
        "  - Supabase client initialisation with env-var keys is SAFE.\n"
        "  - HuggingFace InferenceClient(api_key=VAR) where VAR comes from os.getenv is SAFE.\n"
        "  - LangChain chains, prompts, and memory objects are boilerplate, not vulnerabilities.\n"
        "  - Comments (# TODO, # FIXME, # NOTE, # noqa, type: ignore) are developer annotations "
        "and must NEVER be flagged as vulnerabilities, even if they mention words like 'secret', "
        "'token', or 'password' — comments contain no executable code.\n\n"

        "WHAT TO FLAG:\n"
        "  - TOKEN = \"ghp_abc123...\"       → Hardcoded Secret\n"
        "  - cursor.execute(f\"SELECT ... '{user_id}'\")  → SQL Injection\n"
        "  - eval(user_input)              → Remote Code Execution\n"
        "  - subprocess.run(cmd, shell=True) → Command Injection\n"
        "  - pickle.loads(request.data)   → Insecure Deserialization\n"
        "  - jwt.decode(token, verify=False) → Auth Bypass\n\n"

        "WHAT NOT TO FLAG:\n"
        "  - KEY = os.getenv('KEY')        → SAFE, env-var read\n"
        "  - model = \"org/model-name\"      → SAFE, resource identifier\n"
        "  - history = {}                  → SAFE, empty container\n"
        "  - # TODO: sanitize this later  → SAFE, it is a comment\n"
        "  - # FIXME: token exposed        → SAFE, it is a comment, not code\n\n"

        "RULES:\n"
        "1. Hardcoded secret = raw literal string with actual credential value in source.\n"
        "2. Cite the EXACT dangerous expression in your description.\n"
        "3. Never flag a line just because a variable name sounds sensitive.\n"
        "4. Return ONLY a raw JSON array — no prose, no markdown fences.\n"
        "5. No findings → return []\n\n"

        "Each object must have exactly: "
        "\"type\", \"severity\" (critical/high/medium/low/info), \"line\" (int), \"description\"."
        f"{safe_note}{model_note}"
    )


def _build_user_message(
    ast_result: dict[str, Any],
    rag_context: str,
    source_code: str,
    safe_meta: dict[str, Any],
) -> str:
    imports   = ", ".join(ast_result.get("imports", []))
    functions = json.dumps(ast_result.get("functions", []), indent=2)

    safe_reminder = ""
    if safe_meta["safe_vars"]:
        safe_reminder = (
            f"\n\nREMINDER — safe variables (env-var reads, not secrets): "
            f"{', '.join(safe_meta['safe_vars'])}"
        )

    return (
        f"Analyse the following code for REAL, EXPLOITABLE security vulnerabilities.\n\n"
        f"## Source Code\n```python\n{source_code}\n```\n\n"
        f"## Imports\n{imports}\n\n"
        f"## Functions\n{functions}\n\n"
        f"## Knowledge Base Context\n{rag_context or 'None'}"
        f"{safe_reminder}\n\n"
        f"Return a JSON array of confirmed vulnerabilities, or [] if none.\n"
        f"JSON array:"
    )


# ---------------------------------------------------------------------------
# Model call
# ---------------------------------------------------------------------------

def _call_model(system_prompt: str, user_message: str) -> str:
    try:
        comp = _get_client().chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message},
            ],
            max_tokens=1024,
            temperature=0.05,
        )
        return comp.choices[0].message.content
    except Exception as exc:
        print(f"[vuln_agent] model error: {exc}")
        return "[]"


# ---------------------------------------------------------------------------
# Response parsing & post-filter
# ---------------------------------------------------------------------------

def _parse_response(raw: str) -> list[dict[str, Any]]:
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).replace("```", "").strip()
    for attempt in (cleaned, (re.search(r"\[.*\]", cleaned, re.DOTALL) or type("", (), {"group": lambda *_: "[]"})()).group()):
        try:
            data = json.loads(attempt)
            if isinstance(data, list):
                return [_norm(v) for v in data]
        except (json.JSONDecodeError, AttributeError):
            pass
    print(f"[vuln_agent] parse failed: {raw[:200]}")
    return []


def _norm(v: dict[str, Any]) -> dict[str, Any]:
    sev = str(v.get("severity", "info")).lower()
    return {
        "type":        str(v.get("type", "Unknown")),
        "severity":    sev if sev in _VALID_SEVERITIES else "info",
        "line":        int(v.get("line", 0)),
        "description": str(v.get("description", "")),
    }


def _post_filter(vulns: list[dict[str, Any]], lines: list[str]) -> list[dict[str, Any]]:
    """Remove findings that are contradicted by the actual source line, and deduplicate."""
    seen: set[tuple[str, int]] = set()
    out: list[dict[str, Any]] = []

    for v in vulns:
        key = (v["type"].lower(), v["line"])
        if key in seen:
            continue
        seen.add(key)

        ln = v["line"]
        if 1 <= ln <= len(lines):
            actual = lines[ln - 1]
            # Skip if the actual source line is provably safe
            if any(p.search(actual) for p in _SAFE_PATTERNS):
                print(f"[vuln_agent] filtered safe line: {v['type']} L{ln}: {actual.strip()!r}")
                continue
            # Skip if the line is purely a comment
            stripped = actual.strip()
            if stripped.startswith("#"):
                print(f"[vuln_agent] filtered comment line: {v['type']} L{ln}")
                continue

        out.append(v)

    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def run_vuln_agent(
    ast_result: dict[str, Any],
    rag_context: str,
    source_code: str,
) -> list[dict[str, Any]]:
    """
    Analyse source_code for security vulnerabilities using DeepHat V1.

    Steps: pre-analysis → prompt build → model call → parse → post-filter.
    Returns a list of dicts with keys: type, severity, line, description.
    """
    safe_meta    = _extract_safe_names(source_code)
    source_lines = source_code.splitlines()

    print(f"[vuln_agent] safe_vars={safe_meta['safe_vars']} model_ids={safe_meta['model_ids']}")

    system_prompt = _build_system_prompt(safe_meta)
    user_message  = _build_user_message(ast_result, rag_context, source_code, safe_meta)

    raw_response = _call_model(system_prompt, user_message)
    print(f"[vuln_agent] raw: {raw_response[:300]}")

    raw_vulns = _parse_response(raw_response)
    filtered  = _post_filter(raw_vulns, source_lines)

    print(f"[vuln_agent] {len(raw_vulns)} raw → {len(filtered)} after filter")
    return filtered
