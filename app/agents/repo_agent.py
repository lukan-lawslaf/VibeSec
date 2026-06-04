"""
repo_agent.py — GitHub repository scanner for VibeSec.

Pipeline (deterministic first, AI last):
  1. git clone --depth=1
  2. Secrets scan      — regex patterns across all files
  3. AST pattern scan  — dangerous calls, SQL injection, auth issues
  4. OSV.dev deps      — real CVE data, no hardcoded list
  5. Reachability      — is the vuln reachable from an HTTP route?
  6. Groq triage       — same agent as live scan
  7. Cleanup temp dir

Environment variables
---------------------
GROQ_API_KEY : str   Groq API key (loaded from .env by main.py).
"""

from __future__ import annotations

import ast
import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from openai import AsyncOpenAI

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "")
_GROQ_BASE_URL = "https://api.groq.com/openai/v1"
_GROQ_MODEL    = "llama-3.3-70b-versatile"

_groq_client: AsyncOpenAI | None = None

def _get_client() -> AsyncOpenAI:
    global _groq_client
    if _groq_client is None:
        _groq_client = AsyncOpenAI(api_key=_GROQ_API_KEY, base_url=_GROQ_BASE_URL)
    return _groq_client

# Dirs/extensions to skip during file walks
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}
_SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".ttf", ".pdf", ".zip", ".lock"}


# ---------------------------------------------------------------------------
# Phase 1 — Clone
# ---------------------------------------------------------------------------

def _clone_repo(github_url: str) -> Path:
    """Clone the repo to a temp dir. Returns the Path. Raises on failure."""
    tmp = Path(tempfile.mkdtemp(prefix="vibesec_"))
    result = subprocess.run(
        ["git", "clone", "--depth=1", github_url, str(tmp)],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"git clone failed: {result.stderr.strip()[:300]}")
    return tmp


# ---------------------------------------------------------------------------
# Phase 2 — Secrets Scanner
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("OpenAI API Key",         r"sk-[a-zA-Z0-9]{20,}",                                   "critical"),
    ("AWS Access Key",         r"AKIA[0-9A-Z]{16}",                                       "critical"),
    ("AWS Secret Key",         r'(?i)aws_secret[_a-z]*\s*=\s*["\'][^"\']{30,}',          "critical"),
    ("GitHub Token",           r"ghp_[a-zA-Z0-9]{36}",                                    "critical"),
    ("Private Key",            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----",               "critical"),
    ("DB Connection String",   r"(postgresql|mysql|mongodb)://[^:]+:[^@]+@",              "critical"),
    ("Hardcoded Password",     r'(?i)password\s*=\s*["\'][^"\']{4,}["\']',               "high"),
    ("JWT Secret",             r'(?i)(?:jwt|secret)[_-]?(?:key|secret)\s*=\s*["\'][^"\']{8,}', "high"),
    ("Generic API Key",        r'(?i)api[_-]?key\s*=\s*["\'][^"\']{16,}',               "high"),
    ("Stripe Secret Key",      r"sk_live_[a-zA-Z0-9]{24,}",                              "critical"),
    ("Slack Token",            r"xox[baprs]-[a-zA-Z0-9\-]+",                             "high"),
]


def _scan_secrets(repo_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for f in repo_path.rglob("*"):
        if not f.is_file():
            continue
        if any(d in f.parts for d in _SKIP_DIRS):
            continue
        if f.suffix in _SKIP_EXTS or f.stat().st_size > 500_000:
            continue

        # .env file committed to repo root
        if f.name in (".env", ".env.local", ".env.production", ".env.staging"):
            findings.append({
                "type":   "Committed .env File",
                "severity": "critical",
                "file":   str(f.relative_to(repo_path)),
                "line":   0,
                "detail": ".env file committed to repository — may expose API keys and credentials",
            })

        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for name, pattern, severity in _SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                line_no = content[: m.start()].count("\n") + 1
                snippet  = (m.group()[:40] + "...") if len(m.group()) > 40 else m.group()
                findings.append({
                    "type":     f"Hardcoded Secret — {name}",
                    "severity": severity,
                    "file":     str(f.relative_to(repo_path)),
                    "line":     line_no,
                    "detail":   f"{name} found: {snippet}",
                })

    return findings


# ---------------------------------------------------------------------------
# Phase 3 — AST Pattern Scanner (Python)
# ---------------------------------------------------------------------------

def _scan_ast_patterns(repo_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for pyfile in repo_path.rglob("*.py"):
        if any(d in pyfile.parts for d in _SKIP_DIRS):
            continue

        try:
            source = pyfile.read_text(encoding="utf-8-sig", errors="ignore")  # utf-8-sig strips BOM
            tree   = ast.parse(source)
        except Exception:
            continue

        rel = str(pyfile.relative_to(repo_path))

        for node in ast.walk(tree):

            # ── Dangerous direct calls: eval(), exec() ──────────────────────
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "eval":
                    findings.append({"type": "Dangerous eval()", "severity": "critical",
                                     "file": rel, "line": node.lineno,
                                     "detail": f"eval() at line {node.lineno} — executes arbitrary code"})
                elif node.func.id == "exec":
                    findings.append({"type": "Dangerous exec()", "severity": "critical",
                                     "file": rel, "line": node.lineno,
                                     "detail": f"exec() at line {node.lineno} — executes arbitrary code"})

            # ── Dangerous attribute calls ────────────────────────────────────
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                obj  = node.func.value
                attr = node.func.attr

                if isinstance(obj, ast.Name):
                    # os.system()
                    if obj.id == "os" and attr == "system":
                        findings.append({"type": "OS Command Injection", "severity": "high",
                                         "file": rel, "line": node.lineno,
                                         "detail": f"os.system() at line {node.lineno} — prefer subprocess with args list"})

                    # subprocess.* with shell=True
                    if obj.id == "subprocess" and attr in ("run", "call", "Popen", "check_call", "check_output"):
                        shell_true = any(
                            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                            for kw in node.keywords
                        )
                        if shell_true:
                            findings.append({"type": "Subprocess shell=True", "severity": "high",
                                             "file": rel, "line": node.lineno,
                                             "detail": f"subprocess.{attr}(shell=True) at line {node.lineno}"})

                    # pickle.loads / marshal.loads
                    if obj.id == "pickle" and attr == "loads":
                        findings.append({"type": "Insecure Deserialization (pickle)", "severity": "high",
                                         "file": rel, "line": node.lineno,
                                         "detail": f"pickle.loads() at line {node.lineno} — can execute arbitrary code"})
                    if obj.id == "marshal" and attr == "loads":
                        findings.append({"type": "Insecure Deserialization (marshal)", "severity": "high",
                                         "file": rel, "line": node.lineno,
                                         "detail": f"marshal.loads() at line {node.lineno}"})

                    # yaml.load without SafeLoader
                    if obj.id == "yaml" and attr == "load":
                        findings.append({"type": "Unsafe YAML Load", "severity": "medium",
                                         "file": rel, "line": node.lineno,
                                         "detail": f"yaml.load() at line {node.lineno} — use yaml.safe_load() instead"})

                # SQL injection: cursor.execute(f"...{var}") or "..." + var
                if attr == "execute" and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.JoinedStr):
                        findings.append({"type": "SQL Injection Risk", "severity": "high",
                                         "file": rel, "line": node.lineno,
                                         "detail": f"cursor.execute() with f-string at line {node.lineno} — use parameterized queries"})
                    elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        findings.append({"type": "SQL Injection Risk", "severity": "high",
                                         "file": rel, "line": node.lineno,
                                         "detail": f"cursor.execute() with string concat at line {node.lineno} — use parameterized queries"})

            # ── JWT verify=False ─────────────────────────────────────────────
            if isinstance(node, ast.keyword) and node.arg == "verify":
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    findings.append({"type": "JWT Verification Disabled", "severity": "critical",
                                     "file": rel, "line": getattr(node, "lineno", 0),
                                     "detail": "JWT decoded with verify=False — signatures are not checked"})

            # ── Dangerous assignments ────────────────────────────────────────
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    name = target.id

                    # DEBUG = True
                    if name == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value is True:
                        findings.append({"type": "Debug Mode Enabled", "severity": "high",
                                         "file": rel, "line": node.lineno,
                                         "detail": "DEBUG=True — disable before deploying to production"})

                    # SECRET_KEY = "hardcoded"
                    if name == "SECRET_KEY" and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) > 4:
                        findings.append({"type": "Hardcoded SECRET_KEY", "severity": "critical",
                                         "file": rel, "line": node.lineno,
                                         "detail": "SECRET_KEY hardcoded in source — move to environment variable"})

    return findings


# ---------------------------------------------------------------------------
# Phase 4 — OSV.dev Dependency Lookup
# ---------------------------------------------------------------------------

def _parse_deps(repo_path: Path) -> list[tuple[str, str, str]]:
    """Return [(package, version, ecosystem), ...]"""
    deps: list[tuple[str, str, str]] = []

    req = repo_path / "requirements.txt"
    if req.exists():
        for line in req.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"([a-zA-Z0-9_\-]+)[=<>!~]+([0-9][^\s,;]*)", line)
            if m:
                deps.append((m.group(1), m.group(2), "PyPI"))

    pkg = repo_path / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(errors="ignore"))
            for section in ("dependencies", "devDependencies"):
                for name, ver in data.get(section, {}).items():
                    deps.append((name, re.sub(r"[^0-9.]", "", ver.lstrip("^~>=<")), "npm"))
        except Exception:
            pass

    return deps


def _osv_query(package: str, version: str, ecosystem: str) -> list[dict[str, Any]]:
    if not version:
        return []
    payload = json.dumps({"version": version, "package": {"name": package, "ecosystem": ecosystem}}).encode()
    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query", data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read()).get("vulns", [])
    except Exception:
        return []


def _scan_dependencies(repo_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    deps = _parse_deps(repo_path)

    for package, version, ecosystem in deps[:25]:   # cap to avoid slow scans
        for vuln in _osv_query(package, version, ecosystem)[:2]:   # top 2 CVEs per package
            sev = "medium"
            for s in vuln.get("severity", []):
                try:
                    score = float(s.get("score", 0))
                    if score >= 9.0:
                        sev = "critical"
                    elif score >= 7.0:
                        sev = "high"
                except (TypeError, ValueError):
                    pass

            fixed_in = ""
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_in = event["fixed"]

            findings.append({
                "type":     f"Vulnerable Dependency — {package}",
                "severity": sev,
                "file":     "requirements.txt / package.json",
                "line":     0,
                "detail":   (
                    f"{package}@{version} — {vuln.get('id', 'CVE')}: "
                    f"{vuln.get('summary', '')[:120]}. "
                    f"Fix: upgrade to {fixed_in or 'latest'}"
                ),
            })

    return findings


# ---------------------------------------------------------------------------
# Phase 5 — Reachability
# ---------------------------------------------------------------------------

_ROUTE_RE = re.compile(
    r'@(?:app|router|blueprint|api_router)\.(?:get|post|put|delete|patch|route)\s*\('
    r'|@api_view\s*\('
    r'|router\.(?:get|post|put|delete|patch)\s*\(',
)
_AUTH_RE = re.compile(
    r'@login_required|@jwt_required|@require_auth|@permission_required'
    r'|Depends\s*\(\s*get_current_user|authenticate\s*\(|verify_token\s*\('
    r'|current_user\.is_authenticated|@auth\.login_required',
)


def _check_reachability(repo_path: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    For each finding, check:
    - Is the file a route file? (contains route decorators)
    - Or is it imported by a route file?
    - Does the file have auth protection?

    Escalates severity for reachable + unauthenticated findings.
    """
    route_files: set[str]       = set()
    file_contents: dict[str, str] = {}

    for pyfile in repo_path.rglob("*.py"):
        if any(d in pyfile.parts for d in _SKIP_DIRS):
            continue
        try:
            content = pyfile.read_text(encoding="utf-8", errors="ignore")
            rel     = str(pyfile.relative_to(repo_path))
            file_contents[rel] = content
            if _ROUTE_RE.search(content):
                route_files.add(rel)
        except Exception:
            continue

    enriched: list[dict[str, Any]] = []
    for f in findings:
        finding_file = f.get("file", "")
        ef           = dict(f)

        is_route = finding_file in route_files
        imported_by_route = not is_route and any(
            Path(finding_file).stem in file_contents.get(rf, "")
            for rf in route_files
        )

        reachable  = is_route or imported_by_route
        has_auth   = bool(_AUTH_RE.search(file_contents.get(finding_file, "")))

        ef["reachable"]      = reachable
        ef["auth_protected"] = has_auth if reachable else None

        if reachable and not has_auth:
            ef["reachability_note"] = "Reachable from HTTP route — no auth protection detected"
            # Escalate medium/low to high when unprotected + reachable
            if ef.get("severity") in ("medium", "low"):
                ef["severity"] = "high"
        elif reachable:
            ef["reachability_note"] = "Reachable from HTTP route — auth protection present"
        else:
            ef["reachability_note"] = "Not directly reachable from detected HTTP routes"

        enriched.append(ef)

    return enriched


# ---------------------------------------------------------------------------
# Groq Triage
# ---------------------------------------------------------------------------

_TRIAGE_PROMPT = """You are a senior application security engineer triaging repository scan findings for a developer.

You receive findings from: secrets scanner, AST static analysis, OSV.dev dependency CVEs, and reachability analysis.

Return ONLY a valid JSON object (no prose, no markdown fences):
{
  "findings": [
    {
      "type": "short name",
      "severity": "critical|high|medium|low|info",
      "port": "N/A",
      "description": "one sentence — what the evidence shows",
      "priority": "fix_today|fix_this_week|monitor|likely_false_positive",
      "fix": "one specific actionable fix — be concrete, not generic"
    }
  ],
  "fix_today": ["type1", "type2"],
  "summary": "2-3 sentence summary of the repo security posture"
}

Priority rules:
- fix_today: hardcoded secrets, reachable+unauthenticated vulns, critical CVEs, SQL injection
- fix_this_week: missing configs, authenticated-only vulns, high CVEs
- monitor: low-probability exploitation, informational
- likely_false_positive: test files, dev-only patterns, commented-out code

Only report what the evidence proves. Do not add findings not in the input."""


async def _triage(all_findings: list[dict[str, Any]], repo_url: str) -> dict[str, Any]:
    client   = _get_client()
    evidence = json.dumps(all_findings[:50], indent=2)   # cap at 50 findings

    response = await client.chat.completions.create(
        model=_GROQ_MODEL,
        messages=[
            {"role": "system", "content": _TRIAGE_PROMPT},
            {"role": "user",   "content": f"Repository: {repo_url}\n\nFindings:\n{evidence}\n\nTriage these."},
        ],
        max_tokens=2048,
        temperature=0.1,
    )

    raw     = response.choices[0].message.content or "{}"
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).replace("```", "").strip()

    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError:
        m      = re.search(r"\{.*\}", cleaned, re.DOTALL)
        result = json.loads(m.group()) if m else {}

    result.setdefault("findings", [])
    result.setdefault("fix_today", [])
    result.setdefault("summary", "Scan complete.")

    valid_sevs  = {"critical", "high", "medium", "low", "info"}
    valid_prios = {"fix_today", "fix_this_week", "monitor", "likely_false_positive"}

    for f in result["findings"]:
        f.setdefault("port", "N/A")
        f["severity"] = f.get("severity", "info").lower()
        if f["severity"] not in valid_sevs:
            f["severity"] = "info"
        f["priority"] = f.get("priority", "monitor").lower()
        if f["priority"] not in valid_prios:
            f["priority"] = "monitor"
        f.setdefault("fix", "No specific fix provided.")

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def run_repo_agent(github_url: str) -> dict[str, Any]:
    """
    Scan a GitHub repository for vulnerabilities.

    Returns same shape as run_live_agent():
      { findings: [...], fix_today: [...], summary: str }
    """
    tmp_dir: Path | None = None
    try:
        loop    = asyncio.get_event_loop()

        # Phase 1 — Clone
        print(f"[repo_agent] Cloning: {github_url}")
        tmp_dir = await loop.run_in_executor(None, _clone_repo, github_url)
        print(f"[repo_agent] Cloned to {tmp_dir}")

        # Phases 2, 3, 4 — run concurrently
        secrets_f = loop.run_in_executor(None, _scan_secrets,      tmp_dir)
        ast_f     = loop.run_in_executor(None, _scan_ast_patterns, tmp_dir)
        deps_f    = loop.run_in_executor(None, _scan_dependencies,  tmp_dir)

        secrets, ast_hits, dep_hits = await asyncio.gather(secrets_f, ast_f, deps_f)
        print(f"[repo_agent] Secrets={len(secrets)} AST={len(ast_hits)} Deps={len(dep_hits)}")

        # Phase 5 — Reachability (enriches ast_hits)
        enriched_ast = await loop.run_in_executor(None, _check_reachability, tmp_dir, ast_hits)

        all_findings = secrets + enriched_ast + dep_hits
        print(f"[repo_agent] Total findings: {len(all_findings)}")

        if not all_findings:
            return {"findings": [], "fix_today": [], "summary": "No vulnerabilities detected."}

        # Phase 6 — Groq triage
        return await _triage(all_findings, github_url)

    except Exception as exc:
        print(f"[repo_agent] Error: {exc}")
        return {"findings": [], "fix_today": [], "summary": f"Scan failed: {exc}"}

    finally:
        if tmp_dir and tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
            print("[repo_agent] Temp dir cleaned up")
