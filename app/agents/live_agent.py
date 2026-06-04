"""
live_agent.py — Live URL scanning agent for VibeSec.

Three-phase pipeline:
  1. nmap   — Network/infrastructure scan (open ports, CVEs, service versions)
  2. HTTP probe — Real application-layer evidence collection via urllib
                  (security headers, cookies, exposed paths, CORS, HTTPS)
  3. Groq triage — AI analyst that reads ALL evidence and returns prioritised
                   findings with "fix today / this week / monitor / false positive"
                   labels and a specific fix for each.

This is what separates VibeSec from "nmap + GPT":
  - Real evidence, not hallucinations
  - Prioritised findings, not a raw dump
  - Actionable fixes, not just descriptions

Environment variables
---------------------
GROQ_API_KEY : str   Groq API key (loaded from .env by main.py dotenv).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import urllib.request
import urllib.error
from typing import Any

from openai import AsyncOpenAI

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "")
_GROQ_BASE_URL = "https://api.groq.com/openai/v1"
_GROQ_MODEL    = "llama-3.3-70b-versatile"

# Sensitive paths to probe — catches common vibe-coded mistakes
_PROBE_PATHS = [
    "/",
    "/.env",
    "/.env.local",
    "/.git/HEAD",
    "/admin",
    "/admin/",
    "/debug",
    "/api/debug",
    "/api/health",
    "/api/status",
    "/swagger",
    "/swagger-ui.html",
    "/docs",
    "/graphql",
    "/robots.txt",
    "/sitemap.xml",
    "/config.json",
    "/server-status",
]

# Security headers that should be present on every web app
_REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing — site is vulnerable to protocol downgrade attacks",
    "content-security-policy":   "CSP missing — XSS attacks are not mitigated",
    "x-frame-options":           "X-Frame-Options missing — site is vulnerable to clickjacking",
    "x-content-type-options":    "X-Content-Type-Options missing — MIME sniffing attacks possible",
    "referrer-policy":           "Referrer-Policy missing — sensitive URLs may leak to third parties",
    "permissions-policy":        "Permissions-Policy missing — browser APIs not restricted",
}

# ---------------------------------------------------------------------------
# Groq client
# ---------------------------------------------------------------------------

_groq_client: AsyncOpenAI | None = None


def _get_groq_client() -> AsyncOpenAI:
    global _groq_client
    if _groq_client is None:
        _groq_client = AsyncOpenAI(api_key=_GROQ_API_KEY, base_url=_GROQ_BASE_URL)
    return _groq_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_hostname(url: str) -> str:
    host = url.replace("https://", "").replace("http://", "").split("/")[0]
    return host.split(":")[0]


def _normalise_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url


# ---------------------------------------------------------------------------
# Phase 1 & 2 — nmap (network layer)
# ---------------------------------------------------------------------------

def _nmap_candidates(args: list[str]) -> list[list[str]]:
    return [["wsl", "nmap"] + args, ["nmap"] + args]


def _run_subprocess(candidates: list[list[str]], timeout: int) -> str:
    last_error = "[nmap not found — run: wsl sudo apt install nmap]"
    for cmd in candidates:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = result.stdout.strip()
            if output:
                return output
            last_error = result.stderr.strip() or last_error
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            return f"[nmap timed out after {timeout}s]"
        except Exception as exc:  # noqa: BLE001
            return f"[nmap error: {exc}]"
    return last_error


def _parse_open_ports(nmap_out: str) -> str:
    ports = re.findall(r"(\d+)/tcp\s+open", nmap_out)
    return ",".join(ports)


def _run_nmap(hostname: str) -> str:
    """Two-phase nmap: fast discovery → targeted vuln scan on open ports."""
    print(f"[live_agent] nmap Phase 1: fast port discovery on {hostname}")
    phase1 = _run_subprocess(
        _nmap_candidates(["-T4", "--top-ports", "1000", "--open", hostname]),
        timeout=45,
    )
    if phase1.startswith("["):
        return phase1  # error — bail

    open_ports = _parse_open_ports(phase1)
    print(f"[live_agent] Open ports: {open_ports or 'none'}")

    if not open_ports:
        return f"=== nmap Port Scan ===\n{phase1}\n\n[No open TCP ports found in top 1000]"

    print(f"[live_agent] nmap Phase 2: targeted scan on ports {open_ports}")
    phase2 = _run_subprocess(
        _nmap_candidates([
            "-sV", "-p", open_ports,
            "--script", "vuln,http-headers,http-server-header,banner",
            "--script-timeout", "30s", hostname,
        ]),
        timeout=90,
    )
    return (
        f"=== nmap Port Discovery ===\n{phase1}\n\n"
        f"=== nmap Service & Vuln Scan (ports: {open_ports}) ===\n{phase2}"
    )


# ---------------------------------------------------------------------------
# Phase 3 — HTTP probe (application layer, real evidence)
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: int = 8) -> tuple[int, dict[str, str], str]:
    """
    Perform a GET request and return (status_code, headers_lower, body_snippet).
    Never raises — returns (-1, {}, error_msg) on failure.
    """
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "VibeSec-Scanner/1.0",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            body = resp.read(2048).decode("utf-8", errors="ignore")
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, headers, ""
    except Exception as exc:  # noqa: BLE001
        return -1, {}, str(exc)


def _run_http_probe(target_url: str) -> dict[str, Any]:
    """
    Real HTTP application-layer evidence collection.

    Checks (all from actual HTTP responses — zero hallucination):
    - Missing security headers
    - Cookie security flags (Secure, HttpOnly, SameSite)
    - Server/X-Powered-By version disclosure
    - HTTP → HTTPS redirect
    - CORS misconfiguration
    - Exposed sensitive paths (/.env, /admin, /debug, etc.)

    Returns a structured evidence dict for the Groq triage agent.
    """
    base = _normalise_url(target_url)
    hostname = _extract_hostname(base)
    print(f"[live_agent] HTTP probe: {base}")

    evidence: dict[str, Any] = {
        "url": base,
        "missing_security_headers": [],
        "header_leaks": [],
        "cookie_issues": [],
        "https_issues": [],
        "cors_issues": [],
        "exposed_paths": [],
        "raw_headers": {},
    }

    # --- Root request ---
    status, headers, body = _http_get(base)
    if status == -1:
        evidence["error"] = body
        return evidence

    evidence["status_code"] = status
    evidence["raw_headers"] = dict(headers)

    # 1. Missing security headers
    for header, reason in _REQUIRED_SECURITY_HEADERS.items():
        if header not in headers:
            evidence["missing_security_headers"].append({
                "header": header,
                "impact": reason,
            })

    # 2. Version/tech disclosure
    for leaky in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if leaky in headers:
            evidence["header_leaks"].append({
                "header": leaky,
                "value": headers[leaky],
                "impact": f"Attacker can target known CVEs for {headers[leaky]}",
            })

    # 3. Cookie security flags
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        issues = []
        if "secure" not in set_cookie.lower():
            issues.append("missing Secure flag — cookie sent over HTTP")
        if "httponly" not in set_cookie.lower():
            issues.append("missing HttpOnly flag — cookie accessible via JS (XSS risk)")
        if "samesite" not in set_cookie.lower():
            issues.append("missing SameSite flag — CSRF risk")
        if issues:
            evidence["cookie_issues"] = issues

    # 4. HTTPS redirect check
    if base.startswith("http://"):
        https_url = base.replace("http://", "https://", 1)
        https_status, _, _ = _http_get(https_url)
        if https_status == -1:
            evidence["https_issues"].append("HTTPS not available — all traffic is plaintext")
        elif status not in (301, 302, 307, 308):
            evidence["https_issues"].append(
                "HTTP endpoint does not redirect to HTTPS — users can stay on plaintext"
            )

    # 5. CORS misconfiguration
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        evidence["cors_issues"].append(
            "Access-Control-Allow-Origin: * — any origin can read API responses"
        )
    acac = headers.get("access-control-allow-credentials", "")
    if acac.lower() == "true" and acao == "*":
        evidence["cors_issues"].append(
            "CORS wildcard + credentials=true — critical misconfiguration allows cross-origin auth"
        )

    # 6. Exposed sensitive paths
    for path in _PROBE_PATHS[1:]:   # skip "/" already fetched
        path_url = f"{base.rstrip('/')}{path}"
        pstatus, _, pbody = _http_get(path_url, timeout=5)
        if pstatus in (200, 403):   # 403 means it exists but is guarded
            entry: dict[str, Any] = {
                "path": path,
                "status": pstatus,
            }
            # Quick sniff for sensitive content
            if path == "/.git/HEAD" and ("ref:" in pbody or "HEAD" in pbody):
                entry["impact"] = "Git repository exposed — full source code may be downloadable"
            elif path == "/.env" and ("=" in pbody):
                entry["impact"] = "Environment file exposed — API keys and secrets visible"
            elif path in ("/swagger", "/swagger-ui.html", "/docs"):
                entry["impact"] = "API documentation publicly accessible — all endpoints enumerable"
            elif path in ("/debug", "/api/debug"):
                entry["impact"] = "Debug endpoint active — internal state and stack traces exposed"
            elif path == "/admin" and pstatus == 200:
                entry["impact"] = "Admin panel accessible without authentication check"
            else:
                entry["impact"] = f"Path {path} returned HTTP {pstatus}"
            evidence["exposed_paths"].append(entry)

    print(
        f"[live_agent] HTTP probe complete: "
        f"{len(evidence['missing_security_headers'])} missing headers, "
        f"{len(evidence['exposed_paths'])} exposed paths, "
        f"{len(evidence['cookie_issues'])} cookie issues"
    )
    return evidence


# ---------------------------------------------------------------------------
# Phase 4 — Groq triage agent (the VibeSec differentiator)
# ---------------------------------------------------------------------------

_TRIAGE_SYSTEM_PROMPT = """You are a senior application security engineer triaging findings for a developer.
Your job is NOT to list every finding — your job is to help developers know what to fix first.

You will receive:
- nmap_blocked: boolean — if true, nmap was blocked/filtered and returned NO real port data
- nmap scan output (network/infrastructure evidence)
- HTTP probe evidence (real application-layer data: headers, cookies, exposed paths, CORS)

CRITICAL RULE — HALLUCINATION PREVENTION:
If nmap_blocked is true, you MUST NOT report ANY network-layer findings.
This means: no SSH vulnerabilities, no open port findings, no service version issues,
no CVE findings based on service banners, no firewall/filtering observations.
The nmap data is empty/unreliable — treat it as if it does not exist.
Only report findings backed by the HTTP probe evidence.

Return ONLY a valid JSON object with this exact structure (no prose, no fences):
{
  "findings": [
    {
      "type": "short name",
      "severity": "critical|high|medium|low|info",
      "port": "port number or N/A",
      "description": "one sentence — what the evidence shows",
      "priority": "fix_today|fix_this_week|monitor|likely_false_positive",
      "fix": "one specific actionable fix — e.g. 'Add response.setHeader(Strict-Transport-Security, max-age=31536000)'"
    }
  ],
  "fix_today": ["type1", "type2"],
  "summary": "2-3 sentence executive summary of the risk posture"
}

Priority rules:
- fix_today: directly exploitable, data loss risk, auth bypass, secrets exposed
- fix_this_week: missing defences that raise attacker success rate
- monitor: informational, low-probability exploitation
- likely_false_positive: nmap noise, false CVE matches with no real evidence

Base priority ONLY on the evidence provided. Do not add findings not present in the evidence."""


def _is_nmap_blocked(nmap_output: str) -> bool:
    """
    Return True when nmap produced no useful network data.
    This happens when the target blocks/filters nmap (firewall, IDS, cloud WAF).
    """
    if nmap_output.startswith("["):
        return True  # error string from _run_subprocess
    lower = nmap_output.lower()
    has_open = re.search(r"\d+/tcp\s+open", nmap_output) is not None
    all_filtered = "all 1000 scanned ports" in lower and "filtered" in lower
    host_down = "host seems down" in lower or "0 hosts up" in lower
    return (not has_open) or all_filtered or host_down


async def _ask_groq_triage(
    nmap_output: str,
    http_evidence: dict[str, Any],
    nmap_blocked: bool,
) -> str:
    """Send all evidence to Groq triage agent and return the raw JSON string."""
    client = _get_groq_client()

    blocked_notice = (
        "nmap_blocked: TRUE\n"
        "IMPORTANT: nmap was blocked by the target's firewall/IDS. "
        "Do NOT report any network-layer findings (SSH, open ports, service CVEs). "
        "Only report findings from the HTTP probe evidence below.\n\n"
        if nmap_blocked
        else "nmap_blocked: FALSE\n\n"
    )

    user_content = (
        f"{blocked_notice}"
        "=== NMAP SCAN OUTPUT ===\n"
        f"{nmap_output}\n\n"
        "=== HTTP APPLICATION PROBE EVIDENCE ===\n"
        f"{json.dumps(http_evidence, indent=2)}\n\n"
        "Triage these findings and return the JSON."
    )

    response = await client.chat.completions.create(
        model=_GROQ_MODEL,
        messages=[
            {"role": "system", "content": _TRIAGE_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        max_tokens=2048,
        temperature=0.1,
    )
    return response.choices[0].message.content or "{}"


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_triage_output(raw: str) -> dict[str, Any]:
    """Parse the triage JSON, returning a safe fallback on failure."""
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).replace("```", "").strip()

    # Try direct parse first
    try:
        result = json.loads(cleaned)
        if isinstance(result, dict) and "findings" in result:
            result["findings"] = [_normalise_finding(f) for f in result["findings"]]
            result.setdefault("fix_today", [])
            result.setdefault("summary", "Scan complete.")
            return result
    except json.JSONDecodeError:
        pass

    # Try extracting JSON object from text
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            if isinstance(result, dict):
                result["findings"] = [_normalise_finding(f) for f in result.get("findings", [])]
                result.setdefault("fix_today", [])
                result.setdefault("summary", "Scan complete.")
                return result
        except json.JSONDecodeError:
            pass

    return {"findings": [], "fix_today": [], "summary": f"Could not parse triage output: {raw[:200]}"}


def _normalise_finding(raw: dict[str, Any]) -> dict[str, Any]:
    severity = str(raw.get("severity", "info")).lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "info"

    priority = str(raw.get("priority", "monitor")).lower()
    if priority not in {"fix_today", "fix_this_week", "monitor", "likely_false_positive"}:
        priority = "monitor"

    return {
        "type":        str(raw.get("type", "Unknown")),
        "severity":    severity,
        "port":        str(raw.get("port", "N/A")),
        "description": str(raw.get("description", "")),
        "priority":    priority,
        "fix":         str(raw.get("fix", "No specific fix provided.")),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def run_live_agent(target_url: str) -> dict[str, Any]:
    """
    Full 3-phase VibeSec live scan pipeline.

    Returns
    -------
    dict with keys:
        findings   : list of prioritised vulnerability dicts
        fix_today  : list of finding type names to fix immediately
        summary    : executive summary string
    """
    url_str = str(target_url)
    hostname = _extract_hostname(url_str)
    print(f"[live_agent] Starting full scan of: {url_str}")

    loop = asyncio.get_event_loop()

    # Run nmap (blocking) and HTTP probe (blocking) CONCURRENTLY in thread pool
    nmap_future  = loop.run_in_executor(None, _run_nmap, hostname)
    probe_future = loop.run_in_executor(None, _run_http_probe, url_str)

    nmap_output, http_evidence = await asyncio.gather(nmap_future, probe_future)

    # Detect whether nmap was blocked/filtered — prevents hallucinated network findings
    nmap_blocked = _is_nmap_blocked(nmap_output)
    if nmap_blocked:
        print(f"[live_agent] nmap blocked/filtered — network findings suppressed")
    else:
        print(f"[live_agent] nmap: {len(nmap_output)} chars, ports found")

    # Groq triage on all evidence
    try:
        raw_response = await _ask_groq_triage(nmap_output, http_evidence, nmap_blocked)
        print(f"[live_agent] Groq triage done: {raw_response[:150]}...")
    except Exception as exc:  # noqa: BLE001
        print(f"[live_agent] Groq error: {exc}")
        return {"findings": [], "fix_today": [], "summary": f"Scan failed: {exc}"}

    return _parse_triage_output(raw_response)
