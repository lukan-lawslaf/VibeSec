"""
scan.py — FastAPI router for VibeSec scan endpoints.

Endpoints
---------
POST /api/v1/scan/static
    Accept Python source code, run the full pipeline:
    AST parsing → RAG indexing/retrieval → vulnerability detection → patch generation.

POST /api/v1/scan/live
    Accept a target URL, run nmap via WSL, then analyse with the CAI/Groq
    live agent to return a structured vulnerability report.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl

from app.agents.live_agent import run_live_agent
from app.agents.patch_agent import run_patch_agent
from app.agents.vuln_agent import run_vuln_agent
from app.parsers.ast_parser import parse_code
from app.utils.rag import index_code, retrieve_context

router = APIRouter(prefix="/scan", tags=["scan"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class StaticScanRequest(BaseModel):
    """Payload for the static code analysis endpoint."""
    code: str = Field(
        ...,
        description="Raw Python source code to analyse.",
        examples=["import os\nos.system(input())"],
    )


class VulnerabilityItem(BaseModel):
    """A single detected vulnerability."""
    type:        str = Field(..., description="Vulnerability category.")
    severity:    str = Field(..., description="Severity level: critical / high / medium / low / info.")
    line:        int = Field(..., description="Source line where the issue was found (0 = unknown).")
    description: str = Field(..., description="Human-readable explanation.")


class StaticScanResponse(BaseModel):
    """Full response from the static scan pipeline."""
    ast_summary:  dict[str, Any]       = Field(..., description="Parsed AST structure.")
    vulnerabilities: list[VulnerabilityItem] = Field(..., description="Detected vulnerabilities.")
    patched_code: str                  = Field(..., description="Security-patched source code.")
    diff:         str                  = Field(..., description="Unified diff between original and patched code.")


class LiveScanRequest(BaseModel):
    """Payload for the live URL scan endpoint."""
    url: HttpUrl = Field(
        ...,
        description="Target URL to scan.",
        examples=["https://example.com"],
    )


class LiveVulnerabilityItem(BaseModel):
    """A single prioritised finding from the live scan pipeline."""
    type:        str = Field(..., description="Finding category or vulnerability name.")
    severity:    str = Field(..., description="Severity: critical / high / medium / low / info.")
    port:        str = Field(..., description="Affected port, or 'N/A' if not port-specific.")
    description: str = Field(..., description="One-sentence explanation backed by real evidence.")
    priority:    str = Field(..., description="fix_today / fix_this_week / monitor / likely_false_positive.")
    fix:         str = Field(..., description="Specific actionable remediation step.")


class LiveScanResponse(BaseModel):
    """Prioritised response from the VibeSec 3-phase live scan pipeline."""
    url:             str                         = Field(..., description="The scanned URL.")
    status:          str                         = Field(..., description="Scan status.")
    findings:        list[LiveVulnerabilityItem] = Field(..., description="All discovered findings, prioritised.")
    fix_today:       list[str]                   = Field(..., description="Finding types to fix immediately.")
    summary:         str                         = Field(..., description="Executive summary of risk posture.")
    message:         str                         = Field(..., description="Additional scan metadata.")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/static",
    response_model=StaticScanResponse,
    summary="Static code analysis",
    description=(
        "Run the full VibeSec pipeline on a Python source code string: "
        "AST parsing → RAG context retrieval → vulnerability detection → patch generation."
    ),
    status_code=status.HTTP_200_OK,
)
async def static_scan(request: StaticScanRequest) -> StaticScanResponse:
    """
    Execute the static analysis pipeline on the submitted source code.

    Pipeline steps
    --------------
    1. Parse AST (functions, imports, call graph).
    2. Index code into the RAG vector store.
    3. Retrieve relevant context for vulnerability analysis.
    4. Run the vulnerability detection agent (DeepHat V1 via HF).
    5. Run the patch generation agent (DeepSeek-Coder via HF).
    """
    source = request.code

    # ------------------------------------------------------------------
    # Step 1 — AST parsing
    # ------------------------------------------------------------------
    try:
        ast_result = parse_code(source)
    except SyntaxError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid Python syntax: {exc}",
        )

    # ------------------------------------------------------------------
    # Step 2 — Index code in RAG vector store
    # ------------------------------------------------------------------
    await index_code(source)

    # ------------------------------------------------------------------
    # Step 3 — Retrieve relevant context
    # ------------------------------------------------------------------
    # Use the list of imported module names as the retrieval query so we
    # surface known-insecure usage patterns for those libraries.
    query = "security vulnerabilities in: " + ", ".join(ast_result.get("imports", []))
    rag_context = await retrieve_context(query)

    # ------------------------------------------------------------------
    # Step 4 — Vulnerability detection
    # ------------------------------------------------------------------
    raw_vulns = await run_vuln_agent(ast_result, rag_context, source)
    vulns = [VulnerabilityItem(**v) for v in raw_vulns]

    # ------------------------------------------------------------------
    # Step 5 — Patch generation
    # ------------------------------------------------------------------
    patch_result = await run_patch_agent(source, raw_vulns)

    return StaticScanResponse(
        ast_summary=ast_result,
        vulnerabilities=vulns,
        patched_code=patch_result["patched_code"],
        diff=patch_result["diff"],
    )


@router.post(
    "/live",
    response_model=LiveScanResponse,
    summary="Live URL scan — nmap + HTTP probe + AI triage",
    description=(
        "3-phase VibeSec live scan: (1) nmap network scan via WSL, "
        "(2) real HTTP application-layer probe (headers, cookies, exposed paths, CORS), "
        "(3) Groq triage agent that prioritises findings into fix_today / fix_this_week / "
        "monitor / likely_false_positive with a specific fix for each."
    ),
    status_code=status.HTTP_200_OK,
)
async def live_scan(request: LiveScanRequest) -> LiveScanResponse:
    """
    Full VibeSec live scan pipeline.

    Phases
    ------
    1. nmap fast port discovery + targeted vuln scan (network layer).
    2. HTTP probe — real evidence: missing headers, cookie flags, exposed paths, CORS.
    3. Groq triage — prioritised findings with actionable fixes.

    nmap and HTTP probe run concurrently so total time is ~40-60 s.
    """
    url_str = str(request.url)

    try:
        result = await run_live_agent(url_str)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Live scan failed: {exc}",
        )

    raw_findings = result.get("findings", [])
    findings = [LiveVulnerabilityItem(**f) for f in raw_findings]
    fix_today = result.get("fix_today", [])
    summary   = result.get("summary", "Scan complete.")

    fix_today_count = len(fix_today)
    total = len(findings)

    return LiveScanResponse(
        url=url_str,
        status="completed",
        findings=findings,
        fix_today=fix_today,
        summary=summary,
        message=(
            f"Scan complete. {total} finding(s) — "
            f"{fix_today_count} need immediate attention."
        ),
    )


# ---------------------------------------------------------------------------
# Health check (already present in main.py, kept here for router-level parity)
# ---------------------------------------------------------------------------

@router.get("/health", summary="Router-level health check")
async def health() -> dict[str, str]:
    return {"status": "ok"}