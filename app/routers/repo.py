"""
repo.py — FastAPI router for GitHub repository scanning.

Endpoint
--------
POST /api/v1/scan/repo
    Clone a GitHub repo and run the full VibeSec pipeline:
    secrets → AST patterns → OSV.dev CVEs → reachability → Groq triage.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.agents.repo_agent import run_repo_agent
from app.routers.scan import LiveScanResponse, LiveVulnerabilityItem

router = APIRouter(prefix="/scan", tags=["scan"])


class RepoScanRequest(BaseModel):
    """Payload for the GitHub repository scan endpoint."""
    github_url: str = Field(
        ...,
        description="Public GitHub repository URL to scan.",
        examples=["https://github.com/OWASP/WebGoat"],
    )


@router.post(
    "/repo",
    response_model=LiveScanResponse,
    summary="GitHub repository scan",
    description=(
        "Clone a public GitHub repo and run the full VibeSec pipeline: "
        "(1) secrets detection, "
        "(2) AST pattern analysis (eval, SQL injection, auth issues), "
        "(3) OSV.dev real CVE lookup on dependencies, "
        "(4) reachability — is the vuln reachable from an HTTP route?, "
        "(5) Groq triage with fix_today / fix_this_week / monitor priorities."
    ),
    status_code=status.HTTP_200_OK,
)
async def repo_scan(request: RepoScanRequest) -> LiveScanResponse:
    """
    Scan a GitHub repository for security vulnerabilities.

    Phases (concurrent where possible)
    -----------------------------------
    1. git clone --depth=1
    2. Secrets scan  — regex across all files
    3. AST scan      — dangerous Python patterns with line numbers
    4. OSV.dev       — real CVE data for dependencies
    5. Reachability  — is the finding reachable from an HTTP route?
    6. Groq triage   — prioritised findings with actionable fixes
    7. Cleanup       — temp dir deleted regardless of outcome
    """
    try:
        result = await run_repo_agent(request.github_url)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Repo scan failed: {exc}",
        )

    raw_findings = result.get("findings", [])
    findings     = [LiveVulnerabilityItem(**f) for f in raw_findings]
    fix_today    = result.get("fix_today", [])
    summary      = result.get("summary", "Scan complete.")

    return LiveScanResponse(
        url=request.github_url,
        status="completed",
        findings=findings,
        fix_today=fix_today,
        summary=summary,
        message=(
            f"Repo scan complete. {len(findings)} finding(s) — "
            f"{len(fix_today)} need immediate attention."
        ),
    )
