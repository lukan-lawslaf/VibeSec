import { useCallback } from 'react';
import { VulnerabilityCard, FindingCard, type StaticVulnerability, type LiveFinding } from './VulnerabilityCard';
import GridScan from './GridScan';
import type { ScanMode } from './LeftPanel';

export interface ScanResult {
  mode: ScanMode;
  target: string;
  // Static scan
  staticVulns?: StaticVulnerability[];
  patchedCode?: string;
  diff?: string;
  // Live/repo scan
  findings?: LiveFinding[];
  fixToday?: string[];
  summary?: string;
}

interface RightPanelProps {
  isScanning: boolean;
  result: ScanResult | null;
}

export function RightPanel({ isScanning, result }: RightPanelProps) {
  const hasResults = result !== null;
  const isLiveOrRepo = result?.mode === 'url' || result?.mode === 'repo';
  const findings = result?.findings || [];
  const staticVulns = result?.staticVulns || [];
  const fixToday = result?.fixToday || [];
  const summary = result?.summary || '';

  const totalCount = isLiveOrRepo ? findings.length : staticVulns.length;
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;

  const modeLabel = result?.mode === 'repo' ? 'Repository Scan' : result?.mode === 'url' ? 'Live URL Scan' : 'Code Analysis';

  // ── Export Report ──────────────────────────────────────────────────────────

  const exportReport = useCallback(() => {
    if (!result) return;

    const timestamp = new Date().toISOString();
    const report: Record<string, any> = {
      vibesec_report: {
        version: '1.0',
        generated_at: timestamp,
        scan_mode: result.mode,
        target: result.target,
      },
    };

    if (isLiveOrRepo) {
      report.summary = result.summary;
      report.fix_today = result.fixToday;
      report.total_findings = findings.length;
      report.severity_breakdown = {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
      };
      report.findings = findings.map(f => ({
        type: f.type,
        severity: f.severity,
        priority: f.priority,
        description: f.description,
        fix: f.fix,
        ...(f.port !== 'N/A' ? { port: f.port } : {}),
      }));
    } else {
      report.total_vulnerabilities = staticVulns.length;
      report.vulnerabilities = staticVulns.map(v => ({
        severity: v.severity,
        title: v.title,
        description: v.description,
        file: v.file,
        line: v.line,
        ...(v.cwe !== '0' ? { cwe: `CWE-${v.cwe}` } : {}),
      }));
      if (result.patchedCode) {
        report.patched_code = result.patchedCode;
      }
      if (result.diff) {
        report.diff = result.diff;
      }
    }

    // Build filename
    const targetName = result.target
      .replace(/https?:\/\//, '')
      .replace(/[^a-zA-Z0-9.-]/g, '_')
      .slice(0, 40);
    const dateStr = new Date().toISOString().slice(0, 10);
    const filename = `vibesec_report_${targetName}_${dateStr}.json`;

    // Trigger download
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [result, isLiveOrRepo, findings, staticVulns]);

  return (
    <div className="h-full bg-[#050A15] border-l border-amber-900/20 flex flex-col relative overflow-hidden">
      {/* Background GridScan Effect */}
      <div className="absolute inset-0 z-0 pointer-events-none opacity-90">
        <GridScan
          sensitivity={0.5}
          lineThickness={1}
          linesColor="#050A15"
          gridScale={0.04}
          scanColor="#C71585"
          scanOpacity={0.6}
          enablePost={false}
          noiseIntensity={0.03}
          scanDuration={3.5}
        />
      </div>

      {/* Header */}
      <div className="h-16 border-b border-amber-900/20 px-6 flex items-center justify-between shrink-0 relative z-10 bg-[#050A15]/50 backdrop-blur-md">
        <div className="flex items-center gap-4 text-sm">
          {hasResults ? (
            <>
              <span className="text-foreground font-mono truncate max-w-[300px]">{result.target}</span>
              <span className="text-muted-foreground hidden sm:inline-block">|</span>
              <span className="text-muted-foreground hidden sm:inline-block text-xs">{modeLabel}</span>
            </>
          ) : (
            <span className="text-muted-foreground uppercase tracking-widest text-xs font-semibold">
              Scan Results
            </span>
          )}
        </div>
        {hasResults && (
          <button
            onClick={exportReport}
            className="text-xs font-medium text-muted-foreground hover:text-foreground transition-colors border border-white/5 hover:border-white/20 bg-white/5 px-3 py-1.5 rounded-md flex items-center gap-2"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            Export Report
          </button>
        )}
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto p-6 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent relative z-10">
        {/* Empty state */}
        {!hasResults && !isScanning && (
          <div className="h-full flex flex-col items-center justify-center text-center opacity-70">
            <div className="mb-6 flex items-center justify-center">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" className="text-muted-foreground">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-foreground mb-2">Run your first scan</h3>
            <p className="text-sm text-muted-foreground max-w-[250px]">
              Upload code, enter a live URL, or paste a GitHub repo link to begin.
            </p>
          </div>
        )}

        {/* Scanning state */}
        {isScanning && !hasResults && (
          <div className="h-full flex flex-col items-center justify-center text-center">
            <div className="w-16 h-16 border-4 border-white/5 border-t-amber-600 rounded-full animate-spin mb-6"></div>
            <p className="text-sm text-muted-foreground animate-pulse">Auditing target surface...</p>
          </div>
        )}

        {/* Results */}
        {hasResults && (
          <div className="max-w-3xl mx-auto">

            {/* ── Fix Today Banner (live/repo only) ── */}
            {isLiveOrRepo && fixToday.length > 0 && (
              <div className="mb-6 p-4 rounded-xl border border-red-500/20 bg-red-950/20 backdrop-blur-sm">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-red-400 text-lg">🔴</span>
                  <h3 className="text-sm font-bold text-red-400 uppercase tracking-wider">Fix Today — {fixToday.length} Critical</h3>
                </div>
                <div className="flex flex-wrap gap-2">
                  {fixToday.map((item, i) => (
                    <span key={i} className="text-[11px] font-mono bg-red-500/10 text-red-300 border border-red-500/20 px-2.5 py-1 rounded-md">
                      {item}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* ── Executive Summary (live/repo only) ── */}
            {isLiveOrRepo && summary && (
              <div className="mb-6 p-4 rounded-xl border border-white/5 bg-[#0A111B]">
                <h4 className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2">Executive Summary</h4>
                <p className="text-sm text-foreground/80 leading-relaxed">{summary}</p>
              </div>
            )}

            {/* ── Patched Code Banner (static scan only) ── */}
            {!isLiveOrRepo && result.patchedCode && (
              <div className="mb-6 p-4 rounded-xl border border-emerald-500/20 bg-emerald-950/20 backdrop-blur-sm">
                <div className="flex items-center gap-2 mb-1">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-emerald-400">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  <h3 className="text-sm font-bold text-emerald-400 uppercase tracking-wider">Patched Code Generated</h3>
                </div>
                <p className="text-xs text-emerald-300/70 ml-6">Click "Copy Patched Code" on any vulnerability below to copy the full fixed source.</p>
              </div>
            )}

            {/* ── Stats Bar ── */}
            <div className="mb-6 flex items-center justify-between">
              <h2 className="text-xl font-display text-foreground">
                {isLiveOrRepo ? 'Security Findings' : 'Identified Vulnerabilities'}
              </h2>
              <div className="flex items-center gap-2">
                <span className="bg-amber-500/10 text-amber-500 px-2.5 py-1 rounded text-xs font-bold border border-amber-500/20">
                  {totalCount} Found
                </span>
                {isLiveOrRepo && criticalCount > 0 && (
                  <span className="bg-red-500/10 text-red-400 px-2.5 py-1 rounded text-xs font-bold border border-red-500/20">
                    {criticalCount} Critical
                  </span>
                )}
                {isLiveOrRepo && highCount > 0 && (
                  <span className="bg-orange-500/10 text-orange-400 px-2.5 py-1 rounded text-xs font-bold border border-orange-500/20">
                    {highCount} High
                  </span>
                )}
              </div>
            </div>

            {/* ── Finding Cards ── */}
            <div className="space-y-4">
              {isLiveOrRepo
                ? findings.map((f, i) => <FindingCard key={i} finding={f} />)
                : staticVulns.map((v) => (
                    <VulnerabilityCard key={v.id} vuln={v} patchedCode={result.patchedCode} />
                  ))
              }
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
