import { useState, useCallback, useRef } from 'react';
import { LeftPanel, type ScanMode } from '@/components/dashboard/LeftPanel';
import { RightPanel, type ScanResult } from '@/components/dashboard/RightPanel';

const API_BASE = '/api/v1/scan';

export type LogType = 'info' | 'phase' | 'success' | 'warn' | 'thinking' | 'error' | 'personality';

export interface LogEntry {
  timestamp: string;
  message: string;
  type: LogType;
}

// ── Fun thinking messages that fire while the API is working ──────────────

const CODE_THINKING: { delay: number; msg: string; type: LogType }[] = [
  { delay: 0,     msg: '🧠 Warming up neural pathways...',                                       type: 'thinking' },
  { delay: 800,   msg: '📝 Ingesting your code... every semicolon matters.',                     type: 'phase' },
  { delay: 2200,  msg: '🌳 Building Abstract Syntax Tree...',                                    type: 'info' },
  { delay: 4000,  msg: '↳ Functions, imports, call graph — mapping the terrain.',                 type: 'personality' },
  { delay: 6500,  msg: '🔎 Indexing into RAG vector store for pattern matching...',               type: 'info' },
  { delay: 9000,  msg: '↳ Cross-referencing against known vuln patterns.',                        type: 'personality' },
  { delay: 12000, msg: '🤖 DeepHat agent activated — hunting vulnerabilities...',                 type: 'phase' },
  { delay: 15000, msg: '↳ "Hmm, this looks suspicious..." — DeepHat',                            type: 'personality' },
  { delay: 20000, msg: '🩹 Spinning up patch generation engine...',                               type: 'phase' },
  { delay: 25000, msg: '↳ Writing fixed code... elegantly.',                                      type: 'personality' },
  { delay: 30000, msg: '⏳ Still working — complex code takes a moment...',                       type: 'thinking' },
  { delay: 40000, msg: '↳ Almost there. Validating AST integrity of patches...',                  type: 'thinking' },
];

const LIVE_THINKING: { delay: number; msg: string; type: LogType }[] = [
  { delay: 0,     msg: '🌐 Resolving target...',                                                  type: 'phase' },
  { delay: 1000,  msg: '↳ Hello, is it me you\'re looking for?',                                  type: 'personality' },
  { delay: 2500,  msg: '🔓 Phase 1: nmap fast port discovery...',                                 type: 'phase' },
  { delay: 4000,  msg: '↳ nmap goes brrr — scanning all 65,535 ports.',                           type: 'personality' },
  { delay: 8000,  msg: '↳ Interesting ports found. Zooming in...',                                type: 'info' },
  { delay: 12000, msg: '🍪 Phase 2: HTTP application probe...',                                   type: 'phase' },
  { delay: 14000, msg: '↳ Inspecting cookies... nom nom (checking HttpOnly, SameSite).',          type: 'personality' },
  { delay: 17000, msg: '↳ Checking security headers... CSP, HSTS, X-Frame-Options...',            type: 'info' },
  { delay: 20000, msg: '↳ Snooping for exposed paths — /.env, /debug, /admin...',                 type: 'info' },
  { delay: 25000, msg: '🤖 Phase 3: Groq AI triage engaged...',                                   type: 'phase' },
  { delay: 28000, msg: '↳ "Let me sort the chaos into actionable intel." — Groq',                 type: 'personality' },
  { delay: 35000, msg: '⏳ Nmap doing a deep probe... patience, young padawan.',                   type: 'thinking' },
  { delay: 50000, msg: '↳ Network scans take time. Real evidence > fast guesses.',                 type: 'thinking' },
];

const REPO_THINKING: { delay: number; msg: string; type: LogType }[] = [
  { delay: 0,     msg: '📦 git clone --depth=1 ... pulling the repo.',                            type: 'phase' },
  { delay: 2000,  msg: '↳ Repository cloned. Let\'s see what you\'ve got.',                       type: 'personality' },
  { delay: 3500,  msg: '🔑 Phase 1: Shaking the code tree for secrets...',                        type: 'phase' },
  { delay: 5000,  msg: '↳ API keys, .env files, hardcoded passwords... 👀',                       type: 'personality' },
  { delay: 7000,  msg: '🌳 Phase 2: Walking the AST for dangerous patterns...',                   type: 'phase' },
  { delay: 9000,  msg: '↳ eval() ... I see you. 👁️',                                              type: 'personality' },
  { delay: 11000, msg: '↳ SQL injection, exec(), pickle.loads() — the usual suspects.',            type: 'info' },
  { delay: 13000, msg: '📋 Phase 3: Querying OSV.dev for real CVEs...',                            type: 'phase' },
  { delay: 15000, msg: '↳ Checking your requirements.txt against Google\'s vuln database.',        type: 'info' },
  { delay: 18000, msg: '🗺️ Phase 4: Reachability analysis...',                                     type: 'phase' },
  { delay: 20000, msg: '↳ "Is this vuln reachable from a public route? Let me check..." — VibeSec', type: 'personality' },
  { delay: 23000, msg: '↳ Mapping HTTP routes → auth decorators → vulnerable sinks.',              type: 'info' },
  { delay: 26000, msg: '🤖 Phase 5: Groq AI triage...',                                            type: 'phase' },
  { delay: 28000, msg: '↳ "Fix these 3 today. Ignore those 50." — the whole point.',               type: 'personality' },
  { delay: 35000, msg: '⏳ Groq is reasoning through the findings...',                              type: 'thinking' },
];

export function Dashboard() {
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const startTimeRef = useRef(0);
  const thinkingTimers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const addLog = useCallback((msg: string, type: LogType = 'info') => {
    const elapsed = Math.floor((Date.now() - startTimeRef.current) / 1000);
    setLogs(prev => [...prev, { timestamp: `T+${elapsed}s`, message: msg, type }]);
  }, []);

  const clearThinkingTimers = useCallback(() => {
    thinkingTimers.current.forEach(t => clearTimeout(t));
    thinkingTimers.current = [];
  }, []);

  const startThinkingSequence = useCallback((sequence: typeof CODE_THINKING) => {
    clearThinkingTimers();
    sequence.forEach(({ delay, msg, type }) => {
      const timer = setTimeout(() => {
        addLog(msg, type);
      }, delay);
      thinkingTimers.current.push(timer);
    });
  }, [addLog, clearThinkingTimers]);

  const startScan = useCallback(async (mode: ScanMode, input: string) => {
    setIsScanning(true);
    setLogs([]);
    setResult(null);
    startTimeRef.current = Date.now();

    // Start the thinking sequence immediately
    if (mode === 'code') startThinkingSequence(CODE_THINKING);
    else if (mode === 'url') startThinkingSequence(LIVE_THINKING);
    else if (mode === 'repo') startThinkingSequence(REPO_THINKING);

    try {
      if (mode === 'code') {
        const res = await fetch(`${API_BASE}/static`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: input }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: res.statusText }));
          throw new Error(err.detail || 'Static scan failed');
        }
        const data = await res.json();
        clearThinkingTimers();
        addLog(`✅ ${data.vulnerabilities?.length || 0} vulnerabilities found.`, 'success');
        if (data.patched_code) addLog('✅ Patched code generated.', 'success');
        addLog('🏁 Scan complete. Your code just got a security glow-up.', 'success');

        const diffLines = (data.diff || '').split('\n');
        const oldLines: string[] = [];
        const newLines: string[] = [];
        for (const line of diffLines) {
          if (line.startsWith('-') && !line.startsWith('---')) oldLines.push(line.slice(1));
          else if (line.startsWith('+') && !line.startsWith('+++')) newLines.push(line.slice(1));
        }
        setResult({
          mode: 'code', target: 'code snippet',
          patchedCode: data.patched_code || undefined, diff: data.diff || undefined,
          staticVulns: (data.vulnerabilities || []).map((v: any, i: number) => ({
            id: `vuln-${i}`, severity: (v.severity || 'medium').toUpperCase(),
            title: v.type || 'Vulnerability', description: v.description || '',
            file: 'input', line: v.line || 0, cwe: '0',
            diff: { old: oldLines, new: newLines },
          })),
        });

      } else if (mode === 'url') {
        const res = await fetch(`${API_BASE}/live`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: input }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: res.statusText }));
          throw new Error(err.detail || 'Live scan failed');
        }
        const data = await res.json();
        clearThinkingTimers();
        addLog(`✅ ${data.findings?.length || 0} findings triaged.`, 'success');
        addLog(`🔴 ${data.fix_today?.length || 0} need immediate attention.`, data.fix_today?.length > 0 ? 'warn' : 'success');
        addLog('🏁 Live scan complete.', 'success');
        setResult({
          mode: 'url', target: input,
          findings: data.findings || [], fixToday: data.fix_today || [], summary: data.summary || '',
        });

      } else if (mode === 'repo') {
        const res = await fetch(`${API_BASE}/repo`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ github_url: input }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: res.statusText }));
          throw new Error(err.detail || 'Repo scan failed');
        }
        const data = await res.json();
        clearThinkingTimers();
        addLog(`✅ ${data.findings?.length || 0} findings across all phases.`, 'success');
        addLog(`🔴 ${data.fix_today?.length || 0} need immediate attention.`, data.fix_today?.length > 0 ? 'warn' : 'success');
        addLog('🏁 Repository scan complete. Cleanup done.', 'success');
        setResult({
          mode: 'repo', target: input,
          findings: data.findings || [], fixToday: data.fix_today || [], summary: data.summary || '',
        });
      }

    } catch (err: any) {
      clearThinkingTimers();
      addLog(`💀 ${err.message}`, 'error');
    } finally {
      setIsScanning(false);
    }
  }, [addLog, startThinkingSequence, clearThinkingTimers]);

  return (
    <div className="flex h-screen w-full bg-[#050A15] text-foreground font-sans">
      <div className="w-[40%] min-w-[400px] h-full overflow-y-auto relative z-10 shadow-[10px_0_30px_rgba(0,0,0,0.5)] border-r border-amber-900/20">
        <LeftPanel isScanning={isScanning} onStartScan={startScan} logs={logs} />
      </div>
      <div className="w-[60%] h-full overflow-hidden">
        <RightPanel isScanning={isScanning} result={result} />
      </div>
    </div>
  );
}
