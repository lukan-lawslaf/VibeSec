import { useState, useEffect, useRef, useCallback } from 'react';
import { cn } from '@/lib/utils';
import { Link } from 'react-router-dom';
import DarkVeil from './DarkVeil';

export type ScanMode = 'code' | 'url' | 'repo';

interface LeftPanelProps {
  isScanning: boolean;
  onStartScan: (mode: ScanMode, input: string) => void;
  logs: { timestamp: string; message: string }[];
}

export function LeftPanel({ isScanning, onStartScan, logs }: LeftPanelProps) {
  const [activeTab, setActiveTab] = useState<ScanMode>('code');
  const [codeInput, setCodeInput] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [repoInput, setRepoInput] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [droppedFileName, setDroppedFileName] = useState('');
  const logsEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const handleScan = () => {
    const inputMap = { code: codeInput, url: urlInput, repo: repoInput };
    const input = inputMap[activeTab];
    if (!input.trim()) return;
    onStartScan(activeTab, input.trim());
  };

  // ── File handling (drag/drop + click) ──────────────────────────────────────

  const readFile = useCallback((file: File) => {
    const validExts = ['.py', '.js', '.ts', '.go', '.php', '.rb', '.java', '.c', '.cpp', '.rs', '.jsx', '.tsx', '.vue', '.svelte'];
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!validExts.includes(ext)) {
      alert(`Unsupported file type: ${ext}\nSupported: ${validExts.join(', ')}`);
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      setCodeInput(text);
      setDroppedFileName(file.name);
    };
    reader.readAsText(file);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) readFile(file);
  }, [readFile]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleFileClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) readFile(file);
    // Reset so the same file can be selected again
    e.target.value = '';
  };

  // ── Tab config ─────────────────────────────────────────────────────────────

  const tabConfig = [
    {
      id: 'code' as ScanMode,
      label: 'CODE',
      icon: (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
        </svg>
      ),
    },
    {
      id: 'url' as ScanMode,
      label: 'LIVE URL',
      icon: (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
      ),
    },
    {
      id: 'repo' as ScanMode,
      label: 'GITHUB',
      icon: (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
        </svg>
      ),
    },
  ];

  return (
    <div className="min-h-full flex flex-col p-8 relative overflow-hidden bg-[#0A0710]">
      {/* Background DarkVeil Effect */}
      <div className="absolute inset-0 z-0 pointer-events-none opacity-100 mix-blend-screen">
        <DarkVeil hueShift={210} speed={0.4} noiseIntensity={0.15} warpAmount={0.8} resolutionScale={1} />
      </div>

      {/* Brand Header */}
      <div className="flex items-center gap-3 mb-10 relative z-10">
        <Link to="/" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
          <img src="/logo.svg" alt="VibeSec Logo" className="w-7 h-7 rounded-[8px]" />
          <span className="text-xl font-display text-foreground tracking-tight">VibeSec</span>
        </Link>
        <div className="h-4 w-px bg-white/10 mx-2"></div>
        <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest mt-1">Audit Station</span>
      </div>

      {/* Tabs — 3 tabs */}
      <div className="flex rounded-md border border-white/10 mb-8 shrink-0 overflow-hidden bg-[#120D26] relative z-10">
        {tabConfig.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'flex-1 text-sm font-medium py-2 transition-all flex items-center justify-center gap-2',
              activeTab === tab.id
                ? 'bg-[#6d28d9] text-white shadow-[0_0_20px_rgba(109,40,217,0.6)] relative z-10 rounded-md'
                : 'text-muted-foreground hover:text-foreground hover:bg-white/5 border border-transparent'
            )}
          >
            {tab.label} {tab.icon}
          </button>
        ))}
      </div>

      {/* Input areas */}
      <div className="flex-1 min-h-[250px] mb-8 flex flex-col relative z-10">
        {activeTab === 'code' && (
          <div className="flex-1 flex flex-col gap-4">
            <div className="flex-1 relative border border-white/5 rounded-lg bg-[#03060C] overflow-hidden focus-within:border-amber-500/50 transition-colors">
              <div className="absolute left-0 top-0 bottom-0 w-10 bg-[#0A0A0F] border-r border-white/5 flex flex-col items-center py-3 text-[#4A4A5A] font-mono text-xs select-none">
                {Array.from({ length: Math.max(7, codeInput.split('\n').length) }, (_, i) => (
                  <div key={i}>{i + 1}</div>
                ))}
              </div>
              <textarea
                value={codeInput}
                onChange={(e) => { setCodeInput(e.target.value); setDroppedFileName(''); }}
                className="w-full h-full bg-transparent text-sm font-mono text-foreground/90 p-3 pl-14 outline-none resize-none placeholder:text-[#4A4A5A]"
                placeholder="// Paste vulnerable code here..."
              ></textarea>
            </div>

            {/* ── Drag & Drop Zone ── */}
            <input
              ref={fileInputRef}
              type="file"
              accept=".py,.js,.ts,.go,.php,.rb,.java,.c,.cpp,.rs,.jsx,.tsx,.vue,.svelte"
              className="hidden"
              onChange={handleFileSelect}
            />
            <div
              onClick={handleFileClick}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              className={cn(
                "border-2 border-dotted rounded-lg p-6 flex flex-col items-center justify-center text-center transition-all cursor-pointer shrink-0",
                isDragging
                  ? "border-amber-500 bg-amber-500/10 scale-[1.02]"
                  : "border-white/20 bg-black/40 hover:bg-black/20 hover:border-white/30"
              )}
            >
              {droppedFileName ? (
                <>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-emerald-400 mb-2">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  <span className="text-sm text-emerald-400 font-mono">{droppedFileName}</span>
                  <span className="text-[10px] text-muted-foreground mt-1">File loaded — click to replace</span>
                </>
              ) : (
                <>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-muted-foreground mb-2">
                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" />
                    <line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                  <span className="text-sm text-muted-foreground mb-3">Drag and drop a file or click to browse</span>
                  <div className="flex gap-2">
                    {['.py', '.js', '.go', '.php', '.ts', '.java'].map(ext => (
                      <span key={ext} className="text-[10px] font-mono bg-[#0A111B] border border-white/5 text-muted-foreground px-2 py-0.5 rounded">{ext}</span>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {activeTab === 'url' && (
          <div className="flex-1">
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-muted-foreground mr-2">
                  <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
                  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                </svg>
              </div>
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="w-full bg-[#0A111B] border border-white/5 text-foreground text-sm rounded-lg focus:ring-amber-500 focus:border-amber-500 block pl-10 p-3 outline-none transition-colors"
                placeholder="http://example.com"
              />
            </div>
            <p className="text-xs text-muted-foreground mt-3 leading-relaxed">
              Scans the live endpoint with <span className="text-purple-400">nmap</span> + <span className="text-purple-400">HTTP probe</span> for missing headers, insecure cookies, exposed paths, CORS issues, and known CVEs.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              {['Missing Headers', 'Insecure Cookies', 'CORS', 'Version Leak', 'Debug Mode', 'Exposed Paths'].map(tag => (
                <span key={tag} className="text-[10px] font-mono bg-purple-500/10 border border-purple-500/20 text-purple-300 px-2 py-0.5 rounded">{tag}</span>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'repo' && (
          <div className="flex-1">
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" className="text-muted-foreground mr-2">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
              </div>
              <input
                type="text"
                value={repoInput}
                onChange={(e) => setRepoInput(e.target.value)}
                className="w-full bg-[#0A111B] border border-white/5 text-foreground text-sm rounded-lg focus:ring-amber-500 focus:border-amber-500 block pl-10 p-3 outline-none transition-colors"
                placeholder="https://github.com/user/repo"
              />
            </div>
            <p className="text-xs text-muted-foreground mt-3 leading-relaxed">
              Clones the repo and runs <span className="text-emerald-400">5-phase deep analysis</span>: secrets detection, AST code patterns, OSV.dev CVE lookup, reachability tracing, and AI triage.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              {['Hardcoded Secrets', 'SQL Injection', 'eval/exec', 'CVE Deps', 'Auth Bypass', 'Reachability'].map(tag => (
                <span key={tag} className="text-[10px] font-mono bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded">{tag}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Controls */}
      <div className="space-y-4 shrink-0 relative z-10">
        <button
          onClick={handleScan}
          disabled={isScanning}
          className={cn(
            "w-full py-3.5 rounded-lg text-white font-medium transition-all duration-300 relative overflow-hidden",
            isScanning
              ? "bg-[#6d28d9]/50 cursor-not-allowed"
              : "bg-[#6d28d9] hover:bg-[#5b21b6] hover:shadow-[0_0_20px_rgba(109,40,217,0.6)] border border-[#5b21b6]"
          )}
        >
          {isScanning ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Scanning...
            </span>
          ) : (
            activeTab === 'code' ? 'Analyse Code' : activeTab === 'url' ? 'Scan Live URL' : 'Scan Repository'
          )}
        </button>
      </div>

      {/* Agent Logs */}
      <div className="mt-8 border border-white/5 bg-[#03060C] rounded-lg h-[220px] flex flex-col shrink-0 overflow-hidden relative z-10">
        <div className="bg-[#0A111B] border-b border-white/5 px-4 py-2 flex items-center justify-between z-10">
          <span className="text-[10px] font-mono text-muted-foreground tracking-widest uppercase">Agent Execution Log</span>
          <div className="flex gap-1.5">
            <div className="w-2 h-2 rounded-full bg-red-500/50"></div>
            <div className="w-2 h-2 rounded-full bg-yellow-500/50"></div>
            <div className="w-2 h-2 rounded-full bg-green-500/50"></div>
          </div>
        </div>
        <div className="p-4 overflow-y-auto font-mono text-xs flex-1 space-y-2 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
          {logs.map((log, i) => (
            <div key={i} className="animate-in fade-in slide-in-from-bottom-2 duration-300">
              <span className="text-[#4ADE80] mr-3">[{log.timestamp}]</span>
              <span className="text-white/80">{log.message}</span>
            </div>
          ))}
          {isScanning && (
            <div className="flex items-center text-white/50 animate-pulse mt-2">
              <span className="w-2 h-4 bg-white/50 ml-1 block"></span>
            </div>
          )}
          <div ref={logsEndRef} />
        </div>
      </div>
    </div>
  );
}
