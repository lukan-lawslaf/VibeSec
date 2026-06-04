export function HowItWorks() {
  return (
    <section id="how-it-works" className="w-full bg-background py-24 px-6 border-t border-white/5">
      <div className="max-w-7xl mx-auto grid lg:grid-cols-[0.8fr_1.2fr] gap-16 lg:gap-24 items-start">
        
        <div className="lg:sticky lg:top-32 flex flex-col gap-8">
          <div className="max-w-md">
            <p className="font-mono text-xs tracking-wider uppercase text-accent mb-4">How it works</p>
            <h2 className="text-4xl md:text-5xl font-display leading-[1.1]">Three clear steps between vulnerable code and a safer release.</h2>
          </div>
          <p className="text-lg text-muted-foreground leading-relaxed">
            VibeSec keeps the workflow legible: intake first, DeepHat + CAI analysis second, then fix-agent patch review with AST and RAG guardrails before merge.
          </p>
          <div className="pl-5 border-l border-white/20 text-muted-foreground/80 max-w-sm">
            <p>Every run keeps the evidence visible so teams can trace the finding, inspect the agent-selected patch, and review the exact code change before release.</p>
          </div>
        </div>

        <div className="relative p-8 border border-white/10 rounded-[32px] bg-white/[0.02] shadow-2xl overflow-hidden liquid-glass">
          {/* Decorative screws/dots */}
          <div className="absolute inset-4 pointer-events-none">
            <span className="absolute top-0 left-0 w-4 h-4 rounded-full border border-white/20 bg-background flex items-center justify-center"><span className="w-1.5 h-px bg-white/40"></span><span className="w-px h-1.5 bg-white/40 absolute"></span></span>
            <span className="absolute top-0 right-0 w-4 h-4 rounded-full border border-white/20 bg-background flex items-center justify-center"><span className="w-1.5 h-px bg-white/40"></span><span className="w-px h-1.5 bg-white/40 absolute"></span></span>
            <span className="absolute bottom-0 left-0 w-4 h-4 rounded-full border border-white/20 bg-background flex items-center justify-center"><span className="w-1.5 h-px bg-white/40"></span><span className="w-px h-1.5 bg-white/40 absolute"></span></span>
            <span className="absolute bottom-0 right-0 w-4 h-4 rounded-full border border-white/20 bg-background flex items-center justify-center"><span className="w-1.5 h-px bg-white/40"></span><span className="w-px h-1.5 bg-white/40 absolute"></span></span>
          </div>

          <div className="relative z-10 grid sm:grid-cols-[1fr_240px] gap-8 items-start mt-6">
            <div className="relative flex flex-col gap-6">
              {/* Connecting line */}
              <div className="absolute left-[22px] top-6 bottom-6 w-px bg-white/10 z-0"></div>

              {[
                {
                  num: "01",
                  title: "Upload your code or paste a URL",
                  desc: "Bring in a repository snapshot or point VibeSec at a live surface when you need URL-based scanning.",
                  meta: "Code files and live routes share the same intake so product teams do not need separate workflows."
                },
                {
                  num: "02",
                  title: "DeepHat + CAI map the vulnerable flow",
                  desc: "DeepHat works with your CAI framework to inspect the code path, surface likely vulnerabilities, and isolate the risky business flow before remediation starts.",
                  meta: "The detection layer is purpose-built for reviewable findings, not broad assistant-style guesses or generic code commentary."
                },
                {
                  num: "03",
                  title: "Fix agents patch without breaking logic",
                  desc: "DeepSeek and Qwen source-code agents generate the fix, while AST-aware checks and RAG context help preserve your business logic before the patch is proposed.",
                  meta: "Before-and-after changes stay legible so engineering leads can validate the remediation path, not just accept a blind rewrite."
                }
              ].map((step, i) => (
                <article key={i} className="relative z-10 p-6 pl-16 border border-white/10 rounded-3xl bg-background shadow-xl">
                  <div className="absolute left-[17px] top-7 w-3 h-3 rounded-full bg-accent ring-4 ring-background"></div>
                  <div className="flex flex-col h-full justify-between">
                    <div>
                      <p className="font-mono text-xs tracking-wider uppercase text-muted-foreground mb-6">{step.num}</p>
                      <h3 className="text-xl font-semibold mb-3">{step.title}</h3>
                      <p className="text-base text-muted-foreground mb-6 max-w-sm">{step.desc}</p>
                    </div>
                    <p className="text-sm font-mono text-muted-foreground/60">{step.meta}</p>
                  </div>
                </article>
              ))}
            </div>

            <div className="flex flex-col gap-4">
              <div className="p-5 border border-white/10 rounded-3xl bg-black/40 shadow-2xl">
                <div className="flex justify-between items-center gap-3 mb-4">
                  <div>
                    <p className="font-mono text-[10px] tracking-wider uppercase text-white/50">Active run</p>
                    <p className="font-semibold text-sm">Session auth remediation</p>
                  </div>
                  <span className="px-2 py-1 bg-accent/20 text-accent rounded-full font-mono text-[10px] uppercase tracking-wider">Fix validated</span>
                </div>
                <div className="flex flex-col gap-3">
                  <div className="p-3 border border-white/10 rounded-2xl bg-white/5">
                    <p className="font-mono text-[10px] text-white/60">Source</p>
                    <p className="mt-1 text-xs text-white/80">GitHub repo upload + live URL check</p>
                  </div>
                  <div className="p-3 border border-white/10 rounded-2xl bg-white/5 flex flex-col gap-2">
                    <div className="flex justify-between font-mono text-[10px] text-white/60">
                      <span>Intake normalized</span><span>00:02</span>
                    </div>
                    <div className="flex justify-between font-mono text-[10px] text-white/60">
                      <span>DeepHat + CAI mapped</span><span>00:06</span>
                    </div>
                    <div className="flex justify-between font-mono text-[10px] text-white/60">
                      <span>Fix agents drafted patch</span><span>00:09</span>
                    </div>
                    <div className="flex justify-between font-mono text-[10px] text-white/60">
                      <span>AST + RAG confirmed</span><span>00:11</span>
                    </div>
                  </div>
                </div>
              </div>
              <div className="p-4 border border-white/10 rounded-3xl bg-white/5">
                <p className="font-mono text-[10px] text-white/60">Review output</p>
                <p className="mt-2 text-xs text-white/80">See the risky path, the selected fix-agent output, and the final diff with logic-preserving safeguards before merge.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
