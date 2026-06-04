import { useState, useEffect } from 'react'
import LetterGlitch from './LetterGlitch'

export function LivePatchPreview() {
  const [cycleIndex, setCycleIndex] = useState(0)
  
  useEffect(() => {
    const interval = setInterval(() => {
      setCycleIndex(prev => (prev + 1) % 4)
    }, 1200)
    return () => clearInterval(interval)
  }, [])

  return (
    <section className="w-full bg-background pt-8 pb-24 px-6 relative z-10 flex flex-col items-center">
      <div className="max-w-4xl w-full">
        <div className="relative min-h-[500px] p-6 sm:p-8 border border-white/10 rounded-[32px] bg-background/5 backdrop-blur-xl shadow-2xl overflow-hidden liquid-glass">
          <div className="absolute inset-0 z-0 opacity-20 pointer-events-none mix-blend-screen">
            <LetterGlitch glitchSpeed={100} centerVignette={false} outerVignette={true} smooth={true} />
          </div>
          <div className="absolute top-6 right-8 max-w-[200px] border-t border-white/20 pt-3 text-[13px] text-muted-foreground hidden sm:block text-right z-10">
            Follow the issue from detection to patch generation without leaving the scan flow.
          </div>
          <span className="absolute top-6 left-6 inline-flex items-center px-3 py-1 border border-white/20 rounded-full text-xs text-muted-foreground bg-white/5 z-10">
            Live patch preview
          </span>
          
          <div className="absolute inset-x-4 sm:inset-x-8 md:inset-x-12 top-24 bottom-6 flex flex-col bg-black/60 text-white rounded-[26px] border border-white/10 shadow-2xl overflow-hidden z-10">
            <div className="flex justify-between items-center gap-4 px-6 py-4 border-b border-white/10">
              <div className="flex gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-white/20"></span>
                <span className="w-2.5 h-2.5 rounded-full bg-white/20"></span>
                <span className="w-2.5 h-2.5 rounded-full bg-white/20"></span>
              </div>
              <div className="font-mono text-xs tracking-wider uppercase text-white/50">scan/session-auth.js</div>
            </div>
            
            <div className="flex-1 flex font-mono text-sm overflow-hidden">
              <div className="flex flex-col py-4 text-white/30 bg-white/5 w-12 items-end pr-3 select-none">
                <div>12</div>
                <div className="bg-red-500/20 w-full text-right pr-3 -mr-3">13</div>
                <div className="bg-red-500/20 w-full text-right pr-3 -mr-3">14</div>
                <div>15</div>
                <div className="bg-green-500/20 w-full text-right pr-3 -mr-3">16</div>
                <div className="bg-green-500/20 w-full text-right pr-3 -mr-3">17</div>
                <div>18</div>
              </div>
              
              <div className="flex flex-col py-4 overflow-hidden w-full">
                <div className="px-4 text-white/80">if (!token) return next();</div>
                <div className={`px-4 bg-red-500/10 text-white/70 transition-all duration-300 ${cycleIndex === 0 ? 'translate-x-2' : ''}`}>
                  <span className="text-red-400 mr-2">-</span>const user = jwt.verify(token, process.env.JWT_SECRET);
                </div>
                <div className={`px-4 bg-red-500/10 text-white/70 transition-all duration-300 ${cycleIndex === 1 ? 'translate-x-2' : ''}`}>
                  <span className="text-red-400 mr-2">-</span>req.user = user;
                </div>
                <div className="px-4 text-white/80">const scopes = req.headers["x-vibesec-scope"];</div>
                <div className={`px-4 bg-green-500/10 text-white/90 transition-all duration-300 ${cycleIndex === 2 ? 'translate-x-2' : ''}`}>
                  <span className="text-green-400 mr-2">+</span>const user = await verifySignedToken(token, {"{ audience: 'app' }"});
                </div>
                <div className={`px-4 bg-green-500/10 text-white/90 transition-all duration-300 ${cycleIndex === 3 ? 'translate-x-2' : ''}`}>
                  <span className="text-green-400 mr-2">+</span>req.user = sanitizeSession(user, scopes);
                </div>
                <div className="px-4 text-white/80">return next();</div>
              </div>
            </div>
            
            <div className="flex justify-between items-center gap-4 px-6 py-4 border-t border-white/10 text-white/50 text-[13px]">
              <span className="hidden sm:inline">DeepHat + CAI flagged weak token verification, then DeepSeek and Qwen fix agents generated a constrained patch.</span>
              <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-accent/20 text-accent rounded-full font-mono text-[11px] uppercase tracking-wider whitespace-nowrap">
                Diff output included
              </span>
            </div>
          </div>
          <div className="absolute left-2 bottom-24 w-[140px] -rotate-90 origin-bottom-left font-mono text-xs tracking-wider uppercase text-muted-foreground hidden lg:block">
            Audit -&gt; detect -&gt; patch -&gt; review
          </div>
        </div>
      </div>
    </section>
  )
}
