export function Proof() {
  return (
    <section id="about" className="w-full bg-[#0f0c08] py-24 px-6 border-t border-white/5">
      <div className="max-w-7xl mx-auto flex flex-col gap-16">
        
        <div className="flex flex-col md:flex-row justify-between items-end gap-8">
          <div className="max-w-[34ch] flex flex-col gap-4">
            <p className="font-mono text-xs tracking-wider uppercase text-accent">Proof</p>
            <h2 className="text-4xl md:text-5xl font-display leading-[1.1]">Security claims grounded in what the product actually does.</h2>
          </div>
          <p className="font-mono text-sm text-muted-foreground max-w-[28ch]">
            Built for teams who want a fix path, not just another alert.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8">
          <div className="pt-6 border-t border-white/20 flex flex-col gap-3">
            <div className="text-6xl md:text-8xl font-display font-semibold tracking-tighter">OWASP</div>
            <p className="text-sm text-muted-foreground max-w-[22ch]">Top 10 covered across the scan pipeline.</p>
          </div>
          <div className="pt-6 border-t border-white/20 flex flex-col gap-3">
            <div className="text-6xl md:text-8xl font-display font-semibold tracking-tighter">2</div>
            <p className="text-sm text-muted-foreground max-w-[22ch]">specialized AI models working on detection and patch generation.</p>
          </div>
          <div className="pt-6 border-t border-white/20 flex flex-col gap-3">
            <div className="text-6xl md:text-8xl font-display font-semibold tracking-tighter">0</div>
            <p className="text-sm text-muted-foreground max-w-[22ch]">security expertise required to understand the output and act on it.</p>
          </div>
        </div>

      </div>
    </section>
  )
}
