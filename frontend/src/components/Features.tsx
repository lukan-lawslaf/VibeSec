export function Features() {
  const features = [
    {
      num: "01",
      title: "Dual-mode scanning",
      desc: "Scan static code when you have the source. Scan live URLs when you need to validate the running surface.",
      colorClass: "bg-gradient-to-br from-pink-500/10 from-20% to-sky-400/10 to-80% border-white/10"
    },
    {
      num: "02",
      title: "Security-trained AI",
      desc: "Built for vulnerability discovery and remediation, not a generic model stretched into security work.",
      colorClass: "bg-gradient-to-br from-pink-500/10 from-20% to-sky-400/10 to-80% border-white/10"
    },
    {
      num: "03",
      title: "Instant patches",
      desc: "VibeSec moves beyond detection and proposes an actual fix path, reducing the gap between finding and shipping.",
      colorClass: "bg-gradient-to-br from-pink-500/10 from-20% to-sky-400/10 to-80% border-white/10"
    },
    {
      num: "04",
      title: "Full diff output",
      desc: "Teams can see exactly what changed and why, which keeps trust high during review and merge.",
      colorClass: "bg-gradient-to-br from-pink-500/10 from-20% to-sky-400/10 to-80% border-white/10"
    }
  ]

  return (
    <section id="features" className="w-full bg-background py-24 px-6 border-t border-white/5">
      <div className="max-w-7xl mx-auto grid lg:grid-cols-[0.82fr_1.18fr] gap-16 lg:gap-24 items-start">
        
        <div className="lg:sticky lg:top-32 flex flex-col gap-6">
          <p className="font-mono text-xs tracking-wider uppercase text-accent">Why VibeSec</p>
          <h2 className="text-4xl md:text-5xl font-display leading-[1.1]">
            The <span className="font-semibold text-white/90">security tool</span> that <span className="font-semibold text-white/90">developers</span> can use without changing how they ship.
          </h2>
          <p className="text-lg text-muted-foreground mt-4">
            Every feature is built to keep remediation close to the code, so teams can move from finding a flaw to reviewing a patch in one flow.
          </p>
          <div className="mt-8 pl-5 border-l border-white/20 text-muted-foreground/80 max-w-[30ch]">
            <p>Code in, issue found, patch out, reviewable diff attached. The product earns trust by showing its work.</p>
          </div>
        </div>

        <div className="grid sm:grid-cols-2 gap-8">
          {features.map((feature, i) => (
            <article key={i} className={`min-h-[250px] p-8 border rounded-3xl transition-colors shadow-lg flex flex-col ${feature.colorClass} hover:opacity-80`}>
              <span className="font-mono text-sm text-muted-foreground mb-6">{feature.num}</span>
              <h3 className="text-xl font-semibold mb-3">{feature.title}</h3>
              <p className="text-muted-foreground leading-relaxed">{feature.desc}</p>
            </article>
          ))}
        </div>

      </div>
    </section>
  )
}
