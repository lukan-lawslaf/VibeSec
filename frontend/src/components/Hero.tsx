import { Link } from 'react-router-dom'
import { cn } from '@/lib/utils'
import FuzzyText from './FuzzyText'

export function Hero() {
  return (
    <section className="relative w-full h-screen flex flex-col items-center justify-center text-center px-6 pt-32 pb-40 overflow-hidden">
      {/* Video Background */}
      <video 
        autoPlay 
        loop 
        muted 
        playsInline 
        className="absolute inset-0 w-full h-full object-cover z-0"
        src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260314_131748_f2ca2a28-fed7-44c8-b9a9-bd9acdd5ec31.mp4"
      />
      
      {/* Overlay to ensure text readability if needed (optional) */}
      <div className="absolute inset-0 bg-background/30 mix-blend-multiply z-[1]"></div>
      <div className="absolute inset-0 bg-gradient-to-t from-background via-transparent to-transparent z-[2]"></div>

      {/* Content */}
      <div className="relative z-10 flex flex-col items-center max-w-7xl mx-auto">
        <p className="font-mono text-[12px] tracking-[0.08em] uppercase text-accent mb-6 animate-fade-rise">AI Security Audit Pipeline</p>
        <h1 className="text-5xl sm:text-7xl md:text-8xl leading-[0.95] tracking-[-2.46px] max-w-5xl font-normal font-display animate-fade-rise text-white">
          Your <em className="not-italic text-accent">vibe-coded app</em> has <em className="not-italic text-white font-semibold inline-block transform translate-y-2 lg:translate-y-4">
            <FuzzyText baseIntensity={0.15} hoverIntensity={0.4} enableHover={true} fontSize="clamp(3rem, 8vw, 6rem)" color="#fff">
              vulnerabilities
            </FuzzyText>
          </em>. We find them. We <em className="not-italic text-white font-semibold">fix</em> them.
        </h1>
        
        <p className="text-muted-foreground text-base sm:text-lg max-w-2xl mt-8 leading-relaxed animate-fade-rise-delay">
          VibeSec uses specialized AI to automatically audit your code, detect security vulnerabilities, and generate patched versions in seconds.
        </p>

        <div className="mt-12 flex items-center gap-4 animate-fade-rise-delay-2">
          <Link 
            to="/auth" 
            className={cn(
              "inline-flex items-center justify-center rounded-full px-10 py-4 text-base text-background font-medium",
              "bg-accent hover:bg-white transition-colors cursor-pointer shadow-2xl"
            )}
          >
            Start Free Scan
          </Link>
          <a 
            href="#how-it-works" 
            className={cn(
              "inline-flex items-center justify-center rounded-full px-8 py-4 text-base text-foreground font-medium",
              "liquid-glass hover:scale-[1.03] transition-transform cursor-pointer shadow-2xl"
            )}
          >
            See how it works
          </a>
        </div>
      </div>
    </section>
  )
}
