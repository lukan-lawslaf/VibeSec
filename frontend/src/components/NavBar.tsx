import { Link } from 'react-router-dom'
import { cn } from '@/lib/utils'

export function NavBar() {
  return (
    <div className="fixed top-0 inset-x-0 z-50 py-6 px-8 flex justify-between items-center max-w-7xl mx-auto">
      {/* Mix blend difference or glassmorphic for better contrast */}
      <Link to="/" className="text-3xl tracking-tight font-display text-foreground z-10 flex items-center gap-2">
        <img src="/logo.svg" alt="VibeSec Logo" className="w-8 h-8 rounded-[10px]" />
        VibeSec
      </Link>
      
      <nav className="hidden md:flex gap-8 z-10 bg-background/5 backdrop-blur-md px-6 py-2 rounded-full border border-white/10 shadow-lg">
        <a href="#how-it-works" className="text-sm text-muted-foreground transition-colors hover:text-foreground">How it works</a>
        <a href="#features" className="text-sm text-muted-foreground transition-colors hover:text-foreground">Features</a>
        <a href="#about" className="text-sm text-muted-foreground transition-colors hover:text-foreground">About</a>
      </nav>

      <div className="z-10 flex gap-4">
        <Link 
          to="/auth" 
          className="inline-flex items-center justify-center rounded-full px-4 py-2 text-sm text-foreground hover:text-accent transition-colors cursor-pointer"
        >
          Sign in
        </Link>
        <Link 
          to="/auth" 
          className={cn(
            "inline-flex items-center justify-center rounded-full px-6 py-2.5 text-sm text-foreground",
            "liquid-glass hover:scale-[1.03] transition-transform cursor-pointer"
          )}
        >
          Get started
        </Link>
      </div>
    </div>
  )
}
