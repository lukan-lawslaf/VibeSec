import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { supabase } from '@/lib/supabase'

export function Auth() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  const navigate = useNavigate()

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    
    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    })

    if (error) {
      setError(error.message)
    } else {
      navigate('/app')
    }
    setLoading(false)
  }

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    
    const { error } = await supabase.auth.signUp({
      email,
      password,
    })

    if (error) {
      setError(error.message)
    } else {
      setError('Check your email for the confirmation link!')
    }
    setLoading(false)
  }

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-6 relative overflow-hidden">
      <div className="absolute inset-0 bg-background z-0">
         {/* Subtle background glow or texture if needed */}
         <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-primary/5 blur-[120px] rounded-full pointer-events-none"></div>
      </div>
      
      <div className="z-10 w-full max-w-md">
        <div className="text-center mb-8 animate-fade-rise">
          <Link to="/" className="text-4xl tracking-tight font-display text-foreground flex items-center justify-center mb-2 gap-3">
            <span className="w-10 h-10 rounded-[12px] border border-white/20 flex items-center justify-center font-mono text-sm bg-accent/20">VS</span>
            VibeSec
          </Link>
          <p className="text-muted-foreground">Sign in to continue your journey.</p>
        </div>

        <div className="bg-background/40 backdrop-blur-xl border border-white/10 p-8 rounded-[24px] shadow-2xl animate-fade-rise-delay liquid-glass">
          <form className="flex flex-col gap-5">
            <div className="flex flex-col gap-2">
              <label className="text-sm text-muted-foreground ml-1">Email</label>
              <input 
                type="email" 
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-white/30 transition-colors"
                placeholder="you@example.com"
                required
              />
            </div>
            
            <div className="flex flex-col gap-2">
              <label className="text-sm text-muted-foreground ml-1">Password</label>
              <input 
                type="password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-white/30 transition-colors"
                placeholder="••••••••"
                required
              />
            </div>

            {error && (
              <div className="text-red-400 text-sm mt-1 p-3 bg-red-400/10 rounded-lg border border-red-400/20">
                {error}
              </div>
            )}

            <div className="flex flex-col gap-3 mt-4">
              <button 
                onClick={handleSignIn}
                disabled={loading}
                className="w-full liquid-glass bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl px-4 py-3 text-foreground font-medium transition-colors disabled:opacity-50"
              >
                {loading ? 'Processing...' : 'Sign In'}
              </button>
              
              <div className="relative flex items-center py-2">
                <div className="flex-grow border-t border-white/10"></div>
                <span className="flex-shrink-0 mx-4 text-muted-foreground text-xs uppercase tracking-wider">or</span>
                <div className="flex-grow border-t border-white/10"></div>
              </div>

              <button 
                onClick={handleSignUp}
                disabled={loading}
                className="w-full bg-transparent hover:bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-muted-foreground hover:text-foreground font-medium transition-colors disabled:opacity-50"
              >
                Create Account
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
