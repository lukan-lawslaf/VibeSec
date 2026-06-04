import { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Landing } from '@/pages/Landing'
import { Auth } from '@/pages/Auth'
import { Dashboard } from '@/pages/Dashboard'
import { supabase } from '@/lib/supabase'
import { type Session } from '@supabase/supabase-js'

function App() {
  const [session, setSession] = useState<Session | null>(null)

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session)
    })

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session)
    })

    return () => subscription.unsubscribe()
  }, [])

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/auth" element={!session ? <Auth /> : <Navigate to="/app" />} />
        <Route 
          path="/app" 
          element={
            session ? (
              <Dashboard />
            ) : (
              <Navigate to="/auth" />
            )
          } 
        />
      </Routes>
    </BrowserRouter>
  )
}

export default App
