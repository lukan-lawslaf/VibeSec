import { NavBar } from '@/components/NavBar'
import { Hero } from '@/components/Hero'
import { LivePatchPreview } from '@/components/LivePatchPreview'
import { HowItWorks } from '@/components/HowItWorks'
import { Features } from '@/components/Features'
import { Proof } from '@/components/Proof'
import { Footer } from '@/components/Footer'
import ClickSpark from '@/components/ClickSpark'

export function Landing() {
  return (
    <ClickSpark sparkColor='#fff' sparkSize={10} sparkRadius={15} sparkCount={8} duration={400}>
      <div className="min-h-screen bg-background w-full">
        <NavBar />
        <main>
          <Hero />
          <LivePatchPreview />
          <HowItWorks />
          <Features />
          <Proof />
        </main>
        <Footer />
      </div>
    </ClickSpark>
  )
}
