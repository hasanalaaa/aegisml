import { GlassCard } from "@/components/GlassCard"
import { PrimaryButton } from "@/components/Buttons"
import { Shield, Cpu, Lock, Eye } from "lucide-react"

export const metadata = {
  title: "About | AegisML"
}

export default function AboutPage() {
  return (
    <div className="container" style={{ paddingTop: "120px", paddingBottom: "80px", maxWidth: "1000px", margin: "0 auto" }}>
      
      <section style={{ marginBottom: "6rem", textAlign: "center" }}>
        <h1 style={{ fontSize: "3.5rem", marginBottom: "1.5rem" }}>The AegisML Story</h1>
        <p style={{ fontSize: "1.2rem", color: "var(--text-secondary)", lineHeight: 1.6, maxWidth: "800px", margin: "0 auto" }}>
          As the AI revolution exploded, we noticed a terrifying trend: developers were downloading arbitrary model weights from the internet and executing them with full privileges. The AI community had forgotten the golden rule of security: <strong>Never trust unverified code.</strong> AegisML was born out of necessity—to create the first line of defense for the open-source AI ecosystem.
        </p>
      </section>

      <section style={{ marginBottom: "6rem" }}>
        <h2 style={{ fontSize: "2.5rem", marginBottom: "2rem", textAlign: "center" }}>How It Works</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "2rem" }}>
          <GlassCard style={{ padding: "2rem", textAlign: "center" }}>
            <div style={{ color: "var(--primary)", marginBottom: "1rem" }}><Eye size={48} style={{ margin: "0 auto" }} /></div>
            <h3 style={{ marginBottom: "0.5rem" }}>1. Intercept</h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem" }}>Upload your model directly or provide a HuggingFace URL.</p>
          </GlassCard>
          <GlassCard style={{ padding: "2rem", textAlign: "center" }}>
            <div style={{ color: "var(--primary)", marginBottom: "1rem" }}><Cpu size={48} style={{ margin: "0 auto" }} /></div>
            <h3 style={{ marginBottom: "0.5rem" }}>2. Deconstruct</h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem" }}>The engine maps binary structures and extracts bytecode chains.</p>
          </GlassCard>
          <GlassCard style={{ padding: "2rem", textAlign: "center" }}>
            <div style={{ color: "var(--primary)", marginBottom: "1rem" }}><Shield size={48} style={{ margin: "0 auto" }} /></div>
            <h3 style={{ marginBottom: "0.5rem" }}>3. Analyze</h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem" }}>Scans against 250+ threat patterns and entropy anomalies.</p>
          </GlassCard>
          <GlassCard style={{ padding: "2rem", textAlign: "center" }}>
            <div style={{ color: "var(--primary)", marginBottom: "1rem" }}><Lock size={48} style={{ margin: "0 auto" }} /></div>
            <h3 style={{ marginBottom: "0.5rem" }}>4. Report</h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem" }}>Claude 3 generates a human-readable mitigation report.</p>
          </GlassCard>
        </div>
      </section>

      <section style={{ marginBottom: "6rem", textAlign: "center" }}>
        <h2 style={{ fontSize: "2.5rem", marginBottom: "1.5rem" }}>Open Source Philosophy</h2>
        <p style={{ fontSize: "1.1rem", color: "var(--text-secondary)", lineHeight: 1.6, maxWidth: "800px", margin: "0 auto 2rem auto" }}>
          Security thrives in transparency. By keeping our core engine open-source, we empower the community to audit our methods, contribute new threat patterns, and integrate AegisML directly into their CI/CD pipelines.
        </p>
        <a href="https://github.com/hasanalaaa/aegisml" target="_blank" rel="noopener noreferrer" style={{ textDecoration: "none" }}>
          <PrimaryButton>
            <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-github"><path d="M15 22v-4a4.8 4.8 0 0 0-1-3.02c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A4.8 4.8 0 0 0 8 18v4"></path></svg> Star on GitHub
          </PrimaryButton>
        </a>
      </section>

    </div>
  )
}
