import { GitCommit, Star, ShieldCheck, Box, Zap, Users, ShieldAlert, Cpu } from "lucide-react"

const phases = [
  { version: "v1.8", date: "June 2026", title: "Phase 18: Final Polish", desc: "Added error pages, loading skeletons, empty states, toaster notifications, keyboard shortcuts, and accessibility improvements.", icon: Star },
  { version: "v1.7", date: "June 2026", title: "Phase 17: Growth Engine", desc: "Implemented referral system, newsletter subscriptions, and fully MDX-powered blog.", icon: Users },
  { version: "v1.6", date: "May 2026", title: "Phase 16: Scale & Speed", desc: "Dockerized engine, Kubernetes auto-scaling, GZip compression, and background task queues (ARQ).", icon: Zap },
  { version: "v1.5", date: "May 2026", title: "Phase 15: Security Hardening", desc: "Tiered rate limiting, URL whitelisting, magic byte validation, and strict CORS policies.", icon: ShieldAlert },
  { version: "v1.4", date: "April 2026", title: "Phase 14: Monetization", desc: "Stripe integration for Free, Pro, and Enterprise tiers with webhooks and usage tracking.", icon: Box },
  { version: "v1.3", date: "April 2026", title: "Phase 13: Research API", desc: "High-limit keys and anonymized datasets (CSV/Parquet) for academic security researchers.", icon: Cpu },
  { version: "v1.2", date: "March 2026", title: "Phase 12: HF Monitor", desc: "Real-time auto-scanning of HuggingFace models and email subscription alerts.", icon: Zap },
  { version: "v1.1", date: "March 2026", title: "Phase 11: AI Enhancement", desc: "Integrated Claude for natural language threat queries and automated fix suggestions.", icon: Cpu },
  { version: "v1.0", date: "Feb 2026", title: "Phase 1-10: Core Engine", desc: "Launch of AegisML core components: AST scanning, yara rules, GraphQL, Webhooks, Community Hub, Enterprise RBAC, and CI/CD Integrations.", icon: ShieldCheck },
]

export default function ChangelogPage() {
  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", paddingTop: "120px", paddingBottom: "80px", color: "var(--text-primary)" }}>
      <div style={{ maxWidth: "800px", margin: "0 auto", padding: "0 24px" }}>
        <h1 style={{ fontSize: "3rem", margin: "0 0 16px 0", fontWeight: 800 }}>Changelog</h1>
        <p style={{ color: "var(--text-secondary)", fontSize: "1.1rem", marginBottom: "64px" }}>
          Track the evolution of the AegisML security engine.
        </p>

        <div style={{ position: "relative" }}>
          {/* Timeline line */}
          <div style={{ position: "absolute", left: "24px", top: 0, bottom: 0, width: "2px", background: "var(--border)" }} />

          <div style={{ display: "flex", flexDirection: "column", gap: "48px" }}>
            {phases.map((phase, i) => {
              const Icon = phase.icon
              return (
                <div key={i} style={{ display: "flex", gap: "32px", position: "relative" }}>
                  <div style={{ zIndex: 2, background: "var(--bg-void)", padding: "8px 0" }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: "48px", height: "48px", borderRadius: "50%", background: "var(--bg-elevated)", border: "1px solid var(--gold-border)", color: "var(--gold-bright)" }}>
                      <Icon size={20} />
                    </div>
                  </div>
                  <div style={{ flex: 1, padding: "12px 0" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "8px" }}>
                      <h2 style={{ margin: 0, fontSize: "1.2rem", fontWeight: 700 }}>{phase.title}</h2>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--cyan-accent)", background: "rgba(0,229,255,0.1)", padding: "2px 8px", borderRadius: "4px" }}>{phase.version}</span>
                      <span style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>{phase.date}</span>
                    </div>
                    <p style={{ margin: 0, color: "var(--text-secondary)", lineHeight: 1.6 }}>{phase.desc}</p>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </main>
  )
}
