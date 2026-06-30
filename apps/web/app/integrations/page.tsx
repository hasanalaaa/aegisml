"use client"

import { motion } from "framer-motion"
import { fadeUpVariants } from "@/lib/animations"
import { Blocks, GitBranch, MessageSquare, Terminal } from "lucide-react"
import { GhostButton, PrimaryButton } from "@/components/Buttons"
import Link from "next/link"

export default function IntegrationsPage() {
  const integrations = [
    {
      title: "GitHub Actions",
      icon: <GitBranch size={32} color="var(--text-primary)" />,
      desc: "Block malicious models directly in your CI pipeline before they merge.",
      status: "Available",
      docs: "/docs#github-actions"
    },
    {
      title: "Slack Bot",
      icon: <MessageSquare size={32} color="#E01E5A" />,
      desc: "Run scans via /aegis-scan and get notifications for high-risk threats.",
      status: "Available",
      docs: "/docs#slack"
    },
    {
      title: "Discord Bot",
      icon: <Terminal size={32} color="#5865F2" />,
      desc: "Scan HuggingFace links instantly within your community Discord servers.",
      status: "Available",
      docs: "/docs#discord"
    }
  ]

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ textAlign: "center", marginBottom: "80px" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", background: "rgba(201,168,76,0.1)", color: "var(--gold-bright)", padding: "6px 12px", borderRadius: "100px", fontSize: "0.85rem", fontWeight: 600, marginBottom: "24px", border: "1px solid var(--gold-border)" }}>
            <Blocks size={14} /> Ecosystem
          </div>
          <h1 style={{ fontSize: "3.5rem", margin: "0 0 24px 0", fontWeight: 800 }}>Seamless Integrations</h1>
          <p style={{ color: "var(--text-secondary)", fontSize: "1.2rem", maxWidth: "700px", margin: "0 auto 32px" }}>
            AegisML natively plugs into your existing developer workflows, bots, and CI/CD pipelines.
          </p>
        </motion.div>

        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "24px", marginBottom: "80px" }} className="grid-cols-1 md:grid-cols-3">
          {integrations.map((integ, i) => (
            <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", padding: "32px", borderRadius: "var(--radius-lg)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
              <div>
                <div style={{ width: "64px", height: "64px", background: "rgba(255,255,255,0.05)", borderRadius: "var(--radius-md)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: "24px" }}>
                  {integ.icon}
                </div>
                <h3 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "12px", display: "flex", alignItems: "center", gap: "12px" }}>
                  {integ.title}
                </h3>
                <p style={{ color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: "24px" }}>{integ.desc}</p>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid var(--border)", paddingTop: "24px" }}>
                <span style={{ fontSize: "0.8rem", color: "var(--safe)", background: "rgba(16,185,129,0.1)", padding: "4px 8px", borderRadius: "4px", fontWeight: 700 }}>
                  {integ.status}
                </span>
                <Link href={integ.docs} style={{ color: "var(--cyan-accent)", textDecoration: "none", fontSize: "0.9rem", fontWeight: 600 }}>
                  View Docs →
                </Link>
              </div>
            </div>
          ))}
        </motion.div>
        
      </div>
    </main>
  )
}
