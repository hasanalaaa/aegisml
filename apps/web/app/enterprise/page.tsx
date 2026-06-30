"use client"

import { motion } from "framer-motion"
import { fadeUpVariants } from "@/lib/animations"
import { GhostButton, PrimaryButton } from "@/components/Buttons"
import { ShieldCheck, Zap, Users, Lock, Server } from "lucide-react"

export default function EnterprisePage() {
  const features = [
    { title: "Custom Threat Rules", desc: "Write RegEx patterns and AST rules to block company-specific secrets or bad practices.", icon: <ShieldCheck size={24} color="var(--cyan-accent)" /> },
    { title: "SSO & SCIM", desc: "Integrate with Okta, Google Workspace, or Azure AD for seamless team onboarding.", icon: <Users size={24} color="var(--gold-mid)" /> },
    { title: "Detailed Audit Logs", desc: "Track exactly who scanned what, when, and the detailed verdict of every action.", icon: <Server size={24} color="var(--cyan-accent)" /> },
    { title: "Air-gapped Deployment", desc: "Deploy AegisML entirely within your VPC. No external network requests required.", icon: <Lock size={24} color="var(--gold-mid)" /> },
  ]

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        
        {/* Hero Section */}
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ textAlign: "center", marginBottom: "80px" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", background: "rgba(201,168,76,0.1)", color: "var(--gold-bright)", padding: "6px 12px", borderRadius: "100px", fontSize: "0.85rem", fontWeight: 600, marginBottom: "24px", border: "1px solid var(--gold-border)" }}>
            <Zap size={14} /> Enterprise Suite
          </div>
          <h1 style={{ fontSize: "3.5rem", margin: "0 0 24px 0", fontWeight: 800 }}>Secure Your Entire AI Supply Chain.</h1>
          <p style={{ color: "var(--text-secondary)", fontSize: "1.2rem", maxWidth: "700px", margin: "0 auto 32px" }}>
            Advanced compliance, custom rules engines, and air-gapped deployments tailored for Fortune 500 security teams.
          </p>
          <div style={{ display: "flex", gap: "16px", justifyContent: "center" }}>
            <PrimaryButton>Contact Sales</PrimaryButton>
            <GhostButton href="/enterprise/audit">View Demo Dashboard</GhostButton>
          </div>
        </motion.div>

        {/* Feature Grid */}
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px", marginBottom: "80px" }} className="grid-cols-1 md:grid-cols-2">
          {features.map((f, i) => (
            <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", padding: "32px", borderRadius: "var(--radius-lg)" }}>
              <div style={{ width: "48px", height: "48px", background: "rgba(255,255,255,0.05)", borderRadius: "var(--radius-md)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: "24px" }}>
                {f.icon}
              </div>
              <h3 style={{ fontSize: "1.2rem", fontWeight: 700, marginBottom: "12px" }}>{f.title}</h3>
              <p style={{ color: "var(--text-secondary)", lineHeight: 1.6 }}>{f.desc}</p>
            </div>
          ))}
        </motion.div>
        
      </div>
    </main>
  )
}
