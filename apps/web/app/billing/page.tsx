"use client"
import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { fadeUpVariants } from "@/lib/animations"
import { GlassCard } from "@/components/GlassCard"
import { CreditCard, ExternalLink, AlertTriangle } from "lucide-react"
import { API_BASE_URL } from "@/lib/api"

export default function BillingPage() {
  const [usage, setUsage] = useState<any>(null)

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/v1/billing/usage`, {
      headers: { "Authorization": `Bearer ${localStorage.getItem("token") || ""}` }
    }).then(r => r.json()).then(setUsage).catch(console.error)
  }, [])

  const handlePortal = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/billing/portal`, {
        headers: { "Authorization": `Bearer ${localStorage.getItem("token") || ""}` }
      })
      const data = await res.json()
      if (data.url) window.location.href = data.url
    } catch (err) {
      console.error(err)
    }
  }

  const handleCancel = async () => {
    if (!confirm("Are you sure you want to cancel your subscription and downgrade to Free?")) return
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/billing/cancel`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${localStorage.getItem("token") || ""}` }
      })
      if (res.ok) window.location.reload()
    } catch (err) {
      console.error(err)
    }
  }

  if (!usage) return null

  const pct = usage.scans_limit === -1 ? 0 : Math.min(100, (usage.scans_used / usage.scans_limit) * 100)

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "800px", margin: "0 auto", padding: "0 24px" }}>
        
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "40px" }}>
          <h1 style={{ fontSize: "2.5rem", fontWeight: 800, marginBottom: "16px", display: "flex", alignItems: "center", gap: "16px" }}>
            <CreditCard color="var(--gold-mid)" size={32} /> Billing & Usage
          </h1>
        </motion.div>

        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible">
          <GlassCard style={{ padding: "40px", marginBottom: "32px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "32px" }}>
              <div>
                <h2 style={{ fontSize: "1.1rem", color: "var(--text-secondary)", marginBottom: "8px" }}>Current Plan</h2>
                <div style={{ fontSize: "2rem", fontWeight: 800, textTransform: "capitalize", color: usage.plan === "free" ? "var(--text-primary)" : "var(--gold-mid)" }}>
                  {usage.plan}
                </div>
              </div>
              <button onClick={handlePortal} style={{ background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", color: "var(--text-primary)", padding: "10px 16px", borderRadius: "var(--radius-sm)", fontWeight: 500, cursor: "pointer", display: "flex", alignItems: "center", gap: "8px" }}>
                Manage in Stripe <ExternalLink size={14} />
              </button>
            </div>

            <div style={{ marginBottom: "40px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "12px", fontSize: "0.95rem" }}>
                <span style={{ color: "var(--text-secondary)" }}>API Scans this month</span>
                <span style={{ fontWeight: 600 }}>{usage.scans_used.toLocaleString()} / {usage.scans_limit === -1 ? "Unlimited" : usage.scans_limit.toLocaleString()}</span>
              </div>
              <div style={{ width: "100%", height: "8px", background: "rgba(255,255,255,0.1)", borderRadius: "4px", overflow: "hidden", marginBottom: "12px" }}>
                <div style={{ height: "100%", background: "var(--cyan-accent)", width: `${pct}%`, transition: "width 0.5s ease" }} />
              </div>
              <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                Limits reset on {new Date(usage.reset_date).toLocaleDateString()}
              </div>
            </div>

            {usage.plan !== "free" && (
              <div style={{ borderTop: "1px solid var(--border)", paddingTop: "32px" }}>
                <h3 style={{ fontSize: "1.1rem", fontWeight: 600, color: "var(--danger)", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
                  <AlertTriangle size={18} /> Danger Zone
                </h3>
                <button onClick={handleCancel} style={{ background: "transparent", border: "1px solid var(--danger)", color: "var(--danger)", padding: "10px 16px", borderRadius: "var(--radius-sm)", fontWeight: 500, cursor: "pointer" }}>
                  Cancel Subscription
                </button>
              </div>
            )}
          </GlassCard>
        </motion.div>

      </div>
    </main>
  )
}
