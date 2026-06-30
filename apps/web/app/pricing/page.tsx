"use client"
import { useState } from "react"
import { motion } from "framer-motion"
import { useSession } from "next-auth/react"
import { toast } from "sonner"
import { fadeUpVariants, staggerContainer } from "@/lib/animations"
import { GlassCard } from "@/components/GlassCard"
import { PrimaryButton, GhostButton } from "@/components/Buttons"
import { Check, Zap, Building2, ShieldCheck } from "lucide-react"
import { API_BASE_URL } from "@/lib/api"

export default function PricingPage() {
  const [loading, setLoading] = useState(false)
  const { data: session } = useSession()

  const handleCheckout = async (plan: string) => {
    if (!session) {
      toast.error("You must be logged in to upgrade.")
      return
    }
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/billing/checkout`, {
        method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${localStorage.getItem("token") || ""}` },
        body: JSON.stringify({ plan })
      })
      if (res.ok) {
        const data = await res.json()
        if (data.url) window.location.href = data.url
      } else {
        alert("You must be logged in to upgrade.")
      }
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ textAlign: "center", marginBottom: "60px" }}>
          <h1 style={{ fontSize: "3.5rem", fontWeight: 800, marginBottom: "16px", color: "var(--text-primary)" }}>
            Simple, Transparent <span style={{ color: "var(--gold-mid)" }}>Pricing</span>
          </h1>
          <p style={{ fontSize: "1.2rem", color: "var(--text-secondary)", maxWidth: "600px", margin: "0 auto", lineHeight: 1.6 }}>
            Start for free and upgrade as your scanning needs grow. Protect your ML infrastructure at any scale.
          </p>
        </motion.div>

        <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "32px", marginBottom: "80px" }}>
          
          {/* Free Tier */}
          <GlassCard style={{ padding: "40px", display: "flex", flexDirection: "column", position: "relative" }}>
            <h2 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "8px" }}>Free</h2>
            <div style={{ fontSize: "2.5rem", fontWeight: 800, marginBottom: "24px" }}>$0 <span style={{ fontSize: "1rem", color: "var(--text-muted)", fontWeight: 400 }}>/mo</span></div>
            <p style={{ color: "var(--text-secondary)", marginBottom: "32px", minHeight: "48px" }}>Perfect for individuals exploring AI security.</p>
            <ul style={{ listStyle: "none", padding: 0, margin: "0 0 40px 0", display: "flex", flexDirection: "column", gap: "16px", flex: 1 }}>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> 100 Scans / month</li>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> Basic Threat Patterns</li>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> Community Support</li>
            </ul>
            <GhostButton href="/dashboard" style={{ width: "100%", justifyContent: "center" }}>Get Started</GhostButton>
          </GlassCard>

          {/* Pro Tier */}
          <GlassCard style={{ padding: "40px", display: "flex", flexDirection: "column", position: "relative", border: "1px solid var(--gold-mid)", background: "rgba(201, 168, 76, 0.05)" }}>
            <div style={{ position: "absolute", top: "-14px", left: "50%", transform: "translateX(-50%)", background: "var(--gold-mid)", color: "#000", padding: "4px 16px", borderRadius: "100px", fontSize: "0.8rem", fontWeight: 700, display: "flex", alignItems: "center", gap: "4px" }}>
              <Zap size={14} /> MOST POPULAR
            </div>
            <h2 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "8px", color: "var(--gold-bright)" }}>Pro</h2>
            <div style={{ fontSize: "2.5rem", fontWeight: 800, marginBottom: "24px" }}>$49 <span style={{ fontSize: "1rem", color: "var(--text-muted)", fontWeight: 400 }}>/mo</span></div>
            <p style={{ color: "var(--text-secondary)", marginBottom: "32px", minHeight: "48px" }}>For professionals and small teams building with ML.</p>
            <ul style={{ listStyle: "none", padding: 0, margin: "0 0 40px 0", display: "flex", flexDirection: "column", gap: "16px", flex: 1 }}>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> 5,000 Scans / month</li>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> Advanced AI Analysis</li>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> Webhook Integrations</li>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> Priority Email Support</li>
            </ul>
            <button disabled={loading} onClick={() => handleCheckout("pro")} style={{ background: "var(--gold-mid)", color: "#000", border: "none", padding: "14px", borderRadius: "var(--radius-sm)", fontWeight: 600, fontSize: "1rem", cursor: "pointer", width: "100%" }}>
              {loading ? "Loading..." : "Upgrade to Pro"}
            </button>
          </GlassCard>

          {/* Enterprise Tier */}
          <GlassCard style={{ padding: "40px", display: "flex", flexDirection: "column", position: "relative" }}>
            <h2 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "8px", color: "var(--cyan-accent)" }}>Enterprise</h2>
            <div style={{ fontSize: "2.5rem", fontWeight: 800, marginBottom: "24px" }}>$499 <span style={{ fontSize: "1rem", color: "var(--text-muted)", fontWeight: 400 }}>/mo</span></div>
            <p style={{ color: "var(--text-secondary)", marginBottom: "32px", minHeight: "48px" }}>Unlimited scale for mission-critical ML pipelines.</p>
            <ul style={{ listStyle: "none", padding: 0, margin: "0 0 40px 0", display: "flex", flexDirection: "column", gap: "16px", flex: 1 }}>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> Unlimited Scans</li>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> Custom Threat Rules</li>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> Dedicated Slack Channel</li>
              <li style={{ display: "flex", gap: "12px", alignItems: "center" }}><Check size={18} color="var(--safe)" /> SLA Guarantees</li>
            </ul>
            <button disabled={loading} onClick={() => handleCheckout("enterprise")} style={{ background: "transparent", color: "var(--cyan-accent)", border: "1px solid var(--cyan-accent)", padding: "14px", borderRadius: "var(--radius-sm)", fontWeight: 600, fontSize: "1rem", cursor: "pointer", width: "100%" }}>
              {loading ? "Loading..." : "Upgrade to Enterprise"}
            </button>
          </GlassCard>

        </motion.div>
      </div>
    </main>
  )
}
