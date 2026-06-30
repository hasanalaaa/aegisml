"use client"

import { useEffect, useState } from "react"
import { motion } from "framer-motion"
import { toast } from "sonner"
import { LeaderboardTable, LeaderboardEntry } from "@/components/LeaderboardTable"
import { ReviewCard, ReviewProps } from "@/components/ReviewCard"
import { fadeUpVariants } from "@/lib/animations"
import { API_BASE_URL } from "@/lib/api"
import { Users, ShieldAlert } from "lucide-react"

export default function CommunityPage() {
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([])
  const [reviews, setReviews] = useState<ReviewProps[]>([])
  const [threats, setThreats] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    Promise.allSettled([
      fetch(`${API_BASE_URL}/api/v1/community/leaderboard?limit=20`).then(r => r.json()),
      fetch(`${API_BASE_URL}/api/v1/community/threat-reports`).then(r => r.json()),
    ]).then(([lb, tr]) => {
      if (cancelled) return
      if (lb.status === "fulfilled" && Array.isArray(lb.value)) setLeaderboard(lb.value)
      if (tr.status === "fulfilled" && Array.isArray(tr.value)) setThreats(tr.value)
      // Reviews are keyed per-model on the backend; the community landing
      // page shows the global leaderboard + pending threat reports, so we
      // leave the per-model review feed empty here until a model is selected.
      setReviews([])
      setLoading(false)
    })
    return () => { cancelled = true }
  }, [])

  async function handleReportThreat() {
    const pattern = window.prompt("Threat pattern (e.g. base64.b64decode(...).eval()):")
    if (!pattern) return
    const category = window.prompt("Category (e.g. code_execution, prompt_injection):") || "uncategorized"
    const description = window.prompt("Brief description of the threat:") || ""
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/community/threat-reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern, category, description, evidence: {} }),
      })
      if (!res.ok) throw new Error(`Server returned ${res.status}`)
      const created = await res.json()
      setThreats(prev => [created, ...prev])
      toast.success("Threat report submitted for review")
    } catch (e: any) {
      toast.error("Couldn't submit report", { description: e.message })
    }
  }

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "48px", textAlign: "center" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", background: "rgba(201,168,76,0.1)", color: "var(--gold-bright)", padding: "6px 12px", borderRadius: "100px", fontSize: "0.85rem", fontWeight: 600, marginBottom: "16px", border: "1px solid var(--gold-border)" }}>
            <Users size={14} /> Community Hub
          </div>
          <h1 style={{ fontSize: "3rem", margin: 0, fontWeight: 800 }}>Safest AI Models</h1>
          <p style={{ color: "var(--text-secondary)", marginTop: "16px", fontSize: "1.1rem", maxWidth: "600px", margin: "16px auto 0" }}>
            Discover models verified by the AegisML engine and reviewed by security researchers globally.
          </p>
        </motion.div>

        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "32px" }} className="grid-cols-1 lg:grid-cols-[2fr_1fr]">
          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", flexDirection: "column", gap: "40px" }}>
            <section>
              <h2 style={{ fontSize: "1.5rem", marginBottom: "24px", fontWeight: 700 }}>Global Leaderboard</h2>
              {leaderboard.length === 0 ? (
                <div style={{ textAlign: "center", padding: "48px 0", background: "rgba(255,255,255,0.02)", borderRadius: "var(--radius-lg)", border: "1px solid var(--border)" }}>
                  <div style={{ fontSize: "3rem", marginBottom: "16px", opacity: 0.5 }}>🏆</div>
                  <h4 style={{ margin: "0 0 8px 0", fontSize: "1.2rem", color: "var(--text-primary)" }}>No models ranked yet</h4>
                  <p style={{ color: "var(--text-secondary)" }}>The community leaderboard will populate once scans are submitted.</p>
                </div>
              ) : (
                <LeaderboardTable entries={leaderboard} />
              )}
            </section>

            <section>
              <h2 style={{ fontSize: "1.5rem", marginBottom: "24px", fontWeight: 700 }}>Recent Reviews</h2>
              {reviews.length === 0 ? (
                <div style={{ textAlign: "center", padding: "40px 24px", background: "rgba(255,255,255,0.02)", borderRadius: "var(--radius-lg)", border: "1px solid var(--border)" }}>
                  <div style={{ fontSize: "2.5rem", marginBottom: "12px", opacity: 0.5 }}>✍️</div>
                  <p style={{ color: "var(--text-secondary)", margin: 0 }}>Reviews appear on each model's scan report. Scan a model and be the first to review it.</p>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                  {reviews.map((r, i) => <ReviewCard key={i} {...r} />)}
                </div>
              )}
            </section>
          </motion.div>

          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible">
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: "24px", position: "sticky", top: "100px" }}>
              <h3 style={{ fontSize: "1.2rem", marginBottom: "20px", display: "flex", alignItems: "center", gap: "8px" }}>
                <ShieldAlert size={18} color="var(--warn)" /> Threat Reports
              </h3>
              <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "20px" }}>
                Pending patterns reported by the community to be added to the AegisML database.
              </p>
              
              <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                {threats.length === 0 ? (
                  <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", textAlign: "center", padding: "16px 0" }}>
                    {loading ? "Loading…" : "No pending threat reports."}
                  </p>
                ) : threats.map((t, i) => (
                  <div key={i} style={{ padding: "16px", background: "var(--bg-subtle)", borderRadius: "var(--radius-md)", border: "1px dashed var(--warn)", opacity: 0.8 }}>
                    <div style={{ fontSize: "0.8rem", color: "var(--warn)", textTransform: "uppercase", fontWeight: 700, marginBottom: "8px" }}>{t.category}</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--text-primary)", wordBreak: "break-all", background: "#000", padding: "8px", borderRadius: "4px" }}>{t.pattern}</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "12px", display: "flex", justifyContent: "space-between" }}>
                      <span>Status: {t.status}</span>
                      <span>{new Date(t.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))}
              </div>

              <button onClick={handleReportThreat} style={{ width: "100%", padding: "12px", background: "transparent", border: "1px solid var(--border)", color: "var(--text-primary)", borderRadius: "var(--radius-md)", marginTop: "24px", fontWeight: 600, cursor: "pointer" }} className="hover:bg-white/5">
                Report New Threat
              </button>
            </div>
          </motion.div>
        </div>

      </div>
    </main>
  )
}
