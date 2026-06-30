"use client"
import { useState, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { fadeUpVariants, staggerContainer } from "@/lib/animations"
import { GlassCard } from "@/components/GlassCard"
import { VerdictBadge } from "@/components/VerdictBadge"
import { PrimaryButton, GhostButton } from "@/components/Buttons"
import { Activity, BellRing, Database, Clock, ShieldCheck, Box, BellOff } from "lucide-react"
import { API_BASE_URL } from "@/lib/api"

export default function MonitorPage() {
  const [models, setModels] = useState<any[]>([])
  const [status, setStatus] = useState<any>({ is_running: false, total_scanned: 0, last_run: null })
  const [subscriptions, setSubscriptions] = useState<string[]>([])
  const [subAuthor, setSubAuthor] = useState("")

  useEffect(() => {
    // Initial fetch
    fetchData()
    // Poll every 10s
    const int = setInterval(fetchData, 10000)
    return () => clearInterval(int)
  }, [])

  const fetchData = async () => {
    try {
      const [resModels, resStatus, resSubs] = await Promise.all([
        fetch(`${API_BASE_URL}/api/v1/monitor/recent`).then(r => r.json()),
        fetch(`${API_BASE_URL}/api/v1/monitor/status`).then(r => r.json()),
        fetch(`${API_BASE_URL}/api/v1/monitor/subscriptions`).then(r => r.json())
      ])
      if (resModels.models) setModels(resModels.models)
      if (resStatus) setStatus(resStatus)
      if (resSubs.subscriptions) setSubscriptions(resSubs.subscriptions)
    } catch (err) {
      console.error(err)
    }
  }

  const handleSubscribe = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!subAuthor.trim()) return
    try {
      await fetch(`${API_BASE_URL}/api/v1/monitor/subscribe`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ author: subAuthor })
      })
      setSubAuthor("")
      fetchData()
    } catch (err) {
      console.error(err)
    }
  }

  const handleUnsubscribe = async (author: string) => {
    try {
      await fetch(`${API_BASE_URL}/api/v1/monitor/subscribe/` + author, { method: "DELETE" })
      fetchData()
    } catch (err) {
      console.error(err)
    }
  }

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "40px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "24px" }}>
          <div>
            <h1 style={{ fontSize: "2.5rem", margin: "0 0 12px 0", fontWeight: 800, display: "flex", alignItems: "center", gap: "16px" }}>
              <Activity color="var(--cyan-accent)" size={32} /> HF Monitor
            </h1>
            <p style={{ color: "var(--text-secondary)", fontSize: "1.1rem", maxWidth: "600px" }}>
              AegisML automatically scans newly uploaded models on HuggingFace every 30 minutes to proactively identify threats in the ecosystem.
            </p>
          </div>
          <div style={{ display: "flex", gap: "16px" }}>
            <GlassCard style={{ padding: "16px", minWidth: "160px", display: "flex", flexDirection: "column", gap: "8px" }}>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Monitor Status</span>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", fontWeight: 600 }}>
                <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: status.is_running ? "var(--safe)" : "var(--danger)" }}></span>
                {status.is_running ? "Active" : "Inactive"}
              </div>
            </GlassCard>
            <GlassCard style={{ padding: "16px", minWidth: "160px", display: "flex", flexDirection: "column", gap: "8px" }}>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Auto-Scanned</span>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", fontWeight: 700, fontSize: "1.2rem" }}>
                <Database size={18} color="var(--gold-mid)" /> {status.total_scanned}
              </div>
            </GlassCard>
          </div>
        </motion.div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 350px", gap: "32px" }} className="grid-cols-1 md:grid-cols-[1fr_350px]">
          
          <motion.div variants={staggerContainer} initial="hidden" animate="visible">
            <h2 style={{ fontSize: "1.2rem", fontWeight: 600, marginBottom: "24px", color: "var(--gold-bright)", borderBottom: "1px solid var(--border)", paddingBottom: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
              <Box size={18} /> Live Feed
            </h2>
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <AnimatePresence>
                {models.map((model, i) => (
                  <motion.div key={model.scan_id + i} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}>
                    <GlassCard style={{ padding: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <div style={{ fontSize: "0.85rem", color: "var(--cyan-accent)", fontFamily: "var(--font-mono)", marginBottom: "8px" }}>
                          @{model.author}
                        </div>
                        <div style={{ fontSize: "1.1rem", fontWeight: 600, marginBottom: "8px" }}>{model.name}</div>
                        <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", display: "flex", alignItems: "center", gap: "6px" }}>
                          <Clock size={12} /> {new Date(model.time).toLocaleString()}
                        </div>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "12px" }}>
                        <VerdictBadge verdict={model.risk} />
                        <GhostButton href={"/scan/" + model.scan_id} style={{ fontSize: "0.8rem", padding: "4px 12px" }}>View Report</GhostButton>
                      </div>
                    </GlassCard>
                  </motion.div>
                ))}
                {models.length === 0 && (
                  <div style={{ padding: "48px", textAlign: "center", background: "rgba(255,255,255,0.02)", border: "1px dashed var(--border)", borderRadius: "var(--radius-lg)" }}>
                    <div style={{ fontSize: "3rem", marginBottom: "16px", opacity: 0.5 }}>📡</div>
                    <h4 style={{ margin: "0 0 8px 0", fontSize: "1.2rem", color: "var(--text-primary)" }}>No models intercepted yet.</h4>
                    <p style={{ color: "var(--text-secondary)", margin: 0 }}>Monitor is running and waiting for the next interval...</p>
                  </div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>

          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible">
            <GlassCard style={{ position: "sticky", top: "100px", padding: "24px" }}>
              <h2 style={{ fontSize: "1.2rem", fontWeight: 600, marginBottom: "24px", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "8px" }}>
                <BellRing size={18} color="var(--gold-bright)" /> Alerts & Subscriptions
              </h2>
              <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem", marginBottom: "24px", lineHeight: 1.6 }}>
                Get notified instantly when a specific author uploads a model that is flagged as suspicious or dangerous.
              </p>
              
              <form onSubmit={handleSubscribe} style={{ display: "flex", gap: "8px", marginBottom: "32px" }}>
                <input 
                  type="text" 
                  value={subAuthor}
                  onChange={e => setSubAuthor(e.target.value)}
                  placeholder="Author (e.g. mistralai)" 
                  style={{ flex: 1, padding: "10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "rgba(255,255,255,0.05)", color: "var(--text-primary)", outline: "none" }}
                />
                <button type="submit" style={{ background: "var(--cyan-accent)", color: "#000", border: "none", padding: "10px 16px", borderRadius: "var(--radius-sm)", fontWeight: 600, cursor: "pointer" }}>Add</button>
              </form>

              <h3 style={{ fontSize: "0.9rem", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "16px" }}>Active Subscriptions</h3>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {subscriptions.map(author => (
                  <div key={author} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)" }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.9rem" }}>@{author}</span>
                    <button onClick={() => handleUnsubscribe(author)} style={{ background: "transparent", border: "none", color: "var(--danger)", cursor: "pointer", display: "flex", alignItems: "center" }}>
                      <BellOff size={16} />
                    </button>
                  </div>
                ))}
                {subscriptions.length === 0 && (
                  <div style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>No active subscriptions.</div>
                )}
              </div>
            </GlassCard>
          </motion.div>

        </div>
      </div>
    </main>
  )
}
