"use client"
import { useState } from "react"
import { motion } from "framer-motion"
import { GlassCard } from "@/components/GlassCard"
import { PrimaryButton, GhostButton } from "@/components/Buttons"
import { VerdictBadge } from "@/components/VerdictBadge"
import { fadeUpVariants, staggerContainer } from "@/lib/animations"
import { API_BASE_URL } from "@/lib/api"
import { Check, X, Plus, Trash2, GitCompareArrows } from "lucide-react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, Legend } from "recharts"

type ScanResponse = {
  scan_id: string
  filename: string
  risk_score: number
  risk_level: "clean" | "suspicious" | "malicious" | "critical"
  threats: { category?: string; severity?: string; cvss?: number }[]
  metadata: Record<string, any>
}

const RISK_LEVEL_TO_VERDICT: Record<string, "safe" | "suspicious" | "dangerous" | "critical"> = {
  clean: "safe", suspicious: "suspicious", malicious: "dangerous", critical: "critical",
}

const competitorFeatures = [
  { name: "Byte-Signature Pattern Matching", us: true, them: true },
  { name: "Pickle Opcode-Level RCE Detection", us: true, them: false },
  { name: "GGUF Template SSTI Detection", us: true, them: false },
  { name: "SafeTensors Metadata Poisoning Checks", us: true, them: false },
  { name: "Shannon Entropy Obfuscation Analysis", us: true, them: false },
  { name: "Multi-AI Engine Consensus", us: true, them: false },
  { name: "CI/CD Pass/Fail Gating", us: true, them: false },
]

export default function ComparePage() {
  const [scanIdInput, setScanIdInput] = useState("")
  const [scanIds, setScanIds] = useState<string[]>([])
  const [results, setResults] = useState<Record<string, ScanResponse>>({})
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(false)

  function addScanId() {
    const trimmed = scanIdInput.trim()
    if (!trimmed) return
    if (scanIds.length >= 4) return
    if (scanIds.includes(trimmed)) return
    setScanIds([...scanIds, trimmed])
    setScanIdInput("")
  }

  function removeScanId(id: string) {
    setScanIds(scanIds.filter(s => s !== id))
    const r = { ...results }; delete r[id]; setResults(r)
    const e = { ...errors }; delete e[id]; setErrors(e)
  }

  async function runComparison() {
    if (scanIds.length < 2) return
    setLoading(true)
    const newResults: Record<string, ScanResponse> = {}
    const newErrors: Record<string, string> = {}

    await Promise.all(scanIds.map(async (id) => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/v1/scan/${id}`)
        if (!res.ok) throw new Error(res.status === 404 ? "Not found" : `HTTP ${res.status}`)
        newResults[id] = await res.json()
      } catch (e: any) {
        newErrors[id] = e.message || "Failed to load"
      }
    }))

    setResults(newResults)
    setErrors(newErrors)
    setLoading(false)
  }

  const validResults = scanIds.map(id => results[id]).filter(Boolean) as ScanResponse[]

  const cvssChartData = validResults.map(r => ({
    name: r.filename.length > 18 ? r.filename.slice(0, 16) + "…" : r.filename,
    riskScore: r.risk_score,
  }))

  const categorySet = new Set<string>()
  validResults.forEach(r => r.threats.forEach(t => categorySet.add(t.category || "other")))
  const categories = Array.from(categorySet)

  return (
    <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "120px", paddingBottom: "80px", color: "var(--text-primary)" }}>
      <div style={{ maxWidth: "1100px", margin: "0 auto", padding: "0 24px" }}>

        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ textAlign: "center", marginBottom: "48px" }}>
          <h1 style={{ fontSize: "2.6rem", margin: 0 }}>Model Comparison Matrix</h1>
          <p style={{ color: "var(--text-secondary)", marginTop: "16px", fontSize: "1.1rem", maxWidth: "640px", margin: "16px auto 0" }}>
            Add 2–4 scan IDs to evaluate them side by side — risk scores, threat categories, and entropy, benchmarked against each other.
          </p>
        </motion.div>

        {/* SCAN ID INPUT */}
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "32px" }}>
          <GlassCard style={{ padding: "24px" }}>
            <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
              <input
                type="text"
                value={scanIdInput}
                onChange={e => setScanIdInput(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") addScanId() }}
                placeholder="Paste a scan ID (e.g. from a /scan/{id} URL)"
                style={{ flex: 1, minWidth: "240px" }}
              />
              <GhostButton onClick={addScanId} disabled={!scanIdInput.trim() || scanIds.length >= 4}>
                <Plus size={16} /> Add
              </GhostButton>
            </div>

            {scanIds.length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", marginTop: "16px" }}>
                {scanIds.map(id => (
                  <div key={id} style={{
                    display: "flex", alignItems: "center", gap: "8px",
                    background: "var(--bg-subtle)", border: "1px solid var(--border-fine)",
                    borderRadius: "var(--radius-sm)", padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: "0.85rem"
                  }}>
                    {id.slice(0, 12)}{id.length > 12 ? "…" : ""}
                    {errors[id] && <span style={{ color: "var(--danger)", fontSize: "0.75rem" }}>({errors[id]})</span>}
                    <button onClick={() => removeScanId(id)} style={{ background: "none", border: "none", cursor: "pointer", display: "flex" }}>
                      <Trash2 size={14} color="var(--text-muted)" />
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div style={{ marginTop: "20px", textAlign: "center" }}>
              <PrimaryButton onClick={runComparison} disabled={scanIds.length < 2 || loading} loading={loading}>
                <GitCompareArrows size={16} /> Compare {scanIds.length >= 2 ? `${scanIds.length} Models` : ""}
              </PrimaryButton>
              {scanIds.length < 2 && (
                <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "12px" }}>Add at least 2 scan IDs to compare.</p>
              )}
            </div>
          </GlassCard>
        </motion.div>

        {/* RESULTS MATRIX */}
        {validResults.length >= 2 && (
          <>
            <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: `repeat(${validResults.length}, 1fr)`, gap: "20px", marginBottom: "32px" }} className="grid-cols-1 md:grid-cols-2">
              {validResults.map(r => (
                <GlassCard key={r.scan_id} style={{ textAlign: "center", padding: "32px 20px" }}>
                  <h4 style={{ fontSize: "0.95rem", marginBottom: "16px", color: "var(--text-primary)", wordBreak: "break-word" }}>{r.filename}</h4>
                  <VerdictBadge verdict={RISK_LEVEL_TO_VERDICT[r.risk_level] || "suspicious"} />
                  <div style={{ marginTop: "16px", fontSize: "1.3rem", fontWeight: 700, color: "var(--gold-bright)" }}>{r.risk_score}/100</div>
                  <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginTop: "4px" }}>{r.threats.length} threat{r.threats.length !== 1 ? "s" : ""}</div>
                </GlassCard>
              ))}
            </motion.div>

            <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "32px" }}>
              <GlassCard style={{ height: "320px" }}>
                <h3 style={{ marginBottom: "20px", fontSize: "1.1rem" }}>Risk Score Comparison</h3>
                <ResponsiveContainer width="100%" height="85%">
                  <BarChart data={cvssChartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={12} />
                    <YAxis stroke="var(--text-muted)" fontSize={12} domain={[0, 100]} />
                    <RechartsTooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--gold-border)", borderRadius: "var(--radius-md)" }} />
                    <Bar dataKey="riskScore" fill="var(--gold-bright)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </GlassCard>
            </motion.div>

            {categories.length > 0 && (
              <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "48px" }}>
                <GlassCard style={{ padding: 0, overflow: "hidden" }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Category</th>
                        {validResults.map(r => <th key={r.scan_id} style={{ textAlign: "center" }}>{r.filename.length > 14 ? r.filename.slice(0, 12) + "…" : r.filename}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {categories.map(cat => (
                        <tr key={cat}>
                          <td style={{ textTransform: "capitalize" }}>{cat.replace(/_/g, " ")}</td>
                          {validResults.map(r => {
                            const count = r.threats.filter(t => (t.category || "other") === cat).length
                            return (
                              <td key={r.scan_id} style={{ textAlign: "center", color: count > 0 ? "var(--danger)" : "var(--text-muted)", fontWeight: count > 0 ? 700 : 400 }}>
                                {count}
                              </td>
                            )
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </GlassCard>
              </motion.div>
            )}
          </>
        )}

        {/* WHY AEGISML — supplementary context, not the primary tool on this page */}
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginTop: "64px" }}>
          <h2 style={{ fontSize: "1.6rem", textAlign: "center", marginBottom: "24px", color: "var(--text-secondary)" }}>
            What AegisML Checks That Traditional Scanners Don't
          </h2>
          <GlassCard style={{ padding: 0, overflow: "hidden" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Capability</th>
                  <th style={{ textAlign: "center", color: "var(--gold-bright)" }}>AegisML</th>
                  <th style={{ textAlign: "center" }}>Traditional Scanners</th>
                </tr>
              </thead>
              <tbody>
                {competitorFeatures.map(f => (
                  <tr key={f.name}>
                    <td>{f.name}</td>
                    <td style={{ textAlign: "center" }}>{f.us ? <Check color="var(--safe)" style={{ margin: "0 auto" }} /> : <X color="var(--text-muted)" style={{ margin: "0 auto" }} />}</td>
                    <td style={{ textAlign: "center" }}>{f.them ? <Check color="var(--text-secondary)" style={{ margin: "0 auto" }} /> : <X color="var(--danger)" style={{ margin: "0 auto" }} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </GlassCard>
        </motion.div>

      </div>
    </main>
  )
}
