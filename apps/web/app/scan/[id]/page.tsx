"use client"
import { motion } from "framer-motion"
import { toast } from "sonner"
import { VerdictBadge } from "@/components/VerdictBadge"
import { GlassCard } from "@/components/GlassCard"
import { GhostButton } from "@/components/Buttons"
import { staggerContainer, fadeUpVariants } from "@/lib/animations"
import { API_BASE_URL } from "@/lib/api"
import { ShieldAlert, Download, Share2, RefreshCw, Lightbulb, MessageCircle, FileWarning } from "lucide-react"

import { use, useState, useEffect } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { useScanProgress } from "@/hooks/useScanProgress"
import { ScanProgress } from "@/components/ScanProgress"
import dynamic from "next/dynamic"
const AIChat = dynamic(() => import("@/components/AIChat").then(mod => mod.AIChat), { ssr: false })

type ApiThreat = {
  id?: string
  pattern?: string
  name?: string
  category?: string
  severity?: string
  cvss?: number | string
  description?: string
  remediation?: string
}

type ScanResponse = {
  scan_id: string
  filename: string
  risk_score: number
  risk_level: "clean" | "suspicious" | "malicious" | "critical"
  threats: ApiThreat[]
  metadata: Record<string, any>
  source_url?: string | null
  created_at?: string
  ai_analysis: {
    verdict: string
    confidence: number
    summary_en: string
    summary_ar?: string
    key_risks?: string[]
    recommendation?: string
  }
}

// The scan engine / DB speak in risk_level terms (clean/suspicious/malicious/
// critical); VerdictBadge speaks in verdict terms (safe/suspicious/dangerous/
// critical). Map between them here rather than baking the assumption in twice.
const RISK_LEVEL_TO_VERDICT: Record<string, "safe" | "suspicious" | "dangerous" | "critical"> = {
  clean: "safe",
  suspicious: "suspicious",
  malicious: "dangerous",
  critical: "critical",
}

function severityToVerdict(severity?: string): "safe" | "suspicious" | "dangerous" | "critical" {
  switch ((severity || "").toLowerCase()) {
    case "critical": return "critical"
    case "high": return "dangerous"
    case "medium": return "suspicious"
    default: return "safe"
  }
}

export default function ScanReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const progressData = useScanProgress(id)
  const router = useRouter()

  const [scan, setScan] = useState<ScanResponse | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [rescanning, setRescanning] = useState(false)

  useEffect(() => {
    if (!progressData.isComplete) return
    let cancelled = false
    setLoading(true)
    fetch(`${API_BASE_URL}/api/v1/scan/${id}`)
      .then(async (r) => {
        if (!r.ok) throw new Error(r.status === 404 ? "Scan not found" : `Server error (${r.status})`)
        return r.json()
      })
      .then((data: ScanResponse) => {
        if (!cancelled) setScan(data)
      })
      .catch((err) => {
        if (!cancelled) setLoadError(err.message || "Failed to load scan result")
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [id, progressData.isComplete])

  if (!progressData.isComplete) {
    return (
      <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "120px" }}>
        <ScanProgress scanId={id} />
      </main>
    )
  }

  if (loading) {
    return (
      <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "180px", textAlign: "center", color: "var(--text-secondary)" }}>
        Loading scan report…
      </main>
    )
  }

  if (loadError || !scan) {
    return (
      <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "160px", textAlign: "center", color: "var(--text-primary)" }}>
        <FileWarning size={40} color="var(--danger)" style={{ marginBottom: "16px" }} />
        <h2 style={{ marginBottom: "8px" }}>Couldn't load this report</h2>
        <p style={{ color: "var(--text-secondary)", marginBottom: "24px" }}>{loadError || "Unknown error"}</p>
        <GhostButton href="/">← Back to Scanner</GhostButton>
      </main>
    )
  }

  const verdict = RISK_LEVEL_TO_VERDICT[scan.risk_level] || "suspicious"
  const threats = scan.threats || []
  const groupedThreats = threats.reduce((acc, t) => {
    const cat = t.category || "uncategorized"
    if (!acc[cat]) acc[cat] = []
    acc[cat].push(t)
    return acc
  }, {} as Record<string, ApiThreat[]>)

  const entropy = scan.metadata?.entropy_analysis
  const fileHash: string = scan.metadata?.file_hash || ""
  const formatDetected: string = scan.metadata?.format_detected || scan.metadata?.extension || "unknown"
  const fileSizeBytes: number | undefined = scan.metadata?.file_size

  function formatBytes(n?: number): string {
    if (!n && n !== 0) return "—"
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
  }

  async function handleDownloadPdf() {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/analytics/report/${id}`, { method: "POST" })
      if (!res.ok) throw new Error("Report generation failed")
      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `AegisML_Report_${id}.pdf`
      a.click()
      window.URL.revokeObjectURL(url)
      toast.success("Report downloaded")
    } catch {
      toast.error("Couldn't generate the PDF report. Please try again.")
    }
  }

  function handleShare() {
    navigator.clipboard.writeText(window.location.href)
      .then(() => toast.success("Link copied to clipboard"))
      .catch(() => toast.error("Couldn't copy link"))
  }

  async function handleRescan() {
    if (!scan?.source_url) {
      toast.info("Re-scan from the home page", { description: "This scan was uploaded as a file, so it can't be automatically re-triggered — re-upload it from the scanner." })
      return
    }
    setRescanning(true)
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/scan/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scan.source_url }),
      })
      if (!res.ok) throw new Error("Rescan failed")
      const data = await res.json()
      router.push(`/scan/${data.scan_id}`)
    } catch {
      toast.error("Couldn't start a rescan")
    } finally {
      setRescanning(false)
    }
  }

  return (
    <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "120px", paddingBottom: "80px", color: "var(--text-primary)" }}>
      <div style={{ maxWidth: "1000px", margin: "0 auto", padding: "0 24px" }}>

        {/* Header */}
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "40px", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <Link href="/" style={{ color: "var(--text-secondary)", textDecoration: "none", fontSize: "0.9rem", display: "inline-flex", alignItems: "center", gap: "8px", marginBottom: "16px" }}>
              ← Back to Scanner
            </Link>
            <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
              <h1 style={{ fontSize: "2rem", margin: 0 }}>{scan.filename}</h1>
              {scan.created_at && (
                <span style={{ color: "var(--text-muted)", fontSize: "0.85rem", padding: "4px 8px", background: "var(--bg-subtle)", borderRadius: "var(--radius-sm)" }}>
                  {new Date(scan.created_at).toLocaleString()}
                </span>
              )}
            </div>
          </div>
          <div style={{ display: "flex", gap: "12px" }}>
            <GhostButton href="/community">Write a Review</GhostButton>
          </div>
        </motion.div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px", marginBottom: "24px" }} className="grid-cols-1 md:grid-cols-2">
          {/* VERDICT CARD */}
          <GlassCard style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", textAlign: "center", padding: "48px 24px" }}>
            <VerdictBadge verdict={verdict} large />
            <div style={{ marginTop: "24px", fontSize: "1.1rem", color: "var(--text-secondary)" }}>
              Risk Score: <span style={{ color: "var(--danger)", fontWeight: 700 }}>{scan.risk_score}</span>/100
            </div>
          </GlassCard>

          {/* FILE INFO CARD */}
          <GlassCard style={{ display: "flex", flexDirection: "column", gap: "16px", justifyContent: "center" }}>
            <h3 style={{ color: "var(--gold-bright)", fontSize: "1.1rem", marginBottom: "8px" }}>File Information</h3>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--gold-border)", paddingBottom: "8px" }}>
              <span style={{ color: "var(--text-secondary)" }}>Detected Format</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.9rem" }}>{formatDetected}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--gold-border)", paddingBottom: "8px" }}>
              <span style={{ color: "var(--text-secondary)" }}>Size</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.9rem" }}>{formatBytes(fileSizeBytes)}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--gold-border)", paddingBottom: "8px" }}>
              <span style={{ color: "var(--text-secondary)" }}>Hash</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--text-muted)" }}>
                {fileHash ? `sha256:${fileHash.slice(0, 12)}…${fileHash.slice(-6)}` : "—"}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-secondary)" }}>AI Engine</span>
              <span style={{ fontSize: "0.9rem", color: "var(--gold-bright)" }}>
                {scan.ai_analysis?.confidence ? `Confidence ${scan.ai_analysis.confidence}%` : "—"}
              </span>
            </div>
          </GlassCard>
        </div>

        {/* ENTROPY ANALYSIS */}
        {entropy && (
          <>
            <motion.h3 variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "16px", color: "var(--text-primary)" }}>Entropy Analysis</motion.h3>
            <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "40px" }}>
              <GlassCard style={{ padding: "24px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px" }}>
                <div>
                  <div style={{ fontSize: "1.1rem", fontWeight: 600, marginBottom: "8px" }}>
                    Shannon Entropy: {entropy.overall_entropy?.toFixed?.(2) ?? entropy.overall_entropy ?? "—"}
                  </div>
                  <div style={{ fontSize: "0.9rem", color: "var(--text-secondary)" }}>
                    Risk level: {entropy.risk_level || "unknown"}
                  </div>
                </div>
                <VerdictBadge verdict={severityToVerdict(entropy.risk_level === "critical" ? "critical" : entropy.risk_level === "high" ? "high" : "low")} />
              </GlassCard>
            </motion.div>
          </>
        )}

        {/* THREATS DETECTED (Grouped) */}
        <motion.h3 variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "16px", color: "var(--text-primary)" }}>
          Threats by Category {threats.length > 0 && `(${threats.length})`}
        </motion.h3>

        {threats.length === 0 ? (
          <GlassCard style={{ padding: "40px 24px", textAlign: "center", marginBottom: "40px" }}>
            <VerdictBadge verdict="safe" />
            <p style={{ color: "var(--text-secondary)", marginTop: "16px" }}>
              No threats matched across {scan.metadata?.patterns_checked || "300+"} signature patterns, regex rules, or format-specific checks.
            </p>
          </GlassCard>
        ) : (
          <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "flex", flexDirection: "column", gap: "24px", marginBottom: "40px" }}>
            {Object.entries(groupedThreats).map(([category, catThreats]) => (
              <div key={category}>
                <h4 style={{ color: "var(--gold-mid)", textTransform: "capitalize", marginBottom: "12px", fontSize: "0.95rem" }}>
                  {category.replace(/_/g, " ")} ({catThreats.length})
                </h4>
                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                  {catThreats.map((threat, i) => (
                    <motion.div key={threat.id || `${category}-${i}`} variants={fadeUpVariants} custom={i}>
                      <GlassCard style={{ padding: "16px 24px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
                            <ShieldAlert size={20} color={threat.severity === "critical" ? "var(--danger)" : "var(--warn)"} />
                            <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>{threat.id || threat.pattern}</span>
                            <span style={{ fontWeight: 600 }}>{threat.name || threat.pattern}</span>
                          </div>
                          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                            <button onClick={() => {
                              toast.info(threat.name || "Threat Detail", {
                                description: `${threat.description || "No description available."}${threat.remediation ? ` Remediation: ${threat.remediation}` : ""}`
                              })
                            }} style={{ display: "flex", alignItems: "center", gap: "6px", background: "rgba(0, 229, 255, 0.1)", color: "var(--cyan-accent)", border: "1px solid rgba(0, 229, 255, 0.3)", padding: "4px 8px", borderRadius: "4px", fontSize: "0.8rem", cursor: "pointer" }} className="hover:bg-cyan-900/30">
                              <MessageCircle size={14} /> Details
                            </button>
                            <span style={{ fontSize: "0.85rem", color: "var(--text-secondary)", fontWeight: 600 }}>CVSS: {threat.cvss ?? "—"}</span>
                            <VerdictBadge verdict={severityToVerdict(threat.severity)} />
                          </div>
                        </div>
                      </GlassCard>
                    </motion.div>
                  ))}
                </div>
              </div>
            ))}
          </motion.div>
        )}

        {/* AI ANALYSIS */}
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible">
          <GlassCard style={{ marginBottom: "24px" }}>
            <h3 style={{ color: "var(--gold-bright)", fontSize: "1.2rem", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "1.5rem" }}>✨</span> AI Analysis
            </h3>
            <p style={{ color: "var(--text-secondary)", lineHeight: 1.8, whiteSpace: "pre-wrap" }}>
              {scan.ai_analysis?.summary_en || "AI analysis is not available for this scan."}
            </p>
            {scan.ai_analysis?.recommendation && (
              <p style={{ color: "var(--text-primary)", lineHeight: 1.8, marginTop: "16px", paddingTop: "16px", borderTop: "1px solid var(--gold-border)" }}>
                <strong style={{ color: "var(--gold-bright)" }}>Recommendation: </strong>
                {scan.ai_analysis.recommendation}
              </p>
            )}
          </GlassCard>
        </motion.div>

        {/* FIX SUGGESTIONS (derived from real per-threat remediation fields) */}
        {threats.some(t => t.remediation) && (
          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "40px" }}>
            <details style={{ background: "rgba(201,168,76,0.05)", border: "1px solid var(--gold-border)", borderRadius: "var(--radius-md)", padding: "16px 24px", cursor: "pointer" }}>
              <summary style={{ display: "flex", alignItems: "center", gap: "12px", fontSize: "1.1rem", fontWeight: 700, color: "var(--gold-bright)", listStyle: "none" }}>
                <Lightbulb size={24} /> Fix Suggestions
              </summary>
              <div style={{ marginTop: "24px", display: "flex", flexDirection: "column", gap: "16px", cursor: "default" }}>
                {threats.filter(t => t.remediation).slice(0, 8).map((t, i) => (
                  <div key={t.id || i} style={{ background: "#000", padding: "16px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)" }}>
                    <h5 style={{ color: "var(--text-primary)", fontSize: "1rem", marginBottom: "8px" }}>{t.name || t.pattern}</h5>
                    <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem" }}>{t.remediation}</p>
                  </div>
                ))}
              </div>
            </details>
          </motion.div>
        )}

        {/* ACTIONS */}
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", gap: "16px", flexWrap: "wrap", justifyContent: "center" }}>
          <GhostButton onClick={handleDownloadPdf}><Download size={16} /> Download PDF</GhostButton>
          <GhostButton onClick={handleShare}><Share2 size={16} /> Share</GhostButton>
          <GhostButton onClick={handleRescan}><RefreshCw size={16} /> {rescanning ? "Rescanning…" : "Rescan"}</GhostButton>
        </motion.div>

        <AIChat scanId={id} />
      </div>
    </main>
  )
}
