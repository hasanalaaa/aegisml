"use client"
import { motion } from "framer-motion"
import { toast } from "sonner"
import { VerdictBadge } from "@/components/VerdictBadge"
import { GlassCard } from "@/components/GlassCard"
import { ArchitectureCard, type FormatSpecificMeta } from "@/components/ArchitectureCard"
import { EntropyHeatmap } from "@/components/forensics/EntropyHeatmap"
import { PickleForensicsCard } from "@/components/forensics/PickleForensicsCard"
import { GhostButton } from "@/components/Buttons"
import { NumberTicker } from "@/components/NumberTicker"
import { staggerContainer, fadeUpVariants, blurUpVariants, cascadeContainer, cascadeItem } from "@/lib/animations"
import { API_BASE_URL } from "@/lib/api"
import { ShieldAlert, Download, Share2, RefreshCw, Lightbulb, MessageCircle, FileWarning, Activity } from "lucide-react"

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
  // v3 evidence: where the finding is and what it was matched on.
  location?: string
  region?: string
  byte_offsets?: number[]
  occurrences?: number
  evidence?: string[]
  attack?: string[]
  cwe?: string[]
  references?: string[]
  confidence?: string
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

function EngineEvidence({ metadata }: { metadata: Record<string, any> }) {
  const structure = metadata?.structure || {}
  const profile = metadata?.byte_profile || {}
  const coverage = metadata?.coverage || {}
  const forensics = metadata?.tensor_forensics
  const rows: Array<[string, string]> = []
  if (metadata?.engine_version) rows.push(["engine", `${metadata.engine_version} · rules ${metadata.ruleset_version || "—"}`])
  if (metadata?.signature_tier) rows.push(["signature tier", String(metadata.signature_tier)])
  if (metadata?.signatures_checked) rows.push(["signatures", `${metadata.signatures_checked} across ${metadata.patterns_checked} rules`])
  if (structure?.count) rows.push(["structure", `${structure.count} regions · ${structure.tensors ?? 0} tensors`])
  if (metadata?.embedded_analyzed) rows.push(["nested payloads", String(metadata.embedded_analyzed)])
  if (forensics?.tensors_examined) rows.push(["tensors sampled", `${forensics.tensors_examined} (${Number(forensics.sampled_bytes || 0).toLocaleString()} bytes)`])
  if (profile?.blocks_measured) rows.push(["byte profile", `${profile.blocks_measured} blocks · mean entropy ${profile.mean_block_entropy ?? "—"}`])
  if (metadata?.throughput_mib_s) rows.push(["throughput", `${metadata.throughput_mib_s} MiB/s`])
  const coverageEntries = Object.entries(coverage).filter(([key]) => key !== "complete")
  if (!rows.length && !coverageEntries.length) return null
  return (
    <GlassCard style={{ marginBottom: "24px" }}>
      <h3 style={{ color: "var(--gold-bright)", fontSize: "1.05rem", marginBottom: "14px" }}>
        Engine Evidence
      </h3>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: "10px 24px" }}>
        {rows.map(([key, value]) => (
          <div key={key} style={{ display: "flex", justifyContent: "space-between", gap: "12px", borderBottom: "1px solid var(--gold-border)", paddingBottom: "6px" }}>
            <span style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>{key}</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--text-muted)", textAlign: "right" }}>{value}</span>
          </div>
        ))}
      </div>
      {coverageEntries.length > 0 && (
        <p style={{ marginTop: "14px", fontFamily: "var(--font-mono)", fontSize: "0.74rem", color: "var(--text-muted)", direction: "ltr" }}>
          coverage: {coverageEntries.map(([key, value]) => `${key}=${String(value)}`).join(" · ")}
        </p>
      )}
    </GlassCard>
  )
}

function ThreatEvidence({ threat }: { threat: ApiThreat }) {
  const facts: Array<[string, string]> = []
  if (threat.region) facts.push(["region", threat.region])
  if (threat.location) facts.push(["location", threat.location])
  if (threat.byte_offsets?.length)
    facts.push(["byte offset", threat.byte_offsets.slice(0, 4).map(n => n.toLocaleString()).join(", ")])
  if (threat.occurrences && threat.occurrences > 1) facts.push(["occurrences", String(threat.occurrences)])
  if (threat.attack?.length) facts.push(["technique", threat.attack.join(", ")])
  if (threat.cwe?.length) facts.push(["weakness", threat.cwe.join(", ")])
  if (threat.references?.length) facts.push(["reference", threat.references.join(", ")])
  if (threat.confidence && threat.confidence !== "high") facts.push(["confidence", threat.confidence])
  const evidence = (threat.evidence || []).slice(0, 2)
  if (!facts.length && !evidence.length) return null
  return (
    <div style={{ marginTop: "12px", paddingTop: "12px", borderTop: "1px solid var(--gold-border)" }}>
      {evidence.length > 0 && (
        <pre style={{
          background: "rgba(0,0,0,0.35)", border: "1px solid var(--gold-border)", borderRadius: "8px",
          padding: "10px 12px", overflowX: "auto", fontFamily: "var(--font-mono)",
          fontSize: "0.75rem", color: "var(--text-secondary)", margin: "0 0 10px", direction: "ltr",
        }}>{evidence.join("\n")}</pre>
      )}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px 18px" }}>
        {facts.map(([key, value]) => (
          <span key={key} style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
            <span style={{ opacity: 0.65 }}>{key}: </span>{value}
          </span>
        ))}
      </div>
    </div>
  )
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
  const scanSucceeded = progressData.isComplete && progressData.status === "complete" && progressData.stage === "complete"

  useEffect(() => {
    if (!scanSucceeded) return
    let cancelled = false
    setLoading(true)
    setLoadError(null)
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
  }, [id, scanSucceeded])

  if (!scanSucceeded) {
    return (
      <main style={{ background: "var(--bg-void)", minHeight: "100vh", display: "grid", alignItems: "center", paddingTop: "48px", paddingBottom: "48px", position: "relative" }}>
        <div aria-hidden style={{ position: "fixed", inset: 0, pointerEvents: "none", backgroundImage: "radial-gradient(1100px 560px at 50% -10%, rgba(212,175,55,0.10), transparent 60%)" }} />
        <ScanProgress progressData={progressData} />
      </main>
    )
  }

  if (loading) {
    return (
      <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "180px", textAlign: "center", color: "var(--text-secondary)" }}>
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          style={{ display: "inline-flex", alignItems: "center", gap: "12px" }}
        >
          <motion.span
            animate={{ rotate: 360 }}
            transition={{ repeat: Infinity, duration: 1.2, ease: "linear" }}
            style={{ display: "inline-flex" }}
          >
            <RefreshCw size={18} color="var(--gold-mid)" />
          </motion.span>
          Loading scan report…
        </motion.div>
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
  // The engine historically emitted the literal string "unknown" when magic
  // bytes didn't match (e.g. safetensors has none), and old scans are cached
  // with it. Treat "unknown" as absent and fall back to the file extension.
  const rawFormat = scan.metadata?.format_detected
  const extension = (scan.metadata?.extension || "").replace(/^\./, "")
  const formatDetected: string =
    (rawFormat && rawFormat !== "unknown" ? rawFormat : "") || extension || "unknown"
  const fileSizeBytes: number | undefined = scan.metadata?.file_size
  const formatSpecific: FormatSpecificMeta | undefined = scan.metadata?.format_specific

  function formatBytes(n?: number): string {
    if (!n && n !== 0) return "—"
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
  }

  function handleDownloadJson() {
    const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `AegisML_Report_${id}.json`
    a.click()
    window.URL.revokeObjectURL(url)
    toast.success("JSON report downloaded")
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
    <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "120px", paddingBottom: "80px", color: "var(--text-primary)", position: "relative" }}>
      <div aria-hidden style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, backgroundImage: "radial-gradient(1100px 560px at 82% -6%, rgba(212,175,55,0.10), transparent 60%), radial-gradient(760px 520px at 6% 2%, rgba(212,175,55,0.05), transparent 55%)" }} />
      <div style={{ maxWidth: "1000px", margin: "0 auto", padding: "0 24px", position: "relative", zIndex: 1 }}>

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
            <GhostButton href="/ops"><Activity size={16} /> System</GhostButton>
            <GhostButton href="/">New Scan</GhostButton>
          </div>
        </motion.div>

        <motion.div variants={cascadeContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px", marginBottom: "24px" }} className="grid-cols-1 md:grid-cols-2">
          {/* VERDICT CARD */}
          <motion.div variants={cascadeItem} style={{ height: "100%" }}>
          <motion.div
            animate={{
              boxShadow: verdict === "safe"
                ? ["0 0 0 1px rgba(212,175,55,0.14), 0 0 24px rgba(212,175,55,0.06)", "0 0 0 1px rgba(212,175,55,0.30), 0 0 48px rgba(212,175,55,0.14)", "0 0 0 1px rgba(212,175,55,0.14), 0 0 24px rgba(212,175,55,0.06)"]
                : ["0 0 0 1px rgba(220,38,38,0.18), 0 0 24px rgba(220,38,38,0.08)", "0 0 0 1px rgba(220,38,38,0.38), 0 0 52px rgba(220,38,38,0.18)", "0 0 0 1px rgba(220,38,38,0.18), 0 0 24px rgba(220,38,38,0.08)"],
            }}
            transition={{ duration: 3.4, repeat: Infinity, ease: "easeInOut" }}
            style={{ borderRadius: "var(--radius-lg)", height: "100%" }}
          >
          <GlassCard glow reveal={false} style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", textAlign: "center", padding: "48px 24px", height: "100%" }}>
            <motion.div initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ type: "spring", stiffness: 200, damping: 18, delay: 0.25 }}>
              <VerdictBadge verdict={verdict} large />
            </motion.div>
            <div style={{ marginTop: "24px", fontSize: "1.1rem", color: "var(--text-secondary)" }}>
              Risk Score:{" "}
              <span style={{ color: verdict === "safe" ? "var(--success, #10B981)" : "var(--danger)", fontWeight: 700, fontSize: "1.35rem" }}>
                <NumberTicker value={scan.risk_score} inViewOnly={false} />
              </span>
              /100
            </div>
          </GlassCard>
          </motion.div>
          </motion.div>

          {/* FILE INFO CARD */}
          <motion.div variants={cascadeItem}>
          <GlassCard reveal={false} style={{ display: "flex", flexDirection: "column", gap: "16px", justifyContent: "center", height: "100%" }}>
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
                {scan.ai_analysis?.confidence
                  ? <>Confidence <NumberTicker value={scan.ai_analysis.confidence} suffix="%" /></>
                  : "—"}
              </span>
            </div>
          </GlassCard>
          </motion.div>
        </motion.div>

        {/* ENGINE EVIDENCE — what the scanner actually examined, not just a score. */}
        <EngineEvidence metadata={scan.metadata} />

        {/* MODEL ARCHITECTURE (safetensors) — renders nothing for other formats */}
        <ArchitectureCard meta={formatSpecific} />

        {/* PICKLE OPCODE FORENSICS (.pkl/.pt/.bin) — renders nothing otherwise.
            format_specific carries either safetensors OR pickle fields depending
            on the scanned format, so read it untyped here. */}
        <PickleForensicsCard meta={scan.metadata?.format_specific} />

        {/* ENTROPY HEATMAP — interactive hotspot map with sampled/encrypted flags */}
        <EntropyHeatmap entropy={entropy} />

        {/* THREATS DETECTED (Grouped) */}
        <motion.h3 variants={blurUpVariants} initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-40px" }} style={{ marginBottom: "16px", color: "var(--text-primary)", display: "flex", alignItems: "baseline", gap: "8px" }}>
          Threats by Category
          {threats.length > 0 && (
            <span style={{ color: "var(--gold-mid)" }}>
              (<NumberTicker value={threats.length} />)
            </span>
          )}
        </motion.h3>

        {threats.length === 0 ? (
          <GlassCard style={{ padding: "40px 24px", textAlign: "center", marginBottom: "40px" }}>
            <VerdictBadge verdict="safe" />
            <p style={{ color: "var(--text-secondary)", marginTop: "16px" }}>
              No threats matched across {scan.metadata?.patterns_checked ?? "the active"} signature patterns, regex rules, or format-specific checks.
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
                            <span style={{ fontSize: "0.85rem", color: "var(--text-secondary)", fontWeight: 600 }}>
                              CVSS:{" "}
                              {threat.cvss !== undefined && threat.cvss !== null && !Number.isNaN(Number(threat.cvss))
                                ? <NumberTicker value={Number(threat.cvss)} decimals={1} style={{ color: Number(threat.cvss) >= 9 ? "var(--danger)" : Number(threat.cvss) >= 7 ? "var(--warn)" : "var(--text-primary)" }} />
                                : "—"}
                            </span>
                            <VerdictBadge verdict={severityToVerdict(threat.severity)} />
                          </div>
                        </div>
                        {threat.description && (
                          <p style={{ color: "var(--text-secondary)", fontSize: "0.88rem", lineHeight: 1.7, marginTop: "10px" }}>
                            {threat.description}
                          </p>
                        )}
                        <ThreatEvidence threat={threat} />
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

        {/* ACTIONS ROW */}
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", gap: "16px", flexWrap: "wrap", justifyContent: "center" }}>
          <GhostButton onClick={handleDownloadJson}><Download size={16} /> Download JSON</GhostButton>
          <GhostButton onClick={handleShare}><Share2 size={16} /> Share</GhostButton>
          <GhostButton onClick={handleRescan}><RefreshCw size={16} /> {rescanning ? "Rescanning…" : "Rescan"}</GhostButton>
        </motion.div>

        <AIChat scanId={id} />
      </div>
    </main>
  )
}
