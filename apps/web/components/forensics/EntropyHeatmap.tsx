"use client"
import { motion } from "framer-motion"
import { useState } from "react"
import { GlassCard } from "@/components/GlassCard"
import { fadeUpVariants } from "@/lib/animations"
import { Activity, Flame, Layers } from "lucide-react"

/**
 * Entropy telemetry emitted by scanner/entropy.py (surfaced at
 * metadata.entropy_analysis). Every field is optional so pre-Phase-2 cached
 * scans, empty files, and error results all render gracefully.
 */
export interface EntropySection {
  offset: number
  size: number
  entropy: number
  type?: string
}

export interface EntropyAnalysis {
  overall_entropy?: number
  suspicious_sections?: EntropySection[]
  risk_level?: string
  file_size?: number
  block_count?: number
  high_entropy_blocks?: number
  high_entropy_ratio?: number
  mean_block_entropy?: number
  max_block_entropy?: number
  sampled?: boolean
  error?: string
}

const ENCRYPTED_THRESHOLD = 7.9

function fmtBytes(n?: number): string {
  if (n === undefined || n === null) return "—"
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function fmtOffset(n: number): string {
  return "0x" + n.toString(16).toUpperCase()
}

// Map an entropy value (0..8 bits/byte) to a point on the brass→amber→red ramp.
function entropyColor(e: number): string {
  if (e >= ENCRYPTED_THRESHOLD) return "#DC2626" // encrypted / packed payload
  if (e >= 7.5) return "#EF4444"
  if (e >= 7.0) return "#F59E0B"
  if (e >= 6.0) return "#D4AF37"
  return "#8B6914"
}

function StatTile({ label, value, sub, accent }: { label: string; value: string; sub?: string; accent?: string }) {
  return (
    <div
      style={{
        background: "var(--bg-subtle)",
        border: "1px solid var(--gold-border)",
        borderRadius: "var(--radius-md)",
        padding: "14px 16px",
        display: "flex",
        flexDirection: "column",
        gap: "4px",
        minWidth: 0,
      }}
    >
      <span style={{ fontSize: "0.68rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--text-muted)" }}>{label}</span>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: "1.25rem", fontWeight: 700, color: accent || "var(--text-primary)", lineHeight: 1.1 }}>{value}</span>
      {sub && <span style={{ fontSize: "0.72rem", color: "var(--text-secondary)" }}>{sub}</span>}
    </div>
  )
}

export function EntropyHeatmap({ entropy }: { entropy?: EntropyAnalysis | null }) {
  const [active, setActive] = useState<number | null>(null)

  if (!entropy || entropy.overall_entropy === undefined) return null

  const sections = (entropy.suspicious_sections || []).slice().sort((a, b) => a.offset - b.offset)
  const fileSize = entropy.file_size || (sections.length ? sections[sections.length - 1].offset + sections[sections.length - 1].size : 1)
  const overall = entropy.overall_entropy ?? 0
  const maxBlock = entropy.max_block_entropy ?? overall
  const meanBlock = entropy.mean_block_entropy ?? overall
  const ratio = entropy.high_entropy_ratio ?? 0
  const encryptedCount = sections.filter((s) => s.entropy >= ENCRYPTED_THRESHOLD).length

  // Geometry for the SVG ruler.
  const W = 1000
  const H = 130
  const PAD = 8
  const trackY = H - 34
  const spanW = W - PAD * 2
  const xOf = (off: number) => PAD + (fileSize > 0 ? Math.min(1, off / fileSize) : 0) * spanW
  // Minimum visible width so a 4 KB block on a 5 GB file is still hoverable.
  const wOf = (size: number) => Math.max(4, (fileSize > 0 ? size / fileSize : 0) * spanW)
  // Bar height scales with how far above the 6.0 "interesting" floor the block sits.
  const barH = (e: number) => 12 + Math.min(1, Math.max(0, (e - 6) / 2)) * (trackY - 14)

  const activeSec = active !== null ? sections[active] : null
  const riskLevel = (entropy.risk_level || "low").toLowerCase()
  const riskColor = riskLevel === "critical" || riskLevel === "high" ? "var(--danger)" : riskLevel === "medium" ? "var(--warn)" : "var(--safe)"

  return (
    <>
      <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px", flexWrap: "wrap" }}>
        <h3 style={{ color: "var(--text-primary)", margin: 0, display: "inline-flex", alignItems: "center", gap: "10px" }}>
          <Activity size={20} color="var(--gold-bright)" /> Entropy Heatmap
        </h3>
        {entropy.sampled && (
          <span className="tag tag-info" title="File exceeded the full-scan cap; values are statistical estimates from evenly-spaced samples.">
            <Layers size={12} /> Sampled estimate
          </span>
        )}
        <span
          className="tag"
          style={{ background: "var(--gold-subtle)", border: "1px solid var(--gold-border)", color: riskColor }}
        >
          Entropy risk: {riskLevel}
        </span>
      </motion.div>

      <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "40px" }}>
        <GlassCard style={{ padding: "24px", display: "flex", flexDirection: "column", gap: "20px" }}>

          {/* Summary tiles */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "12px" }}>
            <StatTile label="Overall" value={overall.toFixed(3)} sub="bits / byte" accent={entropyColor(overall)} />
            <StatTile label="Mean Block" value={meanBlock.toFixed(2)} sub="avg 4 KB block" />
            <StatTile label="Peak Block" value={maxBlock.toFixed(2)} sub="hottest region" accent={entropyColor(maxBlock)} />
            <StatTile label="High-Entropy" value={`${entropy.high_entropy_blocks ?? sections.length}`} sub={`${(ratio * 100).toFixed(1)}% of ${entropy.block_count ?? "?"} blocks`} />
            <StatTile label="Encrypted?" value={encryptedCount ? `${encryptedCount}` : "0"} sub={encryptedCount ? "packed regions" : "none ≥ 7.9"} accent={encryptedCount ? "var(--danger)" : undefined} />
          </div>

          {/* Heatmap ruler */}
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)", display: "inline-flex", alignItems: "center", gap: "6px" }}>
                <Flame size={13} color="var(--warn)" /> {sections.length} hotspot{sections.length === 1 ? "" : "s"} across {fmtBytes(fileSize)}
              </span>
              {/* Legend */}
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>0</span>
                <div style={{ width: "120px", height: "8px", borderRadius: "999px", background: "linear-gradient(90deg,#8B6914,#D4AF37,#F59E0B,#EF4444,#DC2626)" }} />
                <span style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>8 bits</span>
              </div>
            </div>

            <div style={{ position: "relative", background: "var(--bg-base)", border: "1px solid var(--border-fine)", borderRadius: "var(--radius-md)", overflow: "hidden" }}>
              <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ width: "100%", height: "130px", display: "block" }}>
                {/* baseline grid */}
                {[0.25, 0.5, 0.75].map((f) => (
                  <line key={f} x1={PAD + f * spanW} y1={10} x2={PAD + f * spanW} y2={trackY} stroke="rgba(255,255,255,0.05)" strokeWidth={1} />
                ))}
                {/* file track */}
                <rect x={PAD} y={trackY} width={spanW} height={6} rx={3} fill="var(--bg-overlay)" />

                {/* hotspot bars */}
                {sections.map((s, i) => {
                  const x = xOf(s.offset)
                  const w = wOf(s.size)
                  const h = barH(s.entropy)
                  const c = entropyColor(s.entropy)
                  const isActive = active === i
                  return (
                    <g key={i} onMouseEnter={() => setActive(i)} onMouseLeave={() => setActive(null)} style={{ cursor: "pointer" }}>
                      {/* generous invisible hit area */}
                      <rect x={x - 3} y={8} width={w + 6} height={trackY} fill="transparent" />
                      <motion.rect
                        initial={{ height: 0, y: trackY }}
                        animate={{ height: h, y: trackY - h }}
                        transition={{ duration: 0.7, delay: Math.min(i * 0.02, 0.5), ease: [0.22, 1, 0.36, 1] }}
                        x={x}
                        width={w}
                        rx={Math.min(2, w / 2)}
                        fill={c}
                        opacity={isActive ? 1 : 0.82}
                        style={{ filter: isActive ? `drop-shadow(0 0 8px ${c})` : s.entropy >= ENCRYPTED_THRESHOLD ? `drop-shadow(0 0 5px ${c})` : "none" }}
                      />
                    </g>
                  )
                })}
              </svg>

              {sections.length === 0 && (
                <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: "0.85rem" }}>
                  No high-entropy hotspots — byte distribution is uniform and unremarkable.
                </div>
              )}
            </div>

            {/* Offset scale */}
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: "6px", fontFamily: "var(--font-mono)", fontSize: "0.68rem", color: "var(--text-muted)" }}>
              <span>0x0</span>
              <span>{fmtOffset(Math.floor(fileSize / 2))}</span>
              <span>{fmtOffset(fileSize)}</span>
            </div>
          </div>

          {/* Active hotspot detail */}
          <div
            style={{
              minHeight: "58px",
              background: activeSec ? "var(--bg-subtle)" : "transparent",
              border: activeSec ? `1px solid ${entropyColor(activeSec.entropy)}55` : "1px dashed var(--border-fine)",
              borderRadius: "var(--radius-md)",
              padding: "12px 16px",
              display: "flex",
              alignItems: "center",
              gap: "20px",
              flexWrap: "wrap",
              transition: "border-color 0.2s, background 0.2s",
            }}
          >
            {activeSec ? (
              <>
                <span style={{ display: "inline-flex", alignItems: "center", gap: "8px", color: entropyColor(activeSec.entropy), fontWeight: 700 }}>
                  <Flame size={16} /> {activeSec.entropy.toFixed(3)} bits
                </span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                  offset {fmtOffset(activeSec.offset)} · {fmtBytes(activeSec.size)}
                </span>
                <span
                  className="tag"
                  style={{
                    background: activeSec.entropy >= ENCRYPTED_THRESHOLD ? "var(--danger-bg)" : "var(--warn-bg)",
                    color: activeSec.entropy >= ENCRYPTED_THRESHOLD ? "var(--danger)" : "var(--warn)",
                    border: "1px solid var(--gold-border)",
                  }}
                >
                  {(activeSec.type || "high_entropy_region").replace(/_/g, " ")}
                </span>
              </>
            ) : (
              <span style={{ color: "var(--text-muted)", fontSize: "0.82rem" }}>
                Hover a bar to inspect its offset, size, and entropy. Bars ≥ 7.9 bits (red) indicate encrypted or compressed payloads hidden inside the weights.
              </span>
            )}
          </div>
        </GlassCard>
      </motion.div>
    </>
  )
}
