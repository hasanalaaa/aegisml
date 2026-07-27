"use client"
import { motion } from "framer-motion"
import { GlassCard } from "@/components/GlassCard"
import { fadeUpVariants } from "@/lib/animations"
import { Cpu, Layers, Database, Binary } from "lucide-react"

/**
 * Deep format-specific forensics emitted by the scan engine
 * (scanner/safetensors_scanner.py → engine "format_specific" → API
 * metadata.format_specific). All fields are optional: non-safetensors
 * formats, failed deep scans, and pre-Phase-2 cached scans return {}
 * or omit the key entirely — the card renders nothing in that case.
 */
export type FormatSpecificMeta = {
  tensor_count?: number
  validated_tensors?: number
  total_declared_params?: number | null
  dtype_histogram?: Record<string, number>
  largest_tensor?: { name?: string; params?: number }
  header_size_bytes?: number
  declared_data_bytes?: number
  actual_data_region_bytes?: number
  unaccounted_data_bytes?: number
  has_metadata?: boolean
  declared_metadata?: Record<string, string>
}

function formatParams(n?: number | null): string {
  if (n === null || n === undefined) return "—"
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`
  return String(n)
}

function formatBytes(n?: number): string {
  if (n === null || n === undefined) return "—"
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
}

const rowStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: "16px",
  borderBottom: "1px solid var(--gold-border)",
  paddingBottom: "8px",
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div style={rowStyle}>
      <span style={{ color: "var(--text-secondary)", display: "inline-flex", alignItems: "center", gap: "8px" }}>
        {icon} {label}
      </span>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.9rem" }}>{value}</span>
    </div>
  )
}

export function ArchitectureCard({ meta }: { meta?: FormatSpecificMeta | null }) {
  // Safe fallback: nothing meaningful to show (non-safetensors file,
  // deep scan failure, or an older scan cached before this field existed).
  const hasArchitecture =
    meta &&
    (meta.tensor_count !== undefined ||
      meta.total_declared_params !== undefined ||
      (meta.dtype_histogram && Object.keys(meta.dtype_histogram).length > 0))

  if (!hasArchitecture) return null

  const dtypes = Object.entries(meta!.dtype_histogram || {}).sort((a, b) => b[1] - a[1])
  const declared = Object.entries(meta!.declared_metadata || {})
  const unaccounted = meta!.unaccounted_data_bytes || 0

  return (
    <>
      <motion.h3 variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "16px", color: "var(--text-primary)" }}>
        Model Architecture
      </motion.h3>
      <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "40px" }}>
        <GlassCard style={{ padding: "24px", display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Headline stats */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px" }}>
            <Stat
              icon={<Layers size={16} color="var(--gold-bright)" />}
              label="Tensors"
              value={
                meta!.tensor_count !== undefined
                  ? `${meta!.tensor_count}${meta!.validated_tensors !== undefined ? ` (${meta!.validated_tensors} validated)` : ""}`
                  : "—"
              }
            />
            <Stat
              icon={<Cpu size={16} color="var(--gold-bright)" />}
              label="Declared Parameters"
              value={formatParams(meta!.total_declared_params)}
            />
            <Stat
              icon={<Database size={16} color="var(--gold-bright)" />}
              label="Header Size"
              value={formatBytes(meta!.header_size_bytes)}
            />
            <Stat
              icon={<Database size={16} color="var(--gold-bright)" />}
              label="Tensor Data"
              value={formatBytes(meta!.declared_data_bytes)}
            />
          </div>

          {/* Dtype histogram as gold chips */}
          {dtypes.length > 0 && (
            <div>
              <div style={{ color: "var(--text-secondary)", fontSize: "0.85rem", marginBottom: "8px", display: "inline-flex", alignItems: "center", gap: "8px" }}>
                <Binary size={14} color="var(--gold-bright)" /> Tensor dtypes
              </div>
              <motion.div
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true }}
                variants={{ hidden: {}, visible: { transition: { staggerChildren: 0.05 } } }}
                style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}
              >
                {dtypes.map(([dtype, count]) => (
                  <motion.span
                    key={dtype}
                    variants={{
                      hidden: { opacity: 0, scale: 0.85, y: 8 },
                      visible: { opacity: 1, scale: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } },
                    }}
                    whileHover={{ scale: 1.06, borderColor: "var(--gold-mid)" }}
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.8rem",
                      color: "var(--gold-bright)",
                      background: "rgba(201,168,76,0.08)",
                      border: "1px solid var(--gold-border)",
                      borderRadius: "var(--radius-sm)",
                      padding: "4px 10px",
                    }}
                  >
                    {dtype} × {count}
                  </motion.span>
                ))}
              </motion.div>
            </div>
          )}

          {/* Largest tensor */}
          {meta!.largest_tensor?.name && (
            <div style={rowStyle}>
              <span style={{ color: "var(--text-secondary)" }}>Largest Tensor</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--text-muted)", maxWidth: "60%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {meta!.largest_tensor.name} ({formatParams(meta!.largest_tensor.params)})
              </span>
            </div>
          )}

          {/* Unaccounted bytes — a forensic signal, highlight if non-zero */}
          {meta!.unaccounted_data_bytes !== undefined && (
            <div style={{ ...rowStyle, borderBottom: "none", paddingBottom: 0 }}>
              <span style={{ color: "var(--text-secondary)" }}>Unaccounted Data</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.9rem", color: unaccounted > 0 ? "var(--warn)" : "var(--text-muted)" }}>
                {unaccounted > 0 ? formatBytes(unaccounted) : "None"}
              </span>
            </div>
          )}

          {/* Declared __metadata__ (benign, surfaced keys only) */}
          {declared.length > 0 && (
            <details style={{ cursor: "pointer" }}>
              <summary style={{ color: "var(--gold-mid)", fontSize: "0.85rem", listStyle: "none" }}>
                Declared metadata ({declared.length})
              </summary>
              <div style={{ marginTop: "12px", display: "flex", flexDirection: "column", gap: "8px", cursor: "default" }}>
                {declared.map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", gap: "16px", fontSize: "0.85rem" }}>
                    <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>{k}</span>
                    <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-secondary)", maxWidth: "60%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(v)}</span>
                  </div>
                ))}
              </div>
            </details>
          )}
        </GlassCard>
      </motion.div>
    </>
  )
}
