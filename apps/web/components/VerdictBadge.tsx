"use client"
import { motion } from "framer-motion"

type Verdict = "safe" | "suspicious" | "dangerous" | "critical"

const VERDICT_CONFIG: Record<Verdict, { color: string; bg: string; glow: string; icon: string; label: string }> = {
  safe:       { color: "var(--safe)",     bg: "var(--safe-bg)",     glow: "var(--safe-glow)",     icon: "✓", label: "SAFE" },
  suspicious: { color: "var(--warn)",     bg: "var(--warn-bg)",     glow: "var(--warn-glow)",     icon: "⚠", label: "SUSPICIOUS" },
  dangerous:  { color: "var(--danger)",   bg: "var(--danger-bg)",   glow: "var(--danger-glow)",   icon: "✕", label: "DANGEROUS" },
  critical:   { color: "var(--critical)", bg: "var(--critical-bg)", glow: "var(--critical-glow)", icon: "☠", label: "CRITICAL" },
}

export function VerdictBadge({ verdict, large }: { verdict: Verdict; large?: boolean }) {
  const cfg = VERDICT_CONFIG[verdict]
  return (
    <motion.div
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
      style={{
        display: "inline-flex", alignItems: "center", gap: "8px",
        padding: large ? "16px 32px" : "6px 14px",
        borderRadius: large ? "var(--radius-lg)" : "var(--radius-sm)",
        background: cfg.bg,
        border: `1px solid ${cfg.color}30`,
        color: cfg.color,
        fontWeight: 700,
        fontSize: large ? "1.5rem" : "0.75rem",
        letterSpacing: "0.05em",
        boxShadow: verdict !== "safe" ? cfg.glow : "none",
        animation: verdict === "critical" ? "criticalPulse 2s ease-in-out infinite" : "none"
      }}
    >
      <span>{cfg.icon}</span>
      <span>{cfg.label}</span>
    </motion.div>
  )
}
