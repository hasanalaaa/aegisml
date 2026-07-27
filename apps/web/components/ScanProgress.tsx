"use client"

import { useEffect } from "react"
import type { ScanProgressData } from "@/hooks/useScanProgress"
import { motion, AnimatePresence } from "framer-motion"
import { NumberTicker } from "@/components/NumberTicker"
import { RadarSweep } from "@/components/motion/RadarSweep"
import { tactileSpring } from "@/lib/animations"
import { toast } from "sonner"
import Link from "next/link"
import { ShieldAlert, CheckCircle, Activity, FileCode2, Zap, WifiOff, RefreshCw } from "lucide-react"

export function ScanProgress({ progressData: data }: { progressData: ScanProgressData }) {

  // Surface a real failure once, instead of an infinite 0% spinner.
  useEffect(() => {
    if (data.status === "error" && data.error) {
      toast.error("Scan stopped", { description: data.error })
    }
  }, [data.status, data.error])

  // ── Error state ────────────────────────────────────────────────
  if (data.status === "error") {
    return (
      <motion.div
        initial={{ opacity: 0, y: 16, filter: "blur(6px)" }}
        animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        style={{ maxWidth: "600px", margin: "0 auto", padding: "40px 20px", textAlign: "center" }}
      >
        <div style={{ display: "grid", placeItems: "center", marginBottom: "16px", color: "var(--danger)" }}>
          <WifiOff size={40} />
        </div>
        <h3 style={{ margin: "0 0 8px 0", color: "var(--text-primary)", fontSize: "1.25rem" }}>
          Scan stopped
        </h3>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", marginBottom: "24px", lineHeight: 1.6 }}>
          {data.error || "The scan did not complete."}
        </p>
        <div style={{ display: "flex", gap: "12px", justifyContent: "center", flexWrap: "wrap" }}>
          <motion.button
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            transition={tactileSpring}
            onClick={() => window.location.reload()}
            style={{
              display: "inline-flex", alignItems: "center", gap: "8px",
              padding: "10px 18px", borderRadius: "var(--radius-sm)", cursor: "pointer",
              background: "var(--brass-mid)", color: "#1c1608", border: "none", fontWeight: 700, fontSize: "0.9rem",
            }}
          >
            <RefreshCw size={16} /> Retry
          </motion.button>
          <Link
            href="/"
            style={{
              display: "inline-flex", alignItems: "center", padding: "10px 18px",
              borderRadius: "var(--radius-sm)", textDecoration: "none",
              background: "transparent", color: "var(--text-secondary)", border: "1px solid var(--border)", fontSize: "0.9rem",
            }}
          >
            Start a new scan
          </Link>
        </div>
      </motion.div>
    )
  }

  // Canonical pipeline — matches the backend's persisted stage vocabulary
  // (header_check → parallel_analysis → ai_analysis → complete). The hook
  // normalizes every raw engine stage (signature_scan, entropy_scan, …) into
  // one of these buckets, so findIndex can never miss.
  const stages = [
    { id: "header_check", label: "Header Check", icon: FileCode2 },
    { id: "parallel_analysis", label: "Parallel Analysis", icon: Activity },
    { id: "ai_analysis", label: "AI Analysis", icon: Zap },
    { id: "complete", label: "Complete", icon: CheckCircle },
  ]

  const currentStageIndex = Math.max(0, stages.findIndex((s) => s.id === data.stage))

  const heading =
    data.status === "connecting" ? "Connecting to scan engine…" : "Scanning Model…"

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      style={{ maxWidth: "640px", margin: "0 auto", padding: "24px 20px" }}
    >
      {/* Command-console shell — ambient radar sweep + continuously glowing border */}
      <motion.div
        animate={{
          boxShadow: [
            "0 0 0 1px rgba(212,175,55,0.16), 0 0 28px rgba(212,175,55,0.07)",
            "0 0 0 1px rgba(212,175,55,0.34), 0 0 56px rgba(212,175,55,0.16)",
            "0 0 0 1px rgba(212,175,55,0.16), 0 0 28px rgba(212,175,55,0.07)",
          ],
        }}
        transition={{ duration: 3.2, repeat: Infinity, ease: "easeInOut" }}
        style={{
          position: "relative", overflow: "hidden",
          borderRadius: "var(--radius-xl)", border: "1px solid var(--brass-border)",
          background: "linear-gradient(180deg, rgba(16,16,18,0.92), rgba(8,8,9,0.96))",
          padding: "36px 28px", backdropFilter: "blur(20px)",
        }}
      >
        <RadarSweep size={520} opacity={0.28} style={{ left: "50%", top: "50%", transform: "translate(-50%, -50%)" }} />
        <div style={{ position: "relative", zIndex: 1 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h3 style={{ margin: 0, color: "var(--text-primary)", fontSize: "1.2rem" }}>
          {heading}
        </h3>
        <span style={{ color: "var(--gold-mid)", fontWeight: 700, fontSize: "1.35rem", textShadow: "0 0 24px rgba(212,175,55,0.35)" }}>
          <NumberTicker value={data.progress} suffix="%" preset="snappy" inViewOnly={false} />
        </span>
      </div>

      <AnimatePresence>
        {data.status === "polling" && (
          <motion.p
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            style={{ margin: "0 0 16px 0", color: "var(--text-muted)", fontSize: "0.8rem", overflow: "hidden" }}
          >
            Live stream unavailable — tracking progress via periodic status checks.
          </motion.p>
        )}
      </AnimatePresence>

      {/* Progress Bar — sprung fill + traveling sheen */}
      <div style={{ height: "8px", background: "var(--bg-subtle)", borderRadius: "999px", overflow: "hidden", marginBottom: "32px", position: "relative" }}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${data.progress}%` }}
          transition={{ type: "spring", stiffness: 60, damping: 20 }}
          style={{
            height: "100%",
            background: "linear-gradient(90deg, var(--brass-deep), var(--brass-mid) 60%, var(--brass-light))",
            borderRadius: "999px",
            position: "relative",
            overflow: "hidden",
            boxShadow: "0 0 16px rgba(212,175,55,0.35)",
          }}
        >
          <motion.div
            animate={{ x: ["-100%", "250%"] }}
            transition={{ repeat: Infinity, duration: 1.8, ease: "easeInOut" }}
            style={{
              position: "absolute", inset: 0, width: "40%",
              background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.35), transparent)",
            }}
          />
        </motion.div>
      </div>

      {/* Stages — staggered mount, sprung active indicator */}
      <motion.div
        initial="hidden"
        animate="visible"
        variants={{ hidden: {}, visible: { transition: { staggerChildren: 0.08, delayChildren: 0.15 } } }}
        style={{ display: "flex", flexDirection: "column", gap: "16px", marginBottom: "24px" }}
      >
        {stages.map((stage, i) => {
          const isActive = i === currentStageIndex && !data.isComplete
          const isPast = i < currentStageIndex || (data.isComplete && i < stages.length - 1)
          const isComplete = data.isComplete && i === stages.length - 1

          let color = "var(--text-muted)"
          if (isActive) color = "var(--gold-mid)"
          if (isPast || isComplete) color = "#10B981" // Green

          const Icon = stage.icon

          return (
            <motion.div
              key={stage.id}
              variants={{
                hidden: { opacity: 0, x: -16 },
                visible: { opacity: 1, x: 0, transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] } },
              }}
              style={{ display: "flex", alignItems: "center", gap: "16px" }}
            >
              <motion.div
                animate={{
                  scale: isActive ? 1.08 : 1,
                  boxShadow: isActive ? "0 0 20px rgba(212,175,55,0.25)" : "0 0 0px rgba(0,0,0,0)",
                }}
                transition={tactileSpring}
                style={{
                  width: "32px", height: "32px", borderRadius: "50%",
                  background: isActive ? "rgba(212, 175, 55, 0.1)" : (isPast || isComplete) ? "rgba(16, 185, 129, 0.1)" : "var(--bg-subtle)",
                  color,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  border: `1px solid ${isActive ? "var(--gold-mid)" : (isPast || isComplete) ? "#10B981" : "transparent"}`,
                }}
              >
                <Icon size={16} />
              </motion.div>
              <span style={{ color, fontWeight: isActive ? 600 : 400, flex: 1, transition: "color 0.4s ease" }}>
                {stage.label}
              </span>
              {isActive && (
                <motion.div
                  layoutId="stage-pulse"
                  animate={{ opacity: [0.5, 1, 0.5], scale: [1, 1.25, 1] }}
                  transition={{ repeat: Infinity, duration: 1.5 }}
                  style={{ width: "8px", height: "8px", borderRadius: "50%", background: "var(--gold-mid)", boxShadow: "0 0 12px rgba(212,175,55,0.6)" }}
                />
              )}
            </motion.div>
          )
        })}
      </motion.div>

      {/* Engine status line — live message from the scanner, crossfaded */}
      <AnimatePresence mode="wait">
        {data.message && (
          <motion.p
            key={data.message}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.3 }}
            style={{ margin: "0 0 24px 0", color: "var(--text-muted)", fontSize: "0.82rem", fontFamily: "var(--font-mono)", textAlign: "center" }}
          >
            {data.message}
          </motion.p>
        )}
      </AnimatePresence>

      {/* Live Threat Counter */}
      <motion.div
        animate={{
          background: data.threatCount > 0 ? "rgba(239, 68, 68, 0.05)" : "var(--bg-subtle)",
          borderColor: data.threatCount > 0 ? "rgba(239, 68, 68, 0.2)" : "var(--border)",
        }}
        style={{
          padding: "16px",
          borderRadius: "var(--radius-lg)", border: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: "16px",
        }}
      >
        <motion.div
          animate={data.threatCount > 0 ? { scale: [1, 1.15, 1] } : { scale: 1 }}
          transition={{ duration: 0.4 }}
          style={{ color: data.threatCount > 0 ? "var(--danger)" : "var(--text-muted)" }}
        >
          <ShieldAlert size={24} />
        </motion.div>
        <div style={{ flex: 1 }}>
          <h4 style={{ margin: 0, color: "var(--text-primary)", fontSize: "1rem" }}>Threats Detected</h4>
          <p style={{ margin: 0, color: "var(--text-secondary)", fontSize: "0.85rem" }}>Live threat analysis</p>
        </div>
        <span style={{ fontSize: "1.5rem", fontWeight: 700, color: data.threatCount > 0 ? "var(--danger)" : "var(--text-primary)" }}>
          <NumberTicker value={data.threatCount} preset="snappy" inViewOnly={false} />
        </span>
      </motion.div>
        </div>
      </motion.div>
    </motion.div>
  )
}
