"use client"
import Link from "next/link"
import { motion } from "framer-motion"
import { ResiliencePanel } from "@/components/forensics/ResiliencePanel"
import { staggerContainer, riseItem } from "@/lib/animations"
import { RadarSweep } from "@/components/motion/RadarSweep"
import { Activity } from "lucide-react"

export default function OpsPage() {
  return (
    <main
      style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "48px", paddingBottom: "80px", color: "var(--text-primary)", position: "relative", overflow: "hidden" }}
    >
      {/* Ambient gold field */}
      <div
        aria-hidden
        style={{
          position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
          backgroundImage:
            "radial-gradient(1100px 560px at 82% -6%, rgba(212,175,55,0.12), transparent 60%), radial-gradient(760px 520px at 6% 2%, rgba(212,175,55,0.05), transparent 55%)",
        }}
      />
      {/* Continuous ops radar — the room is always watching */}
      <RadarSweep size={720} duration={9} opacity={0.16} style={{ position: "fixed", top: "-180px", insetInlineEnd: "-200px", zIndex: 0 }} />

      <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ position: "relative", zIndex: 1, maxWidth: "1180px", margin: "0 auto", padding: "0 24px" }}>

        {/* Header */}
        <motion.div variants={riseItem} style={{ marginBottom: "32px" }}>
          <Link href="/" style={{ color: "var(--text-secondary)", textDecoration: "none", fontSize: "0.9rem", display: "inline-flex", alignItems: "center", gap: "8px", marginBottom: "18px" }}>
            ← Back to Scanner
          </Link>
          <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "8px", flexWrap: "wrap" }}>
            <span className="section-label" style={{ color: "var(--gold-mid)" }}>Operations Command</span>
            <span className="tag tag-info" style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
              <Activity size={12} /> Phase 2 · Fault Tolerance
            </span>
            <span className="tag tag-low" style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
              <span style={{ position: "relative", width: "8px", height: "8px", display: "inline-block" }}>
                <span style={{ position: "absolute", inset: 0, borderRadius: "999px", background: "var(--safe)" }} />
                <span style={{ position: "absolute", inset: 0, borderRadius: "999px", background: "var(--safe)", animation: "pulseRing 2.2s ease-out infinite" }} />
              </span>
              LIVE TELEMETRY
            </span>
          </div>
          <h1 style={{ fontSize: "clamp(2.2rem, 4vw, 3.4rem)", margin: 0 }}>
            System <span className="gold-sheen-text">Resilience</span>
          </h1>
          <p style={{ color: "var(--text-secondary)", marginTop: "12px", maxWidth: "640px", lineHeight: 1.7 }}>
            Real-time fault-tolerance telemetry — AI-provider circuit-breaker states and size-class admission pressure — refreshed live from the scan engine.
          </p>
        </motion.div>

        <motion.div variants={riseItem}>
          <ResiliencePanel />
        </motion.div>
      </motion.div>
    </main>
  )
}
