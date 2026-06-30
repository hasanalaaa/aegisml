"use client"

import { useScanProgress } from "@/hooks/useScanProgress"
import { motion } from "framer-motion"
import { ShieldAlert, CheckCircle, Activity, FileCode2, Zap } from "lucide-react"

export function ScanProgress({ scanId }: { scanId: string }) {
  const data = useScanProgress(scanId)

  const stages = [
    { id: "header_check", label: "Header Check", icon: FileCode2 },
    { id: "signature_scan", label: "Signature Scan", icon: Activity },
    { id: "ai_analysis", label: "AI Analysis", icon: Zap },
    { id: "complete", label: "Complete", icon: CheckCircle }
  ]

  const currentStageIndex = stages.findIndex(s => s.id === data.stage)

  return (
    <div style={{ maxWidth: "600px", margin: "0 auto", padding: "40px 20px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "16px" }}>
        <h3 style={{ margin: 0, color: "var(--text-primary)", fontSize: "1.2rem" }}>
          Scanning Model...
        </h3>
        <span style={{ color: "var(--gold-mid)", fontWeight: 700, fontSize: "1.2rem" }}>
          {data.progress.toFixed(0)}%
        </span>
      </div>

      {/* Progress Bar */}
      <div style={{ height: "8px", background: "var(--bg-subtle)", borderRadius: "999px", overflow: "hidden", marginBottom: "32px" }}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${data.progress}%` }}
          transition={{ ease: "easeOut", duration: 0.5 }}
          style={{ height: "100%", background: "var(--gold-mid)" }}
        />
      </div>

      {/* Stages */}
      <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginBottom: "32px" }}>
        {stages.map((stage, i) => {
          const isActive = i === currentStageIndex
          const isPast = i < currentStageIndex
          const isComplete = data.isComplete && i === stages.length - 1
          
          let color = "var(--text-muted)"
          if (isActive) color = "var(--gold-mid)"
          if (isPast || isComplete) color = "#10B981" // Green

          const Icon = stage.icon

          return (
            <div key={stage.id} style={{ display: "flex", alignItems: "center", gap: "16px" }}>
              <div style={{
                width: "32px", height: "32px", borderRadius: "50%",
                background: isActive ? "rgba(201, 168, 76, 0.1)" : isPast ? "rgba(16, 185, 129, 0.1)" : "var(--bg-subtle)",
                color: color,
                display: "flex", alignItems: "center", justifyContent: "center",
                border: `1px solid ${isActive ? "var(--gold-mid)" : isPast ? "#10B981" : "transparent"}`
              }}>
                <Icon size={16} />
              </div>
              <span style={{ color: color, fontWeight: isActive ? 600 : 400, flex: 1 }}>
                {stage.label}
              </span>
              {isActive && (
                <motion.div
                  animate={{ opacity: [0.5, 1, 0.5] }}
                  transition={{ repeat: Infinity, duration: 1.5 }}
                  style={{ width: "8px", height: "8px", borderRadius: "50%", background: "var(--gold-mid)" }}
                />
              )}
            </div>
          )
        })}
      </div>

      {/* Live Threat Counter */}
      <div style={{
        padding: "16px", background: data.threatCount > 0 ? "rgba(239, 68, 68, 0.05)" : "var(--bg-subtle)",
        borderRadius: "var(--radius-lg)", border: `1px solid ${data.threatCount > 0 ? "rgba(239, 68, 68, 0.2)" : "var(--border)"}`,
        display: "flex", alignItems: "center", gap: "16px"
      }}>
        <div style={{ color: data.threatCount > 0 ? "#EF4444" : "var(--text-muted)" }}>
          <ShieldAlert size={24} />
        </div>
        <div style={{ flex: 1 }}>
          <h4 style={{ margin: 0, color: "var(--text-primary)", fontSize: "1rem" }}>Threats Detected</h4>
          <p style={{ margin: 0, color: "var(--text-secondary)", fontSize: "0.85rem" }}>Live threat analysis</p>
        </div>
        <span style={{ fontSize: "1.5rem", fontWeight: 700, color: data.threatCount > 0 ? "#EF4444" : "var(--text-primary)" }}>
          {data.threatCount}
        </span>
      </div>
    </div>
  )
}
