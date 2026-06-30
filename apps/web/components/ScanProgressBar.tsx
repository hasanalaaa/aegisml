"use client"
import { motion } from "framer-motion"

/**
 * Shown only during the brief network round-trip of submitting a file/URL
 * to the backend (before the real per-scan progress page takes over at
 * /scan/[id], which is driven by real WebSocket events via useScanProgress).
 *
 * Previously this animated a fake 0-100% counter labeled "Analyzing
 * Tensors..." over a fixed 5 seconds, regardless of what was actually
 * happening — misleading because no analysis happens during this step at
 * all; the file is just being uploaded. This is now an honest indeterminate
 * indicator instead of a fabricated percentage.
 */
export function ScanProgressBar() {
  return (
    <div style={{ marginTop: "24px" }}>
      <div style={{ marginBottom: "8px", fontSize: "0.85rem", color: "var(--text-secondary)" }}>
        Uploading and queuing scan…
      </div>
      <div style={{
        height: 6, background: "var(--bg-subtle)", borderRadius: "var(--radius-sm)", overflow: "hidden",
        border: "1px solid rgba(201,168,76,0.1)", position: "relative"
      }}>
        <motion.div
          style={{
            position: "absolute", top: 0, bottom: 0, width: "40%",
            background: "var(--gold-gradient, var(--gold-mid))",
            boxShadow: "0 0 10px rgba(201,168,76,0.5)",
          }}
          animate={{ left: ["-40%", "100%"] }}
          transition={{ duration: 1.1, repeat: Infinity, ease: "easeInOut" }}
        />
      </div>
    </div>
  )
}
