"use client"
import { motion, AnimatePresence } from "framer-motion"
import { X, Command } from "lucide-react"

interface Props {
  isOpen: boolean
  onClose: () => void
}

const shortcuts = [
  { key: "K", label: "Focus scan / Home" },
  { key: "D", label: "Dashboard" },
  { key: "T", label: "Threats Database" },
  { key: "M", label: "HF Monitor Feed" },
  { key: "?", label: "Show shortcuts menu" },
]

export function KeyboardShortcutsModal({ isOpen, onClose }: Props) {
  return (
    <AnimatePresence>
      {isOpen && (
        <div style={{ position: "fixed", inset: 0, zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center", padding: "24px" }}>
          <motion.div 
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} 
            onClick={onClose}
            style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,0.8)", backdropFilter: "blur(4px)" }} 
          />
          <motion.div 
            initial={{ opacity: 0, scale: 0.95, y: 20 }} 
            animate={{ opacity: 1, scale: 1, y: 0 }} 
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            style={{ position: "relative", width: "100%", maxWidth: "400px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden", boxShadow: "0 20px 40px rgba(0,0,0,0.4)" }}
          >
            <div style={{ padding: "20px 24px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", fontWeight: 600, color: "var(--text-primary)" }}>
                <Command size={18} /> Keyboard Shortcuts
              </div>
              <button onClick={onClose} style={{ background: "transparent", border: "none", color: "var(--text-secondary)", cursor: "pointer", padding: "4px" }} aria-label="Close shortcuts">
                <X size={18} />
              </button>
            </div>
            <div style={{ padding: "24px" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                {shortcuts.map(s => (
                  <div key={s.key} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ color: "var(--text-secondary)", fontSize: "0.95rem" }}>{s.label}</span>
                    <kbd style={{ background: "var(--bg-subtle)", border: "1px solid var(--border)", borderRadius: "4px", padding: "4px 8px", fontSize: "0.85rem", fontFamily: "var(--font-mono)", color: "var(--text-primary)", fontWeight: 500, minWidth: "28px", textAlign: "center" }}>
                      {s.key}
                    </kbd>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}
