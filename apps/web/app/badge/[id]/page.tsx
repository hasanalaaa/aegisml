"use client"
import { ShieldCheck, ShieldAlert } from "lucide-react"

import { use } from "react"

export default function BadgePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  // Mock logic for status
  const isSafe = true;

  return (
    <div style={{
      minHeight: "100vh", background: "var(--bg-void)", display: "flex", alignItems: "center", justifyContent: "center"
    }}>
      <div style={{
        display: "inline-flex", alignItems: "center", gap: "8px",
        background: isSafe ? "rgba(16,185,129,0.1)" : "rgba(239,68,68,0.1)",
        border: `1px solid ${isSafe ? "rgba(16,185,129,0.2)" : "rgba(239,68,68,0.2)"}`,
        padding: "4px 12px", borderRadius: "999px",
        fontFamily: "var(--font-sans), sans-serif", color: isSafe ? "#10B981" : "#EF4444",
        fontSize: "0.85rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em",
        textDecoration: "none"
      }}>
        {isSafe ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
        <span>AegisML: {isSafe ? "Safe" : "Dangerous"}</span>
      </div>
    </div>
  )
}
