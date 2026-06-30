"use client"
import { motion } from "framer-motion"

export function AIProvidersSection() {
  const providers = ["Claude 3.5 Sonnet", "GPT-4o", "Gemini 1.5 Pro", "Mistral Large", "Ollama"]
  
  return (
    <div style={{ textAlign: "center", borderTop: "1px solid var(--gold-border)", borderBottom: "1px solid var(--gold-border)", padding: "48px 0" }}>
      <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "32px", fontWeight: 600 }}>
        Powered By Multi-AI Intelligence
      </p>
      <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "center", gap: "40px", opacity: 0.5 }}>
        {providers.map(p => (
          <span key={p} style={{ fontSize: "1.2rem", fontWeight: 700, fontFamily: "var(--font-display)", color: "var(--text-secondary)" }}>
            {p}
          </span>
        ))}
      </div>
    </div>
  )
}
