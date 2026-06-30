"use client"
import { motion } from "framer-motion"
import { staggerContainer, fadeUpVariants } from "../lib/animations"
import { GlassCard } from "./GlassCard"

export function FeaturesGrid() {
  const features = [
    { icon: "🛡️", title: "Pickle Code Execution", desc: "Detects hidden RCE payloads in legacy pickle and PyTorch formats." },
    { icon: "🧩", title: "Tensor Poisoning", desc: "Identifies statistically anomalous weights indicating a backdoor." },
    { icon: "⚙️", title: "Oversized Headers", desc: "Flags buffer overflow attempts in GGUF metadata headers." },
    { icon: "🕵️", title: "Network Traces", desc: "Finds embedded URLs and IPs phoning home." },
    { icon: "📦", title: "Format Validation", desc: "Ensures the file structure strictly adheres to the standard." },
    { icon: "⚡", title: "Multi-AI Engine", desc: "Cross-checks findings against Claude, GPT-4, and Gemini." },
  ]

  return (
    <motion.div variants={staggerContainer} initial="hidden" whileInView="visible" viewport={{ once: true }}>
      <motion.div variants={fadeUpVariants} custom={0} style={{ textAlign: "center", marginBottom: "48px" }}>
        <h2>Complete Threat Coverage</h2>
        <p style={{ color: "var(--text-secondary)", marginTop: "16px" }}>AegisML detects what traditional scanners miss.</p>
      </motion.div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "24px" }}>
        {features.map((f, i) => (
          <motion.div key={f.title} variants={fadeUpVariants} custom={i + 1}>
            <GlassCard style={{ height: "100%", display: "flex", flexDirection: "column", gap: "16px" }}>
              <div style={{ fontSize: "2rem" }}>{f.icon}</div>
              <h3 style={{ fontSize: "1.2rem", color: "var(--text-primary)" }}>{f.title}</h3>
              <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem", lineHeight: 1.6 }}>{f.desc}</p>
            </GlassCard>
          </motion.div>
        ))}
      </div>
    </motion.div>
  )
}
