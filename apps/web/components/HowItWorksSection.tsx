"use client"
import { motion } from "framer-motion"
import { staggerContainer, fadeUpVariants } from "../lib/animations"

export function HowItWorksSection() {
  const steps = [
    { num: "01", title: "Upload Model", desc: "Drop your .gguf or .safetensors file securely." },
    { num: "02", title: "Static Analysis", desc: "AegisML inspects layers, tensors, and headers without executing code." },
    { num: "03", title: "Get Verdict", desc: "Receive a comprehensive threat report with a CVSS score." }
  ]

  return (
    <motion.div variants={staggerContainer} initial="hidden" whileInView="visible" viewport={{ once: true }}>
      <motion.div variants={fadeUpVariants} custom={0} style={{ textAlign: "center", marginBottom: "48px" }}>
        <h2>How It Works</h2>
        <p style={{ color: "var(--text-secondary)", marginTop: "16px" }}>Three simple steps to secure your ML supply chain.</p>
      </motion.div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "24px" }}>
        {steps.map((step, i) => (
          <motion.div key={step.num} variants={fadeUpVariants} custom={i + 1} style={{
            background: "var(--bg-elevated)", border: "1px solid var(--gold-border)",
            borderRadius: "var(--radius-lg)", padding: "32px", position: "relative",
            overflow: "hidden"
          }}>
            <div style={{
              fontSize: "3rem", fontWeight: 800, color: "var(--gold-subtle)",
              position: "absolute", top: -10, right: 10, fontFamily: "var(--font-display)"
            }}>{step.num}</div>
            <h3 style={{ marginBottom: "12px", color: "var(--gold-bright)", position: "relative" }}>{step.title}</h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", lineHeight: 1.6 }}>{step.desc}</p>
          </motion.div>
        ))}
      </div>
    </motion.div>
  )
}
