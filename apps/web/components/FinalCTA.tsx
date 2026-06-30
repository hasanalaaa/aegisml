"use client"
import { motion } from "framer-motion"
import { PrimaryButton } from "./Buttons"
import { fadeUpVariants } from "../lib/animations"

export function FinalCTA() {
  return (
    <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUpVariants} style={{
      background: "radial-gradient(circle at center, rgba(201,168,76,0.1) 0%, transparent 70%)",
      padding: "80px 24px", borderRadius: "var(--radius-xl)", border: "1px solid rgba(201,168,76,0.15)",
      display: "flex", flexDirection: "column", alignItems: "center", gap: "24px"
    }}>
      <h2 style={{ fontSize: "clamp(2rem, 4vw, 3.5rem)" }}>Trust No Model.</h2>
      <p style={{ color: "var(--text-secondary)", fontSize: "1.1rem", maxWidth: "600px", lineHeight: 1.6 }}>
        Start scanning your machine learning artifacts today. Free for public models, enterprise-ready for private infrastructure.
      </p>
      <PrimaryButton href="/scan" style={{ marginTop: "16px", padding: "16px 40px", fontSize: "1.1rem" }}>
        Start Free Scan
      </PrimaryButton>
    </motion.div>
  )
}
