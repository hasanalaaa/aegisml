"use client"
import { motion } from "framer-motion"

interface CardProps {
  children: React.ReactNode
  glow?: boolean
  className?: string
  style?: React.CSSProperties
}

export function GlassCard({ children, glow, className, style }: CardProps) {
  return (
    <motion.div
      whileHover={{ y: -4, boxShadow: glow ? "var(--shadow-gold)" : "var(--shadow-float)" }}
      transition={{ duration: 0.3, ease: "easeOut" }}
      className={className}
      style={{
        background: "var(--bg-elevated)",
        border: "1px solid var(--gold-border)",
        borderRadius: "var(--radius-lg)",
        padding: "var(--space-8)",
        boxShadow: "var(--shadow-card)",
        backdropFilter: "blur(10px)",
        position: "relative",
        overflow: "hidden",
        ...style
      }}
    >
      {/* Corner glow accent */}
      <div style={{
        position: "absolute", top: 0, right: 0, width: "120px", height: "120px",
        background: "radial-gradient(circle at top right, rgba(201,168,76,0.06) 0%, transparent 70%)",
        pointerEvents: "none"
      }}/>
      {children}
    </motion.div>
  )
}
