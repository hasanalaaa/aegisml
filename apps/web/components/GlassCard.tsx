"use client"
import { motion } from "framer-motion"

interface CardProps {
  children: React.ReactNode
  glow?: boolean
  /** Animate in on mount with a blur-up reveal (default true). */
  reveal?: boolean
  className?: string
  style?: React.CSSProperties
}

export function GlassCard({ children, glow, reveal = true, className, style }: CardProps) {
  return (
    <motion.div
      initial={reveal ? { opacity: 0, y: 18, filter: "blur(6px)" } : false}
      whileInView={reveal ? { opacity: 1, y: 0, filter: "blur(0px)" } : undefined}
      viewport={reveal ? { once: true, margin: "-40px" } : undefined}
      whileHover={{ y: -4, boxShadow: glow ? "var(--shadow-gold)" : "var(--shadow-float)" }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
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
      {/* Corner glow accent (brass) */}
      <div style={{
        position: "absolute", top: 0, right: 0, width: "120px", height: "120px",
        background: "radial-gradient(circle at top right, rgba(212,175,55,0.06) 0%, transparent 70%)",
        pointerEvents: "none"
      }}/>
      {/* Hairline top highlight — the "machined edge" */}
      <div style={{
        position: "absolute", top: 0, left: "10%", right: "10%", height: "1px",
        background: "linear-gradient(90deg, transparent, rgba(212,175,55,0.25), transparent)",
        pointerEvents: "none"
      }}/>
      {children}
    </motion.div>
  )
}
