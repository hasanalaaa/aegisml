"use client"
import { motion } from "framer-motion"
import Link from "next/link"

interface ButtonProps {
  children: React.ReactNode
  onClick?: (e?: any) => void
  href?: string
  loading?: boolean
  style?: React.CSSProperties
  className?: string
  disabled?: boolean
  type?: "button" | "submit" | "reset"
}

function Spinner() {
  return (
    <div style={{
      width: 16, height: 16,
      border: "2px solid rgba(0,0,0,0.2)",
      borderTopColor: "rgba(0,0,0,0.8)",
      borderRadius: "50%",
      animation: "spin 1s linear infinite"
    }} />
  )
}

export function PrimaryButton({ children, onClick, href, loading, style, className = "", disabled, type }: ButtonProps) {
  const inner = (
    <motion.button
      whileHover={{ scale: disabled ? 1 : 1.03, boxShadow: disabled ? "none" : "var(--shadow-gold)" }}
      whileTap={{ scale: disabled ? 1 : 0.97 }}
      className={`focus-visible:ring-2 focus-visible:ring-gold-mid ${className}`}
      disabled={disabled || loading}
      type={type || "button"}
      style={{
        display: "inline-flex", alignItems: "center", gap: "8px", justifyContent: "center",
        padding: "12px 28px", borderRadius: "var(--radius-md)",
        background: disabled ? "rgba(255,255,255,0.1)" : "linear-gradient(135deg, #8B6914 0%, #C9A84C 50%, #E4C46B 100%)",
        color: disabled ? "rgba(255,255,255,0.4)" : "#0A0A0F", fontWeight: 700, fontSize: "0.95rem",
        border: "none", cursor: disabled ? "not-allowed" : "pointer", fontFamily: "var(--font-display)",
        letterSpacing: "0.01em", position: "relative", overflow: "hidden",
        ...style
      }}
      onClick={onClick}
    >
      <motion.div
        animate={{ x: ["-100%", "100%"] }}
        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
        style={{
          position: "absolute", inset: 0,
          background: "linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.15) 50%, transparent 100%)",
          pointerEvents: "none"
        }}
      />
      {loading ? <Spinner /> : children}
    </motion.button>
  )
  return href ? <Link href={href}>{inner}</Link> : inner
}

export function GhostButton({ children, onClick, href, loading, style, className = "", disabled, type }: ButtonProps) {
  const inner = (
    <motion.button
      whileHover={{ scale: disabled ? 1 : 1.03, background: "rgba(255,255,255,0.05)" }}
      whileTap={{ scale: disabled ? 1 : 0.97 }}
      className={`focus-visible:ring-2 focus-visible:ring-gold-mid ${className}`}
      disabled={disabled || loading}
      type={type || "button"}
      style={{
        display: "inline-flex", alignItems: "center", gap: "8px", justifyContent: "center",
        padding: "12px 28px", borderRadius: "var(--radius-md)",
        background: "transparent",
        color: disabled ? "rgba(255,255,255,0.4)" : "var(--gold-bright)", fontWeight: 600, fontSize: "0.95rem",
        border: "1px solid " + (disabled ? "rgba(255,255,255,0.1)" : "var(--gold-border)"), 
        cursor: disabled ? "not-allowed" : "pointer", fontFamily: "var(--font-display)",
        ...style
      }}
      onClick={onClick}
    >
      {loading ? <Spinner /> : children}
    </motion.button>
  )
  return href ? <Link href={href}>{inner}</Link> : inner
}
