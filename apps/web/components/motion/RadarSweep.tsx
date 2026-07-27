"use client"
import { motion } from "framer-motion"

interface RadarSweepProps {
  /** Square size in px. */
  size?: number
  /** RGB triplet string, e.g. "212, 175, 55". */
  color?: string
  /** Seconds per full rotation. */
  duration?: number
  opacity?: number
  className?: string
  style?: React.CSSProperties
}

/**
 * Continuous conic radar sweep with range rings, crosshairs, and a pulsing
 * core — pure ambient decoration for ops/scan surfaces. Position it inside a
 * `position: relative; overflow: hidden` parent.
 */
export function RadarSweep({
  size = 420,
  color = "212, 175, 55",
  duration = 7,
  opacity = 1,
  className,
  style,
}: RadarSweepProps) {
  return (
    <div
      aria-hidden
      className={className}
      style={{ position: "absolute", width: size, height: size, pointerEvents: "none", opacity, ...style }}
    >
      {/* range rings */}
      {[0.3, 0.55, 0.8].map((r) => (
        <div
          key={r}
          style={{
            position: "absolute",
            inset: `${((1 - r) / 2) * 100}%`,
            borderRadius: "50%",
            border: `1px solid rgba(${color}, 0.10)`,
          }}
        />
      ))}
      {/* crosshairs */}
      <div style={{ position: "absolute", left: "50%", top: 0, bottom: 0, width: 1, background: `linear-gradient(180deg, transparent, rgba(${color}, 0.08), transparent)` }} />
      <div style={{ position: "absolute", top: "50%", left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, rgba(${color}, 0.08), transparent)` }} />
      {/* rotating beam */}
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ repeat: Infinity, duration, ease: "linear" }}
        style={{
          position: "absolute",
          inset: 0,
          borderRadius: "50%",
          background: `conic-gradient(from 0deg, rgba(${color}, 0.22) 0deg, rgba(${color}, 0.06) 42deg, transparent 74deg, transparent 360deg)`,
          maskImage: "radial-gradient(circle, black 0%, black 78%, transparent 80%)",
          WebkitMaskImage: "radial-gradient(circle, black 0%, black 78%, transparent 80%)",
        }}
      />
      {/* pulsing core ring */}
      <motion.div
        animate={{ scale: [1, 2.8], opacity: [0.5, 0] }}
        transition={{ repeat: Infinity, duration: 2.4, ease: "easeOut" }}
        style={{
          position: "absolute", left: "50%", top: "50%",
          width: 12, height: 12, marginLeft: -6, marginTop: -6,
          borderRadius: "50%", border: `1px solid rgba(${color}, 0.55)`,
        }}
      />
      <div
        style={{
          position: "absolute", left: "50%", top: "50%",
          width: 4, height: 4, marginLeft: -2, marginTop: -2,
          borderRadius: "50%", background: `rgba(${color}, 0.9)`,
          boxShadow: `0 0 12px rgba(${color}, 0.8)`,
        }}
      />
    </div>
  )
}
