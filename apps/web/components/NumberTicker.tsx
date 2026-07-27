"use client"
import { useEffect, useRef } from "react"
import { useMotionValue, useSpring, useInView } from "framer-motion"

interface NumberTickerProps {
  value: number
  /** Decimal places to render. */
  decimals?: number
  prefix?: string
  suffix?: string
  /** Start animating only when scrolled into view (default true). */
  inViewOnly?: boolean
  /** Spring stiffness/damping presets: "smooth" for big stats, "snappy" for live progress. */
  preset?: "smooth" | "snappy"
  className?: string
  style?: React.CSSProperties
}

/**
 * Buttery count-up ticker driven by a framer-motion spring. Writes straight to
 * the DOM node (no React re-render per frame), respects prefers-reduced-motion,
 * and re-animates whenever `value` changes — so it doubles as a live progress
 * readout (0 → 40 → 70 → 100) and a mount-time stat reveal (0 → CVSS 9.8).
 */
export function NumberTicker({
  value,
  decimals = 0,
  prefix = "",
  suffix = "",
  inViewOnly = true,
  preset = "smooth",
  className,
  style,
}: NumberTickerProps) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true, margin: "-40px" })
  const active = inViewOnly ? inView : true

  const motionValue = useMotionValue(0)
  const spring = useSpring(motionValue, preset === "snappy"
    ? { stiffness: 90, damping: 22, mass: 0.6 }
    : { stiffness: 45, damping: 18, mass: 1 })

  useEffect(() => {
    if (!active) return
    if (typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      motionValue.jump(value)
      spring.jump(value)
      if (ref.current) ref.current.textContent = `${prefix}${value.toFixed(decimals)}${suffix}`
      return
    }
    motionValue.set(value)
  }, [active, value, motionValue, spring, prefix, suffix, decimals])

  useEffect(() => {
    const unsub = spring.on("change", (latest) => {
      if (ref.current) {
        ref.current.textContent = `${prefix}${latest.toFixed(decimals)}${suffix}`
      }
    })
    return unsub
  }, [spring, prefix, suffix, decimals])

  return (
    <span
      ref={ref}
      className={className}
      style={{ fontVariantNumeric: "tabular-nums", ...style }}
    >
      {`${prefix}${(0).toFixed(decimals)}${suffix}`}
    </span>
  )
}
