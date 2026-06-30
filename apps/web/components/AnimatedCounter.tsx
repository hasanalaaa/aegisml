"use client"
import { useEffect } from "react"
import { motion, useMotionValue, useTransform, animate } from "framer-motion"
import { useInView } from "react-intersection-observer"

interface CounterProps {
  value: number
  label: string
  prefix?: string
  suffix?: string
}

export function AnimatedCounter({ value, label, prefix = "", suffix = "" }: CounterProps) {
  const { ref, inView } = useInView({ triggerOnce: true })
  const count = useMotionValue(0)
  const rounded = useTransform(count, v => Math.round(v).toLocaleString())

  useEffect(() => {
    if (inView) {
      animate(count, value, { duration: 2, ease: "easeOut" })
    }
  }, [inView, value, count])

  return (
    <div ref={ref} style={{ textAlign: "center" }}>
      <motion.span style={{ fontSize: "2.5rem", fontWeight: 800, fontFamily: "var(--font-display)", display: "flex", justifyContent: "center", alignItems: "center" }}>
        {prefix}
        <motion.span>{rounded}</motion.span>
        {suffix}
      </motion.span>
      <div style={{ color: "var(--text-secondary)", fontSize: "0.85rem", marginTop: "4px" }}>{label}</div>
    </div>
  )
}
