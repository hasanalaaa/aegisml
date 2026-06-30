"use client"
import { useEffect, useRef, useState } from "react"

export function SentinelRing({ scanning = false, size = 400 }: { scanning?: boolean; size?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  useEffect(() => {
    if (!mounted) return
    const canvas = canvasRef.current!
    const ctx = canvas.getContext("2d")!
    canvas.width = size
    canvas.height = size
    const cx = size / 2, cy = size / 2
    let frame = 0, animId: number

    function hexPoints(cx: number, cy: number, r: number) {
      return Array.from({length: 6}, (_, i) => {
        const a = (Math.PI / 3) * i - Math.PI / 6
        return [cx + r * Math.cos(a), cy + r * Math.sin(a)]
      })
    }

    function drawHex(cx: number, cy: number, r: number, opacity: number, stroke: string) {
      const pts = hexPoints(cx, cy, r)
      ctx.beginPath()
      ctx.moveTo(pts[0][0], pts[0][1])
      pts.slice(1).forEach(p => ctx.lineTo(p[0], p[1]))
      ctx.closePath()
      ctx.strokeStyle = stroke
      ctx.globalAlpha = opacity
      ctx.lineWidth = 1
      ctx.stroke()
      ctx.globalAlpha = 1
    }

    function draw() {
      ctx.clearRect(0, 0, size, size)
      const t = frame * 0.005
      const goldColor = "#C9A84C"
      const cyanColor = "#00D4FF"

      // Rotating hex rings
      for (let ring = 3; ring <= 9; ring += 2) {
        const r = ring * (size / 24)
        const opacity = scanning ? 0.15 + Math.sin(t * 2 + ring) * 0.1 : 0.08 + Math.sin(t + ring) * 0.04
        ctx.save()
        ctx.translate(cx, cy)
        ctx.rotate(t * (ring % 2 === 0 ? 0.3 : -0.2))
        ctx.translate(-cx, -cy)
        drawHex(cx, cy, r, opacity, goldColor)
        ctx.restore()
      }

      // Radar sweep when scanning
      if (scanning) {
        const sweepAngle = (t * 3) % (Math.PI * 2)
        const grad = ctx.createConicGradient
          ? ctx.createConicGradient(sweepAngle, cx, cy)
          : null

        // Fallback: draw arc sweep
        ctx.save()
        ctx.beginPath()
        ctx.moveTo(cx, cy)
        ctx.arc(cx, cy, size * 0.45, sweepAngle, sweepAngle + Math.PI * 0.4)
        ctx.closePath()
        const sweepGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, size * 0.45)
        sweepGrad.addColorStop(0, "rgba(0, 212, 255, 0)")
        sweepGrad.addColorStop(0.7, "rgba(0, 212, 255, 0.08)")
        sweepGrad.addColorStop(1, "rgba(0, 212, 255, 0.20)")
        ctx.fillStyle = sweepGrad
        ctx.fill()
        ctx.restore()

        // Pulse rings
        const pulseProgress = ((frame % 120) / 120)
        const pr = pulseProgress * size * 0.45
        ctx.beginPath()
        ctx.arc(cx, cy, pr, 0, Math.PI * 2)
        ctx.strokeStyle = cyanColor
        ctx.globalAlpha = (1 - pulseProgress) * 0.5
        ctx.lineWidth = 1.5
        ctx.stroke()
        ctx.globalAlpha = 1
      }

      // Center glow
      const centerGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, size * 0.15)
      centerGrad.addColorStop(0, "rgba(201, 168, 76, 0.20)")
      centerGrad.addColorStop(1, "rgba(201, 168, 76, 0)")
      ctx.beginPath()
      ctx.arc(cx, cy, size * 0.15, 0, Math.PI * 2)
      ctx.fillStyle = centerGrad
      ctx.fill()

      // Floating particles
      for (let i = 0; i < 12; i++) {
        const angle = (i / 12) * Math.PI * 2 + t * 0.5
        const r = size * 0.35 + Math.sin(t * 2 + i) * size * 0.05
        const px = cx + r * Math.cos(angle)
        const py = cy + r * Math.sin(angle)
        const pSize = 1.5 + Math.sin(t + i) * 0.5
        ctx.beginPath()
        ctx.arc(px, py, pSize, 0, Math.PI * 2)
        ctx.fillStyle = goldColor
        ctx.globalAlpha = 0.4 + Math.sin(t * 3 + i) * 0.3
        ctx.fill()
        ctx.globalAlpha = 1
      }

      frame++
      animId = requestAnimationFrame(draw)
    }

    draw()
    return () => cancelAnimationFrame(animId)
  }, [scanning, size])

  return (
    <canvas
      ref={canvasRef}
      style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)" }}
    />
  )
}
