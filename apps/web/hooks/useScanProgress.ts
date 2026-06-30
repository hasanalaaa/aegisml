import { useState, useEffect } from "react"

interface ScanProgressData {
  progress: number
  stage: "header_check" | "signature_scan" | "ai_analysis" | "complete" | "failed"
  threatCount: number
  isComplete: boolean
}

export function useScanProgress(scanId: string) {
  const [data, setData] = useState<ScanProgressData>({
    progress: 0,
    stage: "header_check",
    threatCount: 0,
    isComplete: false,
  })

  useEffect(() => {
    if (!scanId) return

    let ws: WebSocket | null = null
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000"

    try {
      ws = new WebSocket(`${wsUrl}/ws/scan/${scanId}`)

      ws.onmessage = (event) => {
        const payload = JSON.parse(event.data)
        setData(prev => ({
          ...prev,
          progress: payload.progress ?? prev.progress,
          stage: payload.stage ?? prev.stage,
          threatCount: payload.threat_count ?? prev.threatCount,
          isComplete: payload.stage === "complete" || payload.stage === "failed"
        }))
      }

      ws.onerror = () => {
        console.warn("WebSocket failed, fallback to SSE not fully implemented here but possible")
      }
    } catch (e) {
      console.warn("WebSocket connection failed", e)
    }

    return () => {
      if (ws) ws.close()
    }
  }, [scanId])

  return data
}
