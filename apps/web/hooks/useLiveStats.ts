import { useState, useEffect } from "react"

interface LiveStatsData {
  totalScans: number
  threatsFound: number
  activeScans: number
  isLive: boolean
}

export function useLiveStats() {
  const [stats, setStats] = useState<LiveStatsData>({
    totalScans: 0,
    threatsFound: 0,
    activeScans: 0,
    isLive: false,
  })

  useEffect(() => {
    let ws: WebSocket | null = null
    let reconnectTimer: NodeJS.Timeout
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000"

    const connect = () => {
      try {
        ws = new WebSocket(`${wsUrl}/ws/stats`)

        ws.onopen = () => {
          setStats(prev => ({ ...prev, isLive: true }))
        }

        ws.onmessage = (event) => {
          const payload = JSON.parse(event.data)
          setStats(prev => ({
            totalScans: payload.total_scans ?? prev.totalScans,
            threatsFound: payload.threats_found ?? prev.threatsFound,
            activeScans: payload.active_scans ?? prev.activeScans,
            isLive: true,
          }))
        }

        ws.onclose = () => {
          setStats(prev => ({ ...prev, isLive: false }))
          reconnectTimer = setTimeout(connect, 3000)
        }
      } catch (e) {
        setStats(prev => ({ ...prev, isLive: false }))
        reconnectTimer = setTimeout(connect, 3000)
      }
    }

    connect()

    return () => {
      clearTimeout(reconnectTimer)
      if (ws) {
        ws.onclose = null // prevent reconnect on unmount
        ws.close()
      }
    }
  }, [])

  return stats
}
