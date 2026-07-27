import { useState, useEffect, useCallback } from "react"
import { API_BASE_URL } from "@/lib/api"

export interface PlatformStats {
  total: number
  clean: number
  suspicious: number
  malicious: number
  critical: number
  avg_risk_score: number
  last_updated?: string
}

export interface RecentScan {
  scan_id: string
  filename: string
  risk_score: number
  risk_level: string
  verdict: string
  threats_count: number
  created_at: string | null
}

export interface DashboardData {
  loading: boolean
  error: string | null
  stats: PlatformStats | null
  recent: RecentScan[]
  reload: () => void
}

// Single source of truth for live dashboard stats and recent public scans.
export function useDashboardData(recentLimit = 6): DashboardData {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [stats, setStats] = useState<PlatformStats | null>(null)
  const [recent, setRecent] = useState<RecentScan[]>([])
  const [nonce, setNonce] = useState(0)

  const reload = useCallback(() => setNonce((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    const ctrl = new AbortController()
    setLoading(true)
    setError(null)

    ;(async () => {
      try {
        const [sRes, rRes] = await Promise.all([
          fetch(`${API_BASE_URL}/api/v1/stats`, { signal: ctrl.signal, cache: "no-store" }),
          fetch(`${API_BASE_URL}/api/v1/scans/recent?limit=${recentLimit}`, { signal: ctrl.signal, cache: "no-store" }),
        ])
        if (!sRes.ok) throw new Error(`Live stats unavailable (${sRes.status})`)
        const s = (await sRes.json()) as PlatformStats
        const r = rRes.ok ? await rRes.json() : []
        if (cancelled) return
        setStats(s)
        setRecent(Array.isArray(r) ? (r as RecentScan[]) : [])
      } catch (e) {
        if (cancelled || (e as { name?: string })?.name === "AbortError") return
        setError(e instanceof Error ? e.message : "Failed to load dashboard data")
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()

    return () => {
      cancelled = true
      ctrl.abort()
    }
  }, [recentLimit, nonce])

  return { loading, error, stats, recent, reload }
}
