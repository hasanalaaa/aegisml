import { useState, useEffect, useCallback, useRef } from "react"
import { API_BASE_URL } from "@/lib/api"

/* ── Backend shapes (mirror /api/v1/ops/resilience) ───────────────── */

export type CircuitState = "closed" | "open" | "half_open"

export interface CircuitSnapshot {
  name: string
  state: CircuitState
  consecutive_failures: number
  total_successes: number
  total_failures: number
  times_opened: number
  failure_threshold: number
  reset_timeout_seconds: number
}

export interface AdmissionStats {
  permits?: Record<string, number>
  in_flight?: Record<string, number>
  waiting?: Record<string, number>
  thresholds?: { small_max_bytes?: number; large_min_bytes?: number }
}

export interface ResilienceSummary {
  providers: number
  open_circuits: number
  degraded_circuits: number
  scans_in_flight: number
  scans_waiting: number
}

export interface ResilienceSnapshot {
  posture: "nominal" | "degraded" | "critical"
  circuits: CircuitSnapshot[]
  admission: AdmissionStats
  summary: ResilienceSummary
  timestamp: string
}

export interface ResilienceState {
  data: ResilienceSnapshot | null
  loading: boolean
  error: string | null
  /** True after at least one successful fetch — used to keep charts mounted
   *  across subsequent transient errors instead of flashing skeletons. */
  hasData: boolean
  lastUpdated: number | null
  reload: () => void
}

/**
 * Polls the Phase-2 resilience telemetry endpoint on a fixed cadence.
 *
 * The endpoint is read-only and cheap, so a short interval gives a near
 * real-time view of circuit-breaker transitions and admission pressure
 * without a websocket. Transient fetch errors keep the last good snapshot
 * on screen (so a single dropped poll never blanks the dashboard).
 */
export function useResilience(intervalMs = 4000): ResilienceState {
  const [data, setData] = useState<ResilienceSnapshot | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)
  const [nonce, setNonce] = useState(0)
  const hasDataRef = useRef(false)

  const reload = useCallback(() => setNonce((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | null = null

    const tick = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/v1/ops/resilience`, { cache: "no-store" })
        if (!res.ok) throw new Error(`Telemetry unavailable (${res.status})`)
        const json = (await res.json()) as ResilienceSnapshot
        if (cancelled) return
        setData(json)
        hasDataRef.current = true
        setError(null)
        setLastUpdated(Date.now())
      } catch (e) {
        if (cancelled) return
        // Keep the last good snapshot visible; only surface the error banner.
        setError(e instanceof Error ? e.message : "Failed to load resilience telemetry")
      } finally {
        if (!cancelled) {
          setLoading(false)
          timer = setTimeout(tick, intervalMs)
        }
      }
    }

    setLoading(true)
    void tick()

    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [intervalMs, nonce])

  return { data, loading, error, hasData: hasDataRef.current, lastUpdated, reload }
}
