import { useState, useEffect } from "react"
import { API_BASE_URL } from "@/lib/api"

export type ScanStage = "header_check" | "parallel_analysis" | "ai_analysis" | "complete" | "failed"
export type ScanConnStatus = "connecting" | "streaming" | "polling" | "complete" | "error"

export interface ScanProgressData {
  progress: number
  stage: ScanStage
  threatCount: number
  isComplete: boolean
  status: ScanConnStatus
  error: string | null
  /** Human-readable message from the engine for the current stage, if any. */
  message: string | null
}

// If the socket has not opened in this window we assume it is blocked
// (CSP, proxy, backend down) and fall back to HTTP polling.
const OPEN_TIMEOUT_MS = 8000
// While streaming, if no frame arrives for this long we assume the stream
// stalled (dropped terminal frame / idle proxy) and verify via HTTP.
const STREAM_IDLE_MS = 12000
const POLL_INTERVAL_MS = 2000
// Give the backend up to 5 minutes of *no observable progress* before we give
// up. Each time the polled snapshot advances, the deadline is re-armed, so a
// long-but-alive scan is never killed prematurely.
const POLL_STALL_MS = 5 * 60_000

// The backend speaks a wide stage vocabulary: main.py persists
// initializing/downloading/header_check/parallel_analysis/ai_analysis/error,
// while scanner/engine.py streams header_check/signature_scan/regex_scan/
// structure_scan/entropy_scan/ai_analysis/complete/failed over the socket.
// Normalize all of it into the four canonical UI stages so an unknown raw
// stage can never leave the stepper without a highlighted row (findIndex -1).
function normalizeStage(raw: unknown): ScanStage | null {
  switch (typeof raw === "string" ? raw : "") {
    case "initializing":
    case "downloading":
    case "header_check":
      return "header_check"
    case "signature_scan":
    case "parallel_analysis":
    case "byte_pattern":
    case "regex_scan":
    case "regex_pattern":
    case "structure_scan":
    case "entropy_scan":
      return "parallel_analysis"
    case "ai_analysis":
      return "ai_analysis"
    case "complete":
      return "complete"
    case "failed":
    case "error":
      return "failed"
    default:
      return null
  }
}

// Derive the WebSocket origin. Prefer an explicit env var; otherwise reuse the
// API origin (Railway serves API + WS on the same host) and upgrade the scheme
// so https→wss / http→ws. This prevents a silent ws://localhost fallback in prod.
function resolveWsBase(): string {
  const explicit = process.env.NEXT_PUBLIC_WS_URL
  if (explicit) return explicit.replace(/\/+$/, "")
  if (API_BASE_URL.startsWith("https://")) return "wss://" + API_BASE_URL.slice(8).replace(/\/+$/, "")
  if (API_BASE_URL.startsWith("http://")) return "ws://" + API_BASE_URL.slice(7).replace(/\/+$/, "")
  return "ws://localhost:8000"
}

export function useScanProgress(scanId: string) {
  const [data, setData] = useState<ScanProgressData>({
    progress: 0,
    stage: "header_check",
    threatCount: 0,
    isComplete: false,
    status: "connecting",
    error: null,
    message: null,
  })

  useEffect(() => {
    if (!scanId) return

    let cancelled = false
    let finished = false
    let ws: WebSocket | null = null
    let openTimer: ReturnType<typeof setTimeout> | null = null
    let idleTimer: ReturnType<typeof setTimeout> | null = null
    let pollTimer: ReturnType<typeof setInterval> | null = null
    let pollDeadline = 0
    let lastSeenProgress = 0

    const clearTimers = () => {
      if (openTimer) { clearTimeout(openTimer); openTimer = null }
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null }
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
    }

    // Terminal success and failure stay distinct so a failed scan cannot be
    // mistaken for a completed report.
    const finish = (stage: "complete" | "failed", message?: string) => {
      if (finished || cancelled) return
      finished = true
      clearTimers()
      if (ws) { try { ws.close() } catch { /* noop */ } }
      const failed = stage === "failed"
      setData((prev) => ({
        ...prev,
        stage,
        isComplete: true,
        status: failed ? "error" : "complete",
        error: failed ? (message || "The scan failed on the server. Try starting a new scan.") : null,
        message: message ?? prev.message,
        progress: failed ? prev.progress : 100,
      }))
    }

    const fail = (message: string) => finish("failed", message)

    // Apply a live (non-terminal) snapshot. Progress is monotonic: a stale WS
    // frame arriving after a fresher polled snapshot can never walk it back.
    const applyLive = (
      p: { progress?: number; stage?: unknown; threat_count?: number; message?: string },
      conn: "streaming" | "polling",
    ) => {
      if (finished || cancelled) return
      const stage = normalizeStage(p.stage)
      const progress = typeof p.progress === "number" && Number.isFinite(p.progress)
        ? Math.max(0, Math.min(100, p.progress))
        : undefined
      setData((prev) => ({
        ...prev,
        progress: progress !== undefined ? Math.max(prev.progress, progress) : prev.progress,
        stage: stage ?? prev.stage,
        threatCount: typeof p.threat_count === "number" ? p.threat_count : prev.threatCount,
        status: prev.status === "complete" ? prev.status : conn,
        message: typeof p.message === "string" && p.message ? p.message : prev.message,
        error: null,
      }))
    }

    // HTTP fallback: poll /api/v1/scan/{id}. Thanks to the backend's cached
    // intermediate snapshots this endpoint returns 200 with live progress
    // ({status:"processing", stage, progress, …}) from the moment the scan
    // starts, then the fully materialized report once complete. Handle BOTH
    // shapes — the old code only recognized the final report and silently
    // dropped every intermediate snapshot, which is exactly what froze the UI
    // at 0% whenever the socket was unavailable.
    const startPolling = (reason: string) => {
      if (finished || cancelled || pollTimer) return
      pollDeadline = Date.now() + POLL_STALL_MS
      setData((prev) => (prev.status === "complete" ? prev : { ...prev, status: "polling" }))

      let netFails = 0
      const NET_FAIL_LIMIT = 8 // ~16s of an unreachable backend → fail fast

      const tick = async () => {
        if (finished || cancelled) return
        try {
          const res = await fetch(`${API_BASE_URL}/api/v1/scan/${scanId}`, { cache: "no-store" })
          netFails = 0 // the server answered (even a 404 means it is reachable)
          if (res.ok) {
            const json = (await res.json().catch(() => null)) as Record<string, unknown> | null
            if (json) {
              // 1) Fully materialized report → terminal.
              if (json.ai_analysis || json.risk_level) {
                const failedScan = json.risk_level === "failed" || json.status === "failed"
                finish(
                  failedScan ? "failed" : "complete",
                  typeof json.message === "string" ? json.message : undefined,
                )
                return
              }
              // 2) Persisted terminal error snapshot → surface it, stop looping.
              if (json.status === "error" || json.status === "failed") {
                fail(typeof json.message === "string" && json.message
                  ? json.message
                  : "The scan failed on the server. Try starting a new scan.")
                return
              }
              // 3) Live intermediate snapshot → update the UI and keep polling.
              if (json.status === "processing" || typeof json.progress === "number" || typeof json.stage === "string") {
                applyLive(json as { progress?: number; stage?: unknown; threat_count?: number; message?: string }, "polling")
                const seen = typeof json.progress === "number" ? json.progress : 0
                if (seen > lastSeenProgress) {
                  lastSeenProgress = seen
                  pollDeadline = Date.now() + POLL_STALL_MS // scan is alive → re-arm
                }
              }
            }
          }
          // 404 (not visible yet) / 5xx / partial → keep trying until the deadline.
        } catch {
          netFails++
          if (netFails >= NET_FAIL_LIMIT) {
            fail(`${reason} and the scan engine is unreachable. Confirm the backend is deployed and NEXT_PUBLIC_API_URL is correct.`)
            return
          }
        }
        if (Date.now() > pollDeadline) {
          fail(`${reason}, and the scan made no progress for several minutes. It may still be processing on the server — try refreshing shortly.`)
        }
      }

      void tick()
      pollTimer = setInterval(tick, POLL_INTERVAL_MS)
    }

    // Reset the stream-idle watchdog on every inbound frame.
    const armIdleWatchdog = () => {
      if (idleTimer) clearTimeout(idleTimer)
      idleTimer = setTimeout(() => {
        if (!finished && !cancelled) startPolling("The live stream stalled")
      }, STREAM_IDLE_MS)
    }

    const wsUrl = `${resolveWsBase()}/ws/scan/${scanId}`

    try {
      ws = new WebSocket(wsUrl)

      openTimer = setTimeout(() => {
        if (ws && ws.readyState !== WebSocket.OPEN) {
          try { ws.close() } catch { /* noop */ }
          startPolling("The live connection timed out")
        }
      }, OPEN_TIMEOUT_MS)

      ws.onopen = () => {
        if (openTimer) { clearTimeout(openTimer); openTimer = null }
        if (!cancelled) {
          setData((prev) => (prev.status === "complete" ? prev : { ...prev, status: "streaming", error: null }))
          armIdleWatchdog()
        }
      }

      ws.onmessage = (event) => {
        if (cancelled || finished) return
        armIdleWatchdog()
        let payload: unknown
        try {
          payload = JSON.parse(typeof event.data === "string" ? event.data : "")
        } catch {
          return // ignore malformed frames instead of crashing the listener
        }
        const p = (payload ?? {}) as { progress?: number; stage?: string; threat_count?: number; message?: string }
        const stage = normalizeStage(p.stage)
        applyLive(p, "streaming")
        if (stage === "complete" || stage === "failed") {
          finish(stage, p.message)
        } else if ((typeof p.progress === "number" ? p.progress : 0) >= 100) {
          // Reached 100% but no terminal frame → verify + finalize via HTTP so
          // the UI can never sit frozen at 100%.
          startPolling("Scan reached 100%")
        }
      }

      // onerror is always followed by onclose; defer recovery to onclose/timeout.
      ws.onerror = () => { /* handled via onclose / open-timeout → polling */ }

      ws.onclose = (ev) => {
        if (finished || cancelled) return
        startPolling(ev.wasClean ? "The live connection closed" : "The live connection dropped")
      }
    } catch {
      startPolling("The live connection could not be opened")
    }

    return () => {
      cancelled = true
      clearTimers()
      if (ws) {
        ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null
        try { ws.close() } catch { /* noop */ }
      }
    }
  }, [scanId])

  return data
}
