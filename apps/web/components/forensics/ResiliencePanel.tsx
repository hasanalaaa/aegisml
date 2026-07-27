"use client"
import { motion } from "framer-motion"
import { GlassCard } from "@/components/GlassCard"
import { fadeUpVariants, staggerContainer } from "@/lib/animations"
import { useResilience, type CircuitSnapshot, type CircuitState } from "@/hooks/useResilience"
import { NumberTicker } from "@/components/NumberTicker"
import { RadarSweep } from "@/components/motion/RadarSweep"
import { Activity, ShieldCheck, ShieldAlert, ShieldX, Server, Gauge, RefreshCw } from "lucide-react"

/* ── Circuit state visual language ────────────────────────────────── */
const STATE_META: Record<CircuitState, { color: string; label: string; icon: React.ReactNode; desc: string }> = {
  closed: { color: "var(--safe)", label: "CLOSED", icon: <ShieldCheck size={16} />, desc: "Healthy — traffic flowing" },
  half_open: { color: "var(--warn)", label: "HALF-OPEN", icon: <ShieldAlert size={16} />, desc: "Probing recovery" },
  open: { color: "var(--danger)", label: "OPEN", icon: <ShieldX size={16} />, desc: "Tripped — skipping instantly" },
}

function fmtBytes(n?: number): string {
  if (n === undefined || n === null) return "—"
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(0)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`
}

/* ── Circuit breaker card ─────────────────────────────────────────── */
function BreakerCard({ c }: { c: CircuitSnapshot }) {
  const meta = STATE_META[c.state] ?? STATE_META.closed
  const total = c.total_successes + c.total_failures
  const successRate = total > 0 ? (c.total_successes / total) * 100 : 100
  // Failure pips toward the trip threshold.
  const pips = Array.from({ length: Math.max(1, c.failure_threshold) }, (_, i) => i < c.consecutive_failures)

  // SVG ring (success rate) — brass track, state-colored progress.
  const R = 30
  const C = 2 * Math.PI * R
  const dash = (successRate / 100) * C

  return (
    <motion.div variants={fadeUpVariants}>
      <div
        style={{
          background: "var(--bg-elevated)",
          border: `1px solid ${c.state === "closed" ? "var(--gold-border)" : meta.color + "55"}`,
          borderRadius: "var(--radius-lg)",
          padding: "20px",
          boxShadow: c.state === "open" ? "var(--danger-glow)" : "var(--shadow-card)",
          animation: c.state === "closed" ? "borderGlow 4s ease-in-out infinite" : "none",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
          height: "100%",
          transition: "border-color 0.3s, box-shadow 0.3s",
        }}
      >
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
            <Server size={18} color="var(--gold-bright)" style={{ flexShrink: 0 }} />
            <span style={{ fontWeight: 700, fontSize: "1.05rem", textTransform: "capitalize", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.name}</span>
          </div>
          <span
            className="tag"
            style={{
              flexShrink: 0,
              background: c.state === "closed" ? "var(--safe-bg)" : meta.color + "1A",
              color: meta.color,
              border: `1px solid ${meta.color}55`,
              animation: c.state === "open" ? "borderGlow 2s ease-in-out infinite" : "none",
            }}
          >
            {meta.icon} {meta.label}
          </span>
        </div>

        {/* Ring + rate */}
        <div style={{ display: "flex", alignItems: "center", gap: "18px" }}>
          <div style={{ position: "relative", width: "76px", height: "76px", flexShrink: 0 }}>
            <svg viewBox="0 0 76 76" style={{ width: "76px", height: "76px", transform: "rotate(-90deg)" }}>
              <circle cx="38" cy="38" r={R} fill="none" stroke="var(--bg-base)" strokeWidth="7" />
              <motion.circle
                cx="38" cy="38" r={R} fill="none" stroke={meta.color} strokeWidth="7" strokeLinecap="round"
                initial={{ strokeDasharray: `0 ${C}` }}
                animate={{ strokeDasharray: `${dash} ${C - dash}` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
              />
            </svg>
            <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.95rem", fontWeight: 700, color: meta.color }}><NumberTicker value={successRate} suffix="%" inViewOnly={false} /></span>
              <span style={{ fontSize: "0.58rem", color: "var(--text-muted)", letterSpacing: "0.05em" }}>SUCCESS</span>
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px", flex: 1, minWidth: 0 }}>
            <span style={{ fontSize: "0.78rem", color: meta.color }}>{meta.desc}</span>
            {/* failure pips */}
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "3px", marginBottom: "4px", flexWrap: "wrap" }}>
                {pips.map((on, i) => (
                  <span key={i} style={{ width: "14px", height: "6px", borderRadius: "2px", background: on ? "var(--danger)" : "var(--bg-overlay)", transition: "background 0.3s" }} />
                ))}
              </div>
              <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                {c.consecutive_failures}/{c.failure_threshold} failures to trip · resets in {c.reset_timeout_seconds}s
              </span>
            </div>
          </div>
        </div>

        {/* Lifetime counters */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "8px", borderTop: "1px solid var(--border-subtle)", paddingTop: "12px" }}>
          {[
            { l: "Success", v: c.total_successes, col: "var(--safe)" },
            { l: "Failures", v: c.total_failures, col: c.total_failures > 0 ? "var(--danger)" : "var(--text-secondary)" },
            { l: "Trips", v: c.times_opened, col: c.times_opened > 0 ? "var(--warn)" : "var(--text-secondary)" },
          ].map((s) => (
            <div key={s.l} style={{ textAlign: "center" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "1.05rem", fontWeight: 700, color: s.col }}><NumberTicker value={s.v} inViewOnly={false} /></div>
              <div style={{ fontSize: "0.62rem", letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)" }}>{s.l}</div>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  )
}

/* ── Admission control (size-class concurrency) ───────────────────── */
const CLASS_ORDER = ["small", "medium", "large"]
function AdmissionSection({ admission }: { admission: NonNullable<ReturnType<typeof useResilience>["data"]>["admission"] }) {
  const permits = admission.permits || {}
  const inFlight = admission.in_flight || {}
  const waiting = admission.waiting || {}
  const classes = Array.from(new Set([...CLASS_ORDER, ...Object.keys(permits), ...Object.keys(inFlight), ...Object.keys(waiting)]))
    .filter((k) => k in permits || k in inFlight || k in waiting)
    .sort((a, b) => {
      const ia = CLASS_ORDER.indexOf(a), ib = CLASS_ORDER.indexOf(b)
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib)
    })
  const th = admission.thresholds || {}

  if (classes.length === 0) return null

  return (
    <GlassCard style={{ padding: "24px", display: "flex", flexDirection: "column", gap: "18px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "8px" }}>
        <h3 style={{ margin: 0, display: "inline-flex", alignItems: "center", gap: "10px" }}>
          <Gauge size={20} color="var(--gold-bright)" /> Size-Class Admission Control
        </h3>
        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
          small ≤ {fmtBytes(th.small_max_bytes)} · large ≥ {fmtBytes(th.large_min_bytes)}
        </span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
        {classes.map((cls) => {
          const cap = permits[cls] ?? 0
          const used = inFlight[cls] ?? 0
          const wait = waiting[cls] ?? 0
          const pct = cap > 0 ? Math.min(100, (used / cap) * 100) : 0
          const saturated = cap > 0 && used >= cap
          return (
            <div key={cls}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                <span style={{ fontWeight: 600, textTransform: "capitalize", fontSize: "0.92rem" }}>{cls}</span>
                <span style={{ display: "inline-flex", alignItems: "center", gap: "10px" }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.82rem", color: saturated ? "var(--warn)" : "var(--text-secondary)" }}>
                    {used}/{cap} in flight
                  </span>
                  {wait > 0 && (
                    <span className="tag tag-medium" style={{ fontSize: "0.68rem" }}>{wait} waiting</span>
                  )}
                </span>
              </div>
              <div style={{ display: "flex", gap: "3px" }}>
                {Array.from({ length: Math.max(1, cap) }, (_, i) => (
                  <div
                    key={i}
                    style={{
                      flex: 1,
                      height: "12px",
                      borderRadius: "3px",
                      background: i < used ? (saturated ? "linear-gradient(90deg,#D4AF37,#F59E0B)" : "linear-gradient(90deg,#8B6914,#D4AF37)") : "var(--bg-base)",
                      border: "1px solid var(--border-subtle)",
                      transition: "background 0.3s",
                    }}
                  />
                ))}
              </div>
              <div style={{ height: "2px", marginTop: "6px", background: "var(--bg-base)", borderRadius: "999px", overflow: "hidden" }}>
                <motion.div animate={{ width: `${pct}%` }} transition={{ type: "spring", stiffness: 70, damping: 22 }} style={{ height: "100%", background: saturated ? "var(--warn)" : "var(--gold-mid)", boxShadow: "0 0 8px rgba(212,175,55,0.5)" }} />
              </div>
            </div>
          )
        })}
      </div>
    </GlassCard>
  )
}

/* ── Posture banner ───────────────────────────────────────────────── */
const POSTURE_META: Record<string, { color: string; bg: string; label: string }> = {
  nominal: { color: "var(--safe)", bg: "var(--safe-bg)", label: "All systems nominal" },
  degraded: { color: "var(--warn)", bg: "var(--warn-bg)", label: "Degraded — fallback engaged" },
  critical: { color: "var(--danger)", bg: "var(--danger-bg)", label: "Critical — providers exhausted" },
}

export function ResiliencePanel() {
  const { data, loading, error, hasData, lastUpdated, reload } = useResilience(4000)

  if (loading && !hasData) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: "18px" }}>
        <div className="skeleton" style={{ height: "72px" }} />
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "18px" }}>
          {[0, 1, 2, 3].map((i) => <div key={i} className="skeleton" style={{ height: "230px" }} />)}
        </div>
      </div>
    )
  }

  const posture = data?.posture || "nominal"
  const pm = POSTURE_META[posture] ?? POSTURE_META.nominal
  const s = data?.summary

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "22px" }}>
      {/* Posture banner */}
      <motion.div variants={fadeUpVariants} initial="hidden" animate="visible">
        <div
          style={{
            display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px",
            padding: "18px 24px", background: pm.bg, border: `1px solid ${pm.color}55`, borderRadius: "var(--radius-lg)",
            boxShadow: posture === "critical" ? "var(--danger-glow)" : "none",
            position: "relative", overflow: "hidden",
          }}
        >
          <RadarSweep size={190} duration={6} opacity={0.45} style={{ insetInlineEnd: "-36px", top: "50%", transform: "translateY(-50%)" }} />
          <div style={{ display: "flex", alignItems: "center", gap: "14px", position: "relative", zIndex: 1 }}>
            <span style={{ position: "relative", width: "12px", height: "12px" }}>
              <span style={{ position: "absolute", inset: 0, borderRadius: "999px", background: pm.color, boxShadow: `0 0 10px ${pm.color}` }} />
              <span style={{ position: "absolute", inset: 0, borderRadius: "999px", background: pm.color, animation: "pulse 2s ease-in-out infinite" }} />
            </span>
            <div>
              <div style={{ fontWeight: 700, fontSize: "1.15rem", color: pm.color }}>{pm.label}</div>
              {s && (
                <div style={{ fontSize: "0.82rem", color: "var(--text-secondary)" }}>
                  <NumberTicker value={s.providers} inViewOnly={false} /> providers · <NumberTicker value={s.open_circuits} inViewOnly={false} /> open · <NumberTicker value={s.scans_in_flight} inViewOnly={false} /> scans in flight · <NumberTicker value={s.scans_waiting} inViewOnly={false} /> queued
                </div>
              )}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            {lastUpdated && (
              <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", display: "inline-flex", alignItems: "center", gap: "6px" }}>
                <Activity size={12} color={error ? "var(--warn)" : "var(--safe)"} />
                {error ? "stale" : "live"} · {new Date(lastUpdated).toLocaleTimeString()}
              </span>
            )}
            <button
              onClick={reload}
              style={{ display: "inline-flex", alignItems: "center", gap: "6px", background: "transparent", border: "1px solid var(--gold-border)", color: "var(--gold-bright)", borderRadius: "var(--radius-md)", padding: "8px 14px", cursor: "pointer", fontSize: "0.82rem", width: "auto" }}
            >
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        </div>
      </motion.div>

      {error && !hasData && (
        <GlassCard style={{ padding: "24px", textAlign: "center" }}>
          <ShieldAlert size={28} color="var(--danger)" />
          <p style={{ marginTop: "12px", color: "var(--text-secondary)" }}>Couldn&apos;t reach the resilience telemetry endpoint. {error}</p>
        </GlassCard>
      )}

      {/* Circuit breakers */}
      {data && data.circuits.length > 0 && (
        <div>
          <h3 style={{ marginBottom: "14px", display: "inline-flex", alignItems: "center", gap: "10px" }}>
            <ShieldCheck size={20} color="var(--gold-bright)" /> AI Provider Circuit Breakers
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 400 }}>(fallback order)</span>
          </h3>
          <motion.div
            variants={staggerContainer}
            initial="hidden"
            animate="visible"
            style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: "18px" }}
          >
            {data.circuits.map((c) => <BreakerCard key={c.name} c={c} />)}
          </motion.div>
        </div>
      )}

      {/* Admission control */}
      {data && <AdmissionSection admission={data.admission} />}
    </div>
  )
}
