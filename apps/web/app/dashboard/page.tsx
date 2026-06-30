"use client"
import { motion } from "framer-motion"
import { useEffect, useState } from "react"
import { AnimatedCounter } from "@/components/AnimatedCounter"
import { GlassCard } from "@/components/GlassCard"
import { VerdictBadge } from "@/components/VerdictBadge"
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from "recharts"
import { staggerContainer, fadeUpVariants } from "@/lib/animations"
import { useLiveStats } from "@/hooks/useLiveStats"
import { API_BASE_URL } from "@/lib/api"
import Link from "next/link"

const COLORS = ["var(--gold-bright)", "var(--danger)", "var(--safe)", "var(--cyan-accent)", "var(--warn)", "var(--silver-mid)"]

type Overview = { totalScans: number; threatsFound: number; cleanModels: number }
type TrendPoint = { date: string; safe: number; threats: number }
type ThreatDist = {
  fileTypes: { name: string; value: number }[]
  severities: { name: string; count: number; fill: string }[]
}
type RecentScan = {
  scan_id: string
  filename: string
  risk_score: number
  risk_level: "clean" | "suspicious" | "malicious" | "critical"
  threats_count: number
  created_at: string | null
}

const RISK_LEVEL_TO_VERDICT: Record<string, "safe" | "suspicious" | "dangerous" | "critical"> = {
  clean: "safe", suspicious: "suspicious", malicious: "dangerous", critical: "critical",
}

function timeAgo(iso: string | null): string {
  if (!iso) return "—"
  const diffMs = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diffMs / 60000)
  if (mins < 1) return "just now"
  if (mins < 60) return `${mins} min ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs} hr ago`
  return `${Math.floor(hrs / 24)} d ago`
}

export default function DashboardPage() {
  const liveStats = useLiveStats()
  const [overview, setOverview] = useState<Overview | null>(null)
  const [trends, setTrends] = useState<TrendPoint[]>([])
  const [threatDist, setThreatDist] = useState<ThreatDist | null>(null)
  const [recentScans, setRecentScans] = useState<RecentScan[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    Promise.allSettled([
      fetch(`${API_BASE_URL}/api/v1/analytics/overview`).then(r => r.json()),
      fetch(`${API_BASE_URL}/api/v1/analytics/trends?period=7d`).then(r => r.json()),
      fetch(`${API_BASE_URL}/api/v1/analytics/threats`).then(r => r.json()),
      fetch(`${API_BASE_URL}/api/v1/scans/recent?limit=8`).then(r => r.json()),
    ]).then(([ov, tr, td, rs]) => {
      if (cancelled) return
      if (ov.status === "fulfilled") setOverview(ov.value)
      if (tr.status === "fulfilled") setTrends(tr.value.data || [])
      if (td.status === "fulfilled") setThreatDist(td.value)
      if (rs.status === "fulfilled") setRecentScans(Array.isArray(rs.value) ? rs.value : [])
      setLoading(false)
    })
    return () => { cancelled = true }
  }, [])

  const severityData = threatDist?.severities || []
  const fileTypeData = threatDist?.fileTypes || []

  return (
    <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "120px", paddingBottom: "80px", color: "var(--text-primary)" }}>
      <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>

        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: "40px" }}>
          <div>
            <h1 style={{ fontSize: "2.5rem", margin: 0, display: "flex", alignItems: "center", gap: "16px" }}>
              📊 Live Dashboard
            </h1>
            <p style={{ color: "var(--text-secondary)", marginTop: "8px" }}>
              {liveStats.isLive ? "Live" : "Reconnecting…"}
              <span style={{ display: "inline-block", width: 8, height: 8, marginLeft: 8, background: liveStats.isLive ? "var(--safe)" : "var(--text-muted)", borderRadius: "50%", animation: liveStats.isLive ? "pulse 2s infinite" : "none" }} />
            </p>
          </div>
        </motion.div>

        {/* STATS CARDS */}
        <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "24px", marginBottom: "40px" }}>
          <GlassCard style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
            <AnimatedCounter value={overview?.totalScans ?? 0} label="Total Scans" />
          </GlassCard>
          <GlassCard style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
            <AnimatedCounter value={overview?.threatsFound ?? 0} label="Threats Found" />
          </GlassCard>
          <GlassCard style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
            <AnimatedCounter value={overview?.cleanModels ?? 0} label="Safe Models" />
          </GlassCard>
          <GlassCard style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
            <div style={{ fontSize: "2.5rem", fontWeight: 800, fontFamily: "var(--font-display)", color: "var(--cyan-accent)" }}>
              {liveStats.activeScans}
            </div>
            <div style={{ color: "var(--text-secondary)", fontSize: "0.85rem", marginTop: "4px" }}>Active Scans</div>
            <span style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "8px" }}>
              {liveStats.isLive ? "Streaming…" : "Connecting…"}
            </span>
          </GlassCard>
        </motion.div>

        {/* CHARTS */}
        <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "24px", marginBottom: "24px" }} className="grid-cols-1 lg:grid-cols-3">
          <GlassCard className="lg:col-span-2" style={{ height: "400px" }}>
            <h3 style={{ marginBottom: "24px", fontSize: "1.1rem" }}>Scan Trends (7d)</h3>
            {trends.length === 0 ? (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "85%", color: "var(--text-muted)" }}>
                {loading ? "Loading…" : "No scan activity in this period yet."}
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="85%">
                <LineChart data={trends}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="date" stroke="var(--text-muted)" fontSize={12} />
                  <YAxis stroke="var(--text-muted)" fontSize={12} />
                  <RechartsTooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--gold-border)", borderRadius: "var(--radius-md)" }} />
                  <Line type="monotone" dataKey="safe" stroke="var(--safe)" strokeWidth={2} dot={false} name="Safe" />
                  <Line type="monotone" dataKey="threats" stroke="var(--gold-bright)" strokeWidth={3} dot={{ r: 4, fill: "var(--gold-bright)" }} activeDot={{ r: 6 }} name="Threats" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </GlassCard>

          <GlassCard className="lg:col-span-1" style={{ height: "400px", display: "flex", flexDirection: "column" }}>
            <h3 style={{ marginBottom: "24px", fontSize: "1.1rem" }}>Threats by File Type</h3>
            <div style={{ flex: 1 }}>
              {fileTypeData.length === 0 ? (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", textAlign: "center", padding: "0 16px" }}>
                  {loading ? "Loading…" : "No threats detected yet across any file type."}
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={fileTypeData} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                      {fileTypeData.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                    </Pie>
                    <RechartsTooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--gold-border)", borderRadius: "var(--radius-md)" }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </GlassCard>
        </motion.div>

        <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "24px" }} className="grid-cols-1 lg:grid-cols-3">
          <GlassCard className="lg:col-span-1" style={{ height: "300px" }}>
            <h3 style={{ marginBottom: "24px", fontSize: "1.1rem" }}>Severity Breakdown</h3>
            {severityData.every(s => s.count === 0) ? (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "80%", color: "var(--text-muted)" }}>
                {loading ? "Loading…" : "No scans recorded yet."}
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="80%">
                <BarChart data={severityData} layout="vertical" margin={{ left: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                  <XAxis type="number" stroke="var(--text-muted)" fontSize={12} />
                  <YAxis dataKey="name" type="category" stroke="var(--text-muted)" fontSize={12} width={90} />
                  <RechartsTooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--gold-border)", borderRadius: "var(--radius-md)" }} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {severityData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </GlassCard>

          <GlassCard className="lg:col-span-2">
            <h3 style={{ marginBottom: "24px", fontSize: "1.1rem" }}>Recent Scans</h3>

            {recentScans.length === 0 ? (
              <div style={{ textAlign: "center", padding: "48px 0" }}>
                <div style={{ fontSize: "3rem", marginBottom: "16px", opacity: 0.5 }}>📭</div>
                <h4 style={{ margin: "0 0 8px 0", fontSize: "1.2rem", color: "var(--text-primary)" }}>
                  {loading ? "Loading recent scans…" : "No scans yet"}
                </h4>
                {!loading && (
                  <>
                    <p style={{ color: "var(--text-secondary)", marginBottom: "24px" }}>You haven't scanned any models. Keep your infrastructure safe.</p>
                    <Link href="/#scan" style={{ textDecoration: "none" }}>
                      <button style={{
                        background: "rgba(201,168,76,0.1)", color: "var(--gold-bright)", border: "1px solid var(--gold-border)",
                        padding: "8px 16px", borderRadius: "8px", cursor: "pointer", fontWeight: 600
                      }}>
                        Scan your first model →
                      </button>
                    </Link>
                  </>
                )}
              </div>
            ) : (
              <div style={{ width: "100%", overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid var(--gold-border)", color: "var(--text-secondary)", fontSize: "0.85rem" }}>
                      <th style={{ padding: "12px", fontWeight: 500 }}>ID</th>
                      <th style={{ padding: "12px", fontWeight: 500 }}>Model Name</th>
                      <th style={{ padding: "12px", fontWeight: 500 }}>Verdict</th>
                      <th style={{ padding: "12px", fontWeight: 500 }}>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentScans.map((scan) => (
                      <tr key={scan.scan_id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)", transition: "background 0.2s" }} className="hover:bg-white/5 cursor-pointer">
                        <td style={{ padding: "16px 12px" }}>
                          <Link href={`/scan/${scan.scan_id}`} style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--text-muted)", textDecoration: "none" }}>
                            {scan.scan_id.slice(0, 8)}
                          </Link>
                        </td>
                        <td style={{ padding: "16px 12px", fontWeight: 500 }}>{scan.filename}</td>
                        <td style={{ padding: "16px 12px" }}><VerdictBadge verdict={RISK_LEVEL_TO_VERDICT[scan.risk_level] || "suspicious"} /></td>
                        <td style={{ padding: "16px 12px", color: "var(--text-secondary)", fontSize: "0.85rem" }}>{timeAgo(scan.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </GlassCard>
        </motion.div>

      </div>
    </main>
  )
}
