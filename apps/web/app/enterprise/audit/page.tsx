"use client"

import { useEffect, useState } from "react"
import { motion } from "framer-motion"
import { toast } from "sonner"
import { fadeUpVariants } from "@/lib/animations"
import { authFetch, API_BASE_URL } from "@/lib/api"
import { Server, Download, AlertCircle } from "lucide-react"

type AuditLog = {
  id: number
  action: string
  user_id: string
  resource: string | null
  ip_address: string | null
  created_at: string
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    authFetch("/api/v1/enterprise/audit-logs?limit=100")
      .then(async (r) => {
        if (r.status === 401) throw new Error("Please sign in to view audit logs.")
        if (r.status === 403) throw new Error("Admin or Enterprise plan required to view audit logs.")
        if (!r.ok) throw new Error(`Server returned ${r.status}`)
        return r.json()
      })
      .then((data: AuditLog[]) => { if (!cancelled) setLogs(data) })
      .catch((e) => { if (!cancelled) setError(e.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  function exportCsv() {
    if (logs.length === 0) { toast.info("No logs to export yet."); return }
    const header = ["timestamp", "action", "user_id", "resource", "ip_address"]
    const rows = logs.map(l => [
      new Date(l.created_at).toISOString(), l.action, l.user_id,
      l.resource || "", l.ip_address || "",
    ])
    const csv = [header, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n")
    const blob = new Blob([csv], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url; a.download = "aegisml_audit_logs.csv"; a.click()
    URL.revokeObjectURL(url)
    toast.success("Audit logs exported")
  }

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>

        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: "40px", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", color: "var(--cyan-accent)", fontSize: "0.85rem", fontWeight: 600, marginBottom: "8px" }}>
              <Server size={14} /> Audit Trail
            </div>
            <h1 style={{ fontSize: "2.5rem", margin: 0, fontWeight: 800 }}>Audit Logs</h1>
            <p style={{ color: "var(--text-secondary)", marginTop: "8px" }}>Track all organization activity and security events.</p>
          </div>
          <button onClick={exportCsv} aria-label="Export audit logs as CSV" style={{ display: "flex", alignItems: "center", gap: "8px", padding: "10px 16px", background: "rgba(201,168,76,0.1)", border: "1px solid var(--gold-border)", color: "var(--gold-bright)", borderRadius: "var(--radius-sm)", cursor: "pointer", fontWeight: 600 }}>
            <Download size={16} /> Export CSV
          </button>
        </motion.div>

        {error ? (
          <div style={{ textAlign: "center", padding: "64px 24px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)" }}>
            <AlertCircle size={32} color="var(--warn)" style={{ marginBottom: "16px" }} />
            <h4 style={{ margin: "0 0 8px 0", color: "var(--text-primary)" }}>Couldn't load audit logs</h4>
            <p style={{ color: "var(--text-secondary)" }}>{error}</p>
          </div>
        ) : (
          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)", background: "rgba(255,255,255,0.01)" }}>
                  <th style={{ padding: "16px", color: "var(--text-muted)", fontSize: "0.85rem", fontWeight: 600 }}>TIMESTAMP</th>
                  <th style={{ padding: "16px", color: "var(--text-muted)", fontSize: "0.85rem", fontWeight: 600 }}>ACTION</th>
                  <th style={{ padding: "16px", color: "var(--text-muted)", fontSize: "0.85rem", fontWeight: 600 }}>USER</th>
                  <th style={{ padding: "16px", color: "var(--text-muted)", fontSize: "0.85rem", fontWeight: 600 }}>RESOURCE</th>
                  <th style={{ padding: "16px", color: "var(--text-muted)", fontSize: "0.85rem", fontWeight: 600 }}>IP ADDRESS</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={5} style={{ padding: "48px", textAlign: "center", color: "var(--text-muted)" }}>Loading audit logs…</td></tr>
                ) : logs.length === 0 ? (
                  <tr><td colSpan={5} style={{ padding: "48px", textAlign: "center", color: "var(--text-muted)" }}>No activity recorded yet. Events appear here as your team uses the platform.</td></tr>
                ) : (
                  logs.map((log) => (
                    <tr key={log.id} style={{ borderBottom: "1px solid var(--border)", fontSize: "0.9rem" }}>
                      <td style={{ padding: "16px", color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>{new Date(log.created_at).toLocaleString()}</td>
                      <td style={{ padding: "16px", fontWeight: 600, color: "var(--text-primary)" }}>{log.action}</td>
                      <td style={{ padding: "16px", color: "var(--text-secondary)", fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}>{log.user_id?.slice(0, 8)}…</td>
                      <td style={{ padding: "16px", fontFamily: "var(--font-mono)", color: "var(--gold-bright)" }}>{log.resource || "—"}</td>
                      <td style={{ padding: "16px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{log.ip_address || "—"}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </motion.div>
        )}
      </div>
    </main>
  )
}
