import React from "react"
import { ShieldCheck, ArrowUpRight } from "lucide-react"
import Link from "next/link"

export interface LeaderboardEntry {
  model_url: string
  safety_score: number
  scan_count: number
}

export function LeaderboardTable({ entries }: { entries: LeaderboardEntry[] }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
        <thead>
          <tr style={{ borderBottom: "1px solid var(--border)", background: "rgba(255,255,255,0.01)" }}>
            <th style={{ padding: "16px", color: "var(--text-muted)", fontSize: "0.85rem", fontWeight: 600, textTransform: "uppercase" }}>Rank</th>
            <th style={{ padding: "16px", color: "var(--text-muted)", fontSize: "0.85rem", fontWeight: 600, textTransform: "uppercase" }}>Model</th>
            <th style={{ padding: "16px", color: "var(--text-muted)", fontSize: "0.85rem", fontWeight: 600, textTransform: "uppercase" }}>Safety Score</th>
            <th style={{ padding: "16px", color: "var(--text-muted)", fontSize: "0.85rem", fontWeight: 600, textTransform: "uppercase" }}>Scans</th>
            <th style={{ padding: "16px" }}></th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry, idx) => (
            <tr key={entry.model_url} style={{ borderBottom: "1px solid var(--border)" }}>
              <td style={{ padding: "16px", fontWeight: 700, color: idx < 3 ? "var(--gold-bright)" : "var(--text-secondary)" }}>#{idx + 1}</td>
              <td style={{ padding: "16px", fontFamily: "var(--font-mono)", fontSize: "0.9rem" }}>{entry.model_url.replace("huggingface.co/", "")}</td>
              <td style={{ padding: "16px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--safe)" }}>
                  <ShieldCheck size={16} />
                  <span style={{ fontWeight: 600 }}>{entry.safety_score.toFixed(1)}%</span>
                </div>
              </td>
              <td style={{ padding: "16px", color: "var(--text-secondary)" }}>{entry.scan_count.toLocaleString()}</td>
              <td style={{ padding: "16px", textAlign: "right" }}>
                <Link href={`/scan/new?url=https://${entry.model_url}`} style={{ display: "inline-flex", alignItems: "center", gap: "4px", color: "var(--cyan-accent)", textDecoration: "none", fontSize: "0.85rem", fontWeight: 600 }}>
                  Scan <ArrowUpRight size={14} />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
