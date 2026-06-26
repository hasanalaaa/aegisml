"use client";
import { useEffect, useState } from "react";
import Link from "next/link";

interface Stats {
  total: number; clean: number; suspicious: number;
  malicious: number; critical: number; avg_risk_score: number;
}
interface RecentScan {
  scan_id: string; filename: string; risk_score: number;
  risk_level: string; verdict: string; threats_count: number; created_at: string;
}
interface ThreatPattern {
  pattern: string; severity: string; category: string;
  description_en: string; description_ar: string; times_detected: number;
}

const VERDICT_COLOR: Record<string, string> = {
  SAFE: "#2ECC71", SUSPICIOUS: "#E67E22",
  DANGEROUS: "#E74C3C", CRITICAL: "#C0392B", UNKNOWN: "#A8A8C4",
};
const SEVERITY_COLOR: Record<string, string> = {
  critical: "#E74C3C", high: "#E67E22", medium: "#F1C40F", low: "#2ECC71",
};
const riskColor = (s: number) =>
  s < 30 ? "#2ECC71" : s < 60 ? "#E67E22" : s < 85 ? "#E74C3C" : "#C0392B";

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [threatPatterns, setThreatPatterns] = useState<ThreatPattern[]>([]);
  const [lang, setLang] = useState<"ar" | "en">("ar");
  const [loading, setLoading] = useState(true);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  useEffect(() => {
    Promise.all([
      fetch(`${API}/api/v1/stats`).then((r) => r.json()),
      fetch(`${API}/api/v1/scans/recent?limit=20`).then((r) => r.json()),
      fetch(`${API}/api/v1/threats/patterns`).then((r) => r.json()),
    ])
      .then(([s, scans, threats]) => {
        setStats(s);
        setRecentScans(Array.isArray(scans) ? scans : []);
        setThreatPatterns(threats.patterns || []);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [API]);

  const card: React.CSSProperties = {
    background: "#12121E", border: "1px solid #1E1E2E", borderRadius: 14,
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", color: "#F0F0F8", direction: lang === "ar" ? "rtl" : "ltr", fontFamily: "Cairo, system-ui, sans-serif" }}>
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
        @keyframes shimmer { 0%{background-position:-200% 0} 100%{background-position:200% 0} }
      `}</style>

      <nav style={{ padding: "16px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center", position: "sticky", top: 0, background: "rgba(10,10,15,0.92)", backdropFilter: "blur(12px)", zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <Link href="/" style={{ color: "#C9A84C", textDecoration: "none", fontWeight: 900, fontSize: 20 }}>◆ AegisML</Link>
          <span style={{ color: "#555577", fontSize: 13 }}>/ Dashboard</span>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <div style={{ display: "flex", background: "#0D0D18", border: "1px solid #1E1E2E", borderRadius: 8, padding: 3, gap: 2 }}>
            {(["ar", "en"] as const).map((l) => (
              <button key={l} onClick={() => setLang(l)} style={{ background: lang === l ? "#C9A84C22" : "transparent", border: `1px solid ${lang === l ? "#C9A84C44" : "transparent"}`, color: lang === l ? "#C9A84C" : "#555577", padding: "4px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 700 }}>
                {l === "ar" ? "عربي" : "EN"}
              </button>
            ))}
          </div>
          <div style={{ width: 8, height: 8, background: "#2ECC71", borderRadius: "50%", animation: "pulse 2s infinite" }} />
          <span style={{ color: "#2ECC71", fontSize: 12 }}>Live</span>
          <Link href="/" style={{ background: "linear-gradient(135deg, #C9A84C, #E4C46B)", color: "#0A0A0F", padding: "6px 16px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none" }}>
            {lang === "ar" ? "فحص جديد" : "New Scan"}
          </Link>
        </div>
      </nav>

      <main style={{ maxWidth: 1200, margin: "0 auto", padding: "36px 24px" }}>
        <div style={{ marginBottom: 36 }}>
          <h1 style={{ fontSize: 28, fontWeight: 900, margin: "0 0 8px" }}>
            {lang === "ar" ? "لوحة التحكم العامة" : "Public Dashboard"}
          </h1>
          <p style={{ color: "#A8A8C4", margin: 0 }}>
            {lang === "ar" ? "إحصائيات حية لجميع الفحوصات" : "Live statistics for all platform scans"}
          </p>
        </div>

        {stats && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 16, marginBottom: 32 }}>
            {[
              { label: lang === "ar" ? "إجمالي الفحوصات" : "Total Scans", value: stats.total.toLocaleString(), color: "#C9A84C", icon: "⬡" },
              { label: lang === "ar" ? "آمن" : "Clean", value: stats.clean.toLocaleString(), color: "#2ECC71", icon: "✓" },
              { label: lang === "ar" ? "مشبوه" : "Suspicious", value: stats.suspicious.toLocaleString(), color: "#E67E22", icon: "⚠" },
              { label: lang === "ar" ? "خطير" : "Dangerous", value: stats.malicious.toLocaleString(), color: "#E74C3C", icon: "✗" },
              { label: lang === "ar" ? "حرج" : "Critical", value: stats.critical.toLocaleString(), color: "#C0392B", icon: "☠" },
              { label: lang === "ar" ? "متوسط الخطر" : "Avg Risk", value: String(stats.avg_risk_score), color: riskColor(stats.avg_risk_score), icon: "%" },
            ].map((s2, i) => (
              <div key={i} style={{ ...card, padding: "20px 16px", textAlign: "center" }}>
                <div style={{ fontSize: 24, color: s2.color, marginBottom: 8 }}>{s2.icon}</div>
                <p style={{ color: s2.color, fontSize: 28, fontWeight: 900, margin: "0 0 4px", fontFamily: "monospace" }}>{s2.value}</p>
                <p style={{ color: "#A8A8C4", fontSize: 12, margin: 0 }}>{s2.label}</p>
              </div>
            ))}
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr", gap: 24, marginBottom: 32 }}>
          <div style={{ ...card, padding: 24 }}>
            <h2 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 20px" }}>
              🕐 {lang === "ar" ? "آخر الفحوصات" : "Recent Scans"}
            </h2>
            {loading ? (
              [...Array(5)].map((_, i) => (
                <div key={i} style={{ background: "linear-gradient(90deg, #12121E 25%, #1A1A2E 50%, #12121E 75%)", backgroundSize: "200% 100%", animation: "shimmer 1.5s infinite", height: 52, borderRadius: 8, marginBottom: 8 }} />
              ))
            ) : recentScans.length === 0 ? (
              <p style={{ color: "#555577", textAlign: "center", padding: "24px 0" }}>
                {lang === "ar" ? "لا توجد فحوصات بعد" : "No scans yet"}
              </p>
            ) : (
              recentScans.map((scan, i) => (
                <Link key={i} href={`/scan/${scan.scan_id}`} style={{ textDecoration: "none" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px", borderRadius: 10, background: "#0D0D18", marginBottom: 8, border: "1px solid #1E1E2E", cursor: "pointer" }}
                    onMouseEnter={(e) => ((e.currentTarget as HTMLDivElement).style.borderColor = "#C9A84C33")}
                    onMouseLeave={(e) => ((e.currentTarget as HTMLDivElement).style.borderColor = "#1E1E2E")}
                  >
                    <div style={{ width: 36, height: 36, borderRadius: "50%", background: `${riskColor(scan.risk_score)}18`, border: `1.5px solid ${riskColor(scan.risk_score)}44`, display: "flex", alignItems: "center", justifyContent: "center", color: riskColor(scan.risk_score), fontSize: 13, fontWeight: 800, fontFamily: "monospace", flexShrink: 0 }}>
                      {Math.round(scan.risk_score)}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p style={{ color: "#E0E0F0", fontSize: 13, fontWeight: 600, margin: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{scan.filename}</p>
                      <p style={{ color: "#555577", fontSize: 11, margin: "2px 0 0", fontFamily: "monospace" }}>{scan.scan_id.slice(0, 8)}… · {scan.threats_count} {lang === "ar" ? "تهديد" : "threats"}</p>
                    </div>
                    <span style={{ background: `${VERDICT_COLOR[scan.verdict] || "#A8A8C4"}18`, color: VERDICT_COLOR[scan.verdict] || "#A8A8C4", padding: "2px 10px", borderRadius: 99, fontSize: 10, fontWeight: 700, flexShrink: 0 }}>
                      {scan.verdict || scan.risk_level.toUpperCase()}
                    </span>
                  </div>
                </Link>
              ))
            )}
          </div>

          <div style={{ ...card, padding: 24 }}>
            <h2 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 20px" }}>
              ⚡ {lang === "ar" ? "أكثر أنماط التهديد شيوعاً" : "Top Threat Patterns"}
            </h2>
            {threatPatterns.slice(0, 10).map((p, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderRadius: 8, background: "#0D0D18", marginBottom: 6, borderLeft: `3px solid ${SEVERITY_COLOR[p.severity] || "#A8A8C4"}` }}>
                <div>
                  <code style={{ color: "#C9A84C", fontSize: 13, fontWeight: 700 }}>{p.pattern}</code>
                  <p style={{ color: "#666688", fontSize: 11, margin: "2px 0 0" }}>{lang === "ar" ? p.description_ar : p.description_en}</p>
                </div>
                <span style={{ background: `${SEVERITY_COLOR[p.severity]}22`, color: SEVERITY_COLOR[p.severity], padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700, flexShrink: 0 }}>
                  {p.severity}
                </span>
              </div>
            ))}
          </div>
        </div>

        {stats && stats.total > 0 && (
          <div style={{ ...card, padding: 24 }}>
            <h2 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 20px" }}>
              📊 {lang === "ar" ? "توزيع مستويات الخطر" : "Risk Level Distribution"}
            </h2>
            {[
              { label: lang === "ar" ? "آمن" : "Clean", value: stats.clean, color: "#2ECC71" },
              { label: lang === "ar" ? "مشبوه" : "Suspicious", value: stats.suspicious, color: "#E67E22" },
              { label: lang === "ar" ? "خطير" : "Dangerous", value: stats.malicious, color: "#E74C3C" },
              { label: lang === "ar" ? "حرج" : "Critical", value: stats.critical, color: "#C0392B" },
            ].map((item, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                <span style={{ color: item.color, fontSize: 13, fontWeight: 600, width: 80, flexShrink: 0 }}>{item.label}</span>
                <div style={{ flex: 1, background: "#0A0A0F", borderRadius: 99, height: 10, overflow: "hidden" }}>
                  <div style={{ width: `${stats.total > 0 ? (item.value / stats.total) * 100 : 0}%`, height: "100%", background: `linear-gradient(90deg, ${item.color}88, ${item.color})`, borderRadius: 99, transition: "width 1s ease" }} />
                </div>
                <span style={{ color: "#A8A8C4", fontSize: 13, fontFamily: "monospace", width: 50, textAlign: "center", flexShrink: 0 }}>
                  {stats.total > 0 ? `${Math.round((item.value / stats.total) * 100)}%` : "0%"}
                </span>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
