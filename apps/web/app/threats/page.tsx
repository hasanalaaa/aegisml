"use client";
import { useEffect, useState } from "react";
import Link from "next/link";

interface ThreatPattern {
  pattern: string;
  severity: string;
  category: string;
  description_en: string;
  description_ar: string;
  times_detected: number;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#E74C3C", high: "#E67E22", medium: "#F1C40F", low: "#2ECC71",
};

const ALL_CATEGORIES = [
  "all", "code_execution", "deserialization",
  "network", "system_access", "file_operations", "obfuscation",
];

export default function ThreatsPage() {
  const [patterns, setPatterns] = useState<ThreatPattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [lang, setLang] = useState<"ar" | "en">("ar");
  const [filter, setFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  useEffect(() => {
    fetch(`${API}/api/v1/threats/patterns`)
      .then((r) => r.json())
      .then((data) => setPatterns(data.patterns || []))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [API]);

  const filtered = patterns.filter((p) => {
    const matchCat = filter === "all" || p.category === filter;
    const matchSev = severityFilter === "all" || p.severity === severityFilter;
    const term = search.toLowerCase();
    const matchSearch = !term ||
      p.pattern.toLowerCase().includes(term) ||
      (lang === "ar" ? p.description_ar : p.description_en).toLowerCase().includes(term);
    return matchCat && matchSev && matchSearch;
  });

  const card: React.CSSProperties = {
    background: "#12121E", border: "1px solid #1E1E2E", borderRadius: 14,
  };
  const selectStyle: React.CSSProperties = {
    background: "#0A0A0F", border: "1px solid #2A2A3E",
    borderRadius: 8, padding: "8px 14px", color: "#A8A8C4",
    fontSize: 13, cursor: "pointer", outline: "none",
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", color: "#F0F0F8", direction: lang === "ar" ? "rtl" : "ltr", fontFamily: "Cairo, system-ui, sans-serif" }}>
      <style>{`@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}`}</style>

      <nav style={{ padding: "16px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center", position: "sticky", top: 0, background: "rgba(10,10,15,0.92)", backdropFilter: "blur(12px)", zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <Link href="/" style={{ color: "#C9A84C", textDecoration: "none", fontWeight: 900, fontSize: 20 }}>◆ AegisML</Link>
          <span style={{ color: "#555577", fontSize: 13 }}>/ Threats</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <div style={{ display: "flex", background: "#0D0D18", border: "1px solid #1E1E2E", borderRadius: 8, padding: 3, gap: 2 }}>
            {(["ar", "en"] as const).map((l) => (
              <button key={l} onClick={() => setLang(l)} style={{ background: lang === l ? "#C9A84C22" : "transparent", border: `1px solid ${lang === l ? "#C9A84C44" : "transparent"}`, color: lang === l ? "#C9A84C" : "#555577", padding: "4px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 700 }}>
                {l === "ar" ? "عربي" : "EN"}
              </button>
            ))}
          </div>
          <Link href="/" style={{ background: "linear-gradient(135deg, #C9A84C, #E4C46B)", color: "#0A0A0F", padding: "6px 16px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none" }}>
            {lang === "ar" ? "فحص الآن" : "Scan Now"}
          </Link>
        </div>
      </nav>

      <main style={{ maxWidth: 1100, margin: "0 auto", padding: "40px 24px" }}>
        <div style={{ marginBottom: 36 }}>
          <h1 style={{ fontSize: 32, fontWeight: 900, marginBottom: 8 }}>
            ⚡ {lang === "ar" ? "قاعدة بيانات التهديدات" : "Threat Database"}
          </h1>
          <p style={{ color: "#A8A8C4", fontSize: 16 }}>
            {lang === "ar"
              ? "قاعدة بيانات مفتوحة لأنماط التهديد المعروفة في نماذج الذكاء الاصطناعي"
              : "Open database of known threat patterns in AI model files"}
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12, marginBottom: 28 }}>
          {[
            { label: lang === "ar" ? "إجمالي الأنماط" : "Total Patterns", value: patterns.length, color: "#C9A84C" },
            { label: lang === "ar" ? "حرج" : "Critical", value: patterns.filter((p) => p.severity === "critical").length, color: "#E74C3C" },
            { label: lang === "ar" ? "عالي" : "High",    value: patterns.filter((p) => p.severity === "high").length,     color: "#E67E22" },
            { label: lang === "ar" ? "متوسط" : "Medium", value: patterns.filter((p) => p.severity === "medium").length,   color: "#F1C40F" },
          ].map((s, i) => (
            <div key={i} style={{ ...card, padding: "16px 20px", textAlign: "center" }}>
              <p style={{ color: s.color, fontSize: 26, fontWeight: 900, margin: "0 0 4px", fontFamily: "monospace" }}>{s.value}</p>
              <p style={{ color: "#A8A8C4", fontSize: 12, margin: 0 }}>{s.label}</p>
            </div>
          ))}
        </div>

        <div style={{ ...card, padding: "16px 20px", marginBottom: 24, display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" }}>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={lang === "ar" ? "ابحث عن نمط..." : "Search patterns..."}
            style={{ flex: 1, minWidth: 200, background: "#0A0A0F", border: "1px solid #2A2A3E", borderRadius: 8, padding: "8px 14px", color: "#F0F0F8", fontSize: 13, outline: "none" }}
          />
          <select value={filter} onChange={(e) => setFilter(e.target.value)} style={selectStyle}>
            {ALL_CATEGORIES.map((c) => (
              <option key={c} value={c}>{c === "all" ? (lang === "ar" ? "كل الفئات" : "All Categories") : c}</option>
            ))}
          </select>
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} style={selectStyle}>
            <option value="all">{lang === "ar" ? "كل المستويات" : "All Severities"}</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        {loading ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 14 }}>
            {[...Array(8)].map((_, i) => (
              <div key={i} style={{ background: "linear-gradient(90deg, #12121E 25%, #1A1A2E 50%, #12121E 75%)", backgroundSize: "200% 100%", animation: "shimmer 1.5s infinite", height: 100, borderRadius: 12 }} />
            ))}
          </div>
        ) : (
          <>
            <p style={{ color: "#555577", fontSize: 13, marginBottom: 16 }}>
              {lang === "ar" ? `يُظهر ${filtered.length} من ${patterns.length} نمط` : `Showing ${filtered.length} of ${patterns.length} patterns`}
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 14 }}>
              {filtered.map((p, i) => (
                <div key={i} style={{ background: "#12121E", border: `1px solid ${SEVERITY_COLOR[p.severity] || "#A8A8C4"}22`, borderLeft: `4px solid ${SEVERITY_COLOR[p.severity] || "#A8A8C4"}`, borderRadius: 12, padding: "18px 20px", transition: "transform 0.15s ease" }}
                  onMouseEnter={(e) => ((e.currentTarget as HTMLDivElement).style.transform = "translateY(-2px)")}
                  onMouseLeave={(e) => ((e.currentTarget as HTMLDivElement).style.transform = "translateY(0)")}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
                    <code style={{ color: "#C9A84C", fontSize: 15, fontWeight: 800 }}>{p.pattern}</code>
                    <div style={{ display: "flex", gap: 6 }}>
                      <span style={{ background: `${SEVERITY_COLOR[p.severity]}20`, color: SEVERITY_COLOR[p.severity], padding: "2px 10px", borderRadius: 99, fontSize: 10, fontWeight: 700, textTransform: "uppercase" }}>{p.severity}</span>
                      <span style={{ background: "#C9A84C12", color: "#C9A84C88", padding: "2px 10px", borderRadius: 99, fontSize: 10, fontWeight: 600 }}>{p.category}</span>
                    </div>
                  </div>
                  <p style={{ color: "#A8A8C4", fontSize: 13, lineHeight: 1.6, margin: 0 }}>
                    {lang === "ar" ? p.description_ar : p.description_en}
                  </p>
                  {p.times_detected > 0 && (
                    <p style={{ color: "#555577", fontSize: 11, margin: "8px 0 0", fontFamily: "monospace" }}>
                      {lang === "ar" ? `اكتُشف ${p.times_detected} مرة` : `Detected ${p.times_detected} times`}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </main>
    </div>
  );
}
