"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";

interface Threat {
  pattern: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  location?: string;
}

interface AIAnalysis {
  verdict: "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "CRITICAL" | "UNKNOWN";
  confidence: number;
  summary_en: string;
  summary_ar: string;
  key_risks: string[];
  recommendation: string;
  recommendation_ar: string;
}

interface ScanResult {
  scan_id: string;
  filename: string;
  risk_score: number;
  risk_level: string;
  threats: Threat[];
  metadata: Record<string, unknown>;
  ai_analysis?: AIAnalysis;
}

const VERDICT_CONFIG = {
  SAFE:       { color: "#2ECC71", bg: "rgba(46,204,113,0.12)",  labelAr: "آمن",       labelEn: "SAFE",       icon: "✓" },
  SUSPICIOUS: { color: "#E67E22", bg: "rgba(230,126,34,0.12)",  labelAr: "مشبوه",     labelEn: "SUSPICIOUS", icon: "⚠" },
  DANGEROUS:  { color: "#E74C3C", bg: "rgba(231,76,60,0.12)",   labelAr: "خطير",      labelEn: "DANGEROUS",  icon: "✗" },
  CRITICAL:   { color: "#C0392B", bg: "rgba(192,57,43,0.15)",   labelAr: "حرج جداً",  labelEn: "CRITICAL",   icon: "☠" },
  UNKNOWN:    { color: "#A8A8C4", bg: "rgba(168,168,196,0.10)", labelAr: "غير معروف", labelEn: "UNKNOWN",    icon: "?" },
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#E74C3C",
  high: "#E67E22",
  medium: "#F1C40F",
  low: "#A8A8C4",
};

function RiskGauge({ score }: { score: number }) {
  const color = score < 30 ? "#2ECC71" : score < 60 ? "#E67E22" : score < 85 ? "#E74C3C" : "#C0392B";
  const label = score < 30 ? "آمن" : score < 60 ? "مشبوه" : score < 85 ? "خطير" : "حرج جداً";
  const dash = (score / 100) * 251.2;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
      <svg viewBox="0 0 200 110" width="180" height="100">
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#1A1A2E" strokeWidth="18" strokeLinecap="round" />
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke={color} strokeWidth="18" strokeLinecap="round" strokeDasharray={`${dash} 251.2`} />
        <text x="100" y="90" textAnchor="middle" fill={color} fontSize="32" fontWeight="bold" fontFamily="monospace">{score}</text>
        <text x="100" y="105" textAnchor="middle" fill="#A8A8C4" fontSize="11">/ 100</text>
      </svg>
      <span style={{ color, fontWeight: 700, fontSize: 16 }}>{label}</span>
    </div>
  );
}

function ThreatCard({ threat }: { threat: Threat }) {
  const color = SEVERITY_COLOR[threat.severity] || "#A8A8C4";
  return (
    <div style={{ background: "#0D0D1A", border: `1px solid ${color}33`, borderLeft: `4px solid ${color}`, borderRadius: 8, padding: "14px 18px", marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6, flexWrap: "wrap", gap: 8 }}>
        <code style={{ color: "#C9A84C", fontSize: 14, fontWeight: 700 }}>{threat.pattern}</code>
        <span style={{ background: `${color}22`, color, padding: "2px 12px", borderRadius: 99, fontSize: 11, fontWeight: 700, textTransform: "uppercase" }}>{threat.severity}</span>
      </div>
      <p style={{ color: "#B0B0CC", fontSize: 13, margin: 0, lineHeight: 1.6 }}>{threat.description}</p>
      {threat.location && <p style={{ color: "#555577", fontSize: 12, margin: "6px 0 0", fontFamily: "monospace" }}>📍 {threat.location}</p>}
    </div>
  );
}

export default function ScanResultPage() {
  const params = useParams();
  const scanId = params?.id as string;
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lang, setLang] = useState<"ar" | "en">("ar");

  useEffect(() => {
    if (!scanId) return;
    const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    fetch(`${API}/api/v1/scan/${scanId}`)
      .then(r => { if (!r.ok) throw new Error("لم يتم العثور على نتيجة الفحص"); return r.json(); })
      .then(setResult)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 20 }}>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      <div style={{ width: 52, height: 52, border: "3px solid #1E1E2E", borderTop: "3px solid #C9A84C", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
      <p style={{ color: "#A8A8C4", margin: 0 }}>جارٍ تحميل نتيجة الفحص…</p>
    </div>
  );

  if (error) return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 16 }}>
      <span style={{ fontSize: 56 }}>⚠️</span>
      <p style={{ color: "#E74C3C", fontSize: 18, margin: 0 }}>{error}</p>
      <Link href="/" style={{ color: "#C9A84C", textDecoration: "none" }}>← العودة للرئيسية</Link>
    </div>
  );

  if (!result) return null;

  const ai = result.ai_analysis;
  const vc = ai ? (VERDICT_CONFIG[ai.verdict] ?? VERDICT_CONFIG.UNKNOWN) : null;
  const card: React.CSSProperties = { background: "#12121E", border: "1px solid #1E1E2E", borderRadius: 14, padding: 24 };

  return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", color: "#F0F0F8", fontFamily: "system-ui, sans-serif", direction: lang === "ar" ? "rtl" : "ltr" }}>
      <nav style={{ padding: "16px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Link href="/" style={{ color: "#C9A84C", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>◆ AegisML</Link>
        <div style={{ display: "flex", gap: 8 }}>
          {(["ar", "en"] as const).map(l => (
            <button key={l} onClick={() => setLang(l)} style={{ background: lang === l ? "#C9A84C22" : "transparent", border: `1px solid ${lang === l ? "#C9A84C" : "#2A2A3E"}`, color: lang === l ? "#C9A84C" : "#666688", padding: "5px 16px", borderRadius: 8, cursor: "pointer", fontSize: 13, fontWeight: 600 }}>
              {l === "ar" ? "العربية" : "English"}
            </button>
          ))}
        </div>
      </nav>

      <main style={{ maxWidth: 920, margin: "0 auto", padding: "36px 24px" }}>
        <div style={{ marginBottom: 32 }}>
          <p style={{ color: "#555577", fontSize: 12, fontFamily: "monospace", marginBottom: 6 }}>SCAN · {result.scan_id}</p>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "0 0 6px", wordBreak: "break-all" }}>{result.filename}</h1>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: vc ? "1fr 1.4fr" : "1fr", gap: 20, marginBottom: 24 }}>
          <div style={{ ...card, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
            <p style={{ color: "#A8A8C4", fontSize: 13, margin: "0 0 8px" }}>{lang === "ar" ? "درجة الخطر" : "Risk Score"}</p>
            <RiskGauge score={result.risk_score} />
          </div>

          {vc && ai && (
            <div style={{ ...card, border: `1px solid ${vc.color}33` }}>
              <p style={{ color: "#A8A8C4", fontSize: 13, margin: "0 0 16px" }}>◆ {lang === "ar" ? "تحليل Claude AI" : "Claude AI Analysis"}</p>
              <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 18 }}>
                <div style={{ width: 52, height: 52, background: vc.bg, border: `1.5px solid ${vc.color}44`, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, color: vc.color, fontWeight: 800 }}>{vc.icon}</div>
                <div>
                  <p style={{ color: vc.color, fontWeight: 800, fontSize: 22, margin: 0 }}>{lang === "ar" ? vc.labelAr : vc.labelEn}</p>
                  <p style={{ color: "#666688", fontSize: 12, margin: "3px 0 0" }}>{lang === "ar" ? `الثقة: ${ai.confidence}%` : `Confidence: ${ai.confidence}%`}</p>
                </div>
              </div>
              <p style={{ color: "#C8C8E0", fontSize: 14, lineHeight: 1.7, margin: "0 0 16px" }}>{lang === "ar" ? ai.summary_ar : ai.summary_en}</p>
              <div style={{ background: "#0A0A0F", borderRadius: 10, padding: "12px 16px" }}>
                <p style={{ color: "#C9A84C", fontSize: 12, fontWeight: 700, margin: "0 0 6px", textTransform: "uppercase" }}>{lang === "ar" ? "التوصية" : "Recommendation"}</p>
                <p style={{ color: "#A0A0BC", fontSize: 13, lineHeight: 1.6, margin: 0 }}>{lang === "ar" ? ai.recommendation_ar : ai.recommendation}</p>
              </div>
            </div>
          )}
        </div>

        {ai && ai.key_risks.length > 0 && (
          <div style={{ ...card, marginBottom: 24 }}>
            <h2 style={{ fontSize: 15, fontWeight: 700, margin: "0 0 16px", color: "#E4C46B" }}>⚡ {lang === "ar" ? "المخاطر الرئيسية" : "Key Risks"}</h2>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
              {ai.key_risks.map((r, i) => (
                <span key={i} style={{ background: "#E74C3C12", border: "1px solid #E74C3C44", color: "#E74C3C", padding: "5px 14px", borderRadius: 8, fontSize: 13 }}>{r}</span>
              ))}
            </div>
          </div>
        )}

        {result.threats.length > 0 ? (
          <div style={{ marginBottom: 24 }}>
            <h2 style={{ fontSize: 15, fontWeight: 700, margin: "0 0 16px" }}>🔍 {lang === "ar" ? `التهديدات (${result.threats.length})` : `Threats (${result.threats.length})`}</h2>
            {result.threats.map((t, i) => <ThreatCard key={i} threat={t} />)}
          </div>
        ) : (
          <div style={{ ...card, textAlign: "center", padding: 40, marginBottom: 24, border: "1px solid #2ECC7133" }}>
            <div style={{ fontSize: 48, marginBottom: 12 }}>✓</div>
            <p style={{ color: "#2ECC71", fontSize: 18, fontWeight: 700, margin: 0 }}>{lang === "ar" ? "لم يتم اكتشاف أي تهديدات" : "No Threats Detected"}</p>
          </div>
        )}

        {Object.keys(result.metadata).length > 0 && (
          <div style={{ ...card, marginBottom: 32 }}>
            <h2 style={{ fontSize: 15, fontWeight: 700, margin: "0 0 16px" }}>📋 {lang === "ar" ? "بيانات الملف" : "File Metadata"}</h2>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 10 }}>
              {Object.entries(result.metadata).map(([k, v]) => (
                <div key={k} style={{ background: "#0A0A0F", borderRadius: 8, padding: "10px 14px" }}>
                  <p style={{ color: "#666688", fontSize: 11, margin: "0 0 4px", textTransform: "uppercase" }}>{k}</p>
                  <p style={{ color: "#E0E0F0", fontSize: 13, margin: 0, fontFamily: "monospace", wordBreak: "break-all" }}>{String(v)}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{ textAlign: "center" }}>
          <Link href="/" style={{ display: "inline-block", background: "linear-gradient(135deg, #C9A84C, #E4C46B)", color: "#0A0A0F", padding: "13px 36px", borderRadius: 10, fontWeight: 800, textDecoration: "none", fontSize: 15 }}>
            {lang === "ar" ? "← فحص نموذج جديد" : "← Scan Another Model"}
          </Link>
        </div>
      </main>
    </div>
  );
}
