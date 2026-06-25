"use client";

import { useEffect, useState, useCallback } from "react";
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
  inspector_error?: string;
}

const VERDICT_CONFIG = {
  SAFE:       { color: "#2ECC71", bg: "rgba(46,204,113,0.10)",  border: "rgba(46,204,113,0.25)",  labelAr: "آمن",       labelEn: "SAFE",       icon: "✓", desc: "الملف آمن للاستخدام" },
  SUSPICIOUS: { color: "#E67E22", bg: "rgba(230,126,34,0.10)",  border: "rgba(230,126,34,0.25)",  labelAr: "مشبوه",     labelEn: "SUSPICIOUS", icon: "⚠", desc: "يستوجب المراجعة" },
  DANGEROUS:  { color: "#E74C3C", bg: "rgba(231,76,60,0.10)",   border: "rgba(231,76,60,0.25)",   labelAr: "خطير",      labelEn: "DANGEROUS",  icon: "✗", desc: "لا تستخدم هذا الملف" },
  CRITICAL:   { color: "#C0392B", bg: "rgba(192,57,43,0.15)",   border: "rgba(192,57,43,0.35)",   labelAr: "حرج جداً",  labelEn: "CRITICAL",   icon: "☠", desc: "خطر شديد — احذف الملف" },
  UNKNOWN:    { color: "#A8A8C4", bg: "rgba(168,168,196,0.10)", border: "rgba(168,168,196,0.20)", labelAr: "غير معروف", labelEn: "UNKNOWN",    icon: "?", desc: "لم يتمكن Claude من التحليل" },
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#E74C3C",
  high: "#E67E22",
  medium: "#F1C40F",
  low: "#2ECC71",
};

const SEVERITY_LABEL_AR: Record<string, string> = {
  critical: "حرج",
  high: "عالي",
  medium: "متوسط",
  low: "منخفض",
};

function RiskGauge({ score }: { score: number }) {
  const color = score < 30 ? "#2ECC71" : score < 60 ? "#E67E22" : score < 85 ? "#E74C3C" : "#C0392B";
  const label = score < 30 ? "آمن" : score < 60 ? "مشبوه" : score < 85 ? "خطير" : "حرج جداً";
  const dash = (score / 100) * 251.2;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
      <svg viewBox="0 0 200 110" width="200" height="110">
        <defs>
          <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor={color} stopOpacity="0.6" />
            <stop offset="100%" stopColor={color} />
          </linearGradient>
        </defs>
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#1A1A2E" strokeWidth="20" strokeLinecap="round" />
        <path
          d="M 20 100 A 80 80 0 0 1 180 100"
          fill="none"
          stroke="url(#gaugeGrad)"
          strokeWidth="20"
          strokeLinecap="round"
          strokeDasharray={`${dash} 251.2`}
        />
        <circle cx="100" cy="100" r="8" fill={color} opacity="0.3" />
        <circle cx="100" cy="100" r="4" fill={color} />
        <text x="100" y="86" textAnchor="middle" fill={color} fontSize="30" fontWeight="900" fontFamily="monospace">{score}</text>
        <text x="100" y="102" textAnchor="middle" fill="#555577" fontSize="11">/ 100</text>
      </svg>
      <div style={{ textAlign: "center" }}>
        <span style={{
          background: `${color}18`,
          border: `1px solid ${color}44`,
          color,
          padding: "4px 16px",
          borderRadius: 99,
          fontSize: 14,
          fontWeight: 700,
        }}>{label}</span>
      </div>
    </div>
  );
}

function ThreatCard({ threat, lang }: { threat: Threat; lang: "ar" | "en" }) {
  const color = SEVERITY_COLOR[threat.severity] || "#A8A8C4";
  const severityLabel = lang === "ar" ? (SEVERITY_LABEL_AR[threat.severity] || threat.severity) : threat.severity;
  return (
    <div style={{
      background: "#0D0D1A",
      border: `1px solid ${color}28`,
      borderLeft: `4px solid ${color}`,
      borderRadius: 10,
      padding: "16px 20px",
      marginBottom: 10,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8, gap: 12, flexWrap: "wrap" }}>
        <code style={{ color: "#C9A84C", fontSize: 14, fontWeight: 800, fontFamily: "monospace" }}>{threat.pattern}</code>
        <span style={{
          background: `${color}22`,
          color,
          padding: "2px 12px",
          borderRadius: 99,
          fontSize: 11,
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: 1,
          flexShrink: 0,
        }}>{severityLabel}</span>
      </div>
      <p style={{ color: "#B0B0CC", fontSize: 13, margin: 0, lineHeight: 1.6 }}>{threat.description}</p>
      {threat.location && (
        <p style={{ color: "#444466", fontSize: 12, margin: "8px 0 0", fontFamily: "monospace", display: "flex", alignItems: "center", gap: 6 }}>
          <span>📍</span> {threat.location}
        </p>
      )}
    </div>
  );
}

function SkeletonCard({ height = 120 }: { height?: number }) {
  return (
    <div style={{
      background: "linear-gradient(90deg, #12121E 25%, #1A1A2E 50%, #12121E 75%)",
      backgroundSize: "200% 100%",
      animation: "shimmer 1.5s infinite",
      borderRadius: 14,
      height,
    }} />
  );
}

export default function ScanResultPage() {
  const params = useParams();
  const scanId = params?.id as string;
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lang, setLang] = useState<"ar" | "en">("ar");
  const [copied, setCopied] = useState(false);

  const fetchResult = useCallback(async () => {
    if (!scanId) return;
    const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    try {
      const r = await fetch(`${API}/api/v1/scan/${scanId}`);
      if (!r.ok) throw new Error(r.status === 404 ? "لم يتم العثور على نتيجة الفحص" : `خطأ ${r.status}`);
      const data = await r.json();
      setResult(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "خطأ غير معروف");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => { fetchResult(); }, [fetchResult]);

  function copyLink() {
    navigator.clipboard.writeText(window.location.href).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  function downloadReport() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegisml-report-${result.scan_id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const card: React.CSSProperties = { background: "#12121E", border: "1px solid #1E1E2E", borderRadius: 14 };

  if (loading) return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", color: "#F0F0F8" }}>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}} @keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}`}</style>
      <nav style={{ padding: "18px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ color: "#C9A84C", fontWeight: 900, fontSize: 20 }}>◆ AegisML</span>
      </nav>
      <main style={{ maxWidth: 920, margin: "0 auto", padding: "48px 24px", display: "flex", flexDirection: "column", gap: 20 }}>
        <SkeletonCard height={80} />
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr", gap: 20 }}>
          <SkeletonCard height={220} />
          <SkeletonCard height={220} />
        </div>
        <SkeletonCard height={160} />
      </main>
    </div>
  );

  if (error) return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 20, padding: 24 }}>
      <div style={{ fontSize: 64 }}>⚠️</div>
      <h2 style={{ color: "#E74C3C", fontSize: 22, fontWeight: 700, margin: 0, textAlign: "center" }}>{error}</h2>
      <Link href="/" style={{
        background: "linear-gradient(135deg, #C9A84C, #E4C46B)",
        color: "#0A0A0F",
        padding: "12px 28px",
        borderRadius: 10,
        fontWeight: 700,
        textDecoration: "none",
        fontSize: 15,
      }}>← العودة للرئيسية</Link>
    </div>
  );

  if (!result) return null;

  const ai = result.ai_analysis;
  const vc = ai ? (VERDICT_CONFIG[ai.verdict] ?? VERDICT_CONFIG.UNKNOWN) : null;

  const threatsByRisk = [...(result.threats || [])].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
  });

  return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", color: "#F0F0F8", fontFamily: "system-ui, sans-serif", direction: lang === "ar" ? "rtl" : "ltr" }}>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}} @keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}`}</style>

      {/* NAV */}
      <nav style={{ padding: "16px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center", position: "sticky", top: 0, background: "rgba(10,10,15,0.92)", backdropFilter: "blur(12px)", zIndex: 100 }}>
        <Link href="/" style={{ color: "#C9A84C", textDecoration: "none", fontWeight: 900, fontSize: 20 }}>◆ AegisML</Link>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {(["ar", "en"] as const).map(l => (
            <button key={l} onClick={() => setLang(l)} style={{
              background: lang === l ? "#C9A84C22" : "transparent",
              border: `1px solid ${lang === l ? "#C9A84C" : "#2A2A3E"}`,
              color: lang === l ? "#C9A84C" : "#666688",
              padding: "5px 14px", borderRadius: 8, cursor: "pointer", fontSize: 13, fontWeight: 600,
            }}>{l === "ar" ? "العربية" : "English"}</button>
          ))}
          <button onClick={copyLink} style={{ background: "#12121E", border: "1px solid #2A2A3E", color: copied ? "#2ECC71" : "#A8A8C4", padding: "5px 14px", borderRadius: 8, cursor: "pointer", fontSize: 13 }}>
            {copied ? "✓ تم النسخ" : "🔗 مشاركة"}
          </button>
          <button onClick={downloadReport} style={{ background: "#12121E", border: "1px solid #2A2A3E", color: "#A8A8C4", padding: "5px 14px", borderRadius: 8, cursor: "pointer", fontSize: 13 }}>
            ⬇ JSON
          </button>
        </div>
      </nav>

      <main style={{ maxWidth: 960, margin: "0 auto", padding: "40px 24px" }}>

        {/* HEADER */}
        <div style={{ marginBottom: 36 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
            <span style={{ background: "#C9A84C18", border: "1px solid #C9A84C33", color: "#C9A84C", padding: "3px 12px", borderRadius: 99, fontSize: 11, fontWeight: 700, letterSpacing: 1, fontFamily: "monospace" }}>SCAN REPORT</span>
            <span style={{ color: "#333355", fontSize: 12, fontFamily: "monospace" }}>{result.scan_id}</span>
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 900, margin: "0 0 6px", wordBreak: "break-all" }}>{result.filename}</h1>
          <p style={{ color: "#555577", margin: 0, fontSize: 13 }}>
            {lang === "ar" ? "تقرير الفحص الأمني الكامل بواسطة AegisML + Claude AI" : "Full Security Scan Report by AegisML + Claude AI"}
          </p>
        </div>

        {/* TOP GRID */}
        <div style={{ display: "grid", gridTemplateColumns: vc ? "1fr 1.5fr" : "1fr", gap: 20, marginBottom: 24 }}>

          {/* Risk Score */}
          <div style={{ ...card, padding: 28, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16 }}>
            <p style={{ color: "#A8A8C4", fontSize: 13, margin: 0, fontWeight: 600 }}>
              {lang === "ar" ? "درجة الخطر" : "Risk Score"}
            </p>
            <RiskGauge score={result.risk_score} />
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "center" }}>
              {[
                { label: lang === "ar" ? "التهديدات" : "Threats", value: result.threats?.length ?? 0, color: result.threats?.length > 0 ? "#E74C3C" : "#2ECC71" },
              ].map((s2, i) => (
                <div key={i} style={{ textAlign: "center", background: "#0A0A0F", borderRadius: 8, padding: "8px 20px" }}>
                  <p style={{ color: s2.color, fontSize: 20, fontWeight: 800, margin: "0 0 2px", fontFamily: "monospace" }}>{s2.value}</p>
                  <p style={{ color: "#555577", fontSize: 11, margin: 0 }}>{s2.label}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Claude Verdict */}
          {vc && ai && (
            <div style={{ ...card, border: `1px solid ${vc.border}`, padding: 28 }}>
              <p style={{ color: "#A8A8C4", fontSize: 13, margin: "0 0 18px", display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ color: "#C9A84C", fontSize: 16 }}>◆</span>
                {lang === "ar" ? "تحليل Claude AI" : "Claude AI Analysis"}
              </p>
              <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
                <div style={{
                  width: 56, height: 56,
                  background: vc.bg,
                  border: `2px solid ${vc.color}44`,
                  borderRadius: "50%",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 24, color: vc.color, fontWeight: 900,
                  flexShrink: 0,
                }}>{vc.icon}</div>
                <div>
                  <p style={{ color: vc.color, fontWeight: 900, fontSize: 24, margin: 0 }}>
                    {lang === "ar" ? vc.labelAr : vc.labelEn}
                  </p>
                  <p style={{ color: "#666688", fontSize: 13, margin: "4px 0 0" }}>
                    {lang === "ar" ? vc.desc : vc.desc} · {lang === "ar" ? "الثقة:" : "Confidence:"} <span style={{ color: vc.color }}>{ai.confidence}%</span>
                  </p>
                </div>
              </div>

              {/* Confidence Bar */}
              <div style={{ background: "#0A0A0F", borderRadius: 99, height: 6, marginBottom: 18, overflow: "hidden" }}>
                <div style={{
                  width: `${ai.confidence}%`,
                  height: "100%",
                  background: `linear-gradient(90deg, ${vc.color}88, ${vc.color})`,
                  borderRadius: 99,
                  transition: "width 1s ease",
                }} />
              </div>

              <p style={{ color: "#C8C8E0", fontSize: 14, lineHeight: 1.75, margin: "0 0 18px" }}>
                {lang === "ar" ? ai.summary_ar : ai.summary_en}
              </p>
              <div style={{ background: "#0A0A0F", borderRadius: 10, padding: "14px 18px" }}>
                <p style={{ color: "#C9A84C", fontSize: 11, fontWeight: 700, margin: "0 0 8px", textTransform: "uppercase", letterSpacing: 1 }}>
                  {lang === "ar" ? "التوصية" : "Recommendation"}
                </p>
                <p style={{ color: "#A0A0BC", fontSize: 14, lineHeight: 1.65, margin: 0 }}>
                  {lang === "ar" ? ai.recommendation_ar : ai.recommendation}
                </p>
              </div>
            </div>
          )}
        </div>

        {/* KEY RISKS */}
        {ai && ai.key_risks.length > 0 && (
          <div style={{ ...card, padding: "22px 24px", marginBottom: 20 }}>
            <h2 style={{ fontSize: 14, fontWeight: 700, margin: "0 0 14px", color: "#E4C46B", textTransform: "uppercase", letterSpacing: 1 }}>
              ⚡ {lang === "ar" ? "المخاطر الرئيسية" : "Key Risks"}
            </h2>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
              {ai.key_risks.map((r, i) => (
                <span key={i} style={{
                  background: "#E74C3C10",
                  border: "1px solid #E74C3C33",
                  color: "#E74C3C",
                  padding: "5px 16px",
                  borderRadius: 8,
                  fontSize: 13,
                  fontWeight: 500,
                }}>⚡ {r}</span>
              ))}
            </div>
          </div>
        )}

        {/* THREATS */}
        <div style={{ marginBottom: 20 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 16px", display: "flex", alignItems: "center", gap: 10 }}>
            🔍 {lang === "ar" ? `التهديدات المكتشفة` : `Detected Threats`}
            {result.threats?.length > 0 && (
              <span style={{ background: "#E74C3C22", color: "#E74C3C", padding: "2px 12px", borderRadius: 99, fontSize: 13, fontWeight: 700 }}>
                {result.threats.length}
              </span>
            )}
          </h2>
          {threatsByRisk.length > 0 ? (
            threatsByRisk.map((t, i) => <ThreatCard key={i} threat={t} lang={lang} />)
          ) : (
            <div style={{ ...card, textAlign: "center", padding: 48, border: "1px solid #2ECC7122" }}>
              <div style={{ fontSize: 52, marginBottom: 14 }}>✓</div>
              <p style={{ color: "#2ECC71", fontSize: 20, fontWeight: 800, margin: "0 0 8px" }}>
                {lang === "ar" ? "لم يتم اكتشاف أي تهديدات" : "No Threats Detected"}
              </p>
              <p style={{ color: "#555577", fontSize: 14, margin: 0 }}>
                {lang === "ar" ? "الملف نظيف وفق الفحص الآلي" : "File appears clean based on automated scan"}
              </p>
            </div>
          )}
        </div>

        {/* METADATA */}
        {result.metadata && Object.keys(result.metadata).length > 0 && (
          <div style={{ ...card, padding: "22px 24px", marginBottom: 32 }}>
            <h2 style={{ fontSize: 14, fontWeight: 700, margin: "0 0 16px", textTransform: "uppercase", letterSpacing: 1, color: "#A8A8C4" }}>
              📋 {lang === "ar" ? "بيانات الملف" : "File Metadata"}
            </h2>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 10 }}>
              {Object.entries(result.metadata).map(([k, v]) => (
                <div key={k} style={{ background: "#0A0A0F", borderRadius: 8, padding: "10px 14px" }}>
                  <p style={{ color: "#444466", fontSize: 11, margin: "0 0 4px", textTransform: "uppercase", letterSpacing: 0.5 }}>{k}</p>
                  <p style={{ color: "#E0E0F0", fontSize: 13, margin: 0, fontFamily: "monospace", wordBreak: "break-all" }}>{String(v)}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CTA */}
        <div style={{ textAlign: "center", display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <Link href="/" style={{
            display: "inline-block",
            background: "linear-gradient(135deg, #C9A84C, #E4C46B)",
            color: "#0A0A0F",
            padding: "13px 36px",
            borderRadius: 10,
            fontWeight: 800,
            textDecoration: "none",
            fontSize: 15,
          }}>
            {lang === "ar" ? "← فحص نموذج جديد" : "← Scan Another Model"}
          </Link>
          <button onClick={downloadReport} style={{
            background: "transparent",
            border: "1px solid #2A2A3E",
            color: "#A8A8C4",
            padding: "13px 28px",
            borderRadius: 10,
            fontWeight: 600,
            cursor: "pointer",
          }}>
            {lang === "ar" ? "⬇ تحميل التقرير (JSON)" : "⬇ Download JSON"}
          </button>
        </div>
      </main>
    </div>
  );
}
