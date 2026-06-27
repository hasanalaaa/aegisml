"use client";
import { useEffect, useState } from "react";
import Link from "next/link";

interface ScanSummary {
  scan_id: string;
  filename: string;
  risk_score: number;
  risk_level: string;
  threats: unknown[];
  ai_analysis: { verdict: string; confidence: number };
}

interface CompareResult {
  scan_a: ScanSummary;
  scan_b: ScanSummary;
  comparison: {
    safer: string;
    risk_difference: number;
    a_threat_count: number;
    b_threat_count: number;
  };
}

const riskColor = (s: number) =>
  s < 30 ? "#2ECC71" : s < 60 ? "#E67E22" : s < 85 ? "#E74C3C" : "#C0392B";

export default function ComparePage() {
  const [scanIdA, setScanIdA] = useState("");
  const [scanIdB, setScanIdB] = useState("");
  const [comparison, setComparison] = useState<CompareResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lang, setLang] = useState<"ar" | "en">("ar");

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
  const card: React.CSSProperties = {
    background: "#12121E", border: "1px solid #232326", borderRadius: 14,
  };

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const a = params.get("a");
      const b = params.get("b");
      if (a) setScanIdA(a);
      if (b) setScanIdB(b);
    }
  }, []);

  async function compare() {
    if (!scanIdA.trim() || !scanIdB.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `${API}/api/v1/compare?scan_a=${encodeURIComponent(scanIdA.trim())}&scan_b=${encodeURIComponent(scanIdB.trim())}`
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({})) as { detail?: string };
        throw new Error(err.detail || "Could not compare scans");
      }
      setComparison(await res.json() as CompareResult);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  const inputStyle: React.CSSProperties = {
    width: "100%", background: "#0B0B0C", border: "1px solid #2A2A3E",
    borderRadius: 8, padding: "10px 14px", color: "#D1D1D1",
    fontSize: 13, outline: "none", boxSizing: "border-box",
    direction: "ltr", fontFamily: "monospace",
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0B0B0C", color: "#D1D1D1", direction: lang === "ar" ? "rtl" : "ltr", fontFamily: "Cairo, system-ui, sans-serif" }}>
      <nav style={{ padding: "16px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <Link href="/" style={{ color: "#C9A84C", textDecoration: "none", fontWeight: 900, fontSize: 20 }}>◆ AegisML</Link>
          <span style={{ color: "#71717A", fontSize: 13 }}>/ Compare</span>
        </div>
        <div style={{ display: "flex", background: "#0D0D18", border: "1px solid #232326", borderRadius: 8, padding: 3, gap: 2 }}>
          {(["ar", "en"] as const).map((l) => (
            <button key={l} onClick={() => setLang(l)} style={{ background: lang === l ? "#C9A84C22" : "transparent", border: `1px solid ${lang === l ? "#C9A84C44" : "transparent"}`, color: lang === l ? "#C9A84C" : "#71717A", padding: "4px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 700 }}>
              {l === "ar" ? "عربي" : "EN"}
            </button>
          ))}
        </div>
      </nav>

      <main style={{ maxWidth: 960, margin: "0 auto", padding: "40px 24px" }}>
        <h1 style={{ fontSize: 28, fontWeight: 900, marginBottom: 8 }}>
          ⚖️ {lang === "ar" ? "مقارنة نموذجين" : "Compare Two Models"}
        </h1>
        <p style={{ color: "#A8A8C4", marginBottom: 36 }}>
          {lang === "ar"
            ? "أدخل معرّفَي فحصين لمقارنة مستوى أمانهما"
            : "Enter two scan IDs to compare their security levels"}
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
          {[
            { label: lang === "ar" ? "النموذج الأول (A)" : "Model A", value: scanIdA, set: setScanIdA },
            { label: lang === "ar" ? "النموذج الثاني (B)" : "Model B", value: scanIdB, set: setScanIdB },
          ].map((item, i) => (
            <div key={i} style={{ ...card, padding: "20px 24px" }}>
              <p style={{ color: "#A8A8C4", fontSize: 13, fontWeight: 700, marginBottom: 10 }}>{item.label}</p>
              <input
                type="text"
                value={item.value}
                onChange={(e) => item.set(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                style={inputStyle}
              />
            </div>
          ))}
        </div>

        <button
          onClick={compare}
          disabled={!scanIdA.trim() || !scanIdB.trim() || loading}
          style={{
            background: scanIdA && scanIdB && !loading ? "linear-gradient(135deg, #C9A84C, #E4C46B)" : "#12121E",
            color: scanIdA && scanIdB && !loading ? "#0B0B0C" : "#71717A",
            border: "none", padding: "13px 40px", borderRadius: 10,
            fontWeight: 700, fontSize: 15,
            cursor: scanIdA && scanIdB && !loading ? "pointer" : "not-allowed",
            marginBottom: 28,
          }}
        >
          {loading ? "⏳..." : lang === "ar" ? "⚖️ قارن الآن" : "⚖️ Compare Now"}
        </button>

        {error && <p style={{ color: "#E74C3C", marginBottom: 20 }}>⚠ {error}</p>}

        {comparison && (
          <div>
            <div style={{ ...card, padding: "16px 24px", marginBottom: 20, background: "#2ECC7108", border: "1px solid #2ECC7133" }}>
              <p style={{ color: "#E4C46B", fontSize: 16, fontWeight: 700, margin: 0 }}>
                {lang === "ar" ? "النموذج الأكثر أماناً:" : "Safer Model:"}{" "}
                {comparison.comparison.safer === comparison.scan_a.scan_id
                  ? comparison.scan_a.filename
                  : comparison.scan_b.filename}
              </p>
              <p style={{ color: "#A8A8C4", fontSize: 13, margin: "4px 0 0" }}>
                {lang === "ar"
                  ? `فرق درجة الخطر: ${comparison.comparison.risk_difference.toFixed(0)} نقطة`
                  : `Risk difference: ${comparison.comparison.risk_difference.toFixed(0)} points`}
              </p>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {([comparison.scan_a, comparison.scan_b] as ScanSummary[]).map((scan, i) => (
                <div key={i} style={{ ...card, padding: 24, border: `1px solid ${riskColor(scan.risk_score)}33` }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                    <div style={{ width: 48, height: 48, borderRadius: "50%", background: `${riskColor(scan.risk_score)}18`, border: `2px solid ${riskColor(scan.risk_score)}44`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, fontWeight: 900, color: riskColor(scan.risk_score), fontFamily: "monospace", flexShrink: 0 }}>
                      {Math.round(scan.risk_score)}
                    </div>
                    <div>
                      <p style={{ color: "#D1D1D1", fontWeight: 700, fontSize: 14, margin: 0, wordBreak: "break-all" }}>{scan.filename}</p>
                      <p style={{ color: riskColor(scan.risk_score), fontSize: 12, margin: "2px 0 0", fontWeight: 700 }}>{scan.risk_level.toUpperCase()}</p>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
                    <div style={{ background: "#0B0B0C", borderRadius: 8, padding: "8px 14px", flex: 1, textAlign: "center" }}>
                      <p style={{ color: "#E74C3C", fontSize: 18, fontWeight: 800, margin: 0, fontFamily: "monospace" }}>
                        {i === 0 ? comparison.comparison.a_threat_count : comparison.comparison.b_threat_count}
                      </p>
                      <p style={{ color: "#71717A", fontSize: 11, margin: 0 }}>{lang === "ar" ? "تهديد" : "threats"}</p>
                    </div>
                    <div style={{ background: "#0B0B0C", borderRadius: 8, padding: "8px 14px", flex: 1, textAlign: "center" }}>
                      <p style={{ color: "#C9A84C", fontSize: 18, fontWeight: 800, margin: 0, fontFamily: "monospace" }}>{scan.ai_analysis?.confidence || 0}%</p>
                      <p style={{ color: "#71717A", fontSize: 11, margin: 0 }}>confidence</p>
                    </div>
                  </div>
                  <Link href={`/scan/${scan.scan_id}`} style={{ display: "block", textAlign: "center", color: "#C9A84C", fontSize: 13, textDecoration: "none" }}>
                    {lang === "ar" ? "عرض التقرير الكامل ↗" : "View Full Report ↗"}
                  </Link>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
