"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import ThreatCard from "../../components/ThreatCard";

interface CVERecord {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  published_date: string | null;
  affected_tech: string | null;
}

interface ThreatStats {
  total_scans: number;
  malicious_scans: number;
  clean_scans: number;
  total_cves: number;
  total_iocs: number;
}

export default function ThreatsPage() {
  const [cves, setCves] = useState<CVERecord[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [lang, setLang] = useState<"ar" | "en">("ar");
  const [search, setSearch] = useState("");
  const [hashInput, setHashInput] = useState("");
  const [hashResult, setHashResult] = useState<any>(null);
  const [checkingHash, setCheckingHash] = useState(false);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  useEffect(() => {
    Promise.all([
      fetch(`${API}/api/v1/cve/recent`).then((r) => r.json()),
      fetch(`${API}/api/v1/threats/statistics`).then((r) => r.json())
    ])
      .then(([cveData, statsData]) => {
        setCves(cveData.cves || []);
        setStats(statsData);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [API]);

  const handleHashCheck = async () => {
    if (!hashInput.trim()) return;
    setCheckingHash(true);
    setHashResult(null);
    try {
      const res = await fetch(`${API}/api/v1/ioc/check/${hashInput.trim()}`);
      const data = await res.json();
      setHashResult(data);
    } catch (e) {
      console.error(e);
      setHashResult({ status: "error" });
    } finally {
      setCheckingHash(false);
    }
  };

  const filteredCves = cves.filter((c) => {
    const term = search.toLowerCase();
    return !term ||
      c.cve_id.toLowerCase().includes(term) ||
      c.description.toLowerCase().includes(term) ||
      (c.affected_tech && c.affected_tech.toLowerCase().includes(term));
  });

  const card: React.CSSProperties = {
    background: "#12121E", border: "1px solid #232326", borderRadius: 14,
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0B0B0C", color: "#D1D1D1", direction: lang === "ar" ? "rtl" : "ltr", fontFamily: "Cairo, system-ui, sans-serif" }}>
      <style>{`@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}`}</style>

      <nav style={{ padding: "16px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center", position: "sticky", top: 0, background: "rgba(10,10,15,0.92)", backdropFilter: "blur(12px)", zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <Link href="/" style={{ color: "#C9A84C", textDecoration: "none", fontWeight: 900, fontSize: 20 }}>◆ AegisML</Link>
          <span style={{ color: "#71717A", fontSize: 13 }}>/ Threat Intelligence</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <div style={{ display: "flex", background: "#0D0D18", border: "1px solid #232326", borderRadius: 8, padding: 3, gap: 2 }}>
            {(["ar", "en"] as const).map((l) => (
              <button key={l} onClick={() => setLang(l)} style={{ background: lang === l ? "#C9A84C22" : "transparent", border: `1px solid ${lang === l ? "#C9A84C44" : "transparent"}`, color: lang === l ? "#C9A84C" : "#71717A", padding: "4px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 700 }}>
                {l === "ar" ? "عربي" : "EN"}
              </button>
            ))}
          </div>
          <Link href="/" style={{ background: "linear-gradient(135deg, #C9A84C, #E4C46B)", color: "#0B0B0C", padding: "6px 16px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none" }}>
            {lang === "ar" ? "فحص الآن" : "Scan Now"}
          </Link>
        </div>
      </nav>

      <main style={{ maxWidth: 1100, margin: "0 auto", padding: "40px 24px" }}>
        
        {/* Header & Stats */}
        <div style={{ marginBottom: 36, display: "flex", flexDirection: "column", gap: 8 }}>
          <h1 style={{ fontSize: 32, fontWeight: 900, margin: 0 }}>
            🌍 {lang === "ar" ? "استخبارات التهديدات العالمية" : "Global Threat Intelligence"}
          </h1>
          <p style={{ color: "#A8A8C4", fontSize: 16, margin: 0 }}>
            {lang === "ar"
              ? "منصة متقدمة لرصد مؤشرات الاختراق (IOC) والتكامل المباشر مع NVD لثغرات نماذج الذكاء الاصطناعي."
              : "Advanced platform for tracking IOCs and direct NVD integration for AI model vulnerabilities."}
          </p>
        </div>

        {stats && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12, marginBottom: 36 }}>
            {[
              { label: lang === "ar" ? "إجمالي الفحوصات" : "Total Scans", value: stats.total_scans, color: "#C9A84C" },
              { label: lang === "ar" ? "النماذج المصابة" : "Malicious Found", value: stats.malicious_scans, color: "#E74C3C" },
              { label: lang === "ar" ? "ثغرات مسجلة (CVE)" : "Indexed CVEs", value: stats.total_cves, color: "#2ECC71" },
              { label: lang === "ar" ? "مؤشرات اختراق (IOC)" : "Known IOCs", value: stats.total_iocs, color: "#E67E22" },
            ].map((s, i) => (
              <div key={i} style={{ ...card, padding: "20px", textAlign: "center" }}>
                <p style={{ color: s.color, fontSize: 32, fontWeight: 900, margin: "0 0 4px", fontFamily: "monospace" }}>{s.value}</p>
                <p style={{ color: "#A8A8C4", fontSize: 13, margin: 0, fontWeight: 600 }}>{s.label}</p>
              </div>
            ))}
          </div>
        )}

        {/* IOC Checker */}
        <div style={{ ...card, padding: "24px", marginBottom: 36, background: "linear-gradient(180deg, #12121E, #0B0B0C)" }}>
          <h2 style={{ fontSize: 20, margin: "0 0 16px", color: "#D1D1D1" }}>
            🛡️ {lang === "ar" ? "المحقق الفوري للبصمات (IOC Checker)" : "Instant Hash Checker (IOC)"}
          </h2>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <input
              type="text"
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              placeholder={lang === "ar" ? "أدخل بصمة الملف (SHA256 Hash)..." : "Enter file hash (SHA256)..."}
              style={{ flex: 1, minWidth: 280, background: "#0B0B0C", border: "1px solid #2A2A3E", borderRadius: 8, padding: "12px 16px", color: "#D1D1D1", fontSize: 14, outline: "none", fontFamily: "monospace" }}
            />
            <button 
              onClick={handleHashCheck}
              disabled={checkingHash || !hashInput.trim()}
              style={{ background: "#C9A84C", color: "#0B0B0C", border: "none", padding: "0 24px", borderRadius: 8, fontWeight: 800, cursor: checkingHash ? "not-allowed" : "pointer", opacity: checkingHash ? 0.7 : 1 }}
            >
              {checkingHash ? (lang === "ar" ? "جاري الفحص..." : "Checking...") : (lang === "ar" ? "تحقق" : "Verify")}
            </button>
          </div>
          
          {hashResult && (
            <div style={{ marginTop: 16, padding: "16px", borderRadius: 8, border: `1px solid ${hashResult.status === "clean" ? "#2ECC7144" : "#E74C3C44"}`, background: hashResult.status === "clean" ? "#2ECC7111" : "#E74C3C11" }}>
              {hashResult.status === "clean" ? (
                <p style={{ margin: 0, color: "#2ECC71", fontWeight: 700 }}>✅ {lang === "ar" ? "هذه البصمة غير مدرجة في القائمة السوداء." : "This hash is NOT in the blacklist."}</p>
              ) : hashResult.status === "found" ? (
                <div>
                  <p style={{ margin: "0 0 8px", color: "#E74C3C", fontWeight: 900, fontSize: 16 }}>🚨 {lang === "ar" ? "تحذير: هذه البصمة معروفة كتهديد خبيث!" : "WARNING: This hash is a known threat!"}</p>
                  <p style={{ margin: 0, color: "#D1D1D1", fontSize: 13 }}>
                    Severity: <strong style={{ color: "#E74C3C" }}>{hashResult.details.severity.toUpperCase()}</strong> | 
                    Verified: {hashResult.details.is_verified ? "Yes" : "Pending"}
                  </p>
                </div>
              ) : (
                <p style={{ margin: 0, color: "#E67E22" }}>⚠️ {lang === "ar" ? "حدث خطأ أثناء الفحص." : "Error occurred during check."}</p>
              )}
            </div>
          )}
        </div>

        {/* CVE Feed */}
        <div style={{ marginBottom: 24, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
          <h2 style={{ fontSize: 22, margin: 0, fontWeight: 800 }}>
            🔥 {lang === "ar" ? "أحدث ثغرات الـ AI (CVE Feed)" : "Recent AI Vulnerabilities (CVE Feed)"}
          </h2>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={lang === "ar" ? "ابحث عن ثغرة..." : "Search CVEs..."}
            style={{ width: 250, background: "#12121E", border: "1px solid #2A2A3E", borderRadius: 8, padding: "8px 14px", color: "#D1D1D1", fontSize: 13, outline: "none" }}
          />
        </div>

        {loading ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 16 }}>
            {[...Array(6)].map((_, i) => (
              <div key={i} style={{ background: "linear-gradient(90deg, #12121E 25%, #1A1A2E 50%, #12121E 75%)", backgroundSize: "200% 100%", animation: "shimmer 1.5s infinite", height: 140, borderRadius: 12 }} />
            ))}
          </div>
        ) : (
          <>
            {filteredCves.length === 0 ? (
              <p style={{ color: "#A8A8C4", textAlign: "center", padding: "40px" }}>
                {lang === "ar" ? "لم يتم العثور على ثغرات مطابقة." : "No matching CVEs found."}
              </p>
            ) : (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 16 }}>
                {filteredCves.map((cve) => (
                  <ThreatCard key={cve.cve_id} cve={cve} lang={lang} />
                ))}
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
