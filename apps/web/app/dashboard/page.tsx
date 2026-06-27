"use client";
import React, { useEffect, useState } from "react";
import Link from "next/link";
import dynamic from "next/dynamic";
import TrendLine from "../../components/charts/TrendLine";
import ThreatPie from "../../components/charts/ThreatPie";
import SeverityBar from "../../components/charts/SeverityBar";

// Leaflet requires window, so we must load it dynamically with SSR disabled
const GeoMap = dynamic(() => import("../../components/charts/GeoMap"), { ssr: false, loading: () => <div style={{ height: "100%", width: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "#71717A" }}>Loading Map...</div> });

interface OverviewStats {
  totalScans: number;
  threatsFound: number;
  cleanModels: number;
}

export default function DashboardPage() {
  const [lang, setLang] = useState<"ar" | "en">("ar");
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<OverviewStats>({ totalScans: 0, threatsFound: 0, cleanModels: 0 });
  const [trendData, setTrendData] = useState<any[]>([]);
  const [trendPeriod, setTrendPeriod] = useState("7d");
  const [threatData, setThreatData] = useState<{ fileTypes: any[]; severities: any[] }>({ fileTypes: [], severities: [] });
  const [geoPoints, setGeoPoints] = useState<any[]>([]);
  
  const [recentScans, setRecentScans] = useState<any[]>([]); // Mock recent scans or fetch from another endpoint
  const [downloadingReport, setDownloadingReport] = useState<string | null>(null);

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [ovRes, trendRes, threatRes, geoRes, recentRes] = await Promise.all([
        fetch(`${API}/api/v1/analytics/overview`).then(r => r.json()),
        fetch(`${API}/api/v1/analytics/trends?period=${trendPeriod}`).then(r => r.json()),
        fetch(`${API}/api/v1/analytics/threats`).then(r => r.json()),
        fetch(`${API}/api/v1/analytics/geography`).then(r => r.json()),
        fetch(`${API}/api/v1/scans/recent?limit=5`).then(r => r.json()).catch(() => [])
      ]);
      
      setStats(ovRes);
      setTrendData(trendRes.data || []);
      setThreatData(threatRes);
      setGeoPoints(geoRes.points || []);
      setRecentScans(Array.isArray(recentRes) ? recentRes : (recentRes.scans || []));
    } catch (error) {
      console.error("Dashboard fetch error:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, [API, trendPeriod]);

  const handleDownloadReport = async (scanId: string) => {
    setDownloadingReport(scanId);
    try {
      const response = await fetch(`${API}/api/v1/analytics/report/${scanId}`, { method: "POST" });
      if (!response.ok) throw new Error("Report generation failed");
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `AegisML_Report_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (e) {
      alert("Failed to download PDF report. Ensure the scan exists and the backend is running.");
      console.error(e);
    } finally {
      setDownloadingReport(null);
    }
  };

  const cardStyle: React.CSSProperties = {
    background: "#12121E", border: "1px solid #232326", borderRadius: 14, padding: "24px"
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0B0B0C", color: "#D1D1D1", direction: lang === "ar" ? "rtl" : "ltr", fontFamily: "Cairo, system-ui, sans-serif" }}>
      <nav style={{ padding: "16px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center", position: "sticky", top: 0, background: "rgba(10,10,15,0.92)", backdropFilter: "blur(12px)", zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <Link href="/" style={{ color: "#C9A84C", textDecoration: "none", fontWeight: 900, fontSize: 20 }}>◆ AegisML</Link>
          <span style={{ color: "#71717A", fontSize: 13 }}>/ {lang === "ar" ? "لوحة القيادة" : "Dashboard"}</span>
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
            {lang === "ar" ? "فحص جديد" : "New Scan"}
          </Link>
        </div>
      </nav>

      <main style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 24px" }}>
        {/* Section 1: Stats */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: 16, marginBottom: 24 }}>
          <div style={cardStyle}>
            <p style={{ color: "#A8A8C4", margin: "0 0 8px", fontSize: 14 }}>{lang === "ar" ? "إجمالي النماذج المفحوصة" : "Total Models Scanned"}</p>
            <h2 style={{ margin: 0, fontSize: 36, color: "#C9A84C", fontFamily: "monospace" }}>{stats.totalScans}</h2>
          </div>
          <div style={cardStyle}>
            <p style={{ color: "#A8A8C4", margin: "0 0 8px", fontSize: 14 }}>{lang === "ar" ? "التهديدات المكتشفة" : "Threats Detected"}</p>
            <h2 style={{ margin: 0, fontSize: 36, color: "#E74C3C", fontFamily: "monospace" }}>{stats.threatsFound}</h2>
          </div>
          <div style={cardStyle}>
            <p style={{ color: "#A8A8C4", margin: "0 0 8px", fontSize: 14 }}>{lang === "ar" ? "النماذج الآمنة" : "Safe Models"}</p>
            <h2 style={{ margin: 0, fontSize: 36, color: "#2ECC71", fontFamily: "monospace" }}>{stats.cleanModels}</h2>
          </div>
        </div>

        {/* Section 2: Trend Chart */}
        <div style={{ ...cardStyle, marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
            <h3 style={{ margin: 0, fontSize: 18, color: "#D1D1D1" }}>{lang === "ar" ? "اتجاهات الفحص" : "Scan Trends"}</h3>
            <select 
              value={trendPeriod} 
              onChange={(e) => setTrendPeriod(e.target.value)}
              style={{ background: "#0B0B0C", border: "1px solid #2A2A3E", borderRadius: 8, padding: "6px 12px", color: "#A8A8C4", outline: "none", cursor: "pointer" }}
            >
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="90d">Last 90 Days</option>
              <option value="1y">Last Year</option>
            </select>
          </div>
          <TrendLine data={trendData} lang={lang} />
        </div>

        {/* Section 3: Distribution & Severity */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(350px, 1fr))", gap: 24, marginBottom: 24 }}>
          <div style={cardStyle}>
            <h3 style={{ margin: "0 0 24px", fontSize: 18, color: "#D1D1D1" }}>{lang === "ar" ? "توزيع التهديدات (حسب الامتداد)" : "Threat Distribution (Ext)"}</h3>
            <ThreatPie data={threatData.fileTypes} lang={lang} />
          </div>
          <div style={cardStyle}>
            <h3 style={{ margin: "0 0 24px", fontSize: 18, color: "#D1D1D1" }}>{lang === "ar" ? "مستويات الخطورة" : "Severity Levels"}</h3>
            <SeverityBar data={threatData.severities} lang={lang} />
          </div>
        </div>

        {/* Section 4: Geo Map */}
        <div style={{ ...cardStyle, marginBottom: 24, height: 400, padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "20px 24px", borderBottom: "1px solid #232326" }}>
            <h3 style={{ margin: 0, fontSize: 18, color: "#D1D1D1" }}>{lang === "ar" ? "الطلبات جغرافياً" : "Geographic Request Origins"}</h3>
          </div>
          <div style={{ height: "calc(100% - 62px)" }}>
            <GeoMap points={geoPoints} />
          </div>
        </div>

        {/* Section 5: Recent Scans & Reports */}
        <div style={cardStyle}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
            <h3 style={{ margin: 0, fontSize: 18, color: "#D1D1D1" }}>{lang === "ar" ? "الفحوصات الأخيرة" : "Recent Scans"}</h3>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #2A2A3E", color: "#71717A", fontSize: 13 }}>
                <th style={{ padding: "12px 8px" }}>ID</th>
                <th style={{ padding: "12px 8px" }}>Filename</th>
                <th style={{ padding: "12px 8px" }}>Risk</th>
                <th style={{ padding: "12px 8px" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.length > 0 ? (
                recentScans.map((scan, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid #1A1A2E", fontSize: 14 }}>
                    <td style={{ padding: "16px 8px", color: "#C9A84C", fontFamily: "monospace" }}>{scan.scan_id.substring(0,8)}...</td>
                    <td style={{ padding: "16px 8px", color: "#D1D1D1" }}>{scan.filename}</td>
                    <td style={{ padding: "16px 8px" }}>
                      <span style={{ 
                        color: scan.risk_level === "critical" ? "#E74C3C" : scan.risk_level === "clean" ? "#2ECC71" : "#E67E22",
                        background: scan.risk_level === "critical" ? "#E74C3C22" : scan.risk_level === "clean" ? "#2ECC7122" : "#E67E2222",
                        padding: "4px 8px", borderRadius: 4, fontSize: 12, fontWeight: "bold", textTransform: "uppercase"
                      }}>
                        {scan.risk_level}
                      </span>
                    </td>
                    <td style={{ padding: "16px 8px" }}>
                      <button 
                        onClick={() => handleDownloadReport(scan.scan_id)}
                        disabled={downloadingReport === scan.scan_id}
                        style={{ background: "#2A2A3E", color: "#D1D1D1", border: "none", padding: "6px 12px", borderRadius: 6, cursor: "pointer", fontSize: 12, fontWeight: "bold" }}
                      >
                        {downloadingReport === scan.scan_id ? "Generating PDF..." : "📄 Export PDF"}
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} style={{ padding: "32px", textAlign: "center", color: "#71717A" }}>
                    {lang === "ar" ? "لا توجد فحوصات لعرضها" : "No recent scans available."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

      </main>
    </div>
  );
}
