"use client";
import { useState } from "react";
import Link from "next/link";

interface Endpoint {
  method: string;
  path: string;
  description_ar: string;
  description_en: string;
  body?: string;
  example_response: string;
}

const ENDPOINTS: Endpoint[] = [
  { method: "GET", path: "/health",
    description_ar: "فحص حالة الـ API وميزاته",
    description_en: "Check API health status and features",
    example_response: `{\n  "status": "ok",\n  "version": "1.0.0"\n}` },
  { method: "POST", path: "/api/v1/scan/file",
    description_ar: "فحص ملف نموذج مرفوع مباشرةً",
    description_en: "Scan an uploaded model file",
    body: "multipart/form-data\n  file: <binary>  (required)",
    example_response: `{\n  "scan_id": "uuid",\n  "status": "complete",\n  "result": {\n    "risk_score": 75,\n    "risk_level": "malicious",\n    "ai_analysis": { "verdict": "DANGEROUS" }\n  }\n}` },
  { method: "POST", path: "/api/v1/scan/url",
    description_ar: "فحص نموذج من رابط HuggingFace مباشرة",
    description_en: "Scan a model from a direct HuggingFace URL",
    body: `{\n  "url": "https://huggingface.co/.../model.gguf"\n}`,
    example_response: `{ "scan_id": "uuid", "status": "complete", "result": {...} }` },
  { method: "GET", path: "/api/v1/scan/{scan_id}",
    description_ar: "جلب نتيجة فحص موجود بواسطة الـ ID",
    description_en: "Retrieve an existing scan result by ID",
    example_response: `{\n  "scan_id": "uuid",\n  "filename": "model.gguf",\n  "risk_score": 10,\n  "risk_level": "clean",\n  "threats": [],\n  "ai_analysis": { "verdict": "SAFE", "confidence": 97 }\n}` },
  { method: "GET", path: "/api/v1/stats",
    description_ar: "إحصائيات عامة للمنصة",
    description_en: "Platform-wide scan statistics",
    example_response: `{ "total": 1247, "clean": 892, "suspicious": 203, "malicious": 140, "critical": 12, "avg_risk_score": 18.4 }` },
  { method: "GET", path: "/api/v1/scans/recent",
    description_ar: "آخر الفحوصات العامة",
    description_en: "Recent public scans (up to 50 results)",
    example_response: `[{ "scan_id": "...", "filename": "...", "risk_score": 5, "verdict": "SAFE" }]` },
  { method: "GET", path: "/api/v1/threats/patterns",
    description_ar: "قاعدة بيانات أنماط التهديد المعروفة",
    description_en: "Known threat patterns database",
    example_response: `{ "patterns": [{ "pattern": "os.system", "severity": "critical" }] }` },
  { method: "POST", path: "/api/v1/keys/generate",
    description_ar: "توليد مفتاح API جديد مجاناً",
    description_en: "Generate a new free API key",
    body: `{ "name": "My Project", "email": "dev@example.com" }`,
    example_response: `{ "api_key": "aml_...", "prefix": "aml_abc123", "scans_limit": 500 }` },
];

const METHOD_COLOR: Record<string, string> = {
  GET: "#2ECC71", POST: "#3498DB", DELETE: "#E74C3C", PUT: "#E67E22",
};

export default function DocsPage() {
  const [lang, setLang] = useState<"ar" | "en">("ar");
  const [activeIdx, setActiveIdx] = useState(0);
  const [keyName, setKeyName] = useState("");
  const [generatedKey, setGeneratedKey] = useState("");
  const [generating, setGenerating] = useState(false);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
  const card: React.CSSProperties = { background: "#12121E", border: "1px solid #1E1E2E", borderRadius: 12 };

  async function generateKey() {
    if (!keyName.trim() || generating) return;
    setGenerating(true);
    try {
      const res = await fetch(`${API}/api/v1/keys/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: keyName }),
      });
      const data = await res.json() as { api_key?: string };
      setGeneratedKey(data.api_key || "");
    } catch { /* silent */ }
    finally { setGenerating(false); }
  }

  const ep = ENDPOINTS[activeIdx];

  return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", color: "#F0F0F8", direction: lang === "ar" ? "rtl" : "ltr", fontFamily: "Cairo, system-ui, sans-serif" }}>
      <nav style={{ padding: "16px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center", position: "sticky", top: 0, background: "rgba(10,10,15,0.92)", backdropFilter: "blur(12px)", zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <Link href="/" style={{ color: "#C9A84C", textDecoration: "none", fontWeight: 900, fontSize: 20 }}>◆ AegisML</Link>
          <span style={{ color: "#555577", fontSize: 13 }}>/ Docs</span>
        </div>
        <div style={{ display: "flex", background: "#0D0D18", border: "1px solid #1E1E2E", borderRadius: 8, padding: 3, gap: 2 }}>
          {(["ar", "en"] as const).map((l) => (
            <button key={l} onClick={() => setLang(l)} style={{ background: lang === l ? "#C9A84C22" : "transparent", border: `1px solid ${lang === l ? "#C9A84C44" : "transparent"}`, color: lang === l ? "#C9A84C" : "#555577", padding: "4px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13, fontWeight: 700 }}>
              {l === "ar" ? "عربي" : "EN"}
            </button>
          ))}
        </div>
      </nav>

      <main style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 24px" }}>
        <div style={{ marginBottom: 40 }}>
          <h1 style={{ fontSize: 32, fontWeight: 900, marginBottom: 8 }}>
            {lang === "ar" ? "توثيق الـ API" : "API Documentation"}
          </h1>
          <p style={{ color: "#A8A8C4", marginBottom: 16 }}>
            {lang === "ar" ? "استخدم AegisML في تطبيقاتك مباشرةً" : "Use AegisML directly in your applications"}
          </p>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <span style={{ background: "#C9A84C18", border: "1px solid #C9A84C33", color: "#C9A84C", padding: "4px 14px", borderRadius: 99, fontSize: 12, fontWeight: 700 }}>
              Base URL: {API}
            </span>
            <span style={{ background: "#2ECC7118", border: "1px solid #2ECC7133", color: "#2ECC71", padding: "4px 14px", borderRadius: 99, fontSize: 12, fontWeight: 700 }}>
              Free: 10 scans/min
            </span>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: 24 }}>
          <div style={{ ...card, padding: 16, alignSelf: "start" }}>
            <p style={{ color: "#A8A8C4", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, margin: "0 0 12px" }}>Endpoints</p>
            {ENDPOINTS.map((e, i) => (
              <button key={i} onClick={() => setActiveIdx(i)} style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", borderRadius: 8, background: activeIdx === i ? "#C9A84C12" : "transparent", border: activeIdx === i ? "1px solid #C9A84C33" : "1px solid transparent", cursor: "pointer", marginBottom: 4, textAlign: lang === "ar" ? "right" : "left" }}>
                <span style={{ background: METHOD_COLOR[e.method] + "22", color: METHOD_COLOR[e.method], padding: "1px 8px", borderRadius: 4, fontSize: 10, fontWeight: 800, flexShrink: 0 }}>{e.method}</span>
                <span style={{ color: "#A8A8C4", fontSize: 12, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.path}</span>
              </button>
            ))}
          </div>

          <div>
            <div style={{ ...card, padding: 28, marginBottom: 20 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 20 }}>
                <span style={{ background: METHOD_COLOR[ep.method] + "22", color: METHOD_COLOR[ep.method], padding: "4px 14px", borderRadius: 6, fontSize: 13, fontWeight: 800 }}>{ep.method}</span>
                <code style={{ color: "#C9A84C", fontSize: 16, fontWeight: 700 }}>{ep.path}</code>
              </div>
              <p style={{ color: "#C8C8E0", fontSize: 15, marginBottom: 24 }}>
                {lang === "ar" ? ep.description_ar : ep.description_en}
              </p>
              {ep.body && (
                <div style={{ marginBottom: 20 }}>
                  <p style={{ color: "#A8A8C4", fontSize: 13, fontWeight: 700, marginBottom: 8 }}>Request Body</p>
                  <pre style={{ background: "#0A0A0F", borderRadius: 10, padding: "14px 18px", color: "#E4C46B", fontSize: 13, fontFamily: "monospace", direction: "ltr", overflow: "auto", margin: 0 }}>{ep.body}</pre>
                </div>
              )}
              <div>
                <p style={{ color: "#A8A8C4", fontSize: 13, fontWeight: 700, marginBottom: 8 }}>
                  {lang === "ar" ? "مثال على الاستجابة" : "Example Response"}
                </p>
                <pre style={{ background: "#0A0A0F", borderRadius: 10, padding: "16px 18px", color: "#2ECC71", fontSize: 12, fontFamily: "monospace", direction: "ltr", overflow: "auto", margin: 0 }}>{ep.example_response}</pre>
              </div>
            </div>

            <div style={{ ...card, padding: 28 }}>
              <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 16, color: "#E4C46B" }}>
                🔑 {lang === "ar" ? "احصل على مفتاح API مجاني" : "Get a Free API Key"}
              </h3>
              <input
                type="text"
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                placeholder={lang === "ar" ? "اسم مشروعك..." : "Your project name..."}
                style={{ width: "100%", background: "#0A0A0F", border: "1px solid #2A2A3E", borderRadius: 10, padding: "12px 16px", color: "#F0F0F8", fontSize: 14, outline: "none", marginBottom: 12, boxSizing: "border-box" }}
              />
              <button
                onClick={generateKey}
                disabled={!keyName.trim() || generating}
                style={{ background: keyName.trim() && !generating ? "linear-gradient(135deg, #C9A84C, #E4C46B)" : "#1E1E2E", color: keyName.trim() && !generating ? "#0A0A0F" : "#555577", border: "none", padding: "12px 28px", borderRadius: 10, fontWeight: 700, cursor: keyName.trim() && !generating ? "pointer" : "not-allowed", fontSize: 14 }}
              >
                {generating ? "..." : lang === "ar" ? "توليد المفتاح" : "Generate Key"}
              </button>
              {generatedKey && (
                <div style={{ marginTop: 16, background: "#2ECC7110", border: "1px solid #2ECC7133", borderRadius: 10, padding: "14px 18px" }}>
                  <p style={{ color: "#2ECC71", fontSize: 12, fontWeight: 700, marginBottom: 8 }}>
                    ⚠ {lang === "ar" ? "احفظ هذا المفتاح — لن يظهر مجدداً" : "Save this key — it won't be shown again"}
                  </p>
                  <code style={{ color: "#C9A84C", fontSize: 13, fontFamily: "monospace", display: "block", direction: "ltr", wordBreak: "break-all" }}>
                    {generatedKey}
                  </code>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
