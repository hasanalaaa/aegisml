"use client";

import { useState, useRef } from "react";
import Link from "next/link";
import { useLiveStats } from "../hooks/useLiveStats";
import { AIProviderSelector } from "../components/AIProviderSelector";

const SUPPORTED_FORMATS = [".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth"];

const CONTENT = {
  ar: {
    dir: "rtl" as const,
    navBtn: "ابدأ الفحص",
    badge: "v0.1.0 — Open Beta",
    heroLine1: "افحص نماذج الذكاء الاصطناعي",
    heroLine2: "قبل أن تضرّك",
    heroSub: "اكشف الأبواب الخلفية والتروجانات والكود الخبيث في نماذج AI قبل تشغيلها في الإنتاج",
    dropTitle: "اسحب الملف هنا أو انقر للاختيار",
    dropFormats: "يدعم: .gguf • .safetensors • .pkl • .pt • .pth",
    scanBtn: "⬡ Scan Now",
    scanningBtn: "⏳ جارٍ الفحص...",
    scanningMsg: "جارٍ تحليل الملف…",
    changeFile: "تغيير الملف",
    noStore: "الملفات لا تُحفظ • الفحص آمن وسريع",
    stats: [
      { value: "6", label: "صيغ مدعومة", sub: "Formats Supported" },
      { value: "14+", label: "نمط تهديد", sub: "Threat Patterns" },
      { value: "AGPL-3.0", label: "رخصة مفتوحة", sub: "Open Source" },
    ],
    whyTitle: "لماذا",
    whySuffix: "؟",
    whySub: "نماذج AI يمكن أن تحتوي على كود خبيث مخفي يُنفَّذ عند التحميل. لا تثق، افحص.",
    why: [
      { icon: "🔍", title: "فحص عميق", desc: "يقرأ الملف على مستوى البايت ويكشف الكود الخبيث المخفي في الـ metadata." },
      { icon: "🤖", title: "Claude AI Judge", desc: "تحليل ذكي باستخدام Claude API يشرح المخاطر ويقترح الخطوات التالية." },
      { icon: "⚡", title: "نتيجة فورية", desc: "فحص سريع في ثوانٍ لأي ملف نموذج مهما كان حجمه." },
      { icon: "🛡️", title: "مفتوح المصدر", desc: "كود شفاف 100% برخصة AGPL-3.0. راجع الكود، ساهم، وثق." },
      { icon: "🌍", title: "عربي وإنجليزي", desc: "التقارير متاحة بالعربية والإنجليزية لخدمة مجتمع أوسع." },
      { icon: "🔒", title: "لا تخزين", desc: "ملفاتك لا تُحفظ على خوادمنا. الفحص مؤقت وفوري." },
    ],
    threatsTitle: "أنماط التهديد المكتشفة",
    threatsSub: "أمثلة على ما يكتشفه AegisML",
    threatsMore: "+ 10 أنماط أخرى: import os, __reduce__, base64, URL مشبوهة…",
    threats: [
      { pattern: "os.system", severity: "critical", desc: "تنفيذ أوامر نظام التشغيل" },
      { pattern: "subprocess", severity: "high", desc: "تشغيل عمليات خارجية" },
      { pattern: "eval/exec", severity: "critical", desc: "تنفيذ كود ديناميكي" },
      { pattern: "pickle.loads", severity: "high", desc: "تحميل بيانات خطيرة" },
    ],
    howTitle: "كيف يعمل AegisML؟",
    howSub: "أربع خطوات من الرفع إلى التقرير",
    how: [
      { num: "01", title: "ارفع النموذج", desc: "اسحب ملف الذكاء الاصطناعي أو انقر للاختيار. ندعم GGUF وSafeTensors وPickle." },
      { num: "02", title: "الفحص الآلي", desc: "نحلل الـ metadata والـ opcodes والـ templates بحثاً عن 14+ نمط خطير." },
      { num: "03", title: "Claude AI Judge", desc: "يحلل Claude النتائج ويعطي تقييماً أمنياً شاملاً بالعربية والإنجليزية." },
      { num: "04", title: "تقرير مفصل", desc: "تحصل على درجة الخطر، قائمة التهديدات، والتوصيات الواضحة." },
    ],
    ctaTitle: "جاهز لفحص نموذجك؟",
    ctaSub: "مجاني، مفتوح المصدر، بدون تسجيل",
    ctaBtn: "⬡ ابدأ الفحص الآن",
    footerDesc: "أداة مفتوحة المصدر لفحص نماذج الذكاء الاصطناعي — رخصة AGPL-3.0",
    errFormat: (fmts: string) => `الصيغة غير مدعومة. يدعم AegisML: ${fmts}`,
    errSize: "حجم الملف كبير جداً. الحد الأقصى 500MB.",
    errConn: "فشل الاتصال بالـ Backend.",
    scanModeFile: "📁 رفع ملف",
    scanModeUrl: "🔗 رابط HuggingFace",
    urlPlaceholder: "https://huggingface.co/.../model.gguf",
    urlHint: "يدعم روابط HuggingFace المباشرة — لا روابط الصفحة",
    errUrl: "الرجاء إدخال رابط HuggingFace صحيح",
  },
  en: {
    dir: "ltr" as const,
    navBtn: "Start Scanning",
    badge: "v0.1.0 — Open Beta",
    heroLine1: "Scan AI Models",
    heroLine2: "Before They Harm You",
    heroSub: "Detect backdoors, trojans & malicious code in AI models before running them in production",
    dropTitle: "Drop file here or click to select",
    dropFormats: ".gguf • .safetensors • .pkl • .pt • .pth",
    scanBtn: "⬡ Scan Now",
    scanningBtn: "⏳ Scanning...",
    scanningMsg: "Analyzing file…",
    changeFile: "Change File",
    noStore: "Files not stored • Fast & secure scanning",
    stats: [
      { value: "6", label: "Formats Supported", sub: "صيغ مدعومة" },
      { value: "14+", label: "Threat Patterns", sub: "نمط تهديد" },
      { value: "AGPL-3.0", label: "Open License", sub: "رخصة مفتوحة" },
    ],
    whyTitle: "Why",
    whySuffix: "?",
    whySub: "AI models can contain hidden malicious code that executes on load. Don't trust, scan.",
    why: [
      { icon: "🔍", title: "Deep Scan", desc: "Reads files at byte level to detect malicious code hidden in metadata." },
      { icon: "🤖", title: "Claude AI Judge", desc: "Smart analysis using Claude API explaining risks and suggesting next steps." },
      { icon: "⚡", title: "Instant Results", desc: "Fast scanning in seconds for any model file regardless of size." },
      { icon: "🛡️", title: "Open Source", desc: "100% transparent code under AGPL-3.0. Review, contribute, and trust." },
      { icon: "🌍", title: "Bilingual", desc: "Reports available in both Arabic and English to serve a wider community." },
      { icon: "🔒", title: "No Storage", desc: "Your files are never saved on our servers. Scanning is temporary and instant." },
    ],
    threatsTitle: "Detected Threat Patterns",
    threatsSub: "Examples of what AegisML detects",
    threatsMore: "+ 10 more patterns: import os, __reduce__, base64, suspicious URLs...",
    threats: [
      { pattern: "os.system", severity: "critical", desc: "System command execution" },
      { pattern: "subprocess", severity: "high", desc: "Running external processes" },
      { pattern: "eval/exec", severity: "critical", desc: "Dynamic code execution" },
      { pattern: "pickle.loads", severity: "high", desc: "Loading dangerous data" },
    ],
    howTitle: "How AegisML Works?",
    howSub: "Four steps from upload to report",
    how: [
      { num: "01", title: "Upload Model", desc: "Drag your AI model file or click to select. Supports GGUF, SafeTensors, and Pickle." },
      { num: "02", title: "Automated Scan", desc: "We analyze metadata, opcodes, and templates for 14+ known dangerous patterns." },
      { num: "03", title: "Claude AI Judge", desc: "Claude analyzes results and provides a comprehensive security rating in both languages." },
      { num: "04", title: "Detailed Report", desc: "Get the risk score, threat list, and clear actionable recommendations." },
    ],
    ctaTitle: "Ready to Scan Your Model?",
    ctaSub: "Free, open-source, no registration required",
    ctaBtn: "⬡ Start Scanning Now",
    footerDesc: "Open-source tool for scanning AI models — AGPL-3.0 License",
    errFormat: (fmts: string) => `Format not supported. AegisML supports: ${fmts}`,
    errSize: "File too large. Maximum size is 500MB.",
    errConn: "Failed to connect to Backend.",
    scanModeFile: "📁 Upload File",
    scanModeUrl: "🔗 HuggingFace URL",
    urlPlaceholder: "https://huggingface.co/.../model.gguf",
    urlHint: "Supports direct HuggingFace file URLs — not page links",
    errUrl: "Please enter a valid HuggingFace URL",
  },
};

export default function HomePage() {
  const liveStats = useLiveStats();
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [lang, setLang] = useState<"ar" | "en">("ar");
  const [scanMode, setScanMode] = useState<"file" | "url">("file");
  const [urlInput, setUrlInput] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [aiProvider, setAiProvider] = useState("");
  const [aiModel, setAiModel] = useState("");
  const [apiKey, setApiKey] = useState<string | null>(null);

  const t = CONTENT[lang];

  function validateFile(f: File): string | null {
    const ext = "." + f.name.split(".").pop()?.toLowerCase();
    if (!SUPPORTED_FORMATS.includes(ext)) return t.errFormat(SUPPORTED_FORMATS.join(" • "));
    if (f.size > 500 * 1024 * 1024) return t.errSize;
    return null;
  }

  function handleFileSelect(f: File) {
    setUploadError(null);
    const err = validateFile(f);
    if (err) { setUploadError(err); setFile(null); return; }
    setFile(f);
  }

  async function handleScan() {
    if (scanMode === "file") {
      if (!file || scanning) return;
      setScanning(true);
      setUploadError(null);
      const formData = new FormData();
      formData.append("file", file);
      if (aiProvider) formData.append("ai_provider", aiProvider);
      if (aiModel) formData.append("ai_model", aiModel);
      if (apiKey) formData.append("api_key", apiKey);
      const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      try {
        const res = await fetch(`${API}/api/v1/scan/file`, { method: "POST", body: formData });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.detail || `Error ${res.status}`);
        }
        const data = await res.json();
        window.location.href = `/scan/${data.scan_id}`;
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Unknown error";
        setUploadError(`${t.errConn}: ${msg}`);
        setScanning(false);
      }
    } else {
      if (!urlInput.trim() || scanning) return;
      if (!urlInput.includes("huggingface.co") && !urlInput.includes("hf.co")) {
        setUploadError(t.errUrl);
        return;
      }
      setScanning(true);
      setUploadError(null);
      const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      try {
        const res = await fetch(`${API}/api/v1/scan/url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ 
            url: urlInput.trim(),
            ai_provider: aiProvider || undefined,
            ai_model: aiModel || undefined,
            api_key: apiKey || undefined
          }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.detail || `Error ${res.status}`);
        }
        const data = await res.json();
        window.location.href = `/scan/${data.scan_id}`;
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Unknown error";
        setUploadError(`${t.errConn}: ${msg}`);
        setScanning(false);
      }
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  };

  const card: React.CSSProperties = { background: "#12121E", border: "1px solid #232326", borderRadius: 14 };
  const sectionStyle: React.CSSProperties = { maxWidth: 1100, margin: "0 auto", padding: "80px 24px" };

  return (
    <div style={{ minHeight: "100vh", background: "#0B0B0C", color: "#D1D1D1", direction: t.dir, fontFamily: "Cairo, system-ui, sans-serif" }}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
      `}</style>

      {/* NAVBAR */}
      <nav style={{
        padding: "18px 40px",
        borderBottom: "1px solid #1A1A2E",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        position: "sticky",
        top: 0,
        background: "rgba(10,10,15,0.92)",
        backdropFilter: "blur(12px)",
        zIndex: 100,
      }}>
        <span style={{ color: "#C9A84C", fontWeight: 900, fontSize: 20, letterSpacing: 1 }}>◆ AegisML</span>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <div style={{ display: "flex", background: "#0D0D18", border: "1px solid #232326", borderRadius: 8, padding: 3, gap: 2 }}>
            {(["ar", "en"] as const).map(l => (
              <button
                key={l}
                onClick={() => setLang(l)}
                style={{
                  background: lang === l ? "#C9A84C22" : "transparent",
                  border: `1px solid ${lang === l ? "#C9A84C44" : "transparent"}`,
                  color: lang === l ? "#C9A84C" : "#71717A",
                  padding: "4px 14px",
                  borderRadius: 6,
                  cursor: "pointer",
                  fontSize: 13,
                  fontWeight: 700,
                  transition: "all 0.15s",
                }}
              >
                {l === "ar" ? "عربي" : "EN"}
              </button>
            ))}
          </div>
          <Link href="/dashboard" style={{ color: "#A8A8C4", textDecoration: "none", fontSize: 13, padding: "6px 14px", border: "1px solid #2A2A3E", borderRadius: 8 }}>
            📊 Dashboard
          </Link>
          <Link href="/docs" style={{ color: "#A8A8C4", textDecoration: "none", fontSize: 13, padding: "6px 14px", border: "1px solid #2A2A3E", borderRadius: 8 }}>
            {lang === "ar" ? "📖 توثيق الـ API" : "📖 API Docs"}
          </Link>
          <Link href="/threats" style={{ color: "#A8A8C4", textDecoration: "none", fontSize: 13, padding: "6px 14px", border: "1px solid #2A2A3E", borderRadius: 8 }}>
            {lang === "ar" ? "⚡ التهديدات" : "⚡ Threats"}
          </Link>
          <Link
            href="https://github.com/hasanalaaa/aegisml"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "#A8A8C4", textDecoration: "none", fontSize: 14, padding: "6px 16px", border: "1px solid #2A2A3E", borderRadius: 8 }}
          >
            GitHub ↗
          </Link>
          <button
            onClick={() => document.getElementById("scan-section")?.scrollIntoView({ behavior: "smooth" })}
            style={{
              background: "linear-gradient(135deg, #C9A84C, #E4C46B)",
              color: "#0B0B0C",
              border: "none",
              padding: "6px 18px",
              borderRadius: 8,
              fontWeight: 700,
              fontSize: 14,
              cursor: "pointer",
            }}
          >
            {t.navBtn}
          </button>
        </div>
      </nav>

      {/* HERO */}
      <section style={{ textAlign: "center", padding: "100px 24px 60px", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 800px 400px at 50% 0%, #C9A84C08, transparent)",
          pointerEvents: "none",
        }} />
        <div style={{
          display: "inline-block", background: "#C9A84C18", border: "1px solid #C9A84C44",
          color: "#C9A84C", padding: "5px 18px", borderRadius: 99, fontSize: 12,
          fontWeight: 700, marginBottom: 28, letterSpacing: 1, textTransform: "uppercase",
        }}>
          {t.badge}
        </div>
        <h1 style={{ fontSize: "clamp(36px, 6vw, 72px)", fontWeight: 900, lineHeight: 1.15, marginBottom: 24 }}>
          {t.heroLine1}<br />
          <span style={{
            background: "linear-gradient(135deg, #C9A84C, #E4C46B)",
            backgroundClip: "text", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
          }}>{t.heroLine2}</span>
        </h1>
        <p style={{ color: "#A8A8C4", fontSize: 18, maxWidth: 580, margin: "0 auto 48px", lineHeight: 1.7 }}>
          {t.heroSub}
        </p>

        {/* SCAN BOX */}
        <div id="scan-section" style={{ maxWidth: 600, margin: "0 auto" }}>

          {/* Mode Toggle */}
          <div style={{
            display: "flex",
            background: "#0D0D18",
            border: "1px solid #232326",
            borderRadius: 12,
            padding: 4,
            marginBottom: 16,
            gap: 4,
          }}>
            {(["file", "url"] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => {
                  setScanMode(mode);
                  setFile(null);
                  setUrlInput("");
                  setUploadError(null);
                }}
                style={{
                  flex: 1,
                  padding: "10px 16px",
                  borderRadius: 10,
                  border: "none",
                  background: scanMode === mode
                    ? "linear-gradient(135deg, #C9A84C22, #E4C46B11)"
                    : "transparent",
                  color: scanMode === mode ? "#C9A84C" : "#71717A",
                  fontWeight: 700,
                  fontSize: 14,
                  cursor: "pointer",
                  transition: "all 0.25s ease",
                  borderBottom: scanMode === mode
                    ? "2px solid #C9A84C"
                    : "2px solid transparent",
                }}
              >
                {mode === "file" ? t.scanModeFile : t.scanModeUrl}
              </button>
            ))}
          </div>

          {scanMode === "file" ? (
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFileSelect(f); }}
              onClick={() => !scanning && fileInputRef.current?.click()}
              style={{
                border: `2px dashed ${dragOver ? "#C9A84C" : file ? "#2ECC71" : uploadError ? "#E74C3C" : "#2A2A3E"}`,
                borderRadius: 16, padding: "40px 28px", textAlign: "center",
                cursor: scanning ? "not-allowed" : "pointer",
                background: dragOver ? "rgba(201,168,76,0.06)" : file ? "rgba(46,204,113,0.04)" : "rgba(255,255,255,0.01)",
                transition: "all 0.25s ease", marginBottom: 14, position: "relative", overflow: "hidden",
              }}
            >
              {scanning && (
                <div style={{
                  position: "absolute", left: 0, top: 0, height: 2,
                  background: "linear-gradient(90deg, transparent, #C9A84C, transparent)",
                  animation: "shimmer 1.2s infinite", backgroundSize: "200% 100%", width: "100%",
                }} />
              )}
              <input ref={fileInputRef} type="file" accept={SUPPORTED_FORMATS.join(",")} style={{ display: "none" }}
                onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFileSelect(f); }} />
              {scanning ? (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14 }}>
                  <div style={{ width: 44, height: 44, border: "3px solid #C9A84C22", borderTop: "3px solid #C9A84C", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                  <p style={{ color: "#C9A84C", fontWeight: 700, margin: 0 }}>{t.scanningMsg}</p>
                  <p style={{ color: "#71717A", fontSize: 13, margin: 0 }}>{file?.name}</p>
                </div>
              ) : file ? (
                <div>
                  <div style={{ fontSize: 36, marginBottom: 10 }}>📦</div>
                  <p style={{ color: "#2ECC71", fontWeight: 700, fontSize: 16, margin: "0 0 4px" }}>✓ {file.name}</p>
                  <p style={{ color: "#666688", fontSize: 13, margin: "0 0 12px" }}>{formatFileSize(file.size)}</p>
                  <button
                    onClick={(e) => { e.stopPropagation(); setFile(null); setUploadError(null); }}
                    style={{ background: "transparent", border: "1px solid #2A2A3E", color: "#A8A8C4", padding: "4px 14px", borderRadius: 6, cursor: "pointer", fontSize: 12 }}
                  >
                    {t.changeFile}
                  </button>
                </div>
              ) : (
                <div>
                  <div style={{ fontSize: 44, marginBottom: 14, opacity: 0.5 }}>⬡</div>
                  <p style={{ color: "#D0D0E8", fontWeight: 600, margin: "0 0 8px", fontSize: 16 }}>{t.dropTitle}</p>
                  <p style={{ color: "#71717A", margin: 0, fontSize: 13 }}>{t.dropFormats}</p>
                </div>
              )}
            </div>
          ) : (
            <div
              style={{
                border: `2px dashed ${uploadError ? "#E74C3C" : "#2A2A3E"}`,
                borderRadius: 16, padding: "40px 28px", textAlign: "center",
                background: "rgba(255,255,255,0.01)",
                marginBottom: 14, position: "relative", overflow: "hidden",
              }}
            >
              {scanning && (
                <div style={{
                  position: "absolute", left: 0, top: 0, height: 2,
                  background: "linear-gradient(90deg, transparent, #C9A84C, transparent)",
                  animation: "shimmer 1.2s infinite", backgroundSize: "200% 100%", width: "100%",
                }} />
              )}
              {scanning ? (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14 }}>
                  <div style={{ width: 44, height: 44, border: "3px solid #C9A84C22", borderTop: "3px solid #C9A84C", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                  <p style={{ color: "#C9A84C", fontWeight: 700, margin: 0 }}>{t.scanningMsg}</p>
                  <p style={{ color: "#71717A", fontSize: 13, margin: 0, wordBreak: "break-all" }}>{urlInput}</p>
                </div>
              ) : (
                <div>
                  <div style={{ fontSize: 44, marginBottom: 14, opacity: 0.5 }}>🔗</div>
                  <input
                    type="text"
                    placeholder={t.urlPlaceholder}
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "14px 18px",
                      borderRadius: 12,
                      border: "1px solid #2A2A3E",
                      background: "#0D0D18",
                      color: "#D1D1D1",
                      fontSize: 14,
                      outline: "none",
                      transition: "border-color 0.2s",
                      marginBottom: 10,
                      textAlign: "left",
                    }}
                  />
                  <p style={{ color: "#71717A", margin: 0, fontSize: 13 }}>{t.urlHint}</p>
                </div>
              )}
            </div>
          )}

          {uploadError && (
            <div style={{
              background: "#E74C3C10", border: "1px solid #E74C3C33", borderRadius: 10,
              padding: "10px 16px", marginBottom: 12, color: "#E74C3C", fontSize: 13,
              textAlign: lang === "ar" ? "right" : "left",
            }}>
              ⚠ {uploadError}
            </div>
          )}

          <AIProviderSelector 
            disabled={scanning}
            onSelect={(prov, mod, key) => {
              setAiProvider(prov);
              setAiModel(mod);
              setApiKey(key);
            }} 
          />
          <div style={{ height: 16 }} />

          <button
            onClick={handleScan}
            disabled={scanning || (scanMode === "file" ? !file : !urlInput.trim())}
            style={{
              width: "100%", padding: "15px", borderRadius: 12, fontSize: 16, fontWeight: 800, border: "none",
              background: (scanMode === "file" ? file : urlInput.trim()) && !scanning ? "linear-gradient(135deg, #C9A84C, #E4C46B)" : "#12121E",
              color: (scanMode === "file" ? file : urlInput.trim()) && !scanning ? "#0B0B0C" : "#333355",
              cursor: (scanMode === "file" ? file : urlInput.trim()) && !scanning ? "pointer" : "not-allowed",
              transition: "all 0.25s ease", letterSpacing: 0.5,
            }}
          >
            {scanning ? t.scanningBtn : t.scanBtn}
          </button>
          <p style={{ color: "#333355", fontSize: 12, textAlign: "center", marginTop: 10 }}>{t.noStore}</p>
        </div>
      </section>

      {/* STATS */}
      <section style={{ borderTop: "1px solid #1A1A2E", borderBottom: "1px solid #1A1A2E" }}>
        <div style={{ ...sectionStyle, padding: "48px 24px" }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20 }}>
            <div style={{ ...card, padding: "28px 20px", textAlign: "center", position: "relative", overflow: "hidden" }}>
              <p style={{ color: "#C9A84C", fontSize: 36, fontWeight: 900, margin: "0 0 6px", fontFamily: "monospace" }}>{liveStats?.totalScans ?? "-"}</p>
              <p style={{ color: "#D1D1D1", fontSize: 15, fontWeight: 600, margin: "0 0 4px" }}>{lang === "ar" ? "إجمالي الفحوصات" : "Total Scans"}</p>
              <p style={{ color: "#71717A", fontSize: 12, margin: 0 }}>Powered by PostgreSQL</p>
            </div>
            <div style={{ ...card, padding: "28px 20px", textAlign: "center", position: "relative", overflow: "hidden" }}>
              <p style={{ color: "#E74C3C", fontSize: 36, fontWeight: 900, margin: "0 0 6px", fontFamily: "monospace" }}>{liveStats?.threatsFound ?? "-"}</p>
              <p style={{ color: "#D1D1D1", fontSize: 15, fontWeight: 600, margin: "0 0 4px" }}>{lang === "ar" ? "التهديدات المكتشفة" : "Threats Found"}</p>
              <p style={{ color: "#71717A", fontSize: 12, margin: 0 }}>Blocked Malicious Models</p>
            </div>
            <div style={{ ...card, padding: "28px 20px", textAlign: "center", position: "relative", overflow: "hidden" }}>
              {liveStats?.activeScans ? <div style={{ position: "absolute", top: 12, right: 12, width: 8, height: 8, borderRadius: "50%", background: "#2ECC71", boxShadow: "0 0 8px #2ECC71", animation: "pulse 1.5s infinite" }} /> : null}
              <p style={{ color: "#2ECC71", fontSize: 36, fontWeight: 900, margin: "0 0 6px", fontFamily: "monospace" }}>{liveStats?.activeScans ?? 0}</p>
              <p style={{ color: "#D1D1D1", fontSize: 15, fontWeight: 600, margin: "0 0 4px" }}>{lang === "ar" ? "فحوصات نشطة الآن" : "Active Scans Now"}</p>
              <p style={{ color: "#71717A", fontSize: 12, margin: 0 }}>Live WebSocket Stream</p>
            </div>
          </div>
        </div>
      </section>

      {/* WHY AEGISML */}
      <section style={sectionStyle}>
        <div style={{ textAlign: "center", marginBottom: 56 }}>
          <h2 style={{ fontSize: 36, fontWeight: 800, marginBottom: 14 }}>
            {t.whyTitle} <span style={{ color: "#C9A84C" }}>AegisML</span>{t.whySuffix}
          </h2>
          <p style={{ color: "#A8A8C4", fontSize: 16, maxWidth: 560, margin: "0 auto" }}>{t.whySub}</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 20 }}>
          {t.why.map((item, i) => (
            <div key={i} style={{ ...card, padding: "28px 24px", transition: "transform 0.2s ease, border-color 0.2s ease", cursor: "default" }}
              onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.transform = "translateY(-3px)"; (e.currentTarget as HTMLDivElement).style.borderColor = "#C9A84C33"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.transform = "translateY(0)"; (e.currentTarget as HTMLDivElement).style.borderColor = "#232326"; }}
            >
              <div style={{ fontSize: 36, marginBottom: 16 }}>{item.icon}</div>
              <h3 style={{ fontSize: 17, fontWeight: 700, marginBottom: 10, color: "#E4C46B" }}>{item.title}</h3>
              <p style={{ color: "#A8A8C4", fontSize: 14, lineHeight: 1.7, margin: 0 }}>{item.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* THREAT PREVIEW */}
      <section style={{ background: "#0D0D18", borderTop: "1px solid #1A1A2E", borderBottom: "1px solid #1A1A2E" }}>
        <div style={sectionStyle}>
          <div style={{ textAlign: "center", marginBottom: 48 }}>
            <h2 style={{ fontSize: 30, fontWeight: 800, marginBottom: 12 }}>{t.threatsTitle}</h2>
            <p style={{ color: "#A8A8C4", fontSize: 15 }}>{t.threatsSub}</p>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 14 }}>
            {t.threats.map((th, i) => (
              <div key={i} style={{
                background: "#12121E",
                border: `1px solid ${th.severity === "critical" ? "#E74C3C33" : "#E67E2233"}`,
                borderLeft: `4px solid ${th.severity === "critical" ? "#E74C3C" : "#E67E22"}`,
                borderRadius: 10, padding: "16px 20px",
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                  <code style={{ color: "#C9A84C", fontSize: 14, fontWeight: 700 }}>{th.pattern}</code>
                  <span style={{
                    background: th.severity === "critical" ? "#E74C3C22" : "#E67E2222",
                    color: th.severity === "critical" ? "#E74C3C" : "#E67E22",
                    padding: "2px 10px", borderRadius: 99, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                  }}>{th.severity}</span>
                </div>
                <p style={{ color: "#A8A8C4", fontSize: 13, margin: 0 }}>{th.desc}</p>
              </div>
            ))}
          </div>
          <p style={{ textAlign: "center", color: "#71717A", fontSize: 13, marginTop: 24 }}>{t.threatsMore}</p>
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section style={sectionStyle}>
        <div style={{ textAlign: "center", marginBottom: 56 }}>
          <h2 style={{ fontSize: 30, fontWeight: 800, marginBottom: 12 }}>{t.howTitle}</h2>
          <p style={{ color: "#A8A8C4", fontSize: 15 }}>{t.howSub}</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 20 }}>
          {t.how.map((step, i) => (
            <div key={i} style={{ ...card, padding: "28px 22px" }}>
              <div style={{ fontSize: 42, fontWeight: 900, fontFamily: "monospace", color: "#C9A84C18", marginBottom: 16, lineHeight: 1 }}>{step.num}</div>
              <h3 style={{ fontSize: 17, fontWeight: 700, marginBottom: 10 }}>{step.title}</h3>
              <p style={{ color: "#A8A8C4", fontSize: 14, lineHeight: 1.7, margin: 0 }}>{step.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section style={{ textAlign: "center", padding: "80px 24px", background: "linear-gradient(180deg, transparent, #0D0D18)" }}>
        <h2 style={{ fontSize: 32, fontWeight: 800, marginBottom: 16 }}>{t.ctaTitle}</h2>
        <p style={{ color: "#A8A8C4", fontSize: 16, marginBottom: 32 }}>{t.ctaSub}</p>
        <button
          onClick={() => document.getElementById("scan-section")?.scrollIntoView({ behavior: "smooth" })}
          style={{
            background: "linear-gradient(135deg, #C9A84C, #E4C46B)", color: "#0B0B0C", border: "none",
            padding: "16px 48px", borderRadius: 12, fontWeight: 800, fontSize: 17, cursor: "pointer", marginBottom: 16,
          }}
        >
          {t.ctaBtn}
        </button>
        <p style={{ color: "#71717A", fontSize: 13 }}>{SUPPORTED_FORMATS.join(" • ")}</p>
      </section>

      {/* FOOTER */}
      <footer style={{ borderTop: "1px solid #1A1A2E", padding: "48px 24px", textAlign: "center" }}>
        <p style={{ color: "#C9A84C", fontWeight: 800, fontSize: 20, marginBottom: 8 }}>◆ AegisML</p>
        <p style={{ color: "#71717A", fontSize: 13, marginBottom: 24, maxWidth: 440, margin: "0 auto 24px" }}>
          {t.footerDesc}
        </p>
        <div style={{ display: "flex", justifyContent: "center", gap: 28, flexWrap: "wrap", marginBottom: 24 }}>
          {[
            { label: "GitHub", href: "https://github.com/hasanalaaa/aegisml" },
            { label: "Security Policy", href: "https://github.com/hasanalaaa/aegisml/blob/main/SECURITY.md" },
            { label: "Contributing", href: "https://github.com/hasanalaaa/aegisml/blob/main/CONTRIBUTING.md" },
            { label: "License", href: "https://github.com/hasanalaaa/aegisml/blob/main/LICENSE" },
          ].map((link, i) => (
            <Link key={i} href={link.href} target="_blank" rel="noopener noreferrer"
              style={{ color: "#71717A", fontSize: 13, textDecoration: "none" }}>
              {link.label}
            </Link>
          ))}
        </div>
        <p style={{ color: "#2A2A3E", fontSize: 12 }}>
          Built with ◆ Claude API · Anthropic Open Source 2026
        </p>
      </footer>
    </div>
  );
}
