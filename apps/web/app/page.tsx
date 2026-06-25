"use client";

import { useState, useRef } from "react";
import Link from "next/link";

const SUPPORTED_FORMATS = [".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth"];

const STATS = [
  { value: "6", label: "صيغ مدعومة", sub: "Formats Supported" },
  { value: "14+", label: "نمط خطير", sub: "Threat Patterns" },
  { value: "AGPL-3.0", label: "رخصة مفتوحة", sub: "Open Source" },
];

const HOW_IT_WORKS = [
  { num: "01", title: "ارفع النموذج", desc: "اسحب ملف الذكاء الاصطناعي أو انقر للاختيار. ندعم GGUF وSafeTensors وPickle." },
  { num: "02", title: "الفحص الآلي", desc: "نحلل الـ metadata والـ opcodes والـ templates بحثاً عن 14+ نمط خطير معروف." },
  { num: "03", title: "Claude AI Judge", desc: "يحلل Claude النتائج ويعطي تقييماً أمنياً شاملاً بالعربية والإنجليزية." },
  { num: "04", title: "تقرير مفصل", desc: "تحصل على درجة الخطر، قائمة التهديدات، والتوصيات الواضحة." },
];

const WHY_AEGISML = [
  { icon: "🔍", title: "فحص عميق", desc: "يقرأ الملف على مستوى البايت ويكشف الكود الخبيث المخفي في الـ metadata." },
  { icon: "🤖", title: "Claude AI Judge", desc: "تحليل ذكي باستخدام Claude API يشرح المخاطر ويقترح الخطوات التالية." },
  { icon: "⚡", title: "نتيجة فورية", desc: "فحص سريع في ثوانٍ لأي ملف نموذج مهما كان حجمه." },
  { icon: "🛡️", title: "مفتوح المصدر", desc: "كود شفاف 100% برخصة AGPL-3.0. راجع الكود، ساهم، وثق." },
  { icon: "🌍", title: "عربي وإنجليزي", desc: "التقارير متاحة بالعربية والإنجليزية لخدمة مجتمع أوسع." },
  { icon: "🔒", title: "لا تخزين", desc: "ملفاتك لا تُحفظ على خوادمنا. الفحص مؤقت وفوري." },
];

const THREAT_EXAMPLES = [
  { pattern: "os.system", severity: "critical", desc: "تنفيذ أوامر نظام التشغيل" },
  { pattern: "subprocess", severity: "high", desc: "تشغيل عمليات خارجية" },
  { pattern: "eval/exec", severity: "critical", desc: "تنفيذ كود ديناميكي" },
  { pattern: "pickle.loads", severity: "high", desc: "تحميل بيانات خطيرة" },
];

export default function HomePage() {
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  function validateFile(f: File): string | null {
    const ext = "." + f.name.split(".").pop()?.toLowerCase();
    if (!SUPPORTED_FORMATS.includes(ext)) {
      return `الصيغة غير مدعومة. يدعم AegisML: ${SUPPORTED_FORMATS.join(" • ")}`;
    }
    if (f.size > 500 * 1024 * 1024) {
      return "حجم الملف كبير جداً. الحد الأقصى 500MB.";
    }
    return null;
  }

  function handleFileSelect(f: File) {
    setUploadError(null);
    const err = validateFile(f);
    if (err) { setUploadError(err); setFile(null); return; }
    setFile(f);
  }

  async function handleScan() {
    if (!file || scanning) return;
    setScanning(true);
    setUploadError(null);
    const formData = new FormData();
    formData.append("file", file);
    const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    try {
      const res = await fetch(`${API}/api/v1/scan/file`, { method: "POST", body: formData });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `خطأ ${res.status}`);
      }
      const data = await res.json();
      window.location.href = `/scan/${data.scan_id}`;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "خطأ غير معروف";
      setUploadError(`فشل الاتصال بالـ Backend: ${msg}`);
      setScanning(false);
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  };

  const s = {
    gold: { color: "#C9A84C" } as React.CSSProperties,
    card: { background: "#12121E", border: "1px solid #1E1E2E", borderRadius: 14 } as React.CSSProperties,
    section: { maxWidth: 1100, margin: "0 auto", padding: "80px 24px" } as React.CSSProperties,
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", color: "#F0F0F8" }}>

      {/* ── ANNOUNCEMENT BAR ── */}
      <div style={{
        background: "linear-gradient(90deg, transparent, #C9A84C15, transparent)",
        borderBottom: "1px solid #C9A84C22",
        padding: "10px 24px",
        textAlign: "center",
        fontSize: 13,
        color: "#C9A84C",
        letterSpacing: 0.3,
      }}>
        ◆ &nbsp; AegisML مقدم للحصول على منحة <strong>Claude for Open Source</strong> من Anthropic
      </div>

      {/* ── NAVBAR ── */}
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
          <Link
            href="https://github.com/hasanalaaa/aegisml"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              color: "#A8A8C4",
              textDecoration: "none",
              fontSize: 14,
              padding: "6px 16px",
              border: "1px solid #2A2A3E",
              borderRadius: 8,
              transition: "all 0.2s",
            }}
          >
            GitHub ↗
          </Link>
          <button
            onClick={() => document.getElementById("scan-section")?.scrollIntoView({ behavior: "smooth" })}
            style={{
              background: "linear-gradient(135deg, #C9A84C, #E4C46B)",
              color: "#0A0A0F",
              border: "none",
              padding: "6px 18px",
              borderRadius: 8,
              fontWeight: 700,
              fontSize: 14,
              cursor: "pointer",
            }}
          >
            ابدأ الفحص
          </button>
        </div>
      </nav>

      {/* ── HERO ── */}
      <section style={{ textAlign: "center", padding: "100px 24px 60px", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 800px 400px at 50% 0%, #C9A84C08, transparent)",
          pointerEvents: "none",
        }} />
        <div style={{
          display: "inline-block",
          background: "#C9A84C18",
          border: "1px solid #C9A84C44",
          color: "#C9A84C",
          padding: "5px 18px",
          borderRadius: 99,
          fontSize: 12,
          fontWeight: 700,
          marginBottom: 28,
          letterSpacing: 1,
          textTransform: "uppercase",
        }}>
          v0.1.0 — Open Beta
        </div>
        <h1 style={{ fontSize: "clamp(36px, 6vw, 72px)", fontWeight: 900, lineHeight: 1.1, marginBottom: 24 }}>
          افحص نماذج الذكاء الاصطناعي<br />
          <span style={{
            background: "linear-gradient(135deg, #C9A84C, #E4C46B)",
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}>قبل أن تضرّك</span>
        </h1>
        <p style={{ color: "#A8A8C4", fontSize: 18, maxWidth: 560, margin: "0 auto 48px", lineHeight: 1.7 }}>
          اكشف الأبواب الخلفية والتروجانات والكود الخبيث في نماذج AI قبل تشغيلها في الإنتاج
        </p>

        {/* ── SCAN BOX ── */}
        <div id="scan-section" style={{ maxWidth: 560, margin: "0 auto" }}>
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault(); setDragOver(false);
              const f = e.dataTransfer.files[0];
              if (f) handleFileSelect(f);
            }}
            onClick={() => !scanning && fileInputRef.current?.click()}
            style={{
              border: `2px dashed ${dragOver ? "#C9A84C" : file ? "#2ECC71" : uploadError ? "#E74C3C" : "#2A2A3E"}`,
              borderRadius: 16,
              padding: "36px 28px",
              textAlign: "center",
              cursor: scanning ? "not-allowed" : "pointer",
              background: dragOver ? "rgba(201,168,76,0.06)" : file ? "rgba(46,204,113,0.04)" : "rgba(255,255,255,0.01)",
              transition: "all 0.25s ease",
              marginBottom: 14,
              position: "relative",
              overflow: "hidden",
            }}
          >
            {scanning && (
              <div style={{
                position: "absolute", left: 0, top: 0,
                height: 2, background: "linear-gradient(90deg, transparent, #C9A84C, transparent)",
                animation: "shimmer 1.2s infinite",
                backgroundSize: "200% 100%",
                width: "100%",
              }} />
            )}
            <input
              ref={fileInputRef}
              type="file"
              accept={SUPPORTED_FORMATS.join(",")}
              style={{ display: "none" }}
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFileSelect(f); }}
            />
            {scanning ? (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14 }}>
                <div style={{ width: 44, height: 44, border: "3px solid #C9A84C22", borderTop: "3px solid #C9A84C", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                <p style={{ color: "#C9A84C", fontWeight: 700, margin: 0 }}>جارٍ تحليل الملف…</p>
                <p style={{ color: "#555577", fontSize: 13, margin: 0 }}>{file?.name}</p>
              </div>
            ) : file ? (
              <div>
                <div style={{ fontSize: 32, marginBottom: 10 }}>📦</div>
                <p style={{ color: "#2ECC71", fontWeight: 700, fontSize: 16, margin: "0 0 4px" }}>✓ {file.name}</p>
                <p style={{ color: "#666688", fontSize: 13, margin: "0 0 10px" }}>{formatFileSize(file.size)}</p>
                <button
                  onClick={(e) => { e.stopPropagation(); setFile(null); setUploadError(null); }}
                  style={{ background: "transparent", border: "1px solid #2A2A3E", color: "#A8A8C4", padding: "4px 14px", borderRadius: 6, cursor: "pointer", fontSize: 12 }}
                >
                  تغيير الملف
                </button>
              </div>
            ) : (
              <div>
                <div style={{ fontSize: 40, marginBottom: 14, opacity: 0.6 }}>⬡</div>
                <p style={{ color: "#D0D0E8", fontWeight: 600, margin: "0 0 8px", fontSize: 16 }}>اسحب الملف هنا أو انقر للاختيار</p>
                <p style={{ color: "#555577", margin: 0, fontSize: 13 }}>
                  {SUPPORTED_FORMATS.join(" • ")}
                </p>
              </div>
            )}
          </div>

          {uploadError && (
            <div style={{
              background: "#E74C3C12",
              border: "1px solid #E74C3C44",
              borderRadius: 10,
              padding: "10px 16px",
              marginBottom: 12,
              color: "#E74C3C",
              fontSize: 13,
              textAlign: "right",
            }}>
              ⚠ {uploadError}
            </div>
          )}

          <button
            onClick={handleScan}
            disabled={!file || scanning}
            style={{
              width: "100%",
              padding: "15px",
              borderRadius: 12,
              fontSize: 16,
              fontWeight: 800,
              border: "none",
              background: file && !scanning ? "linear-gradient(135deg, #C9A84C, #E4C46B)" : "#12121E",
              color: file && !scanning ? "#0A0A0F" : "#333355",
              cursor: file && !scanning ? "pointer" : "not-allowed",
              transition: "all 0.25s ease",
              letterSpacing: 0.5,
            }}
          >
            {scanning ? "⏳ جارٍ الفحص..." : "⬡ Scan Now"}
          </button>
          <p style={{ color: "#333355", fontSize: 12, textAlign: "center", marginTop: 10 }}>
            الملفات لا تُحفظ • الفحص آمن وسريع
          </p>
        </div>
      </section>

      {/* ── STATS ── */}
      <section style={{ borderTop: "1px solid #1A1A2E", borderBottom: "1px solid #1A1A2E" }}>
        <div style={{ ...s.section, padding: "48px 24px" }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20 }}>
            {STATS.map((stat, i) => (
              <div key={i} style={{ ...s.card, padding: "28px 20px", textAlign: "center" }}>
                <p style={{ color: "#C9A84C", fontSize: 36, fontWeight: 900, margin: "0 0 6px", fontFamily: "monospace" }}>{stat.value}</p>
                <p style={{ color: "#F0F0F8", fontSize: 15, fontWeight: 600, margin: "0 0 4px" }}>{stat.label}</p>
                <p style={{ color: "#555577", fontSize: 12, margin: 0 }}>{stat.sub}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── WHY AEGISML ── */}
      <section style={s.section}>
        <div style={{ textAlign: "center", marginBottom: 56 }}>
          <h2 style={{ fontSize: 36, fontWeight: 800, marginBottom: 14 }}>
            لماذا <span style={{ color: "#C9A84C" }}>AegisML</span>؟
          </h2>
          <p style={{ color: "#A8A8C4", fontSize: 16, maxWidth: 540, margin: "0 auto" }}>
            نماذج AI يمكن أن تحتوي على كود خبيث مخفي يُنفَّذ عند التحميل. لا تثق، افحص.
          </p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 20 }}>
          {WHY_AEGISML.map((item, i) => (
            <div key={i} style={{
              ...s.card,
              padding: "28px 24px",
              transition: "transform 0.2s ease, border-color 0.2s ease",
              cursor: "default",
            }}
              onMouseEnter={e => {
                (e.currentTarget as HTMLDivElement).style.transform = "translateY(-3px)";
                (e.currentTarget as HTMLDivElement).style.borderColor = "#C9A84C33";
              }}
              onMouseLeave={e => {
                (e.currentTarget as HTMLDivElement).style.transform = "translateY(0)";
                (e.currentTarget as HTMLDivElement).style.borderColor = "#1E1E2E";
              }}
            >
              <div style={{ fontSize: 36, marginBottom: 16 }}>{item.icon}</div>
              <h3 style={{ fontSize: 17, fontWeight: 700, marginBottom: 10, color: "#E4C46B" }}>{item.title}</h3>
              <p style={{ color: "#A8A8C4", fontSize: 14, lineHeight: 1.7, margin: 0 }}>{item.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── THREAT PREVIEW ── */}
      <section style={{ background: "#0D0D18", borderTop: "1px solid #1A1A2E", borderBottom: "1px solid #1A1A2E" }}>
        <div style={s.section}>
          <div style={{ textAlign: "center", marginBottom: 48 }}>
            <h2 style={{ fontSize: 30, fontWeight: 800, marginBottom: 12 }}>أنماط التهديد المكتشفة</h2>
            <p style={{ color: "#A8A8C4", fontSize: 15 }}>أمثلة على ما يكتشفه AegisML</p>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 14 }}>
            {THREAT_EXAMPLES.map((t, i) => (
              <div key={i} style={{
                background: "#12121E",
                border: `1px solid ${t.severity === "critical" ? "#E74C3C33" : "#E67E2233"}`,
                borderLeft: `4px solid ${t.severity === "critical" ? "#E74C3C" : "#E67E22"}`,
                borderRadius: 10,
                padding: "16px 20px",
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                  <code style={{ color: "#C9A84C", fontSize: 14, fontWeight: 700 }}>{t.pattern}</code>
                  <span style={{
                    background: t.severity === "critical" ? "#E74C3C22" : "#E67E2222",
                    color: t.severity === "critical" ? "#E74C3C" : "#E67E22",
                    padding: "2px 10px", borderRadius: 99, fontSize: 10, fontWeight: 700, textTransform: "uppercase"
                  }}>{t.severity}</span>
                </div>
                <p style={{ color: "#A8A8C4", fontSize: 13, margin: 0 }}>{t.desc}</p>
              </div>
            ))}
          </div>
          <p style={{ textAlign: "center", color: "#555577", fontSize: 13, marginTop: 24 }}>
            + 10 أنماط أخرى مثل: import os, __reduce__, base64, URL مشبوهة…
          </p>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section style={s.section}>
        <div style={{ textAlign: "center", marginBottom: 56 }}>
          <h2 style={{ fontSize: 30, fontWeight: 800, marginBottom: 12 }}>كيف يعمل AegisML؟</h2>
          <p style={{ color: "#A8A8C4", fontSize: 15 }}>أربع خطوات من الرفع إلى التقرير</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 20 }}>
          {HOW_IT_WORKS.map((step, i) => (
            <div key={i} style={{ ...s.card, padding: "28px 22px", position: "relative" }}>
              <div style={{
                fontSize: 42, fontWeight: 900, fontFamily: "monospace",
                color: "#C9A84C18", marginBottom: 16, lineHeight: 1,
              }}>{step.num}</div>
              <h3 style={{ fontSize: 17, fontWeight: 700, marginBottom: 10 }}>{step.title}</h3>
              <p style={{ color: "#A8A8C4", fontSize: 14, lineHeight: 1.7, margin: 0 }}>{step.desc}</p>
              {i < HOW_IT_WORKS.length - 1 && (
                <div style={{
                  position: "absolute", top: "50%", left: -14,
                  color: "#C9A84C44", fontSize: 20, transform: "translateY(-50%)",
                  display: "none",
                }}>→</div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* ── CTA ── */}
      <section style={{ textAlign: "center", padding: "80px 24px", background: "linear-gradient(180deg, transparent, #0D0D18)" }}>
        <h2 style={{ fontSize: 32, fontWeight: 800, marginBottom: 16 }}>
          جاهز لفحص نموذجك؟
        </h2>
        <p style={{ color: "#A8A8C4", fontSize: 16, marginBottom: 32 }}>
          مجاني، مفتوح المصدر، بدون تسجيل
        </p>
        <button
          onClick={() => document.getElementById("scan-section")?.scrollIntoView({ behavior: "smooth" })}
          style={{
            background: "linear-gradient(135deg, #C9A84C, #E4C46B)",
            color: "#0A0A0F",
            border: "none",
            padding: "16px 48px",
            borderRadius: 12,
            fontWeight: 800,
            fontSize: 17,
            cursor: "pointer",
            marginBottom: 16,
          }}
        >
          ⬡ ابدأ الفحص الآن
        </button>
        <p style={{ color: "#555577", fontSize: 13 }}>
          يدعم: {SUPPORTED_FORMATS.join(" • ")}
        </p>
      </section>

      {/* ── FOOTER ── */}
      <footer style={{ borderTop: "1px solid #1A1A2E", padding: "48px 24px", textAlign: "center" }}>
        <p style={{ color: "#C9A84C", fontWeight: 800, fontSize: 20, marginBottom: 8 }}>◆ AegisML</p>
        <p style={{ color: "#555577", fontSize: 13, marginBottom: 24, maxWidth: 440, margin: "0 auto 24px" }}>
          أداة مفتوحة المصدر لفحص نماذج الذكاء الاصطناعي — رخصة AGPL-3.0
        </p>
        <div style={{ display: "flex", justifyContent: "center", gap: 28, flexWrap: "wrap", marginBottom: 24 }}>
          {[
            { label: "GitHub", href: "https://github.com/hasanalaaa/aegisml" },
            { label: "Security Policy", href: "https://github.com/hasanalaaa/aegisml/blob/main/SECURITY.md" },
            { label: "Contributing", href: "https://github.com/hasanalaaa/aegisml/blob/main/CONTRIBUTING.md" },
            { label: "License", href: "https://github.com/hasanalaaa/aegisml/blob/main/LICENSE" },
          ].map((link, i) => (
            <Link key={i} href={link.href} target="_blank" rel="noopener noreferrer"
              style={{ color: "#555577", fontSize: 13, textDecoration: "none" }}>
              {link.label}
            </Link>
          ))}
        </div>
        <p style={{ color: "#2A2A3E", fontSize: 12 }}>
          Built with ◆ Claude API · Anthropic Open Source Grant 2026
        </p>
      </footer>

    </div>
  );
}
