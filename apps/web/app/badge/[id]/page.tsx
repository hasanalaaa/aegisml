"use client";
import { useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";

export default function BadgePage() {
  const params = useParams();
  const scanId = params?.id as string;
  const [copied, setCopied] = useState<string | null>(null);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const badgeImgUrl   = `${API}/api/v1/badge/${scanId}`;
  const reportUrl     = `https://aegisml.vercel.app/scan/${scanId}`;
  const shieldsUrl    = `${API}/api/v1/badge/${scanId}/json`;
  const badgeMarkdown = `[![AegisML Scan](${badgeImgUrl})](${reportUrl})`;
  const badgeHTML     = `<a href="${reportUrl}"><img src="${badgeImgUrl}" alt="AegisML Scan"/></a>`;
  const badgeShields  = `[![AegisML](https://img.shields.io/endpoint?url=${encodeURIComponent(shieldsUrl)})](${reportUrl})`;

  function copy(text: string, key: string) {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  }

  const card: React.CSSProperties = {
    background: "#12121E", border: "1px solid #232326",
    borderRadius: 12, padding: "20px 24px", marginBottom: 16,
  };
  const codeStyle: React.CSSProperties = {
    background: "#0B0B0C", borderRadius: 8, padding: "12px 16px",
    fontFamily: "monospace", fontSize: 12, color: "#C9A84C",
    wordBreak: "break-all", direction: "ltr", marginBottom: 12, display: "block",
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0B0B0C", color: "#D1D1D1", fontFamily: "Cairo, system-ui, sans-serif" }}>
      <nav style={{ padding: "16px 32px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Link href="/" style={{ color: "#C9A84C", textDecoration: "none", fontWeight: 900, fontSize: 20 }}>◆ AegisML</Link>
        <Link href={`/scan/${scanId}`} style={{ color: "#A8A8C4", textDecoration: "none", fontSize: 13 }}>← العودة للتقرير</Link>
      </nav>
      <main style={{ maxWidth: 700, margin: "0 auto", padding: "40px 24px" }}>
        <h1 style={{ fontSize: 26, fontWeight: 900, marginBottom: 8 }}>🏷️ Badge Generator</h1>
        <p style={{ color: "#A8A8C4", marginBottom: 32 }}>أضف شارة الأمان لـ README مشروعك</p>

        <div style={{ ...card, textAlign: "center", marginBottom: 24 }}>
          <p style={{ color: "#A8A8C4", fontSize: 13, marginBottom: 12 }}>معاينة الشارة</p>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={badgeImgUrl} alt="AegisML Badge" style={{ height: 20 }} />
        </div>

        {[
          { key: "md",      label: "Markdown (GitHub README)", code: badgeMarkdown },
          { key: "html",    label: "HTML",                     code: badgeHTML },
          { key: "shields", label: "Shields.io Dynamic",       code: badgeShields },
        ].map(({ key, label, code }) => (
          <div key={key} style={card}>
            <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 12, color: "#E4C46B" }}>{label}</h3>
            <code style={codeStyle}>{code}</code>
            <button
              onClick={() => copy(code, key)}
              style={{
                background: copied === key ? "#2ECC7122" : "#12121E",
                border: `1px solid ${copied === key ? "#2ECC71" : "#2A2A3E"}`,
                color: copied === key ? "#2ECC71" : "#A8A8C4",
                padding: "6px 16px", borderRadius: 8, cursor: "pointer", fontSize: 13,
              }}
            >
              {copied === key ? "✓ تم النسخ" : "نسخ"}
            </button>
          </div>
        ))}
      </main>
    </div>
  );
}
