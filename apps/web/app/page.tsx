"use client";

import { useState, useRef } from "react";

/* ─── Steps data ─────────────────────────────────────────────────── */

const steps = [
  {
    number: "01",
    title: "Upload Model",
    desc: "Provide a file path or HuggingFace repo ID",
  },
  {
    number: "02",
    title: "Static Analysis",
    desc: "Scan binary for dangerous patterns & payloads",
  },
  {
    number: "03",
    title: "Behavioral Check",
    desc: "Detect deserialization hooks & code injection",
  },
  {
    number: "04",
    title: "Get Risk Score",
    desc: "Receive a 0–100 risk score with detailed findings",
  },
];

/* ─── Stats data ─────────────────────────────────────────────────── */

const stats = [
  { value: "6", label: "Formats Supported" },
  { value: "14+", label: "Threat Patterns" },
  { value: "MIT", label: "Open Source" },
];

/* ─── Page component ─────────────────────────────────────────────── */

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleScan() {
    if (!file || scanning) return;
    setScanning(true);
    const formData = new FormData();
    formData.append("file", file);
    const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    try {
      const res = await fetch(`${API}/api/v1/scan/file`, { method: "POST", body: formData });
      if (!res.ok) throw new Error("فشل الفحص");
      const data = await res.json();
      window.location.href = `/scan/${data.scan_id}`;
    } catch {
      alert("فشل الاتصال بالـ Backend.");
      setScanning(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* ── Navbar ──────────────────────────────────────────────── */}
      <nav className="w-full border-b border-white/5">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <span className="text-aegis-gold font-bold text-lg tracking-tight">
            &#9670; AegisML
          </span>
          <a
            href="https://github.com/hasanalaaa/aegisml"
            target="_blank"
            rel="noopener noreferrer"
            className="text-aegis-muted text-sm hover:text-aegis-text transition-colors"
          >
            GitHub
          </a>
        </div>
      </nav>

      {/* ── Hero ────────────────────────────────────────────────── */}
      <main className="flex-1">
        <section className="max-w-3xl mx-auto px-6 pt-24 pb-16 text-center">
          <h1 className="text-4xl sm:text-5xl font-bold tracking-tight leading-tight">
            Scan AI Models
            <br />
            <span className="text-aegis-gold">for Malware</span>
          </h1>
          <p className="mt-4 text-aegis-muted text-lg max-w-xl mx-auto">
            Detect backdoors, trojans &amp; malicious code before they reach
            production
          </p>

          {/* ── Scan form ──────────────────────────────────────── */}
          <div className="mt-10 max-w-xl mx-auto">
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) setFile(f); }}
              onClick={() => fileInputRef.current?.click()}
              style={{
                border: `2px dashed ${dragOver ? "#C9A84C" : file ? "#2ECC71" : "#2A2A3E"}`,
                borderRadius: 12,
                padding: "32px 24px",
                textAlign: "center",
                cursor: "pointer",
                background: dragOver ? "rgba(201,168,76,0.05)" : "transparent",
                transition: "all 0.2s",
                marginBottom: 16,
              }}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".gguf,.safetensors,.pkl,.pickle,.pt,.pth"
                style={{ display: "none" }}
                onChange={(e) => { const f = e.target.files?.[0]; if (f) setFile(f); }}
              />
              {file ? (
                <div>
                  <p style={{ color: "#2ECC71", fontWeight: 700, margin: "0 0 4px", fontSize: 16 }}>✓ {file.name}</p>
                  <p style={{ color: "#666688", margin: 0, fontSize: 13 }}>{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
              ) : (
                <div>
                  <p style={{ color: "#A8A8C4", margin: "0 0 4px", fontSize: 15 }}>اسحب الملف هنا أو انقر للاختيار</p>
                  <p style={{ color: "#555577", margin: 0, fontSize: 12 }}>يدعم: .gguf • .safetensors • .pkl • .pt • .pth</p>
                </div>
              )}
            </div>

            <button
              onClick={handleScan}
              disabled={!file || scanning}
              style={{
                background: file && !scanning ? "linear-gradient(135deg, #C9A84C, #E4C46B)" : "#1E1E2E",
                color: file && !scanning ? "#0A0A0F" : "#555577",
                border: "none",
                padding: "14px 40px",
                borderRadius: 10,
                fontWeight: 800,
                fontSize: 16,
                cursor: file && !scanning ? "pointer" : "not-allowed",
                transition: "all 0.2s",
                width: "100%",
              }}
            >
              {scanning ? "⏳ جارٍ الفحص..." : "⬡ Scan Now"}
            </button>
          </div>
        </section>

        {/* ── Stats ─────────────────────────────────────────────── */}
        <section className="max-w-4xl mx-auto px-6 pb-16">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {stats.map((s) => (
              <div
                key={s.label}
                className="rounded-lg bg-aegis-card border border-white/5 p-6 text-center"
              >
                <div className="text-3xl font-bold text-aegis-gold">
                  {s.value}
                </div>
                <div className="mt-1 text-sm text-aegis-muted">{s.label}</div>
              </div>
            ))}
          </div>
        </section>

        {/* ── How It Works ──────────────────────────────────────── */}
        <section className="max-w-5xl mx-auto px-6 pb-24">
          <h2 className="text-2xl font-bold text-center mb-10">
            How It Works
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {steps.map((step) => (
              <div
                key={step.number}
                className="rounded-lg bg-aegis-card border border-white/5 p-6"
              >
                <div className="text-aegis-gold text-sm font-mono mb-2">
                  {step.number}
                </div>
                <h3 className="font-semibold text-aegis-text mb-1">
                  {step.title}
                </h3>
                <p className="text-sm text-aegis-muted leading-relaxed">
                  {step.desc}
                </p>
              </div>
            ))}
          </div>
        </section>
      </main>

      {/* ── Footer ──────────────────────────────────────────────── */}
      <footer className="border-t border-white/5 py-6">
        <p className="text-center text-xs text-aegis-muted">
          AegisML &mdash; Open-source AI model security. MIT License.
        </p>
      </footer>
    </div>
  );
}
