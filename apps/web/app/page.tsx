"use client";

import { useState } from "react";

/* ─── Types ──────────────────────────────────────────────────────── */

interface Finding {
  type: string;
  severity: string;
  description: string;
  pattern: string | null;
}

interface ScanResult {
  scan_id: string;
  status: string;
  risk_score: number;
  severity: string;
  findings: Finding[];
  duration_ms: number | null;
  model_format: string | null;
  filename: string | null;
  repo_id?: string;
}

/* ─── Severity helpers ───────────────────────────────────────────── */

const severityColor: Record<string, string> = {
  clean: "text-aegis-clean",
  suspicious: "text-aegis-suspicious",
  malicious: "text-aegis-critical",
  critical: "text-aegis-critical",
};

const severityBorder: Record<string, string> = {
  clean: "border-aegis-clean",
  suspicious: "border-aegis-suspicious",
  malicious: "border-aegis-critical",
  critical: "border-aegis-critical",
};

const severityBg: Record<string, string> = {
  clean: "bg-aegis-clean/10",
  suspicious: "bg-aegis-suspicious/10",
  malicious: "bg-aegis-critical/10",
  critical: "bg-aegis-critical/10",
};

const severityLabel: Record<string, string> = {
  clean: "CLEAN",
  suspicious: "SUSPICIOUS",
  malicious: "MALICIOUS",
  critical: "CRITICAL",
};

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
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleScan() {
    const value = input.trim();
    if (!value) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("http://localhost:8000/api/v1/scan/hf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_id: value }),
      });

      if (!res.ok) {
        const errBody = await res.json().catch(() => null);
        throw new Error(
          errBody?.detail || `Server responded with ${res.status}`
        );
      }

      const data: ScanResult = await res.json();
      setResult(data);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Failed to connect to scan engine. Is the backend running?");
      }
    } finally {
      setLoading(false);
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
            href="https://github.com/aegisml/aegisml"
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
          <div className="mt-10 flex flex-col sm:flex-row gap-3 max-w-xl mx-auto">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              placeholder="Enter HuggingFace repo ID or file path..."
              className="flex-1 px-4 py-3 rounded-lg bg-aegis-card border border-white/10 text-aegis-text placeholder:text-aegis-muted/50 outline-none focus:border-aegis-gold/50 transition-colors"
            />
            <button
              onClick={handleScan}
              disabled={loading || !input.trim()}
              className="px-6 py-3 rounded-lg bg-aegis-gold text-aegis-bg font-semibold hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {loading ? "Scanning..." : "Scan Now"}
            </button>
          </div>

          {/* ── Error display ──────────────────────────────────── */}
          {error && (
            <div className="mt-6 max-w-xl mx-auto p-4 rounded-lg bg-aegis-critical/10 border border-aegis-critical/30 text-aegis-critical text-sm text-left">
              <span className="font-semibold">Error: </span>
              {error}
            </div>
          )}

          {/* ── Scan result ────────────────────────────────────── */}
          {result && (
            <div className="mt-8 max-w-xl mx-auto text-left">
              {/* Summary card */}
              <div
                className={`rounded-lg border p-5 ${
                  severityBorder[result.severity] || "border-white/10"
                } ${severityBg[result.severity] || ""}`}
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs text-aegis-muted font-mono">
                    {result.scan_id}
                  </span>
                  <span
                    className={`text-xs font-bold px-2 py-0.5 rounded ${
                      severityColor[result.severity] || "text-aegis-text"
                    }`}
                  >
                    {severityLabel[result.severity] || result.severity.toUpperCase()}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-aegis-muted block text-xs">
                      Risk Score
                    </span>
                    <span
                      className={`text-2xl font-bold ${
                        severityColor[result.severity] || "text-aegis-text"
                      }`}
                    >
                      {result.risk_score}
                    </span>
                    <span className="text-aegis-muted text-sm"> / 100</span>
                  </div>
                  <div>
                    <span className="text-aegis-muted block text-xs">
                      Status
                    </span>
                    <span className="text-lg font-semibold text-aegis-text">
                      {result.status}
                    </span>
                  </div>
                  {result.model_format && (
                    <div>
                      <span className="text-aegis-muted block text-xs">
                        Format
                      </span>
                      <span className="text-aegis-text">
                        {result.model_format}
                      </span>
                    </div>
                  )}
                  {result.duration_ms != null && (
                    <div>
                      <span className="text-aegis-muted block text-xs">
                        Duration
                      </span>
                      <span className="text-aegis-text">
                        {result.duration_ms.toFixed(1)} ms
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Findings list */}
              {result.findings && result.findings.length > 0 && (
                <div className="mt-4 space-y-2">
                  <h3 className="text-sm font-semibold text-aegis-muted mb-2">
                    Findings ({result.findings.length})
                  </h3>
                  {result.findings.map((f, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-lg bg-aegis-card border border-white/5 text-sm"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span
                          className={`text-xs font-bold ${
                            severityColor[f.severity] || "text-aegis-muted"
                          }`}
                        >
                          {f.severity.toUpperCase()}
                        </span>
                        <span className="text-aegis-muted text-xs font-mono">
                          {f.type}
                        </span>
                        {f.pattern && (
                          <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-aegis-gold">
                            {f.pattern}
                          </code>
                        )}
                      </div>
                      <p className="text-aegis-text/80 text-xs leading-relaxed">
                        {f.description}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
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
