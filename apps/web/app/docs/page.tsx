"use client"
import { useState } from "react"
import { motion } from "framer-motion"
import { GlassCard } from "@/components/GlassCard"
import { GhostButton, PrimaryButton } from "@/components/Buttons"
import { fadeUpVariants } from "@/lib/animations"
import { API_BASE_URL } from "@/lib/api"

interface Endpoint {
  method: string
  path: string
  description: string
  body?: string
  example_response: string
}

const ENDPOINTS: Endpoint[] = [
  { method: "GET", path: "/health", description: "Check API health status and features", example_response: `{\n  "status": "ok",\n  "version": "1.0.0"\n}` },
  { method: "POST", path: "/api/v1/scan/file", description: "Scan an uploaded model file", body: "multipart/form-data\n  file: <binary>  (required)", example_response: `{\n  "scan_id": "uuid",\n  "status": "complete",\n  "result": {\n    "risk_score": 75,\n    "risk_level": "malicious",\n    "ai_analysis": { "verdict": "DANGEROUS" }\n  }\n}` },
  { method: "POST", path: "/api/v1/scan/url", description: "Scan a model from a direct HuggingFace URL", body: `{\n  "url": "https://huggingface.co/.../model.gguf"\n}`, example_response: `{ "scan_id": "uuid", "status": "complete", "result": {...} }` },
  { method: "GET", path: "/api/v1/scan/{scan_id}", description: "Retrieve an existing scan result by ID", example_response: `{\n  "scan_id": "uuid",\n  "filename": "model.gguf",\n  "risk_score": 10,\n  "risk_level": "clean",\n  "threats": [],\n  "ai_analysis": { "verdict": "SAFE", "confidence": 97 }\n}` },
]

const METHOD_COLOR: Record<string, string> = {
  GET: "var(--safe)", POST: "var(--cyan-accent)", DELETE: "var(--danger)", PUT: "var(--warn)",
}

export default function DocsPage() {
  const [activeIdx, setActiveIdx] = useState(0)
  const ep = ENDPOINTS[activeIdx]

  return (
    <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "120px", paddingBottom: "80px", color: "var(--text-primary)" }}>
      <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "40px" }}>
          <h1 style={{ fontSize: "2.5rem", margin: 0 }}>API Documentation</h1>
          <p style={{ color: "var(--text-secondary)", marginTop: "8px", maxWidth: "600px", lineHeight: 1.6 }}>
            Integrate AegisML's scanning engine directly into your CI/CD pipelines, model registries, or custom platforms.
          </p>
          <div style={{ display: "flex", gap: "16px", marginTop: "24px" }}>
            <span style={{ fontSize: "0.85rem", padding: "4px 12px", background: "rgba(201,168,76,0.1)", color: "var(--gold-bright)", borderRadius: "var(--radius-sm)", border: "1px solid var(--gold-border)" }}>Base URL: https://api.aegisml.com</span>
            <span style={{ fontSize: "0.85rem", padding: "4px 12px", background: "rgba(16,185,129,0.1)", color: "var(--safe)", borderRadius: "var(--radius-sm)", border: "1px solid rgba(16,185,129,0.2)" }}>Free Tier: 100 scans/mo</span>
            <a href=`${API_BASE_URL}/graphql` target="_blank" rel="noopener noreferrer" style={{ fontSize: "0.85rem", padding: "4px 12px", background: "rgba(225,0,152,0.1)", color: "#E10098", borderRadius: "var(--radius-sm)", border: "1px solid rgba(225,0,152,0.3)", textDecoration: "none", fontWeight: 600, display: "flex", alignItems: "center", gap: "6px" }}>
              <svg width="14" height="14" viewBox="0 0 400 400"><path fill="#E10098" d="M57.468 122.06l86.066-49.69L199.99 43.352l56.455 29.017 86.066 49.69v99.382l-86.066 49.69-56.455 29.018-56.455-29.018-86.066-49.69z"/><path fill="#fff" d="M200 137.91l54.43 31.425v62.85L200 263.61l-54.43-31.425v-62.85L200 137.91z"/></svg>
              Open GraphQL Playground
            </a>
          </div>
        </motion.div>

        <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: "32px" }} className="grid-cols-1 md:grid-cols-[300px_1fr]">
          {/* Sidebar */}
          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible">
            <GlassCard style={{ padding: "16px", position: "sticky", top: "100px" }}>
              <div style={{ fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--text-muted)", marginBottom: "16px", fontWeight: 700 }}>Endpoints</div>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {ENDPOINTS.map((e, i) => (
                  <button key={i} onClick={() => setActiveIdx(i)} style={{
                    display: "flex", alignItems: "center", gap: "12px", padding: "12px", borderRadius: "var(--radius-sm)",
                    background: activeIdx === i ? "rgba(201,168,76,0.1)" : "transparent",
                    border: activeIdx === i ? "1px solid var(--gold-border)" : "1px solid transparent",
                    cursor: "pointer", textAlign: "left", transition: "all 0.2s"
                  }} className="hover:bg-white/5">
                    <span style={{ fontSize: "0.7rem", fontWeight: 800, padding: "2px 6px", borderRadius: "4px", color: METHOD_COLOR[e.method], background: "rgba(255,255,255,0.05)" }}>{e.method}</span>
                    <span style={{ fontSize: "0.85rem", fontFamily: "var(--font-mono)", color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.path}</span>
                  </button>
                ))}
              </div>
            </GlassCard>
          </motion.div>

          {/* Content */}
          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" key={activeIdx}>
            <GlassCard style={{ padding: "40px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "24px" }}>
                <span style={{ fontSize: "0.9rem", fontWeight: 800, padding: "4px 12px", borderRadius: "6px", color: METHOD_COLOR[ep.method], background: "rgba(255,255,255,0.05)" }}>{ep.method}</span>
                <span style={{ fontSize: "1.2rem", fontFamily: "var(--font-mono)", color: "var(--gold-bright)", fontWeight: 600 }}>{ep.path}</span>
              </div>
              <p style={{ color: "var(--text-secondary)", fontSize: "1.1rem", marginBottom: "32px" }}>{ep.description}</p>
              
              {ep.body && (
                <div style={{ marginBottom: "32px" }}>
                  <h4 style={{ fontSize: "0.9rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "12px" }}>Request Body</h4>
                  <pre style={{ background: "#000", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--border)", color: "var(--gold-subtle)", fontFamily: "var(--font-mono)", fontSize: "0.9rem", overflowX: "auto" }}>
                    {ep.body}
                  </pre>
                </div>
              )}

              <div>
                <h4 style={{ fontSize: "0.9rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "12px" }}>Example Response</h4>
                <pre style={{ background: "#000", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--border)", color: "var(--safe)", fontFamily: "var(--font-mono)", fontSize: "0.9rem", overflowX: "auto" }}>
                  {ep.example_response}
                </pre>
              </div>
            </GlassCard>

            <div style={{ marginTop: "32px", display: "flex", gap: "16px" }}>
              <PrimaryButton href="#generate">Generate API Key</PrimaryButton>
              <GhostButton href="#support">Need Help?</GhostButton>
            </div>
          </motion.div>
        </div>

        {/* Integrations Section */}
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginTop: "80px", paddingTop: "80px", borderTop: "1px solid var(--border)" }}>
          <h2 id="github-actions" style={{ fontSize: "2rem", marginBottom: "24px" }}>GitHub Actions Integration</h2>
          <p style={{ color: "var(--text-secondary)", marginBottom: "24px" }}>Scan your models automatically on every push or pull request using our official GitHub Action.</p>
          <pre style={{ background: "#000", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--border)", color: "var(--gold-subtle)", fontFamily: "var(--font-mono)", fontSize: "0.9rem", overflowX: "auto", marginBottom: "48px" }}>{`name: Model Security Scan
on: [push, pull_request]

jobs:
  scan-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: AegisML Scan
        uses: aegisml/scan-action@v1
        with:
          model-url: 'huggingface.co/your-org/your-model'
          api-key: \${{ secrets.AEGISML_API_KEY }}
          fail-on: 'CRITICAL'`}</pre>

          <h2 id="slack" style={{ fontSize: "2rem", marginBottom: "24px" }}>Slack Bot</h2>
          <p style={{ color: "var(--text-secondary)", marginBottom: "24px" }}>Invoke scans directly from any Slack channel using the \`/aegis-scan\` slash command.</p>
          <pre style={{ background: "#000", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--border)", color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: "0.9rem", overflowX: "auto", marginBottom: "48px" }}>{`/aegis-scan https://huggingface.co/mistralai/Mistral-7B-v0.1`}</pre>

          <h2 id="discord" style={{ fontSize: "2rem", marginBottom: "24px" }}>Discord Bot</h2>
          <p style={{ color: "var(--text-secondary)", marginBottom: "24px" }}>Protect your community by deploying the AegisML bot. Use the \`!scan\` command.</p>
          <pre style={{ background: "#000", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--border)", color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: "0.9rem", overflowX: "auto", marginBottom: "48px" }}>{`!scan https://huggingface.co/mistralai/Mistral-7B-v0.1`}</pre>
        </motion.div>

      </div>
    </main>
  )
}
