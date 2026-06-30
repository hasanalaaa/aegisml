"use client"
import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { fadeUpVariants, staggerContainer } from "@/lib/animations"
import { GlassCard } from "@/components/GlassCard"
import { PrimaryButton } from "@/components/Buttons"
import { Download, Database, BookOpen, Quote, ShieldAlert } from "lucide-react"
import { API_BASE_URL } from "@/lib/api"

export default function ResearchPage() {
  const [stats, setStats] = useState<any>(null)
  const [citation, setCitation] = useState<any>(null)
  const [formData, setFormData] = useState({ name: "", institution: "", use_case: "", email: "" })
  const [requested, setRequested] = useState(false)
  const [format, setFormat] = useState("json")

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/v1/research/stats/aggregate`).then(r => r.json()).then(setStats).catch(console.error)
    fetch(`${API_BASE_URL}/api/v1/research/citation`).then(r => r.json()).then(setCitation).catch(console.error)
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await fetch(`${API_BASE_URL}/api/v1/research/api-key`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData)
      })
      setRequested(true)
    } catch (err) {
      console.error(err)
    }
  }

  const handleDownload = () => {
    window.open(`${API_BASE_URL}/api/v1/research/dataset?format=${format}&limit=1000`, "_blank")
  }

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ textAlign: "center", marginBottom: "60px" }}>
          <h1 style={{ fontSize: "3rem", fontWeight: 800, marginBottom: "16px", color: "var(--cyan-accent)", display: "flex", alignItems: "center", justifyContent: "center", gap: "16px" }}>
            <BookOpen size={40} /> AegisML Research Program
          </h1>
          <p style={{ fontSize: "1.2rem", color: "var(--text-secondary)", maxWidth: "800px", margin: "0 auto", lineHeight: 1.6 }}>
            Empowering the cybersecurity and AI research community with anonymized threat datasets, aggregated statistics, and high-limit API access for academic and non-profit use cases.
          </p>
        </motion.div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "32px", marginBottom: "40px" }} className="grid-cols-1 md:grid-cols-2">
          
          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible">
            <GlassCard style={{ padding: "32px", height: "100%" }}>
              <h2 style={{ fontSize: "1.5rem", fontWeight: 600, marginBottom: "24px", display: "flex", alignItems: "center", gap: "8px" }}>
                <ShieldAlert color="var(--gold-bright)" /> Request Research API Key
              </h2>
              {requested ? (
                <div style={{ padding: "20px", background: "rgba(16, 185, 129, 0.1)", border: "1px solid var(--safe)", borderRadius: "var(--radius-md)", color: "var(--safe)", textAlign: "center" }}>
                  Request submitted successfully! We will review your application and contact you via email shortly.
                </div>
              ) : (
                <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                  <div>
                    <label style={{ display: "block", marginBottom: "8px", color: "var(--text-secondary)", fontSize: "0.9rem" }}>Full Name</label>
                    <input required value={formData.name} onChange={e => setFormData({...formData, name: e.target.value})} style={{ width: "100%", padding: "12px", background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "#fff" }} />
                  </div>
                  <div>
                    <label style={{ display: "block", marginBottom: "8px", color: "var(--text-secondary)", fontSize: "0.9rem" }}>Email Address</label>
                    <input required type="email" value={formData.email} onChange={e => setFormData({...formData, email: e.target.value})} style={{ width: "100%", padding: "12px", background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "#fff" }} />
                  </div>
                  <div>
                    <label style={{ display: "block", marginBottom: "8px", color: "var(--text-secondary)", fontSize: "0.9rem" }}>Institution / Organization</label>
                    <input required value={formData.institution} onChange={e => setFormData({...formData, institution: e.target.value})} style={{ width: "100%", padding: "12px", background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "#fff" }} />
                  </div>
                  <div>
                    <label style={{ display: "block", marginBottom: "8px", color: "var(--text-secondary)", fontSize: "0.9rem" }}>Intended Use Case</label>
                    <textarea required rows={4} value={formData.use_case} onChange={e => setFormData({...formData, use_case: e.target.value})} style={{ width: "100%", padding: "12px", background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "#fff", resize: "vertical" }} />
                  </div>
                  <button type="submit" style={{ background: "var(--cyan-accent)", color: "#000", border: "none", padding: "14px", borderRadius: "var(--radius-sm)", fontWeight: 600, fontSize: "1rem", cursor: "pointer", marginTop: "8px" }}>
                    Submit Request
                  </button>
                </form>
              )}
            </GlassCard>
          </motion.div>

          <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "flex", flexDirection: "column", gap: "32px" }}>
            
            <GlassCard style={{ padding: "32px" }}>
              <h2 style={{ fontSize: "1.5rem", fontWeight: 600, marginBottom: "24px", display: "flex", alignItems: "center", gap: "8px" }}>
                <Database color="var(--cyan-accent)" /> Download Anonymized Dataset
              </h2>
              <p style={{ color: "var(--text-secondary)", marginBottom: "24px", lineHeight: 1.5 }}>
                Access our anonymized dataset of model scans containing file types, threat categories, CVSS scores, and entropy metrics. Limited to 1,000 records without a Research Key.
              </p>
              <div style={{ display: "flex", gap: "16px", alignItems: "center" }}>
                <select value={format} onChange={e => setFormat(e.target.value)} style={{ padding: "12px", background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "#fff", flex: 1, outline: "none", cursor: "pointer" }}>
                  <option value="json">JSON (Standard)</option>
                  <option value="csv">CSV (Spreadsheet)</option>
                  <option value="parquet">Parquet (Data Science)</option>
                </select>
                <PrimaryButton onClick={handleDownload} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "12px 24px" }}>
                  <Download size={18} /> Download
                </PrimaryButton>
              </div>
            </GlassCard>

            <GlassCard style={{ padding: "32px" }}>
              <h2 style={{ fontSize: "1.3rem", fontWeight: 600, marginBottom: "16px" }}>Live Aggregate Stats</h2>
              {stats ? (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                  <div style={{ background: "rgba(255,255,255,0.03)", padding: "16px", borderRadius: "var(--radius-sm)", textAlign: "center" }}>
                    <div style={{ fontSize: "0.9rem", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "8px" }}>Total Scans</div>
                    <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "var(--gold-mid)" }}>{stats.total_scans.toLocaleString()}</div>
                  </div>
                  <div style={{ background: "rgba(255,255,255,0.03)", padding: "16px", borderRadius: "var(--radius-sm)", textAlign: "center" }}>
                    <div style={{ fontSize: "0.9rem", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "8px" }}>Critical Threats</div>
                    <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "var(--danger)" }}>{stats.verdict_distribution.critical.toLocaleString()}</div>
                  </div>
                </div>
              ) : (
                <div style={{ color: "var(--text-muted)" }}>Loading stats...</div>
              )}
            </GlassCard>

          </motion.div>
        </div>

        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible">
          <GlassCard style={{ padding: "32px" }}>
            <h2 style={{ fontSize: "1.3rem", fontWeight: 600, marginBottom: "24px", display: "flex", alignItems: "center", gap: "8px" }}>
              <Quote color="var(--text-secondary)" /> Cite AegisML
            </h2>
            <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: "24px" }}>
              {citation ? (
                <>
                  <div>
                    <h3 style={{ fontSize: "0.9rem", color: "var(--text-muted)", marginBottom: "8px" }}>APA</h3>
                    <div style={{ background: "rgba(0,0,0,0.3)", padding: "16px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", fontFamily: "var(--font-mono)", fontSize: "0.9rem", color: "var(--text-secondary)" }}>
                      {citation.apa}
                    </div>
                  </div>
                  <div>
                    <h3 style={{ fontSize: "0.9rem", color: "var(--text-muted)", marginBottom: "8px" }}>BibTeX</h3>
                    <div style={{ background: "rgba(0,0,0,0.3)", padding: "16px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", fontFamily: "var(--font-mono)", fontSize: "0.9rem", color: "var(--text-secondary)", whiteSpace: "pre-wrap" }}>
                      {citation.bibtex}
                    </div>
                  </div>
                </>
              ) : (
                <div style={{ color: "var(--text-muted)" }}>Loading citations...</div>
              )}
            </div>
          </GlassCard>
        </motion.div>

      </div>
    </main>
  )
}
