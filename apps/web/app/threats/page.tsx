"use client"
import { useState, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { GlassCard } from "@/components/GlassCard"
import { staggerContainer, fadeUpVariants } from "@/lib/animations"
import { Search, Sparkles, Bot } from "lucide-react"
import { API_BASE_URL } from "@/lib/api"

export default function ThreatsPage() {
  const [searchTerm, setSearchTerm] = useState("")
  const [categoryFilter, setCategoryFilter] = useState("")
  const [threatsData, setThreatsData] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [nlpQuery, setNlpQuery] = useState("")
  const [aiAnswer, setAiAnswer] = useState<{answer: string, related_patterns: string[]} | null>(null)
  const [aiLoading, setAiLoading] = useState(false)

  const handleNlpSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!nlpQuery.trim()) return
    setAiLoading(true)
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/threats/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: nlpQuery }),
      })
      if (!res.ok) throw new Error(`Server returned ${res.status}`)
      const data = await res.json()
      setAiAnswer({
        answer: data.answer || "No answer returned.",
        related_patterns: data.related_patterns || [],
      })
    } catch (err) {
      console.error(err)
      setAiAnswer({
        answer: "Couldn't reach the AI search service. Please try again.",
        related_patterns: [],
      })
    } finally {
      setAiLoading(false)
    }
  }

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        let url = `${API_BASE_URL}/api/v1/threats/patterns?limit=500`
        if (categoryFilter) url += `&category=${categoryFilter}`
        if (searchTerm) url += `&search=${searchTerm}`

        const res = await fetch(url)
        if (res.ok) {
          const data = await res.json()
          setThreatsData(data.data || [])
        }
      } catch (err) {
        console.error("Failed to load threats", err)
      } finally {
        setLoading(false)
      }
    }
    
    // Add simple debounce
    const timeout = setTimeout(fetchThreats, 300)
    return () => clearTimeout(timeout)
  }, [categoryFilter, searchTerm])

  const categories = ["code_execution", "network_exfiltration", "safetensors_anomaly", "template_injection", "backdoor_trojan", "supply_chain", "obfuscation", "steganography", "prompt_injection", "format_anomaly"]

  return (
    <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "120px", paddingBottom: "80px", color: "var(--text-primary)" }}>
      <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "flex-end", gap: "24px", marginBottom: "40px" }}>
          <div>
            <h1 style={{ fontSize: "2.5rem", margin: 0, display: "flex", alignItems: "center", gap: "16px" }}>
              ☣️ Threat Intelligence (200+ Patterns)
            </h1>
            <p style={{ color: "var(--text-secondary)", marginTop: "8px", maxWidth: "500px", lineHeight: 1.6 }}>
              Global ledger of known AI model vulnerabilities, payload injections, and poisoned weights.
            </p>
          </div>
          
          <form onSubmit={handleNlpSearch} style={{ position: "relative", width: "100%", flex: 1, minWidth: "300px" }}>
            <Sparkles size={18} style={{ position: "absolute", left: "16px", top: "50%", transform: "translateY(-50%)", color: "var(--cyan-accent)" }} />
            <input 
              type="text" 
              placeholder="Ask anything about threats (e.g., 'What is a pickle sleeper agent?')" 
              value={nlpQuery}
              onChange={(e) => setNlpQuery(e.target.value)}
              style={{
                width: "100%", padding: "16px 16px 16px 48px", borderRadius: "var(--radius-lg)",
                background: "rgba(0, 229, 255, 0.05)", border: "1px solid rgba(0, 229, 255, 0.2)", color: "var(--cyan-accent)",
                outline: "none", fontSize: "1rem", fontWeight: 500
              }}
            />
            <button type="submit" disabled={aiLoading} style={{ position: "absolute", right: "12px", top: "50%", transform: "translateY(-50%)", background: "var(--cyan-accent)", color: "#000", border: "none", padding: "8px 16px", borderRadius: "6px", fontWeight: 700, cursor: "pointer" }}>
              {aiLoading ? "Thinking..." : "Ask AI"}
            </button>
          </form>
        </motion.div>

        <AnimatePresence>
          {aiAnswer && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} style={{ marginBottom: "40px" }}>
              <GlassCard style={{ background: "rgba(201,168,76,0.1)", border: "1px solid var(--gold-border)", padding: "24px" }}>
                <div style={{ display: "flex", gap: "16px" }}>
                  <div style={{ width: "40px", height: "40px", borderRadius: "50%", background: "var(--gold-mid)", display: "flex", alignItems: "center", justifyContent: "center", color: "#000", flexShrink: 0 }}>
                    <Bot size={24} />
                  </div>
                  <div>
                    <h3 style={{ fontSize: "1.2rem", fontWeight: 700, color: "var(--gold-bright)", marginBottom: "8px" }}>Aegis AI</h3>
                    <p style={{ color: "var(--text-primary)", lineHeight: 1.6, marginBottom: "16px" }}>{aiAnswer.answer}</p>
                    <div style={{ display: "flex", gap: "8px" }}>
                      <span style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>Related Patterns:</span>
                      {aiAnswer.related_patterns.map((p, i) => (
                        <span key={i} style={{ fontSize: "0.8rem", padding: "2px 8px", background: "rgba(255,255,255,0.1)", borderRadius: "4px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>{p}</span>
                      ))}
                    </div>
                  </div>
                </div>
              </GlassCard>
            </motion.div>
          )}
        </AnimatePresence>

        <div style={{ display: "flex", gap: "12px", overflowX: "auto", paddingBottom: "16px", marginBottom: "24px" }}>
          <button 
            onClick={() => setCategoryFilter("")}
            style={{ padding: "8px 16px", borderRadius: "var(--radius-full)", background: categoryFilter === "" ? "var(--gold-mid)" : "var(--bg-subtle)", color: categoryFilter === "" ? "#000" : "var(--text-secondary)", border: "none", cursor: "pointer", whiteSpace: "nowrap" }}
          >
            All Categories
          </button>
          {categories.map(c => (
            <button 
              key={c}
              onClick={() => setCategoryFilter(c)}
              style={{ padding: "8px 16px", borderRadius: "var(--radius-full)", background: categoryFilter === c ? "var(--gold-mid)" : "var(--bg-subtle)", color: categoryFilter === c ? "#000" : "var(--text-secondary)", border: "none", cursor: "pointer", whiteSpace: "nowrap", textTransform: "capitalize" }}
            >
              {c.replace("_", " ")}
            </button>
          ))}
        </div>

        {loading ? (
          <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>Loading patterns...</div>
        ) : (
          <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "24px" }}>
            {threatsData.map((threat, i) => (
              <motion.div key={threat.id} variants={fadeUpVariants} custom={i}>
                <GlassCard style={{ height: "100%", display: "flex", flexDirection: "column" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "16px", borderBottom: "1px solid var(--gold-border)", paddingBottom: "16px" }}>
                    <div>
                      <span style={{ fontSize: "0.85rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)", background: "var(--bg-subtle)", padding: "2px 6px", borderRadius: "4px" }}>{threat.id}</span>
                      <h3 style={{ fontSize: "1.1rem", marginTop: "8px", lineHeight: 1.4 }}>{threat.name}</h3>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <span style={{ fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", padding: "4px 8px", borderRadius: "4px", background: threat.severity === "critical" ? "var(--danger)" : threat.severity === "high" ? "#f97316" : threat.severity === "medium" ? "var(--warn)" : "var(--safe)", color: "#000", display: "inline-block", marginBottom: "4px" }}>
                        {threat.severity}
                      </span>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", fontWeight: 600 }}>CVSS: {threat.cvss}</div>
                    </div>
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ marginBottom: "16px", fontSize: "0.85rem", color: "var(--text-secondary)", display: "flex", justifyContent: "space-between", textTransform: "capitalize" }}>
                      <span>Category: <span style={{ color: "var(--text-primary)", fontFamily: "var(--font-mono)" }}>{threat.category.replace("_", " ")}</span></span>
                    </div>
                    <p style={{ fontSize: "0.95rem", color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: "16px" }}>{threat.description}</p>
                    
                    {threat.references && threat.references.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginBottom: "16px" }}>
                        {threat.references.map((ref: string) => (
                          <span key={ref} style={{ fontSize: "0.75rem", padding: "2px 8px", borderRadius: "4px", background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)" }}>{ref.startsWith("http") ? <a href={ref} target="_blank" style={{ color: "var(--gold-mid)" }}>Link</a> : ref}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div style={{ background: "rgba(201,168,76,0.05)", padding: "16px", borderRadius: "var(--radius-md)", borderLeft: "2px solid var(--gold-bright)", marginTop: "auto" }}>
                    <span style={{ display: "block", fontSize: "0.75rem", textTransform: "uppercase", color: "var(--gold-bright)", fontWeight: 700, marginBottom: "4px" }}>Mitigation</span>
                    <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", margin: 0 }}>{threat.remediation}</p>
                  </div>
                </GlassCard>
              </motion.div>
            ))}
          </motion.div>
        )}

      </div>
    </main>
  )
}
