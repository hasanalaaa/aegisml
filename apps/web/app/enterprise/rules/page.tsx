"use client"

import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { toast } from "sonner"
import { fadeUpVariants } from "@/lib/animations"
import { authFetch } from "@/lib/api"
import { ShieldCheck, Plus, Trash2, X, AlertCircle } from "lucide-react"

type ThreatRule = {
  id: number
  name: string
  regex_pattern: string
  severity: string
  description: string | null
  is_active: boolean
  created_at: string
}

const SEVERITIES = ["low", "medium", "high", "critical"]

export default function RulesPage() {
  const [rules, setRules] = useState<ThreatRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [form, setForm] = useState({ name: "", regex_pattern: "", severity: "high", description: "" })

  async function loadRules() {
    setLoading(true)
    try {
      const r = await authFetch("/api/v1/enterprise/threat-rules")
      if (r.status === 401) throw new Error("Please sign in to manage threat rules.")
      if (r.status === 403) throw new Error("Admin or Enterprise plan required.")
      if (!r.ok) throw new Error(`Server returned ${r.status}`)
      setRules(await r.json())
      setError(null)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadRules() }, [])

  async function createRule() {
    if (!form.name.trim() || !form.regex_pattern.trim()) {
      toast.error("Name and regex pattern are required."); return
    }
    // Validate the regex client-side before sending
    try { new RegExp(form.regex_pattern) }
    catch { toast.error("Invalid regular expression."); return }

    setSubmitting(true)
    try {
      const r = await authFetch("/api/v1/enterprise/threat-rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      })
      if (!r.ok) {
        const b = await r.json().catch(() => ({}))
        throw new Error(b.detail || `Server returned ${r.status}`)
      }
      toast.success("Threat rule created")
      setForm({ name: "", regex_pattern: "", severity: "high", description: "" })
      setShowForm(false)
      loadRules()
    } catch (e: any) {
      toast.error("Couldn't create rule", { description: e.message })
    } finally {
      setSubmitting(false)
    }
  }

  async function deleteRule(id: number) {
    try {
      const r = await authFetch(`/api/v1/enterprise/threat-rules/${id}`, { method: "DELETE" })
      if (!r.ok) throw new Error(`Server returned ${r.status}`)
      toast.success("Rule deleted")
      setRules(prev => prev.filter(rule => rule.id !== id))
    } catch (e: any) {
      toast.error("Couldn't delete rule", { description: e.message })
    }
  }

  const sevColor = (s: string) => s === "critical" ? "var(--critical)" : s === "high" ? "var(--danger)" : s === "medium" ? "var(--warn)" : "var(--safe)"

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "1000px", margin: "0 auto", padding: "0 24px" }}>

        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: "40px", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", color: "var(--cyan-accent)", fontSize: "0.85rem", fontWeight: 600, marginBottom: "8px" }}>
              <ShieldCheck size={14} /> Custom Engine
            </div>
            <h1 style={{ fontSize: "2.5rem", margin: 0, fontWeight: 800 }}>Threat Rules</h1>
            <p style={{ color: "var(--text-secondary)", marginTop: "8px" }}>Define custom RegEx patterns to block proprietary bad practices.</p>
          </div>
          <button onClick={() => setShowForm(s => !s)} aria-label="Create new threat rule" style={{ display: "flex", alignItems: "center", gap: "8px", padding: "10px 16px", background: "var(--cyan-accent)", color: "#000", borderRadius: "var(--radius-sm)", cursor: "pointer", fontWeight: 700, border: "none" }}>
            {showForm ? <X size={18} /> : <Plus size={18} />} {showForm ? "Cancel" : "New Rule"}
          </button>
        </motion.div>

        {showForm && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} style={{ overflow: "hidden", marginBottom: "24px" }}>
            <div style={{ padding: "24px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--gold-border)", borderRadius: "var(--radius-lg)", display: "flex", flexDirection: "column", gap: "16px" }}>
              <input placeholder="Rule name (e.g. Block external file loads)" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
              <input placeholder="RegEx pattern (e.g. file://.*)" value={form.regex_pattern} onChange={e => setForm({ ...form, regex_pattern: e.target.value })} style={{ fontFamily: "var(--font-mono)" }} />
              <textarea placeholder="Description (optional)" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={2} />
              <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })} style={{ width: "auto" }}>
                  {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <button onClick={createRule} disabled={submitting} style={{ padding: "10px 20px", background: "var(--gold-mid)", color: "#000", border: "none", borderRadius: "var(--radius-sm)", fontWeight: 700, cursor: submitting ? "not-allowed" : "pointer", opacity: submitting ? 0.6 : 1 }}>
                  {submitting ? "Creating…" : "Create Rule"}
                </button>
              </div>
            </div>
          </motion.div>
        )}

        {error ? (
          <div style={{ textAlign: "center", padding: "64px 24px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)" }}>
            <AlertCircle size={32} color="var(--warn)" style={{ marginBottom: "16px" }} />
            <h4 style={{ margin: "0 0 8px 0", color: "var(--text-primary)" }}>Couldn't load rules</h4>
            <p style={{ color: "var(--text-secondary)" }}>{error}</p>
          </div>
        ) : loading ? (
          <div style={{ textAlign: "center", padding: "48px", color: "var(--text-muted)" }}>Loading rules…</div>
        ) : rules.length === 0 ? (
          <div style={{ textAlign: "center", padding: "64px 24px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)" }}>
            <div style={{ fontSize: "3rem", marginBottom: "16px", opacity: 0.5 }}>📋</div>
            <h4 style={{ margin: "0 0 8px 0", fontSize: "1.2rem", color: "var(--text-primary)" }}>No custom rules yet</h4>
            <p style={{ color: "var(--text-secondary)" }}>Create your first rule to extend the scanner with org-specific patterns.</p>
          </div>
        ) : (
          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            {rules.map(rule => (
              <div key={rule.id} style={{ padding: "24px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "16px" }}>
                  <div>
                    <h3 style={{ fontSize: "1.2rem", fontWeight: 700, margin: "0 0 8px 0" }}>{rule.name}</h3>
                    <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                      <span style={{ fontSize: "0.8rem", padding: "4px 8px", background: "rgba(239,68,68,0.1)", color: sevColor(rule.severity), borderRadius: "var(--radius-sm)", fontWeight: 700, textTransform: "uppercase" }}>
                        {rule.severity}
                      </span>
                      <span style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>Active: {rule.is_active ? "Yes" : "No"}</span>
                    </div>
                  </div>
                  <button onClick={() => deleteRule(rule.id)} aria-label={`Delete rule ${rule.name}`} style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
                    <Trash2 size={18} />
                  </button>
                </div>
                {rule.description && <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem", marginBottom: "12px" }}>{rule.description}</p>}
                <div style={{ background: "#000", padding: "16px", borderRadius: "var(--radius-md)", border: "1px solid var(--border)" }}>
                  <code style={{ fontFamily: "var(--font-mono)", color: "var(--gold-bright)", fontSize: "0.9rem" }}>{rule.regex_pattern}</code>
                </div>
              </div>
            ))}
          </motion.div>
        )}
      </div>
    </main>
  )
}
