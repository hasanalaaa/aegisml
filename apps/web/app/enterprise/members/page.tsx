"use client"

import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { toast } from "sonner"
import { fadeUpVariants } from "@/lib/animations"
import { authFetch } from "@/lib/api"
import { Users, UserPlus, Shield, X, AlertCircle } from "lucide-react"

type Member = {
  id: number
  email: string
  role: string
  status: string
  joined_at: string
}

const ROLES = ["admin", "editor", "viewer"]

export default function MembersPage() {
  const [members, setMembers] = useState<Member[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [form, setForm] = useState({ email: "", role: "viewer" })

  async function loadMembers() {
    setLoading(true)
    try {
      const r = await authFetch("/api/v1/enterprise/members")
      if (r.status === 401) throw new Error("Please sign in to manage members.")
      if (r.status === 403) throw new Error("Admin or Enterprise plan required.")
      if (!r.ok) throw new Error(`Server returned ${r.status}`)
      setMembers(await r.json())
      setError(null)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadMembers() }, [])

  async function inviteMember() {
    if (!form.email.trim() || !/^[^@]+@[^@]+\.[^@]+$/.test(form.email)) {
      toast.error("Enter a valid email address."); return
    }
    setSubmitting(true)
    try {
      const r = await authFetch("/api/v1/enterprise/members/invite", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      })
      if (!r.ok) {
        const b = await r.json().catch(() => ({}))
        throw new Error(b.detail || `Server returned ${r.status}`)
      }
      toast.success(`Invitation sent to ${form.email}`)
      setForm({ email: "", role: "viewer" })
      setShowForm(false)
      loadMembers()
    } catch (e: any) {
      toast.error("Couldn't invite member", { description: e.message })
    } finally {
      setSubmitting(false)
    }
  }

  async function removeMember(id: number) {
    if (id === 0) { toast.info("The organization owner can't be removed."); return }
    try {
      const r = await authFetch(`/api/v1/enterprise/members/${id}`, { method: "DELETE" })
      if (!r.ok) throw new Error(`Server returned ${r.status}`)
      toast.success("Member removed")
      setMembers(prev => prev.filter(m => m.id !== id))
    } catch (e: any) {
      toast.error("Couldn't remove member", { description: e.message })
    }
  }

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div className="container" style={{ maxWidth: "1000px", margin: "0 auto", padding: "0 24px" }}>

        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: "40px", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", color: "var(--cyan-accent)", fontSize: "0.85rem", fontWeight: 600, marginBottom: "8px" }}>
              <Users size={14} /> Team Management
            </div>
            <h1 style={{ fontSize: "2.5rem", margin: 0, fontWeight: 800 }}>Members</h1>
            <p style={{ color: "var(--text-secondary)", marginTop: "8px" }}>Manage access control and RBAC for your organization.</p>
          </div>
          <button onClick={() => setShowForm(s => !s)} aria-label="Invite a new member" style={{ display: "flex", alignItems: "center", gap: "8px", padding: "10px 16px", background: "var(--gold-mid)", color: "#000", borderRadius: "var(--radius-sm)", cursor: "pointer", fontWeight: 700, border: "none" }}>
            {showForm ? <X size={18} /> : <UserPlus size={18} />} {showForm ? "Cancel" : "Invite Member"}
          </button>
        </motion.div>

        {showForm && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} style={{ overflow: "hidden", marginBottom: "24px" }}>
            <div style={{ padding: "24px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--gold-border)", borderRadius: "var(--radius-lg)", display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
              <input placeholder="colleague@company.com" type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} style={{ flex: 1, minWidth: "240px" }} />
              <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })} style={{ width: "auto" }}>
                {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
              <button onClick={inviteMember} disabled={submitting} style={{ padding: "10px 20px", background: "var(--gold-mid)", color: "#000", border: "none", borderRadius: "var(--radius-sm)", fontWeight: 700, cursor: submitting ? "not-allowed" : "pointer", opacity: submitting ? 0.6 : 1 }}>
                {submitting ? "Sending…" : "Send Invite"}
              </button>
            </div>
          </motion.div>
        )}

        {error ? (
          <div style={{ textAlign: "center", padding: "64px 24px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)" }}>
            <AlertCircle size={32} color="var(--warn)" style={{ marginBottom: "16px" }} />
            <h4 style={{ margin: "0 0 8px 0", color: "var(--text-primary)" }}>Couldn't load members</h4>
            <p style={{ color: "var(--text-secondary)" }}>{error}</p>
          </div>
        ) : loading ? (
          <div style={{ textAlign: "center", padding: "48px", color: "var(--text-muted)" }}>Loading members…</div>
        ) : (
          <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            {members.map(m => (
              <div key={m.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "20px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                  <div style={{ width: "40px", height: "40px", borderRadius: "50%", background: "var(--bg-subtle)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <Shield size={20} color={m.role === "admin" ? "var(--gold-bright)" : "var(--text-muted)"} />
                  </div>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: "1.1rem" }}>{m.email}</div>
                    <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginTop: "4px", textTransform: "capitalize" }}>
                      {m.role} • <span style={{ color: m.status === "active" ? "var(--safe)" : "var(--warn)" }}>{m.status}</span>
                    </div>
                  </div>
                </div>
                {m.id !== 0 && (
                  <button onClick={() => removeMember(m.id)} aria-label={`Remove ${m.email}`} style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: "8px" }}>
                    <X size={20} />
                  </button>
                )}
              </div>
            ))}
          </motion.div>
        )}
      </div>
    </main>
  )
}
