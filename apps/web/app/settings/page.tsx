"use client"

import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { ShieldCheck, AlertCircle, Loader2, Key } from "lucide-react"

export default function SettingsPage() {
  const [keys, setKeys] = useState<{id: string, provider: string, is_active: boolean}[]>([])
  const [provider, setProvider] = useState("anthropic")
  const [apiKey, setApiKey] = useState("")
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState<{text: string, type: "success"|"error"} | null>(null)

  useEffect(() => {
    fetchKeys()
  }, [])

  const fetchKeys = async () => {
    try {
      // In a real app, pass the token in headers
      const res = await fetch("/api/v1/user/api-keys")
      if (res.ok) {
        const data = await res.json()
        setKeys(data.keys || [])
      }
    } catch (e) {
      console.error(e)
    }
  }

  const handleSaveKey = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setMessage(null)

    try {
      // Validate key first
      const valRes = await fetch("/api/v1/ai/validate-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, api_key: apiKey })
      })
      const valData = await valRes.json()

      if (!valData.valid) {
        setMessage({ text: "Invalid API Key. Please check and try again.", type: "error" })
        setLoading(false)
        return
      }

      // Save key
      const saveRes = await fetch("/api/v1/user/api-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, api_key: apiKey })
      })

      if (saveRes.ok) {
        setMessage({ text: "API Key saved successfully!", type: "success" })
        setApiKey("")
        fetchKeys()
      } else {
        setMessage({ text: "Failed to save API key.", type: "error" })
      }
    } catch (err) {
      setMessage({ text: "An error occurred.", type: "error" })
    }
    setLoading(false)
  }

  const handleDelete = async (id: string) => {
    try {
      await fetch(`/api/v1/user/api-keys/${id}`, { method: "DELETE" })
      fetchKeys()
    } catch (e) {
      console.error(e)
    }
  }

  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", paddingTop: "120px" }}>
      <div className="container" style={{ maxWidth: "800px", margin: "0 auto", padding: "0 24px" }}>
        <h1 style={{ fontSize: "2rem", marginBottom: "32px", fontWeight: 700 }}>Settings</h1>

        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: "32px" }}>
          <h2 style={{ fontSize: "1.2rem", marginBottom: "24px", display: "flex", alignItems: "center", gap: "8px" }}>
            <Key size={20} color="var(--gold-mid)" /> API Keys
          </h2>

          <form onSubmit={handleSaveKey} style={{ display: "flex", flexDirection: "column", gap: "16px", marginBottom: "32px" }}>
            <div style={{ display: "flex", gap: "16px" }}>
              <select 
                value={provider} 
                onChange={e => setProvider(e.target.value)}
                style={{ width: "200px", padding: "12px", background: "var(--bg-subtle)", color: "white", border: "1px solid var(--border)", borderRadius: "var(--radius-md)" }}
              >
                <option value="anthropic">Anthropic</option>
                <option value="openai">OpenAI</option>
                <option value="google">Google Gemini</option>
                <option value="mistral">Mistral</option>
                <option value="groq">Groq</option>
              </select>
              
              <input 
                type="password" 
                value={apiKey} 
                onChange={e => setApiKey(e.target.value)} 
                placeholder="Enter API Key"
                required
                style={{ flex: 1, padding: "12px", background: "var(--bg-subtle)", color: "white", border: "1px solid var(--border)", borderRadius: "var(--radius-md)" }}
              />
            </div>
            
            <button 
              type="submit" 
              disabled={loading}
              style={{ background: "var(--gold-mid)", color: "black", padding: "12px 24px", borderRadius: "var(--radius-md)", border: "none", fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: "8px", alignSelf: "flex-start" }}
            >
              {loading ? <Loader2 size={18} className="animate-spin" /> : "Save & Verify Key"}
            </button>

            {message && (
              <div style={{ color: message.type === "success" ? "#10b981" : "#ef4444", fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "6px" }}>
                {message.type === "success" ? <ShieldCheck size={16} /> : <AlertCircle size={16} />}
                {message.text}
              </div>
            )}
          </form>

          <h3 style={{ fontSize: "1rem", color: "var(--text-secondary)", marginBottom: "16px" }}>Saved Keys</h3>
          {keys.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>No API keys saved yet.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {keys.map(k => (
                <div key={k.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px", background: "var(--bg-subtle)", borderRadius: "var(--radius-md)", border: "1px solid var(--border)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <span style={{ fontWeight: 600, textTransform: "capitalize" }}>{k.provider}</span>
                    <span style={{ fontSize: "0.8rem", padding: "4px 8px", background: "rgba(16, 185, 129, 0.1)", color: "#10b981", borderRadius: "100px" }}>Active</span>
                  </div>
                  <button 
                    onClick={() => handleDelete(k.id)}
                    style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer", fontSize: "0.9rem", fontWeight: 500 }}
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: "32px", marginTop: "32px" }}>
          <h2 style={{ fontSize: "1.2rem", marginBottom: "24px", display: "flex", alignItems: "center", gap: "8px" }}>
            <ShieldCheck size={20} color="var(--gold-mid)" /> Webhooks
          </h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem", marginBottom: "24px" }}>Configure webhooks to receive real-time events when scans complete or critical threats are detected.</p>
          
          <div style={{ display: "flex", gap: "16px", marginBottom: "32px" }}>
            <input 
              type="url" 
              placeholder="https://your-domain.com/webhook"
              style={{ flex: 1, padding: "12px", background: "var(--bg-subtle)", color: "white", border: "1px solid var(--border)", borderRadius: "var(--radius-md)" }}
            />
            <button 
              type="button" 
              style={{ background: "var(--gold-mid)", color: "black", padding: "12px 24px", borderRadius: "var(--radius-md)", border: "none", fontWeight: 600, cursor: "pointer" }}
            >
              Add Webhook
            </button>
          </div>
          
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {/* Mock Webhook */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px", background: "var(--bg-subtle)", borderRadius: "var(--radius-md)", border: "1px solid var(--border)" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                <span style={{ fontWeight: 600 }}>https://internal-security.aegisml.local/hook</span>
                <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>Events: scan.completed, threat.critical</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                <button style={{ background: "none", border: "none", color: "var(--safe)", cursor: "pointer", fontSize: "0.9rem", fontWeight: 500 }}>Test</button>
                <button style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer", fontSize: "0.9rem", fontWeight: 500 }}>Remove</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  )
}
