import React, { useState, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { MessageSquare, X, Send, Bot } from "lucide-react"
import { API_BASE_URL } from "@/lib/api"

type ChatMessage = { role: "user" | "ai"; text: string }

export function AIChat({ scanId }: { scanId: string }) {
  const [isOpen, setIsOpen] = useState(false)
  const [messages, setMessages] = useState<ChatMessage[]>([
    { role: "ai", text: `Hello! I've loaded scan ${scanId.slice(0, 8)}. Ask me about any of the findings and I'll answer based on the actual scan results.` }
  ])
  const [input, setInput] = useState("")
  const [sending, setSending] = useState(false)
  const [scanContext, setScanContext] = useState<{ filename: string; threats: any[] } | null>(null)

  useEffect(() => {
    if (!isOpen || scanContext) return
    fetch(`${API_BASE_URL}/api/v1/scan/${scanId}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data) setScanContext({ filename: data.filename, threats: data.threats || [] })
      })
      .catch(() => { /* chat still works without prefetched context — the backend can still answer generically */ })
  }, [isOpen, scanId, scanContext])

  const handleSend = async () => {
    const question = input.trim()
    if (!question || sending) return
    setMessages(prev => [...prev, { role: "user", text: question }])
    setInput("")
    setSending(true)

    try {
      // Ground the question in this specific scan's findings by passing
      // them as the `patterns` context to the real NLP query endpoint —
      // this used to be a setTimeout() that always returned the exact same
      // hardcoded sentence regardless of what was asked.
      const res = await fetch(`${API_BASE_URL}/api/v1/threats/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: scanContext
            ? `Regarding the scan of "${scanContext.filename}": ${question}`
            : question,
          patterns: scanContext?.threats?.length ? scanContext.threats : undefined,
        }),
      })
      if (!res.ok) throw new Error(`Server returned ${res.status}`)
      const data = await res.json()
      setMessages(prev => [...prev, { role: "ai", text: data.answer || "No answer returned." }])
    } catch (err) {
      setMessages(prev => [...prev, { role: "ai", text: "Sorry, I couldn't reach the analysis service. Please try again." }])
    } finally {
      setSending(false)
    }
  }

  return (
    <>
      <button
        onClick={() => setIsOpen(true)}
        aria-label="Open AI assistant"
        style={{ position: "fixed", bottom: "32px", right: "32px", width: "64px", height: "64px", borderRadius: "50%", background: "var(--gold-mid)", color: "#000", border: "none", display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer", boxShadow: "0 8px 32px rgba(201,168,76,0.3)", zIndex: 50 }}
      >
        <MessageSquare size={28} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 50, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 50, scale: 0.9 }}
            style={{ position: "fixed", bottom: "110px", right: "32px", width: "400px", height: "500px", background: "var(--bg-card, var(--bg-elevated))", border: "1px solid var(--gold-border)", borderRadius: "var(--radius-lg)", boxShadow: "0 24px 64px rgba(0,0,0,0.5)", zIndex: 50, display: "flex", flexDirection: "column", overflow: "hidden" }}
          >
            <div style={{ padding: "16px", background: "rgba(201,168,76,0.1)", borderBottom: "1px solid var(--gold-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", fontWeight: 700, color: "var(--gold-bright)" }}>
                <Bot size={20} /> Aegis AI Assistant
              </div>
              <button onClick={() => setIsOpen(false)} aria-label="Close AI assistant" style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
                <X size={20} />
              </button>
            </div>

            <div style={{ flex: 1, overflowY: "auto", padding: "16px", display: "flex", flexDirection: "column", gap: "16px" }}>
              {messages.map((m, i) => (
                <div key={i} style={{ alignSelf: m.role === "user" ? "flex-end" : "flex-start", maxWidth: "85%", background: m.role === "user" ? "var(--cyan-accent)" : "rgba(255,255,255,0.05)", color: m.role === "user" ? "#000" : "var(--text-primary)", padding: "12px 16px", borderRadius: "16px", borderBottomRightRadius: m.role === "user" ? 0 : "16px", borderBottomLeftRadius: m.role === "ai" ? 0 : "16px", fontSize: "0.95rem", lineHeight: 1.5 }}>
                  {m.text}
                </div>
              ))}
              {sending && (
                <div style={{ alignSelf: "flex-start", color: "var(--text-muted)", fontSize: "0.85rem" }}>Thinking…</div>
              )}
            </div>

            <div style={{ padding: "16px", borderTop: "1px solid var(--border)", display: "flex", gap: "12px" }}>
              <input
                type="text"
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleSend()}
                placeholder="Ask about this scan..."
                disabled={sending}
                style={{ flex: 1, background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", padding: "12px", borderRadius: "var(--radius-sm)", color: "var(--text-primary)", outline: "none" }}
              />
              <button onClick={handleSend} disabled={sending} aria-label="Send message" style={{ background: "var(--gold-mid)", color: "#000", border: "none", borderRadius: "var(--radius-sm)", width: "44px", display: "flex", alignItems: "center", justifyContent: "center", cursor: sending ? "not-allowed" : "pointer", opacity: sending ? 0.6 : 1 }}>
                <Send size={18} />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
