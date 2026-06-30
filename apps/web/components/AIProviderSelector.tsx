"use client"
import { API_BASE_URL } from "@/lib/api"

import { useState, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"

interface AIProvider {
  name: string
  models: string[]
  requires_key: boolean
  description: string
}

const PROVIDER_NAMES: Record<string, string> = {
  "anthropic": "🤖 Claude (Anthropic)",
  "openai": "🤖 GPT-4o (OpenAI)",
  "google": "🤖 Gemini 1.5 Pro (Google)",
  "mistral": "🤖 Mistral Large",
  "groq": "⚡ Groq (Fast)",
  "ollama": "💻 Ollama (Local)"
}

export function AIProviderSelector({ style, onSelect }: { style?: React.CSSProperties, onSelect?: (provider: string, model: string, key?: string) => void }) {
  const [providers, setProviders] = useState<AIProvider[]>([])
  const [selectedProvider, setSelectedProvider] = useState<string>("anthropic")
  const [selectedModel, setSelectedModel] = useState<string>("")
  const [apiKey, setApiKey] = useState<string>("")
  const [showKeyInput, setShowKeyInput] = useState<boolean>(false)

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/v1/ai/providers`)
      .then(r => r.json())
      .then(data => {
        setProviders(data.providers)
        const anthropic = data.providers.find((p: any) => p.name === "anthropic")
        if (anthropic && anthropic.models.length > 0) {
          setSelectedModel(anthropic.models[0])
        }
      })
      .catch(e => console.error("Failed to load providers", e))
  }, [])

  useEffect(() => {
    if (onSelect) {
      onSelect(selectedProvider, selectedModel, apiKey || undefined)
    }
  }, [selectedProvider, selectedModel, apiKey, onSelect])

  const handleProviderChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const prov = e.target.value
    setSelectedProvider(prov)
    const pInfo = providers.find(p => p.name === prov)
    if (pInfo && pInfo.models.length > 0) {
      setSelectedModel(pInfo.models[0])
    }
    if (pInfo && !pInfo.requires_key) {
      setShowKeyInput(false)
      setApiKey("")
    }
  }

  const pInfo = providers.find(p => p.name === selectedProvider)

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", textAlign: "left", ...style }}>
      <label style={{ fontSize: "0.85rem", color: "var(--text-secondary)", fontWeight: 600 }}>AI Analysis Engine</label>
      
      <div style={{ display: "flex", gap: "12px" }}>
        <select 
          value={selectedProvider} 
          onChange={handleProviderChange}
          style={{ flex: 1, padding: "10px", background: "var(--bg-subtle)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)" }}
        >
          {providers.map(p => (
            <option key={p.name} value={p.name}>{PROVIDER_NAMES[p.name] || p.name}</option>
          ))}
        </select>

        {pInfo && pInfo.models.length > 0 && (
          <select 
            value={selectedModel} 
            onChange={(e) => setSelectedModel(e.target.value)}
            style={{ flex: 1, padding: "10px", background: "var(--bg-subtle)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)" }}
          >
            {pInfo.models.map(m => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
        )}
      </div>

      {pInfo?.requires_key && (
        <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "4px" }}>
          <button 
            type="button" 
            onClick={() => setShowKeyInput(!showKeyInput)}
            style={{ background: "none", border: "none", color: "var(--gold-mid)", cursor: "pointer", textAlign: "left", fontSize: "0.85rem", padding: 0 }}
          >
            {showKeyInput ? "Hide API Key field" : "+ Provide custom API Key (optional)"}
          </button>
          
          <AnimatePresence>
            {showKeyInput && (
              <motion.div 
                initial={{ height: 0, opacity: 0 }} 
                animate={{ height: "auto", opacity: 1 }} 
                exit={{ height: 0, opacity: 0 }}
                style={{ overflow: "hidden" }}
              >
                <input 
                  type="password" 
                  placeholder={`Your ${PROVIDER_NAMES[pInfo.name] || pInfo.name} API Key`}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  style={{ width: "100%", padding: "10px", background: "var(--bg-void)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", fontSize: "0.9rem" }}
                />
                <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "4px" }}>
                  Key used once, not stored unless you save it in Settings.
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </div>
  )
}
