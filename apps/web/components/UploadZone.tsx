"use client"
import { useState, useRef } from "react"
import { motion } from "framer-motion"
import { toast } from "sonner"
import { PrimaryButton } from "./Buttons"
import { AIProviderSelector } from "./AIProviderSelector"
import { ScanProgressBar } from "./ScanProgressBar"
import { useRouter } from "next/navigation"
import { API_BASE_URL } from "@/lib/api"
import { X, FileCode2 } from "lucide-react"

const SUPPORTED_EXTENSIONS = [".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth", ".bin", ".onnx", ".h5", ".keras", ".npz", ".joblib"]

function URLInput({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div style={{ display: "flex", width: "100%", gap: "8px" }}>
      <input
        type="text"
        placeholder="https://huggingface.co/org/model/resolve/main/model.safetensors"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          flex: 1, padding: "12px 16px", borderRadius: "var(--radius-sm)",
          background: "var(--bg-subtle)", border: "1px solid var(--gold-border)",
          color: "var(--text-primary)", fontSize: "0.95rem", outline: "none"
        }}
        onClick={(e) => e.stopPropagation()}
      />
    </div>
  )
}

export function UploadZone() {
  const [dragging, setDragging] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [urlValue, setUrlValue] = useState("")
  const [aiConfig, setAiConfig] = useState<{ provider: string; model: string; key?: string }>({ provider: "anthropic", model: "" })
  const router = useRouter()
  const fileInputRef = useRef<HTMLInputElement>(null)

  function isSupportedFile(name: string): boolean {
    const lower = name.toLowerCase()
    return SUPPORTED_EXTENSIONS.some(ext => lower.endsWith(ext))
  }

  function pickFile(file: File) {
    if (!isSupportedFile(file.name)) {
      toast.error("Unsupported file type", { description: `Supported: ${SUPPORTED_EXTENSIONS.join(", ")}` })
      return
    }
    setSelectedFile(file)
    setUrlValue("")
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files?.[0]
    if (file) pickFile(file)
  }

  const handleZoneClick = () => {
    if (!scanning && !selectedFile) fileInputRef.current?.click()
  }

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) pickFile(file)
  }

  const handleScan = async (e: React.MouseEvent) => {
    e.stopPropagation()
    if (!selectedFile && !urlValue.trim()) {
      toast.error("Add a model first", { description: "Drop a file, click to browse, or paste a HuggingFace URL." })
      return
    }

    setScanning(true)
    try {
      let res: Response
      if (selectedFile) {
        const formData = new FormData()
        formData.append("file", selectedFile)
        if (aiConfig.provider) formData.append("ai_provider", aiConfig.provider)
        if (aiConfig.model) formData.append("ai_model", aiConfig.model)
        if (aiConfig.key) formData.append("api_key", aiConfig.key)

        res = await fetch(`${API_BASE_URL}/api/v1/scan/file`, {
          method: "POST",
          body: formData,
        })
      } else {
        res = await fetch(`${API_BASE_URL}/api/v1/scan/url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            url: urlValue.trim(),
            ai_provider: aiConfig.provider || undefined,
            ai_model: aiConfig.model || undefined,
            api_key: aiConfig.key || undefined,
          }),
        })
      }

      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail || `Server returned ${res.status}`)
      }

      const data = await res.json()
      if (!data.scan_id) throw new Error("Server did not return a scan ID")

      router.push(`/scan/${data.scan_id}`)
    } catch (err: any) {
      setScanning(false)
      toast.error("Scan failed to start", { description: err.message || "Please try again." })
    }
  }

  return (
    <motion.div
      whileHover={{ scale: 1.005 }}
      style={{
        maxWidth: "720px", margin: "0 auto",
        background: "var(--bg-elevated)",
        border: `2px dashed ${dragging ? "var(--gold-mid)" : "var(--gold-border)"}`,
        borderRadius: "var(--radius-xl)",
        padding: "60px 40px",
        textAlign: "center",
        cursor: scanning ? "default" : "pointer",
        position: "relative",
        overflow: "hidden",
        transition: "border-color 0.3s, box-shadow 0.3s",
        boxShadow: dragging ? "var(--shadow-gold, var(--shadow-card))" : "var(--shadow-card)"
      }}
      onDragOver={e => { if (!scanning) { e.preventDefault(); setDragging(true) } }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={handleZoneClick}
    >
      <input
        ref={fileInputRef}
        type="file"
        accept={SUPPORTED_EXTENSIONS.join(",")}
        onChange={handleFileInputChange}
        style={{ display: "none" }}
      />

      {dragging && (
        <motion.div
          initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          style={{
            position: "absolute", inset: 0,
            background: "radial-gradient(ellipse at center, rgba(201,168,76,0.08) 0%, transparent 70%)",
            pointerEvents: "none"
          }}
        />
      )}

      <div style={{ fontSize: "3rem", marginBottom: "16px" }}>
        {scanning ? "🔍" : selectedFile ? "📄" : "🛡️"}
      </div>

      <h3 style={{ marginBottom: "8px", color: "var(--text-primary)" }}>
        {scanning ? "Starting scan..." : selectedFile ? selectedFile.name : "Drop your model file here"}
      </h3>

      {selectedFile && !scanning ? (
        <button
          onClick={(e) => { e.stopPropagation(); setSelectedFile(null) }}
          style={{ display: "inline-flex", alignItems: "center", gap: "6px", marginTop: "4px", background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "4px 10px", color: "var(--text-muted)", fontSize: "0.85rem", cursor: "pointer" }}
        >
          <X size={14} /> Remove · {(selectedFile.size / 1024 / 1024).toFixed(1)} MB
        </button>
      ) : (
        <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem" }}>
          Supports .gguf · .safetensors · .pkl · .pt · .bin · .onnx
          <br/>
          <span style={{ color: "var(--text-muted)" }}>Max 500MB free · 5GB Pro</span>
        </p>
      )}

      {!selectedFile && (
        <>
          <div style={{ margin: "24px 0", display: "flex", alignItems: "center", gap: "12px" }}>
            <div style={{ flex: 1, height: 1, background: "var(--gold-border)" }}/>
            <span style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>or</span>
            <div style={{ flex: 1, height: 1, background: "var(--gold-border)" }}/>
          </div>

          <URLInput value={urlValue} onChange={setUrlValue} />
        </>
      )}

      <div onClick={(e) => e.stopPropagation()}>
        <AIProviderSelector
          style={{ marginTop: "20px" }}
          onSelect={(p, m, k) => setAiConfig({ provider: p, model: m, key: k })}
        />
      </div>

      {!scanning && (
        <PrimaryButton onClick={handleScan} style={{ marginTop: "24px", width: "100%" }}>
          🛡️ Scan Now
        </PrimaryButton>
      )}

      {scanning && <ScanProgressBar />}
    </motion.div>
  )
}
