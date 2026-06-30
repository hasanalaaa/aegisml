"use client"
import { useSession } from "next-auth/react"
import { useState, useEffect } from "react"
import { GlassCard } from "@/components/GlassCard"
import Image from "next/image"
import { PrimaryButton } from "@/components/Buttons"
import { motion } from "framer-motion"
import { fadeUpVariants } from "@/lib/animations"
import { signOut } from "next-auth/react"
import { toast } from "sonner"
import { API_BASE_URL } from "@/lib/api"

function ReferralSection() {
  const [data, setData] = useState<{code: string | null, referred_count: number} | null>(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/v1/referral/stats`).then(res => res.json()).then(setData).catch(console.error)
  }, [])

  async function handleGenerate() {
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/referral/create`, { method: "POST" })
      const created = await res.json()
      setData({ code: created.code, referred_count: 0 })
    } catch {}
    setLoading(false)
  }

  function handleCopy() {
    if (!data?.code) return
    navigator.clipboard.writeText(`https://aegisml.vercel.app?ref=${data.code}`)
    setCopied(true)
    toast.success("Referral link copied to clipboard")
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <GlassCard>
      <h3 style={{ margin: "0 0 16px 0", fontSize: "1.2rem", color: "var(--gold-bright)" }}>Refer a Friend</h3>
      <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", marginBottom: "16px" }}>
        Invite your network to AegisML.
      </p>
      
      {data?.code ? (
        <div>
          <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "12px" }}>
            <input 
              type="text" 
              readOnly 
              value={`https://aegisml.vercel.app?ref=${data.code}`} 
              style={{ flex: 1, background: "rgba(0,0,0,0.5)", border: "1px solid var(--gold-border)", color: "var(--text-primary)", padding: "12px", borderRadius: "8px", fontFamily: "var(--font-mono)", fontSize: "0.9rem" }}
            />
            <PrimaryButton onClick={handleCopy}>{copied ? "Copied!" : "Copy Link"}</PrimaryButton>
          </div>
          <p style={{ margin: 0, fontSize: "0.9rem", color: "var(--text-secondary)" }}>
            Friends Referred: <strong style={{ color: "var(--primary)" }}>{data.referred_count}</strong>
          </p>
        </div>
      ) : (
        <PrimaryButton onClick={handleGenerate} disabled={loading}>
          {loading ? "Generating..." : "Generate Referral Link"}
        </PrimaryButton>
      )}
    </GlassCard>
  )
}

export default function ProfilePage() {
  const { data: session, status } = useSession()

  if (status === "loading") {
    return <main style={{ minHeight: "100vh", background: "var(--bg-void)", paddingTop: "120px", textAlign: "center" }}>Loading...</main>
  }

  if (!session) {
    return (
      <main style={{ minHeight: "100vh", background: "var(--bg-void)", paddingTop: "120px", textAlign: "center" }}>
        <h1 style={{ color: "var(--text-primary)" }}>Access Denied</h1>
        <p style={{ color: "var(--text-secondary)" }}>Please log in to view your profile.</p>
      </main>
    )
  }

  return (
    <main style={{ background: "var(--bg-void)", minHeight: "100vh", paddingTop: "120px", paddingBottom: "80px", color: "var(--text-primary)" }}>
      <div style={{ maxWidth: "800px", margin: "0 auto", padding: "0 24px" }}>
        
        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "48px" }}>
          <h1 style={{ fontSize: "2.5rem", margin: 0 }}>My Profile</h1>
          <p style={{ color: "var(--text-secondary)", marginTop: "8px" }}>Manage your API keys and plan.</p>
        </motion.div>

        <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ display: "grid", gap: "24px" }}>
          
          <GlassCard>
            <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
              {session.user?.image && <Image src={session.user.image} alt="Avatar" width={64} height={64} style={{ borderRadius: "50%" }} />}
              <div>
                <h2 style={{ margin: 0, fontSize: "1.5rem" }}>{session.user?.name}</h2>
                <p style={{ color: "var(--text-secondary)", margin: 0 }}>{session.user?.email}</p>
                <div style={{ marginTop: "8px", display: "inline-block", background: "rgba(201,168,76,0.1)", color: "var(--gold-bright)", padding: "4px 12px", borderRadius: "99px", fontSize: "0.8rem", fontWeight: 700, textTransform: "uppercase" }}>
                  Free Plan
                </div>
              </div>
            </div>
          </GlassCard>

          <GlassCard>
            <h3 style={{ margin: "0 0 16px 0", fontSize: "1.2rem", color: "var(--gold-bright)" }}>API Key</h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", marginBottom: "16px" }}>
              Use this key to authenticate with the AegisML API and CLI. Do not share it.
            </p>
            <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
              <input 
                type="text" 
                readOnly 
                value="sk_aegis_••••••••••••••••••••" 
                style={{ flex: 1, background: "rgba(0,0,0,0.5)", border: "1px solid var(--gold-border)", color: "var(--text-primary)", padding: "12px", borderRadius: "8px", fontFamily: "var(--font-mono)" }}
              />
              <PrimaryButton onClick={() => toast.success("New API key generated successfully")}>Regenerate</PrimaryButton>
            </div>
          </GlassCard>

          <ReferralSection />

          <GlassCard>
            <h3 style={{ margin: "0 0 16px 0", fontSize: "1.2rem", color: "var(--gold-bright)" }}>Scan History</h3>
            <div style={{ textAlign: "center", padding: "32px 0", background: "rgba(255,255,255,0.02)", borderRadius: "var(--radius-lg)", border: "1px solid var(--border)" }}>
              <div style={{ fontSize: "2.5rem", marginBottom: "16px", opacity: 0.5 }}>📊</div>
              <h4 style={{ margin: "0 0 8px 0", fontSize: "1.1rem", color: "var(--text-primary)" }}>No scans yet</h4>
              <p style={{ color: "var(--text-secondary)", marginBottom: "16px", fontSize: "0.95rem" }}>You have completed 0 scans this month.</p>
              <a href="/scan" style={{ textDecoration: "none" }}>
                <PrimaryButton style={{ fontSize: "0.85rem", padding: "8px 16px" }}>Run a Scan</PrimaryButton>
              </a>
            </div>
          </GlassCard>

          <div style={{ textAlign: "right" }}>
            <button onClick={() => signOut()} style={{ background: "transparent", color: "var(--danger)", border: "none", cursor: "pointer", fontWeight: 600 }}>Log Out</button>
          </div>

        </motion.div>
      </div>
    </main>
  )
}
