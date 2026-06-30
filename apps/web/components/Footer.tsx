"use client"
import Link from "next/link"
import { LogoFull } from "./Logo"
import { useState } from "react"
import { PrimaryButton } from "./Buttons"

import { toast } from "sonner"
import { API_BASE_URL } from "@/lib/api"

function Newsletter() {
  const [email, setEmail] = useState("")
  const [status, setStatus] = useState<"idle" | "loading">("idle")

  async function handleSubscribe(e: React.FormEvent) {
    e.preventDefault()
    setStatus("loading")
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/newsletter/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email })
      })
      const data = await res.json()
      if (res.ok) {
        setStatus("idle")
        toast.success(data.message)
        setEmail("")
      } else {
        setStatus("idle")
        toast.error(data.detail || "Subscription failed")
      }
    } catch {
      setStatus("idle")
      toast.error("Network error")
    }
  }

  return (
    <div style={{ marginTop: "24px", maxWidth: "300px" }}>
      <h4 style={{ color: "var(--text-primary)", fontWeight: 600, marginBottom: "8px", fontSize: "0.9rem" }}>Subscribe to Newsletter</h4>
      <form onSubmit={handleSubscribe} style={{ display: "flex", gap: "8px" }}>
        <input 
          type="email" 
          value={email} 
          onChange={e => setEmail(e.target.value)} 
          placeholder="Email address" 
          required
          style={{
            background: "var(--bg-elevated)", border: "1px solid var(--border)", 
            color: "white", padding: "8px 12px", borderRadius: "4px", outline: "none", flex: 1,
            fontSize: "0.9rem"
          }}
        />
        <PrimaryButton type="submit" disabled={status === "loading"} style={{ padding: "8px 16px" }}>
          {status === "loading" ? "..." : "Join"}
        </PrimaryButton>
      </form>
    </div>
  )
}

function FooterColumn({ title, links }: { title: string; links: string[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", alignItems: "flex-start" }}>
      <h4 style={{ color: "var(--text-primary)", fontWeight: 600, marginBottom: "8px" }}>{title}</h4>
      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
        {links.map(link => (
          <Link key={link} href={`/${link.toLowerCase()}`} style={{
            color: "var(--text-secondary)", fontSize: "0.9rem", textDecoration: "none",
            transition: "color 0.2s"
          }} className="hover:text-white">
            {link}
          </Link>
        ))}
      </div>
    </div>
  )
}

export function Footer() {
  return (
    <footer style={{
      borderTop: "1px solid var(--gold-border)",
      background: "var(--bg-surface)",
      padding: "60px clamp(24px, 8vw, 120px) 40px"
    }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "40px", marginBottom: "48px" }}>
        <div style={{ gridColumn: "1 / -1", maxWidth: "350px" }} className="lg:col-span-2">
          <LogoFull />
          <p style={{ marginTop: "16px", color: "var(--text-secondary)", fontSize: "0.9rem", lineHeight: 1.7 }}>
            The world's first multi-AI security scanner for machine learning models.
            Open source, forever.
          </p>
          <Newsletter />
        </div>
        <FooterColumn title="Product" links={["Scan", "Dashboard", "Compare", "Badge"]}/>
        <FooterColumn title="Developers" links={["Docs", "API", "SDK", "Research"]}/>
        <FooterColumn title="Company" links={["About", "Blog", "Security", "Changelog"]}/>
      </div>
      <div style={{ borderTop: "1px solid var(--gold-border)", paddingTop: "24px", display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: "16px" }}>
        <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
          © 2026 AegisML · AGPL-3.0 License
        </span>
        <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
          Trust No Model 🛡️
        </span>
      </div>
    </footer>
  )
}
