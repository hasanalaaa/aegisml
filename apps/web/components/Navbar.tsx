"use client"
import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { LogoFull } from "./Logo"
import { PrimaryButton } from "./Buttons"
import { AuthButton } from "./AuthButton"
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts"
import { KeyboardShortcutsModal } from "./KeyboardShortcutsModal"
import { API_BASE_URL } from "@/lib/api"

function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  const pathname = usePathname()
  const isActive = pathname === href || (pathname?.startsWith(href) && href !== "/")
  
  return (
    <Link href={href} style={{
      color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
      fontWeight: isActive ? 600 : 500,
      fontSize: "0.95rem",
      textDecoration: "none",
      transition: "color 0.2s"
    }}>
      {children}
    </Link>
  )
}

function LiveScanCount() {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: "8px",
      padding: "6px 12px", borderRadius: "var(--radius-sm)",
      background: "var(--bg-subtle)",
      border: "1px solid var(--gold-border)",
      fontSize: "0.8rem", color: "var(--text-secondary)"
    }}>
      <span style={{
        width: 6, height: 6, borderRadius: "50%", background: "var(--safe)",
        animation: "pulse 2s infinite", display: "inline-block"
      }}/>
      <span style={{ color: "var(--text-primary)", fontWeight: 700 }}>24,891</span> Scans
    </div>
  )
}

function UsageIndicator() {
  const [usage, setUsage] = useState<any>(null)

  useEffect(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null
    if (token) {
      fetch(`${API_BASE_URL}/api/v1/billing/usage`, {
        headers: { "Authorization": `Bearer ${token}` }
      }).then(r => r.json()).then(setUsage).catch(console.error)
    }
  }, [])

  if (!usage) return null
  
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: "8px",
      padding: "6px 12px", borderRadius: "var(--radius-sm)",
      background: "var(--bg-subtle)",
      border: "1px solid var(--border)",
      fontSize: "0.8rem", color: "var(--text-secondary)",
      marginLeft: "16px"
    }}>
      <span style={{ color: "var(--gold-mid)", fontWeight: 700 }}>
        {usage.scans_used.toLocaleString()} / {usage.scans_limit === -1 ? "Unlimited" : usage.scans_limit.toLocaleString()}
      </span> scans
    </div>
  )
}

export function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const { isModalOpen, setIsModalOpen } = useKeyboardShortcuts()

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener("scroll", onScroll)
    return () => window.removeEventListener("scroll", onScroll)
  }, [])

  return (
    <>
      <motion.nav
        style={{
          position: "fixed", top: 0, left: 0, right: 0, zIndex: 1000,
          padding: "16px clamp(24px, 8vw, 120px)",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          backdropFilter: scrolled ? "blur(20px) saturate(150%)" : "none",
          background: scrolled ? "rgba(5, 5, 12, 0.85)" : "transparent",
          borderBottom: scrolled ? "1px solid rgba(201, 168, 76, 0.10)" : "none",
          transition: "all 0.4s ease"
        }}
      >
        <Link href="/" style={{ textDecoration: "none" }}>
          <LogoFull />
        </Link>

        <div style={{ display: "flex", gap: "32px", alignItems: "center" }} className="hidden md:flex">
          {["Dashboard", "Threats", "Monitor", "Compare", "Docs", "Pricing"].map(link => (
            <NavLink key={link} href={`/${link.toLowerCase()}`}>{link}</NavLink>
          ))}
        </div>

        <div style={{ display: "flex", gap: "16px", alignItems: "center" }}>
          <div className="hidden sm:block">
            <LiveScanCount />
          </div>
          <div className="hidden sm:block">
            <UsageIndicator />
          </div>
          <button 
            onClick={() => setIsModalOpen(true)}
            style={{ display: "flex", alignItems: "center", justifyContent: "center", width: "32px", height: "32px", borderRadius: "50%", background: "var(--bg-subtle)", border: "1px solid var(--border)", color: "var(--text-secondary)", cursor: "pointer", fontFamily: "var(--font-mono)", fontSize: "0.9rem" }}
            aria-label="Keyboard Shortcuts"
            className="focus-visible:ring-2 focus-visible:ring-gold-mid"
          >
            ?
          </button>
          <AuthButton />
        </div>
      </motion.nav>
      <KeyboardShortcutsModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} />
    </>
  )
}
