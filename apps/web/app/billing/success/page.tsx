"use client"
import { motion } from "framer-motion"
import { fadeUpVariants } from "@/lib/animations"
import { GlassCard } from "@/components/GlassCard"
import { CheckCircle } from "lucide-react"
import Link from "next/link"

export default function BillingSuccessPage() {
  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", color: "var(--text-primary)", display: "flex", alignItems: "center", justifyContent: "center", padding: "24px" }}>
      <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ width: "100%", maxWidth: "500px" }}>
        <GlassCard style={{ padding: "48px", textAlign: "center" }}>
          <CheckCircle size={64} color="var(--safe)" style={{ margin: "0 auto 24px" }} />
          <h1 style={{ fontSize: "2rem", fontWeight: 800, marginBottom: "16px" }}>Upgrade Successful!</h1>
          <p style={{ color: "var(--text-secondary)", marginBottom: "32px", lineHeight: 1.6 }}>
            Thank you for upgrading. Your account has been updated with your new limits.
          </p>
          <Link href="/dashboard" style={{ display: "inline-block", background: "var(--gold-mid)", color: "#000", textDecoration: "none", padding: "12px 24px", borderRadius: "var(--radius-sm)", fontWeight: 600 }}>
            Return to Dashboard
          </Link>
        </GlassCard>
      </motion.div>
    </main>
  )
}
