"use client"
import { motion } from "framer-motion"
import { staggerContainer, fadeUpVariants } from "@/lib/animations"
import { PrimaryButton, GhostButton } from "@/components/Buttons"
import dynamic from "next/dynamic"
const HexGridBackground = dynamic(() => import("@/components/HexGridBackground").then(mod => mod.HexGridBackground), { ssr: false })
const SentinelRing = dynamic(() => import("@/components/SentinelRing").then(mod => mod.SentinelRing), { ssr: false })
import { LogoFull } from "@/components/Logo"
import { UploadZone } from "@/components/UploadZone"
import { HowItWorksSection } from "@/components/HowItWorksSection"
import { FeaturesGrid } from "@/components/FeaturesGrid"
import { AIProvidersSection } from "@/components/AIProvidersSection"
import { FinalCTA } from "@/components/FinalCTA"

import { useLiveStats } from "@/hooks/useLiveStats"

function LiveStatsBar() {
  const stats = useLiveStats()
  return (
    <div style={{ display: "flex", gap: "24px", color: "var(--text-secondary)", fontSize: "0.9rem" }}>
      <div><strong style={{ color: "var(--text-primary)" }}>{(stats.totalScans / 1000).toFixed(1)}K+</strong> Scans</div>
      <div><strong style={{ color: "var(--safe)" }}>{stats.activeScans}</strong> Active</div>
      <div><strong style={{ color: "var(--danger)" }}>{stats.threatsFound}</strong> Threats</div>
    </div>
  )
}

function ScrollIndicator() {
  return (
    <div style={{ position: "absolute", bottom: "40px", left: "50%", transform: "translateX(-50%)", textAlign: "center" }}>
      <motion.div 
        animate={{ y: [0, 10, 0] }} 
        transition={{ duration: 2, repeat: Infinity }}
        style={{ color: "var(--text-secondary)", fontSize: "0.8rem", textTransform: "uppercase", letterSpacing: "2px" }}
      >
        Scroll
      </motion.div>
    </div>
  )
}

export default function Home() {
  return (
    <main style={{ background: "var(--bg-void)", minHeight: "100vh", overflow: "hidden", position: "relative" }}>
      {/* === SECTION 1: HERO === */}
      <section style={{ position: "relative", minHeight: "100vh", display: "flex", alignItems: "center" }}>
        {/* Background hex grid */}
        <HexGridBackground />

        {/* Left: Content */}
        <div style={{ position: "relative", zIndex: 10, padding: "0 clamp(24px, 8vw, 120px)", maxWidth: "800px" }}>
          <motion.div variants={staggerContainer} initial="hidden" animate="visible">
            {/* Tag line */}
            <motion.div variants={fadeUpVariants} custom={0}>
              <span style={{
                display: "inline-flex", alignItems: "center", gap: "8px",
                padding: "6px 14px", borderRadius: "999px",
                border: "1px solid var(--gold-border)",
                background: "var(--gold-subtle)",
                fontSize: "0.75rem", fontWeight: 600,
                color: "var(--gold-bright)", letterSpacing: "0.08em", textTransform: "uppercase"
              }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#10B981",
                  animation: "pulse 2s infinite", display: "inline-block" }}/>
                AI Model Security Scanner
              </span>
            </motion.div>

            {/* H1 */}
            <motion.h1 variants={fadeUpVariants} custom={1} style={{ marginTop: "24px", marginBottom: "0", fontSize: "4rem", lineHeight: 1.1 }}>
              Every Model Hides a
              <br/>
              <span style={{ color: "var(--gold-bright)" }}>Secret.</span>
              <br/>
              We Find It.
            </motion.h1>

            {/* Subheading */}
            <motion.p variants={fadeUpVariants} custom={2} style={{
              marginTop: "24px", fontSize: "1.15rem", color: "var(--text-secondary)",
              lineHeight: 1.8, maxWidth: "500px"
            }}>
              Upload any <code>.gguf</code>, <code>.safetensors</code>, or <code>.pkl</code> file.
              AegisML's multi-AI engine scans for hidden threats in seconds.
            </motion.p>

            {/* CTA Buttons */}
            <motion.div variants={fadeUpVariants} custom={3} style={{ display: "flex", gap: "16px", marginTop: "40px", flexWrap: "wrap" }}>
              <PrimaryButton onClick={() => window.location.href="#scan"}>Scan a Model</PrimaryButton>
              <GhostButton onClick={() => window.location.href="/docs"}>API Docs →</GhostButton>
            </motion.div>

            {/* Live Stats Bar */}
            <motion.div variants={fadeUpVariants} custom={4} style={{ marginTop: "48px" }}>
              <LiveStatsBar />
            </motion.div>
          </motion.div>
        </div>

        {/* Right: Sentinel Ring */}
        <div style={{
          position: "absolute", right: "5%", top: "50%", transform: "translateY(-50%)",
          width: "min(500px, 45vw)", height: "min(500px, 45vw)",
          display: "flex", alignItems: "center", justifyContent: "center"
        }} className="hidden lg:flex">
          <SentinelRing size={500} />
          {/* Center Logo */}
          <div style={{ position: "absolute", zIndex: 10 }}>
            <LogoFull />
          </div>
        </div>

        {/* Scroll indicator */}
        <ScrollIndicator />
      </section>

      {/* === SECTION 2: UPLOAD ZONE === */}
      <section id="scan" style={{ padding: "var(--space-24) clamp(24px, 8vw, 120px)", position: "relative", zIndex: 10 }}>
        <UploadZone />
      </section>

      {/* === SECTION 3: HOW IT WORKS === */}
      <section style={{ padding: "var(--space-24) clamp(24px, 8vw, 120px)", position: "relative", zIndex: 10 }}>
        <HowItWorksSection />
      </section>

      {/* === SECTION 4: FEATURES GRID === */}
      <section style={{ padding: "var(--space-24) clamp(24px, 8vw, 120px)", position: "relative", zIndex: 10 }}>
        <FeaturesGrid />
      </section>

      {/* === SECTION 5: AI PROVIDERS === */}
      <section style={{ padding: "var(--space-24) clamp(24px, 8vw, 120px)", position: "relative", zIndex: 10 }}>
        <AIProvidersSection />
      </section>

      {/* === SECTION 6: FINAL CTA === */}
      <section style={{ padding: "var(--space-24) clamp(24px, 8vw, 120px)", textAlign: "center", position: "relative", zIndex: 10 }}>
        <FinalCTA />
      </section>
    </main>
  )
}