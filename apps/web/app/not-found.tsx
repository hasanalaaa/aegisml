import Link from "next/link"
import { LogoFull } from "@/components/Logo"
import { GhostButton } from "@/components/Buttons"

export default function NotFound() {
  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      background: "var(--bg-void)",
      color: "var(--text-primary)",
      textAlign: "center"
    }}>
      <LogoFull />
      <h1 style={{ fontSize: "3rem", margin: "2rem 0 1rem" }}>404 — Model Not Found</h1>
      <p style={{ color: "var(--text-secondary)", marginBottom: "2rem", fontSize: "1.2rem" }}>
        The page or model you are looking for does not exist or has been intercepted.
      </p>
      <GhostButton href="/">Return Home</GhostButton>
    </div>
  )
}
