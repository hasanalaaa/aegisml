"use client"
import { LogoFull } from "@/components/Logo"
import { PrimaryButton } from "@/components/Buttons"
import { useEffect } from "react"

export default function Error({ error, reset }: { error: Error & { digest?: string }, reset: () => void }) {
  useEffect(() => {
    console.error(error)
  }, [error])

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
      <h1 style={{ fontSize: "3rem", margin: "2rem 0 1rem" }}>Something went wrong</h1>
      <p style={{ color: "var(--text-secondary)", marginBottom: "2rem", fontSize: "1.2rem" }}>
        An unexpected error occurred in the engine.
      </p>
      <PrimaryButton onClick={() => reset()}>Retry</PrimaryButton>
    </div>
  )
}
