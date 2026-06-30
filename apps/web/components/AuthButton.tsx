"use client"
import { signIn, signOut, useSession } from "next-auth/react"
import { PrimaryButton } from "./Buttons"
import { LogOut, User as UserIcon } from "lucide-react"
import Image from "next/image"

export function AuthButton() {
  const { data: session } = useSession()

  if (session && session.user) {
    return (
      <div style={{ position: "relative", display: "inline-block", marginLeft: "16px" }}>
        <button 
          onClick={() => window.location.href = "/profile"}
          style={{ 
            display: "flex", alignItems: "center", gap: "8px", 
            background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)",
            padding: "6px 12px", borderRadius: "99px", cursor: "pointer", color: "var(--text-primary)"
          }}
        >
          {session.user.image ? (
            <Image src={session.user.image} alt="Avatar" width={24} height={24} style={{ borderRadius: "50%" }} />
          ) : (
            <UserIcon size={16} />
          )}
          <span style={{ fontSize: "0.9rem", fontWeight: 500 }}>{session.user.name?.split(" ")[0]}</span>
        </button>
      </div>
    )
  }

  return (
    <div style={{ marginLeft: "16px", display: "flex", gap: "12px" }}>
      <button 
        onClick={() => signIn("github")}
        style={{
          background: "transparent", color: "var(--text-secondary)", border: "none", cursor: "pointer",
          fontSize: "0.95rem", fontWeight: 500, padding: "8px"
        }}
      >
        Log In
      </button>
      <PrimaryButton onClick={() => signIn("github")} style={{ padding: "8px 16px" }}>
        Sign Up
      </PrimaryButton>
    </div>
  )
}
