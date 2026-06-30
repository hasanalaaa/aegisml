import React from "react"
import { Star, User } from "lucide-react"

export interface ReviewProps {
  model_url: string
  rating: number
  comment: string
  created_at: string
  username?: string
}

export function ReviewCard({ model_url, rating, comment, created_at, username = "Anonymous" }: ReviewProps) {
  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: "20px", display: "flex", flexDirection: "column", gap: "12px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ width: "40px", height: "40px", borderRadius: "50%", background: "var(--bg-subtle)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <User size={20} color="var(--text-muted)" />
          </div>
          <div>
            <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>{username}</div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{new Date(created_at).toLocaleDateString()}</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: "2px" }}>
          {[1, 2, 3, 4, 5].map((star) => (
            <Star key={star} size={16} fill={star <= rating ? "var(--gold-mid)" : "transparent"} color={star <= rating ? "var(--gold-mid)" : "var(--border)"} />
          ))}
        </div>
      </div>
      <div style={{ fontSize: "0.85rem", color: "var(--gold-bright)", fontFamily: "var(--font-mono)" }}>{model_url}</div>
      <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", lineHeight: 1.5 }}>"{comment}"</p>
    </div>
  )
}
