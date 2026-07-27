import { ImageResponse } from "next/og"
export const runtime = "edge"
export async function GET() {
  return new ImageResponse(
    <div style={{
      width: "100%", height: "100%", display: "flex",
      flexDirection: "column", alignItems: "center", justifyContent: "center",
      background: "#05050C", fontFamily: "sans-serif"
    }}>
      <div style={{ fontSize: 80, color: "#C9A84C", marginBottom: 20 }}>🛡️</div>
      <div style={{ fontSize: 60, fontWeight: 800, color: "#F0F0F8" }}>AegisML</div>
      <div style={{ fontSize: 28, color: "#9494B8", marginTop: 16 }}>Trust No Model</div>
      <div style={{ fontSize: 20, color: "#C9A84C", marginTop: 40, letterSpacing: 4 }}>
        AI MODEL SECURITY SCANNER
      </div>
    </div>,
    { width: 1200, height: 630 }
  )
}
