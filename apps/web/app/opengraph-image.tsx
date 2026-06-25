import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "AegisML — Scan AI Models for Malware";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          background: "#0A0A0F",
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          fontFamily: "sans-serif",
          position: "relative",
        }}
      >
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, bottom: 0,
          background: "radial-gradient(ellipse 900px 450px at 50% 0%, rgba(201,168,76,0.10), transparent)",
        }} />

        <div style={{ color: "#C9A84C", fontSize: 28, fontWeight: 900, marginBottom: 48, letterSpacing: 3, display: "flex" }}>
          ◆ AegisML
        </div>

        <div style={{ color: "#F0F0F8", fontSize: 68, fontWeight: 900, textAlign: "center", lineHeight: 1.1, marginBottom: 20, display: "flex" }}>
          Scan AI Models
        </div>
        <div style={{ color: "#C9A84C", fontSize: 68, fontWeight: 900, textAlign: "center", marginBottom: 36, display: "flex" }}>
          Before They Harm You
        </div>

        <div style={{ color: "#A8A8C4", fontSize: 22, textAlign: "center", maxWidth: 720, lineHeight: 1.5, marginBottom: 52, display: "flex" }}>
          Detect backdoors, trojans & malicious code in AI models
        </div>

        <div style={{ display: "flex", gap: 14, flexWrap: "wrap", justifyContent: "center" }}>
          {["GGUF", "SafeTensors", "Pickle", "PyTorch", "Claude AI", "AGPL-3.0"].map((badge) => (
            <div key={badge} style={{
              background: "rgba(201,168,76,0.12)",
              border: "1px solid rgba(201,168,76,0.35)",
              color: "#C9A84C",
              padding: "8px 20px",
              borderRadius: 8,
              fontSize: 16,
              fontWeight: 700,
              display: "flex",
            }}>
              {badge}
            </div>
          ))}
        </div>

        <div style={{ position: "absolute", bottom: 36, color: "#333355", fontSize: 15, display: "flex" }}>
          aegisml.vercel.app
        </div>
      </div>
    ),
    { ...size }
  );
}
