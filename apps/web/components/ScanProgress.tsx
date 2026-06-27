"use client";

import { useEffect } from "react";
import { useScanProgress } from "../hooks/useScanProgress";

export default function ScanProgress({ scanId, onComplete }: { scanId: string, onComplete?: () => void }) {
  const { data, error } = useScanProgress(scanId);

  useEffect(() => {
    if (data?.stage === "complete" && onComplete) {
      // Small delay to ensure DB commit
      const t = setTimeout(onComplete, 1000);
      return () => clearTimeout(t);
    }
  }, [data?.stage, onComplete]);

  if (!data && !error) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "400px", gap: 16 }}>
        <div style={{ width: 40, height: 40, borderRadius: "50%", border: "3px solid #1E1E2E", borderTopColor: "#C9A84C", animation: "spin 1s linear infinite" }}></div>
        <p style={{ color: "#A8A8C4", margin: 0, fontWeight: 600 }}>Connecting to Real-Time Engine...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: 24, background: "rgba(231,76,60,0.1)", border: "1px solid rgba(231,76,60,0.2)", borderRadius: 12, textAlign: "center", maxWidth: 600, margin: "0 auto" }}>
        <p style={{ color: "#E74C3C", fontWeight: 700 }}>{error}</p>
      </div>
    );
  }

  if (!data) return null;

  const STAGES = [
    { id: "downloading", label: "Download" },
    { id: "header_check", label: "Header Check" },
    { id: "signature_scan", label: "Signature Scan" },
    { id: "ai_analysis", label: "AI Analysis" },
    { id: "complete", label: "Complete" },
  ];

  // If upload, ignore downloading stage
  const currentStages = data.stage !== "downloading" && data.progress >= 10 && STAGES[0].id === "downloading" ? STAGES.slice(1) : STAGES;

  const currentStageIndex = currentStages.findIndex(s => s.id === data.stage);
  
  return (
    <div style={{ background: "#12121E", border: "1px solid #1E1E2E", borderRadius: 16, padding: "32px", maxWidth: 600, margin: "40px auto", color: "#F0F0F8" }}>
      <h3 style={{ margin: "0 0 8px", fontSize: 20, color: "#C9A84C", fontWeight: 800 }}>Scanning in Progress...</h3>
      <p style={{ margin: "0 0 32px", color: "#8888AA", fontSize: 14 }}>{data.message || "Initializing..."}</p>

      {/* Progress Bar Container */}
      <div style={{ position: "relative", height: 8, background: "#1A1A2E", borderRadius: 99, marginBottom: 32, overflow: "hidden" }}>
        <div style={{ 
          position: "absolute", left: 0, top: 0, bottom: 0, 
          width: `${data.progress}%`, 
          background: "linear-gradient(90deg, #C9A84C, #E4C46B)",
          transition: "width 0.5s ease-out",
          boxShadow: "0 0 10px rgba(201,168,76,0.5)"
        }} />
      </div>

      {/* Stages Grid */}
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 32 }}>
        {currentStages.map((stage, idx) => {
          const isActive = idx === currentStageIndex;
          const isDone = idx < currentStageIndex || data.stage === "complete";
          
          let color = "#333355";
          if (isActive) color = "#C9A84C";
          if (isDone) color = "#2ECC71";
          if (data.stage === "error") color = "#E74C3C";
          
          return (
            <div key={stage.id} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, opacity: isDone || isActive ? 1 : 0.4 }}>
              <div style={{ 
                width: 24, height: 24, borderRadius: "50%", 
                background: isActive ? "rgba(201,168,76,0.2)" : (isDone ? "rgba(46,204,113,0.2)" : "#1A1A2E"),
                border: `2px solid ${color}`,
                display: "flex", alignItems: "center", justifyContent: "center",
                transition: "all 0.3s"
              }}>
                {isDone && !isActive && <span style={{ color: "#2ECC71", fontSize: 12 }}>✓</span>}
                {isActive && <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#C9A84C", animation: "pulse 1.5s infinite" }} />}
              </div>
              <span style={{ fontSize: 11, fontWeight: 600, color, textAlign: "center" }}>{stage.label}</span>
            </div>
          );
        })}
      </div>

      {/* Threat Counter */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", background: "#0A0A0F", padding: "16px 24px", borderRadius: 12, border: "1px solid #1A1A2E" }}>
        <span style={{ color: "#8888AA", fontSize: 13, fontWeight: 600 }}>Threats Discovered</span>
        <span style={{ 
          color: data.threat_count > 0 ? "#E74C3C" : "#2ECC71", 
          fontSize: 24, fontWeight: 900, fontFamily: "monospace",
          transition: "color 0.3s"
        }}>
          {data.threat_count}
        </span>
      </div>

      <style>{`
        @keyframes pulse {
          0% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.5); opacity: 0.5; }
          100% { transform: scale(1); opacity: 1; }
        }
      `}</style>
    </div>
  );
}
