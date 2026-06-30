"use client";
import React from "react";
import { motion } from "framer-motion";
import { AlertTriangle, ShieldAlert, Shield, Bug } from "lucide-react";

export type SeverityType = "Critical" | "High" | "Medium" | "Low";

interface ThreatCardProps {
  id: string;
  name: string;
  severity: SeverityType;
  cve: string;
  description: string;
  files: string[];
}

const severityConfig: Record<SeverityType, { color: string; bg: string; icon: any }> = {
  Critical: { color: "#E74C3C", bg: "rgba(231, 76, 60, 0.05)", icon: ShieldAlert },
  High: { color: "#E67E22", bg: "rgba(230, 126, 34, 0.05)", icon: AlertTriangle },
  Medium: { color: "#F1C40F", bg: "rgba(241, 196, 15, 0.05)", icon: Bug },
  Low: { color: "#3498DB", bg: "rgba(52, 152, 219, 0.05)", icon: Shield },
};

export default function ThreatCard({ id, name, severity, cve, description, files }: ThreatCardProps) {
  const config = severityConfig[severity];
  const Icon = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ scale: 1.02 }}
      className="rounded-2xl p-6 relative overflow-hidden flex flex-col h-full"
      style={{
        background: "rgba(10, 10, 15, 0.6)",
        backdropFilter: "blur(12px)",
        border: `1px solid ${config.color}30`,
        boxShadow: `0 4px 30px ${config.bg}`,
      }}
    >
      <div className="flex justify-between items-start mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg" style={{ background: config.bg, color: config.color }}>
            <Icon size={24} />
          </div>
          <div>
            <h3 className="text-lg font-bold" style={{ color: "#F0F0F8" }}>{name}</h3>
            <span className="text-xs font-mono tracking-widest uppercase" style={{ color: config.color }}>
              {severity}
            </span>
          </div>
        </div>
        <div className="px-2 py-1 rounded text-xs font-mono" style={{ background: "rgba(255,255,255,0.05)", color: "#A8A8C4" }}>
          {cve}
        </div>
      </div>
      
      <p className="text-sm flex-grow mb-6 leading-relaxed" style={{ color: "#A8A8C4" }}>
        {description}
      </p>

      <div className="mt-auto pt-4 flex flex-wrap gap-2" style={{ borderTop: "1px solid rgba(255,255,255,0.05)" }}>
        {files.map(f => (
          <span key={f} className="text-xs font-mono px-2 py-1 rounded" style={{ background: "rgba(201,168,76,0.1)", color: "#C9A84C" }}>
            .{f}
          </span>
        ))}
      </div>
    </motion.div>
  );
}
