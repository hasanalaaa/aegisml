import React from "react";

export type StatusType = "safe" | "danger" | "warning" | "scanning" | "unknown";

interface StatusBadgeProps {
  status: StatusType;
  label?: string;
  className?: string;
}

const statusConfig: Record<StatusType, { color: string; bg: string; border: string; defaultLabel: string }> = {
  safe: { color: "#34A853", bg: "rgba(52, 168, 83, 0.1)", border: "rgba(52, 168, 83, 0.2)", defaultLabel: "Safe" },
  danger: { color: "#EA4335", bg: "rgba(234, 67, 53, 0.1)", border: "rgba(234, 67, 53, 0.2)", defaultLabel: "Danger" },
  warning: { color: "#FBBC05", bg: "rgba(251, 188, 5, 0.1)", border: "rgba(251, 188, 5, 0.2)", defaultLabel: "Warning" },
  scanning: { color: "#C9A84C", bg: "rgba(201, 168, 76, 0.1)", border: "rgba(201, 168, 76, 0.2)", defaultLabel: "Scanning..." },
  unknown: { color: "#A8A8C4", bg: "rgba(168, 168, 196, 0.1)", border: "rgba(168, 168, 196, 0.2)", defaultLabel: "Unknown" },
};

export default function StatusBadge({ status, label, className = "" }: StatusBadgeProps) {
  const config = statusConfig[status];

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono tracking-wider uppercase ${className}`}
      style={{
        background: config.bg,
        border: `1px solid ${config.border}`,
        color: config.color,
      }}
    >
      {status === "scanning" && (
        <span className="relative flex h-2 w-2 mr-1">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ backgroundColor: config.color }}></span>
          <span className="relative inline-flex rounded-full h-2 w-2" style={{ backgroundColor: config.color }}></span>
        </span>
      )}
      {label || config.defaultLabel}
    </span>
  );
}
