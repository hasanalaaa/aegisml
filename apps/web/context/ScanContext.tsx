"use client";

import React, { createContext, useContext, useState } from "react";

export type ScanResult = {
  id: string;
  name: string;
  type: string;
  risk: "None" | "Low" | "High" | "Critical";
  status: "Verified" | "Quarantined" | "Flagged";
  clean: boolean;
  timestamp: number;
};

type ScanContextType = {
  scans: ScanResult[];
  addScan: (scan: ScanResult) => void;
};

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export function ScanProvider({ children }: { children: React.ReactNode }) {
  // Initialize with some dummy realistic data
  const [scans, setScans] = useState<ScanResult[]>([
    { id: "1", name: "llama-3-8b-instruct.safetensors", type: "Safetensors", risk: "None", status: "Verified", clean: true, timestamp: Date.now() - 100000 },
    { id: "2", name: "mistral-7b-v0.3.gguf", type: "GGUF", risk: "None", status: "Verified", clean: true, timestamp: Date.now() - 500000 },
    { id: "3", name: "untrusted-eval-model.pt", type: "PyTorch (Pickle)", risk: "High", status: "Quarantined", clean: false, timestamp: Date.now() - 900000 },
  ]);

  const addScan = (scan: ScanResult) => {
    setScans((prev) => [scan, ...prev]);
  };

  return <ScanContext.Provider value={{ scans, addScan }}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const context = useContext(ScanContext);
  if (!context) throw new Error("useScan must be used within a ScanProvider");
  return context;
}
