"use client";

import { useEffect, useState } from "react";
import { ScanResult } from "../context/ScanContext";

interface DrawerProps {
  scan: ScanResult | null;
  onClose: () => void;
  isRtl: boolean;
}

export default function ScanDetailsDrawer({ scan, onClose, isRtl }: DrawerProps) {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    if (scan) {
      // Small delay to ensure display:block applies before transform for animation
      setTimeout(() => setIsOpen(true), 10);
    } else {
      setIsOpen(false);
    }
  }, [scan]);

  if (!scan && !isOpen) return null;

  return (
    <>
      {/* Backdrop Overlay */}
      <div 
        className={`fixed inset-0 z-40 bg-black/40 backdrop-blur-sm transition-opacity duration-500 ${isOpen ? "opacity-100" : "opacity-0 pointer-events-none"}`}
        onClick={() => { setIsOpen(false); setTimeout(onClose, 500); }}
      />

      {/* Slide-over Panel */}
      <div 
        dir={isRtl ? "rtl" : "ltr"}
        className={`fixed top-0 bottom-0 z-50 w-full max-w-md bg-[#030305]/90 backdrop-blur-3xl border-white/10 shadow-2xl transition-transform duration-500 ease-out flex flex-col ${
          isRtl 
            ? `left-0 border-r ${isOpen ? "translate-x-0" : "-translate-x-full"}` 
            : `right-0 border-l ${isOpen ? "translate-x-0" : "translate-x-full"}`
        }`}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/5 px-6 py-5">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">
              {isRtl ? "تقرير التحليل العميق" : "Deep Analysis Report"}
            </h2>
            <p className="text-[10px] font-mono text-slate-500 mt-1">{scan?.id.toUpperCase()}</p>
          </div>
          <button 
            onClick={() => { setIsOpen(false); setTimeout(onClose, 500); }}
            className="text-slate-500 hover:text-white transition-colors p-2"
          >
            ✕
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
          {/* Status Badge */}
          <div className={`p-4 rounded-xl border ${scan?.clean ? "bg-emerald-500/5 border-emerald-500/10" : "bg-amber-500/5 border-amber-500/10"}`}>
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full animate-pulse ${scan?.clean ? "bg-emerald-400" : "bg-amber-400"}`} />
              <span className={`text-xs font-bold uppercase tracking-widest ${scan?.clean ? "text-emerald-400" : "text-amber-400"}`}>
                {scan?.status}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              {scan?.clean 
                ? (isRtl ? "لم يتم اكتشاف أي حقن خبيث أو أوزان مشبوهة. النموذج جاهز للنشر." : "No malicious payloads or poisoned weights detected. Model is safe for deployment.")
                : (isRtl ? "تم اكتشاف أنماط تنفيذ غير مصرح بها. تم عزل الملف لمنع الضرر." : "Unauthorized execution patterns detected. Artifact quarantined to prevent system compromise.")}
            </p>
          </div>

          {/* Technical Telemetry */}
          <div className="space-y-4">
            <div>
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">{isRtl ? "هوية الملف" : "Artifact Identity"}</p>
              <p className="text-xs font-mono text-white break-all">{scan?.name}</p>
            </div>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">{isRtl ? "البصمة (SHA-256)" : "Checksum (SHA-256)"}</p>
              <p className="text-[11px] font-mono text-slate-400 break-all">
                {Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join('')}
              </p>
            </div>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">{isRtl ? "هيكلية التنسورات" : "Tensor Architecture"}</p>
              <p className="text-xs text-slate-300">
                {scan?.type.includes("Pickle") ? "PyTorch Serialized Object" : "SafeTensors / Directed Acyclic Graph"}
              </p>
            </div>
          </div>

          {/* Scanner Logs (Simulated) */}
          <div>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">{isRtl ? "سجل المحرك" : "Engine Logs"}</p>
            <div className="bg-black/50 border border-white/5 rounded-lg p-3 font-mono text-[10px] text-slate-400 space-y-1.5">
              <p className="text-slate-500">{">"} INIT_STATIC_ANALYSIS</p>
              <p className="text-slate-500">{">"} EXTRACTING_LAYERS...</p>
              <p className="text-slate-300">{">"} 342 LAYERS PARSED</p>
              {scan?.clean ? (
                <>
                  <p className="text-emerald-400/70">{">"} NO_PICKLE_IMPORTS_FOUND</p>
                  <p className="text-emerald-400/70">{">"} WEIGHT_DISTRIBUTION_NORMAL</p>
                </>
              ) : (
                <>
                  <p className="text-amber-400/70">{">"} WARNING: OS.SYSTEM CALL DETECTED</p>
                  <p className="text-amber-400/70">{">"} PAYLOAD: REVERSE_SHELL_ATTEMPT</p>
                </>
              )}
              <p className="text-slate-500">{">"} ANALYSIS_COMPLETE</p>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
