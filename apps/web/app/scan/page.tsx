"use client";
import React, { useState } from "react";
import { motion } from "framer-motion";
import { useRouter } from "next/navigation";
import DropZone from "@/components/scan/DropZone";
import RevealText from "@/components/animations/RevealText";
import { Shield, Link as LinkIcon, Loader2 } from "lucide-react";

export default function ScanPage() {
  const router = useRouter();
  const [modelUrl, setModelUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [progressValue, setProgressValue] = useState(0);

  const simulateScan = () => {
    setIsScanning(true);
    setProgressValue(0);
    const interval = setInterval(() => {
      setProgressValue((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          // Navigate to a sample report page after scan
          router.push("/scan/demo-report-123");
          return 100;
        }
        return prev + 5;
      });
    }, 150);
  };

  const handleFileDrop = (file: File) => {
    simulateScan();
  };

  const handleUrlScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!modelUrl) return;
    simulateScan();
  };

  return (
    <div className="min-h-screen pt-32 pb-20 px-6 flex flex-col items-center">
      <div className="max-w-3xl w-full text-center mb-12">
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
          className="inline-flex items-center justify-center p-4 rounded-2xl mb-6"
          style={{
            background: "linear-gradient(135deg, rgba(201, 168, 76, 0.1), rgba(201, 168, 76, 0.02))",
            border: "1px solid rgba(201, 168, 76, 0.2)",
          }}
        >
          <Shield size={32} className="text-[#C9A84C]" />
        </motion.div>
        
        <RevealText className="text-4xl md:text-5xl font-bold mb-4 block" style={{ color: "#F0F0F8" }}>
          محرك فحص النماذج
        </RevealText>
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.5 }}
          className="text-lg max-w-xl mx-auto"
          style={{ color: "#A8A8C4" }}
        >
          قم برفع نموذج الذكاء الاصطناعي الخاص بك أو أدخل رابطه المباشر لتحليله وتفكيكه بحثاً عن الثغرات والأبواب الخلفية.
        </motion.p>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3, duration: 0.6 }}
        className="w-full max-w-2xl"
      >
        <DropZone onFileDrop={handleFileDrop} isScanning={isScanning} />

        <div className="flex items-center gap-4 my-8">
          <div className="flex-1 h-px" style={{ background: "rgba(255,255,255,0.05)" }} />
          <span className="text-xs font-mono uppercase tracking-widest text-[#A8A8C4]">أو عبر الرابط</span>
          <div className="flex-1 h-px" style={{ background: "rgba(255,255,255,0.05)" }} />
        </div>

        <form onSubmit={handleUrlScan} className="relative group">
          <div className="absolute inset-y-0 right-0 pl-3 flex items-center pr-4 pointer-events-none">
            <LinkIcon size={18} className="text-[#A8A8C4] group-focus-within:text-[#C9A84C] transition-colors" />
          </div>
          <input
            type="url"
            value={modelUrl}
            onChange={(e) => setModelUrl(e.target.value)}
            disabled={isScanning}
            placeholder="أدخل رابط HuggingFace (مثل: https://huggingface.co/model)"
            className="w-full bg-[#121214]/60 backdrop-blur-xl border border-white/10 rounded-xl py-4 pr-12 pl-32 text-[#F0F0F8] placeholder-[#A8A8C4]/50 focus:outline-none focus:border-[#C9A84C]/50 transition-all"
            dir="ltr"
          />
          <button
            type="submit"
            disabled={isScanning || !modelUrl}
            className={`absolute inset-y-2 left-2 px-6 rounded-lg text-sm font-medium transition-all ${
              isScanning || !modelUrl ? "opacity-50 cursor-not-allowed" : "hover:scale-105"
            }`}
            style={{
              background: "linear-gradient(90deg, #C9A84C, #E4C46B)",
              color: "#0A0A0F",
            }}
          >
            {isScanning ? <Loader2 size={18} className="animate-spin mx-auto" /> : "ابدأ الفحص"}
          </button>
        </form>

        {/* Cinematic Progress */}
        {isScanning && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            className="mt-8 overflow-hidden"
          >
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm font-mono text-[#C9A84C]">جاري التحليل...</span>
              <span className="text-sm font-mono text-[#F0F0F8]">{progressValue}%</span>
            </div>
            <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
              <motion.div
                className="h-full rounded-full relative"
                style={{ background: "linear-gradient(90deg, #C9A84C, #E4C46B)" }}
                initial={{ width: 0 }}
                animate={{ width: `${progressValue}%` }}
              >
                <div className="absolute inset-0 w-full h-full animate-pulse opacity-50 bg-white" />
              </motion.div>
            </div>
            <p className="text-xs text-center mt-3 font-mono text-[#A8A8C4]">
              {progressValue < 30 && "استخراج طبقات النموذج..."}
              {progressValue >= 30 && progressValue < 60 && "تحليل AST والهيكلة..."}
              {progressValue >= 60 && progressValue < 90 && "فحص الثغرات المحتملة..."}
              {progressValue >= 90 && "توليد تقرير الأمان..."}
            </p>
          </motion.div>
        )}
      </motion.div>
    </div>
  );
}
