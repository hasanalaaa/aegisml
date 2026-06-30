"use client";
import React from "react";
import { motion } from "framer-motion";
import { Bot, Sparkles } from "lucide-react";

interface AnalysisCardProps {
  insight: string;
}

export default function AnalysisCard({ insight }: AnalysisCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="relative rounded-2xl p-6 overflow-hidden mt-8"
      style={{
        background: "rgba(10, 10, 15, 0.6)",
        backdropFilter: "blur(12px)",
        border: "1px solid rgba(201, 168, 76, 0.2)",
      }}
    >
      <div className="absolute top-0 right-0 w-32 h-32 bg-[#C9A84C]/5 rounded-full blur-3xl" />
      <div className="absolute bottom-0 left-0 w-32 h-32 bg-[#E4C46B]/5 rounded-full blur-3xl" />
      
      <div className="relative z-10">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 rounded-lg" style={{ background: "rgba(201,168,76,0.1)", color: "#C9A84C" }}>
            <Bot size={20} />
          </div>
          <div>
            <h3 className="font-bold text-lg" style={{ color: "#F0F0F8" }}>تحليل Claude AI</h3>
            <span className="text-xs font-mono tracking-widest uppercase flex items-center gap-1" style={{ color: "#C9A84C" }}>
              <Sparkles size={10} />
              AI Judge
            </span>
          </div>
        </div>
        
        <div className="prose prose-invert max-w-none text-sm md:text-base leading-relaxed" style={{ color: "#A8A8C4" }}>
          {/* We use a simple paragraph here, but in production this would map markdown */}
          <p className="font-sans whitespace-pre-line">{insight}</p>
        </div>
      </div>
    </motion.div>
  );
}
