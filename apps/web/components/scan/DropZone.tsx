"use client";
import React, { useState, useCallback } from "react";
import { motion } from "framer-motion";
import { UploadCloud } from "lucide-react";

interface DropZoneProps {
  onFileDrop: (file: File) => void;
  isScanning?: boolean;
}

export default function DropZone({ onFileDrop, isScanning = false }: DropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        onFileDrop(e.dataTransfer.files[0]);
      }
    },
    [onFileDrop]
  );

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files && e.target.files.length > 0) {
        onFileDrop(e.target.files[0]);
      }
    },
    [onFileDrop]
  );

  return (
    <motion.div
      className="relative w-full rounded-2xl overflow-hidden cursor-pointer"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      animate={{
        scale: isDragging ? 1.02 : 1,
        boxShadow: isDragging
          ? "0 0 40px rgba(201, 168, 76, 0.2)"
          : "0 0 0px rgba(201, 168, 76, 0)",
      }}
      transition={{ duration: 0.3 }}
    >
      <div
        className="absolute inset-0 z-0 pointer-events-none"
        style={{
          background: isDragging
            ? "radial-gradient(circle at center, rgba(201, 168, 76, 0.08) 0%, transparent 70%)"
            : "transparent",
          transition: "background 0.3s ease",
        }}
      />
      <div
        className={`relative z-10 flex flex-col items-center justify-center py-20 px-6 border-2 border-dashed transition-colors duration-300 ${
          isDragging ? "border-[#C9A84C]" : "border-[#262626]"
        }`}
        style={{
          background: "rgba(10, 10, 15, 0.6)",
          backdropFilter: "blur(12px)",
          borderRadius: "inherit",
        }}
      >
        <UploadCloud
          size={48}
          className={`mb-4 transition-colors duration-300 ${
            isDragging ? "text-[#C9A84C]" : "text-[#A8A8C4]"
          }`}
        />
        <h3 className="text-xl font-bold mb-2" style={{ color: "#F0F0F8" }}>
          اسحب وأفلت النموذج هنا
        </h3>
        <p className="text-sm mb-6 text-center max-w-sm" style={{ color: "#A8A8C4" }}>
          يدعم ملفات .pkl, .h5, .pt, .onnx، أو يمكنك إدخال رابط HuggingFace في الأسفل
        </p>

        <label
          className={`px-6 py-2.5 rounded-lg text-sm font-medium transition-all ${
            isScanning ? "opacity-50 cursor-not-allowed" : "cursor-pointer hover:scale-105"
          }`}
          style={{
            background: "linear-gradient(135deg, rgba(201,168,76,0.15), rgba(228,196,107,0.05))",
            border: "1px solid rgba(201,168,76,0.3)",
            color: "#C9A84C",
          }}
        >
          {isScanning ? "جاري الفحص..." : "تصفح الملفات"}
          <input
            type="file"
            className="hidden"
            onChange={handleFileChange}
            disabled={isScanning}
          />
        </label>
      </div>
    </motion.div>
  );
}
