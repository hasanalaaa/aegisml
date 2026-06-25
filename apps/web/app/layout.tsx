import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "AegisML — Scan AI Models for Malware",
  description: "Detect backdoors, trojans & malicious code in AI models before they reach production. Open-source security scanner for .gguf, .safetensors, .pkl files.",
  keywords: ["AI security", "model scanning", "malware detection", "GGUF", "safetensors", "pickle", "backdoor"],
  authors: [{ name: "AegisML", url: "https://aegisml.vercel.app" }],
  openGraph: {
    title: "AegisML — Scan AI Models for Malware",
    description: "Detect backdoors, trojans & malicious code in AI models before they reach production.",
    url: "https://aegisml.vercel.app",
    siteName: "AegisML",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "AegisML — Scan AI Models for Malware",
    description: "Open-source security scanner for AI models.",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ar" dir="rtl">
      <body className={inter.className} style={{ margin: 0, background: "#0A0A0F" }}>
        {children}
      </body>
    </html>
  );
}
