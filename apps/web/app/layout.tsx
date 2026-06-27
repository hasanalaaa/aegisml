import type { Metadata } from "next";
import { Cairo } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/Navbar";

const cairo = Cairo({
  subsets: ["latin", "arabic"],
  weight: ["400", "500", "600", "700", "800", "900"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "AegisML — Advanced AI Model Security & Threat Intelligence Platform",
  description: "Detect backdoors, trojans & malicious code in AI models before they reach production. Open-source scanner for .gguf, .safetensors, .pkl files.",
  keywords: ["AI security", "model scanning", "malware detection", "GGUF", "safetensors", "pickle", "LLM security", "open source", "Threat Intelligence"],
  authors: [{ name: "AegisML", url: "https://aegisml.vercel.app" }],
  openGraph: {
    title: "AegisML — Advanced AI Model Security & Threat Intelligence Platform",
    description: "Detect backdoors, trojans & malicious code in AI models before running them in production.",
    url: "https://aegisml.vercel.app",
    siteName: "AegisML",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "AegisML — Advanced AI Model Security & Threat Intelligence Platform",
    description: "Open-source security scanner for AI models. Detect backdoors before running in production.",
  },
  robots: { index: true, follow: true },
};

import SessionProviderWrapper from "@/components/SessionProviderWrapper";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ar">
      <body className={cairo.className} style={{ margin: 0, background: "#0B0B0C" }}>
        <SessionProviderWrapper>
          <Navbar />
          {children}
        </SessionProviderWrapper>
      </body>
    </html>
  );
}
