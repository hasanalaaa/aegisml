import { Sora, Inter, Fira_Code } from "next/font/google"
import { Navbar } from "@/components/Navbar"
import { Footer } from "@/components/Footer"
import "./globals.css"
import type { Metadata, Viewport } from "next"

const sora = Sora({ subsets: ["latin"], variable: "--font-sora", weight: ["300","400","600","700","800"] })
const inter = Inter({ subsets: ["latin"], variable: "--font-inter" })
const firaCode = Fira_Code({ subsets: ["latin"], variable: "--font-mono", weight: ["400","500"] })

export const viewport: Viewport = {
  themeColor: "#C9A84C",
}

export const metadata = {
  title: { default: "AegisML — AI Model Security Scanner", template: "%s | AegisML" },
  description: "Scan .gguf, .safetensors, .pkl files for hidden backdoors, trojans, and malicious code. Powered by Claude AI. 250+ threat patterns.",
  keywords: ["AI security", "model scanning", "HuggingFace security", "gguf scanner", "safetensors security", "machine learning security", "AI model scanner"],
  authors: [{ name: "hasanalaaa", url: "https://github.com/hasanalaaa" }],
  creator: "hasanalaaa",
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://aegisml.vercel.app",
    siteName: "AegisML",
    title: "AegisML — Trust No Model",
    description: "The world's most advanced open-source AI model security scanner. Powered by Claude AI.",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "AegisML Security Scanner" }]
  },
  twitter: {
    card: "summary_large_image",
    title: "AegisML — AI Model Security Scanner",
    description: "Scan AI models for hidden threats. Free & open source.",
    images: ["/og-image.png"]
  },
  robots: { index: true, follow: true },
  manifest: "/manifest.json",
  themeColor: "#C9A84C",
  viewport: "width=device-width, initial-scale=1, maximum-scale=5"
}

import { Providers } from "@/components/Providers"
import { Toaster } from "sonner"

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sora.variable} ${inter.variable} ${firaCode.variable}`}>
      <head>
        <link rel="prefetch" href="/scan" />
        <link rel="prefetch" href="/dashboard" />
        <link rel="prefetch" href="/threats" />
      </head>
      <body>
        <Providers>
          <Navbar />
          <main style={{ paddingTop: "72px" }}>{children}</main>
          <Footer />
          <Toaster theme="dark" toastOptions={{ style: { background: "var(--bg-elevated)", border: "1px solid var(--gold-border)", color: "var(--text-primary)" } }} />
        </Providers>
      </body>
    </html>
  )
}