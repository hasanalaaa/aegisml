import { Cormorant_Garamond, Manrope, JetBrains_Mono, Cairo } from "next/font/google"
import "./globals.css"
import type { Viewport } from "next"

const cormorant = Cormorant_Garamond({
  subsets: ["latin"],
  variable: "--font-cormorant",
  weight: ["400", "500", "600", "700"],
  display: "swap",
})
const manrope = Manrope({
  subsets: ["latin"],
  variable: "--font-manrope",
  weight: ["300", "400", "500", "600", "700"],
  display: "swap",
})
const jetbrains = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  weight: ["400", "500", "600"],
  display: "swap",
})
const cairo = Cairo({
  subsets: ["arabic", "latin"],
  variable: "--font-cairo",
  weight: ["400", "500", "600", "700"],
  display: "swap",
})

export const viewport: Viewport = {
  themeColor: "#000000",
}

export const metadata = {
  metadataBase: new URL("https://aegisml.vercel.app"),
  title: { default: "AegisML — AI Model Security Scanner", template: "%s | AegisML" },
  description: "Statically inspect supported AI model files for suspicious bytes, unsafe serialization, and structural anomalies. Open source with a self-hosted scan engine.",
  keywords: ["AI security", "model scanning", "HuggingFace security", "gguf scanner", "safetensors security", "machine learning security", "AI model scanner"],
  authors: [{ name: "hasanalaaa", url: "https://github.com/hasanalaaa" }],
  creator: "hasanalaaa",
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://aegisml.vercel.app",
    siteName: "AegisML",
    title: "AegisML — Trust No Model",
    description: "Open-source static analysis for supported AI model files, with a scan engine you can self-host.",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "AegisML Security Scanner" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "AegisML — AI Model Security Scanner",
    description: "Statically inspect supported AI model files with an open-source, self-hostable scan engine.",
    images: ["/og-image.png"],
  },
  robots: { index: true, follow: true },
  manifest: "/manifest.json",
}

import { Toaster } from "sonner"

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${cormorant.variable} ${manrope.variable} ${jetbrains.variable} ${cairo.variable}`}>
      <body>
        {children}
        <Toaster theme="dark" toastOptions={{ style: { background: "#141416", border: "1px solid rgba(216,178,94,0.28)", color: "#EDEAE3" } }} />
      </body>
    </html>
  )
}
