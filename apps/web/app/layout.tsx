import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AegisML — AI Model Malware Inspector",
  description:
    "Scan AI model files for backdoors, trojans, and malicious code before they reach production.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-aegis-bg text-aegis-text antialiased">
        {children}
      </body>
    </html>
  );
}
