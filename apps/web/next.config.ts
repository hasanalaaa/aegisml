import type { NextConfig } from "next"

// Next.js dev (React Fast Refresh / HMR / hydration bootstrap) needs
// 'unsafe-eval' and a localhost websocket. Relax CSP in development only;
// keep it strict in production.
const isDev = process.env.NODE_ENV !== "production"

const DEFAULT_API_ORIGIN = "http://localhost:8000"

function safeOrigin(url: string, fallback: string): string {
  try {
    return new URL(url).origin
  } catch {
    return fallback
  }
}

// Derive the exact API + WebSocket origins the browser is allowed to reach from
// the same env the client uses. This keeps connect-src in lock-step with the
// configured backend host — including the ws(s):// counterpart — so local
// self-hosting works by default and public deployments opt in explicitly.
const apiUrl = process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_ORIGIN
const wsUrl = process.env.NEXT_PUBLIC_WS_URL || apiUrl.replace(/^http/, "ws")
const apiOrigin = safeOrigin(apiUrl, DEFAULT_API_ORIGIN)
const wsOrigin = safeOrigin(wsUrl, DEFAULT_API_ORIGIN.replace(/^http/, "ws"))

const connectSrc = [
  "'self'",
  apiOrigin,
  wsOrigin,
  isDev ? "ws://localhost:* http://localhost:*" : "",
].filter(Boolean).join(" ")

const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  `connect-src ${connectSrc}`,
  "font-src 'self' https://fonts.gstatic.com",
].join("; ")

const nextConfig: NextConfig = {
  // Pin the workspace root to THIS app so Next ignores the stray
  // C:\Users\hasan\package-lock.json (and any other parent lockfile) when
  // inferring the file-tracing root. Silences the multi-lockfile warning.
  outputFileTracingRoot: process.cwd(),
  pageExtensions: ["js", "jsx", "ts", "tsx"],
  images: { formats: ["image/avif", "image/webp"] },
  compress: true,
  poweredByHeader: false,
  async headers() {
    return [{
      source: "/(.*)",
      headers: [
        { key: "X-Frame-Options", value: "DENY" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), browsing-topics=()" },
        { key: "X-DNS-Prefetch-Control", value: "on" },
        { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
        { key: "Content-Security-Policy", value: contentSecurityPolicy }
      ]
    }]
  },
  // Strict production builds: TypeScript type errors AND ESLint errors both
  // fail the build (Vercel included). No silent failures.
  eslint: {
    ignoreDuringBuilds: false,
  },
  typescript: {
    ignoreBuildErrors: false,
  },
}

export default nextConfig
