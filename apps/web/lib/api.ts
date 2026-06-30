/**
 * Centralized API base URL resolution.
 *
 * Previously, ~13 files across the frontend hardcoded `http://localhost:8000`
 * directly in fetch() calls. That meant the production build deployed to
 * Vercel could never reach the real Railway backend — every data-driven
 * page (billing usage, profile, monitor feed, research stats, threats
 * search, pricing checkout, docs examples, AI provider list) silently
 * failed in production and fell back to whatever local/empty state the
 * component defaulted to.
 *
 * All API calls should import API_BASE_URL from here instead of inlining
 * a host. NEXT_PUBLIC_WS_URL for WebSocket hooks was already handled
 * correctly via env var fallback in useScanProgress.ts / useLiveStats.ts
 * and did not need this fix.
 */
export const API_BASE_URL: string =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`
}

/**
 * Authenticated fetch helper. The app's convention (established by the
 * billing page) is to store the backend JWT in localStorage under "token"
 * and send it as a Bearer header. Enterprise endpoints require this — they
 * are now protected by real role checks on the backend (previously the
 * backend's require_role() was a no-op that always returned a fake admin).
 */
export async function authFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const token = typeof window !== "undefined" ? window.localStorage.getItem("token") || "" : ""
  const headers = new Headers(init.headers || {})
  if (token) headers.set("Authorization", `Bearer ${token}`)
  return fetch(`${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`, { ...init, headers })
}
