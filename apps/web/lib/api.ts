/** Centralized browser API origin; local self-hosting is the safe default. */
export const API_BASE_URL: string =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`
}
