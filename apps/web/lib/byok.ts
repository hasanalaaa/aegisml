/**
 * BYOK (Bring Your Own Key) browser storage.
 *
 * Provider keys are encrypted at rest (AES-256-GCM, see byok-crypto.ts) with
 * a non-extractable key held in IndexedDB. When BYOK is explicitly enabled,
 * the decrypted provider key is sent to the configured scan engine in request
 * headers. Server-side handling is outside this browser storage boundary.
 *
 * Storage model: localStorage["aegis_byok_keys"] holds an AES-GCM ciphertext
 * blob of the provider->key JSON. To keep the historically-synchronous public
 * API (getKey / byokHeaders are called in hot paths and cannot be async), the
 * decrypted map is mirrored into an in-memory cache. Call initByok() once on
 * app start to populate that cache; synchronous reads return "" until it
 * resolves.
 */

import { encryptString, decryptString, isCryptoAvailable } from "./byok-crypto"

export type ByokKeys = Record<string, string>

const KEYS_STORAGE = "aegis_byok_keys"
const PROVIDER_STORAGE = "aegis_ai_provider"

// In-memory decrypted cache — source of truth for synchronous reads.
let cache: ByokKeys = {}
let initialized = false

export const BYOK_PROVIDERS: { id: string; label: string; placeholder: string; keyUrl: string }[] = [
  { id: "anthropic", label: "Claude (Anthropic)", placeholder: "sk-ant-...", keyUrl: "https://console.anthropic.com/settings/keys" },
  { id: "openai", label: "GPT (OpenAI)", placeholder: "sk-...", keyUrl: "https://platform.openai.com/api-keys" },
  { id: "google", label: "Gemini (Google)", placeholder: "AIza...", keyUrl: "https://aistudio.google.com/app/apikey" },
  { id: "mistral", label: "Mistral", placeholder: "...", keyUrl: "https://console.mistral.ai/api-keys" },
  { id: "groq", label: "Groq", placeholder: "gsk_...", keyUrl: "https://console.groq.com/keys" },
]

function isBrowser(): boolean {
  return typeof window !== "undefined"
}

async function persist(keys: ByokKeys): Promise<void> {
  if (!isBrowser()) return
  if (!isCryptoAvailable()) throw new Error("Secure browser storage is unavailable")
  const ciphertext = await encryptString(JSON.stringify(keys))
  window.localStorage.setItem(KEYS_STORAGE, ciphertext)
}

/**
 * Decrypt stored keys into the in-memory cache. Idempotent. Legacy plaintext
 * and malformed values are discarded instead of being retained or migrated.
 */
export async function initByok(): Promise<void> {
  if (!isBrowser() || initialized) return
  const raw = window.localStorage.getItem(KEYS_STORAGE)
  if (!raw) {
    initialized = true
    return
  }
  try {
    if (!isCryptoAvailable()) throw new Error("Secure browser storage is unavailable")
    const json = await decryptString(raw)
    if (!json) throw new Error("Stored key data could not be decrypted")
    cache = JSON.parse(json) as ByokKeys
  } catch {
    cache = {}
    window.localStorage.removeItem(KEYS_STORAGE)
  }
  initialized = true
}

export function getKey(provider: string): string {
  return cache[provider] || ""
}

/**
 * Encrypt-and-persist a provider key, resolving only once the ciphertext is
 * written. Await this from the UI before showing a "sealed" confirmation.
 */
export async function sealKey(provider: string, key: string): Promise<void> {
  const trimmed = key.trim()
  const next = { ...cache }
  if (trimmed) next[provider] = trimmed
  else delete next[provider]
  await persist(next)
  cache = next
}

export function getActiveProvider(): string {
  if (!isBrowser()) return "anthropic"
  return window.localStorage.getItem(PROVIDER_STORAGE) || "anthropic"
}

export function setActiveProvider(provider: string): void {
  if (!isBrowser()) return
  window.localStorage.setItem(PROVIDER_STORAGE, provider)
}

/**
 * Build BYOK headers only after an explicit UI opt-in. The active provider's
 * decrypted key is exposed to the configured scan engine for this request.
 */
export function byokHeaders(enabled: boolean): Record<string, string> {
  if (!enabled) return {}
  const provider = getActiveProvider()
  const key = getKey(provider)
  return key ? { "X-AI-Provider": provider, "X-AI-Key": key } : {}
}
