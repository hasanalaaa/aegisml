/**
 * Client-side AES-256-GCM sealing for BYOK provider keys.
 *
 * THREAT MODEL — read this before trusting the word "sealed":
 * The AES key is a NON-EXTRACTABLE CryptoKey generated in the browser and
 * kept in IndexedDB. Ciphertext lives in localStorage. This protects against:
 *   - casual inspection of localStorage (keys are not readable as plaintext),
 *   - exfiltration of the raw AES key material (it is non-extractable).
 * It does NOT protect against code already running on this origin (including
 * XSS) or a user with full local access — such code can still call decrypt().
 * When BYOK is enabled, the decrypted key is sent to the configured scan
 * engine. This layer protects local storage only; it is not an end-to-end
 * secrecy boundary.
 */

const DB_NAME = "aegis-secure"
const STORE = "keys"
const MASTER_ID = "byok-master"

export function isCryptoAvailable(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.crypto !== "undefined" &&
    typeof window.crypto.subtle !== "undefined" &&
    typeof window.indexedDB !== "undefined"
  )
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = window.indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE)
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function idbGet(db: IDBDatabase, key: string): Promise<CryptoKey | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly")
    const req = tx.objectStore(STORE).get(key)
    req.onsuccess = () => resolve(req.result as CryptoKey | undefined)
    req.onerror = () => reject(req.error)
  })
}

function idbSet(db: IDBDatabase, key: string, value: CryptoKey): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite")
    tx.objectStore(STORE).put(value, key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

async function getMasterKey(): Promise<CryptoKey> {
  const db = await openDb()
  const existing = await idbGet(db, MASTER_ID)
  if (existing) return existing
  // non-extractable: the raw bytes can never leave the browser's key store
  const key = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
  await idbSet(db, MASTER_ID, key)
  return key
}

function toB64(bytes: Uint8Array): string {
  let s = ""
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

// Return type is inferred as Uint8Array<ArrayBuffer> (an explicit `: Uint8Array`
// annotation widens to ArrayBufferLike, which is not a valid BufferSource).
function fromB64(b64: string) {
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

/** Returns a self-describing blob: `v1.<iv-b64>.<ciphertext-b64>`. */
export async function encryptString(plain: string): Promise<string> {
  const key = await getMasterKey()
  const iv = window.crypto.getRandomValues(new Uint8Array(12))
  const ct = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plain),
  )
  return `v1.${toB64(iv)}.${toB64(new Uint8Array(ct))}`
}

/** Inverse of encryptString. Returns "" on any parse/format/decrypt failure. */
export async function decryptString(blob: string): Promise<string> {
  try {
    const parts = blob.split(".")
    if (parts.length !== 3 || parts[0] !== "v1") return ""
    const key = await getMasterKey()
    const iv = fromB64(parts[1])
    const ct = fromB64(parts[2])
    const pt = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
    return new TextDecoder().decode(pt)
  } catch {
    // Corrupted blob, rotated master key, or tampered ciphertext — treat all
    // as "no key stored" instead of throwing.
    return ""
  }
}
