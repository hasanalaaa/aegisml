import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import { test } from "node:test"

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8")

test("public copy describes static-analysis boundaries without absolute trust claims", () => {
  const app = read("components/aegis/AegisApp.tsx")
  const layout = read("app/layout.tsx")
  const banned = /absolute certainty|يقين مطلق|zero[- ]retention|SOC\s?2|cryptographically wiped|تُمحى تشفيريًا|we never see|لا نراها|zero-knowledge|عديم المعرفة|end-to-end|الطرف إلى الطرف|99\.98%|ephemeral enclave|حاوية عابرة|immutable audit|غير قابل للتغيير|FIDO2|air-gapped|معزول شبكيًا|world's most advanced/i

  assert.match(app, /Local-first deployment/)
  assert.match(app, /Static analysis can miss runtime-only behavior/)
  assert.match(app, /تشغيل محلي أولاً/)
  assert.match(app, /قد يفوّت التحليل الساكن سلوكاً لا يظهر إلا وقت التشغيل/)
  assert.doesNotMatch(`${app}\n${layout}`, banned)
})

test("BYOK never writes plaintext and requires an explicit enabled flag", () => {
  const byok = read("lib/byok.ts")
  const app = read("components/aegis/AegisApp.tsx")

  assert.doesNotMatch(byok, /setItem\(KEYS_STORAGE,\s*json\)/)
  assert.doesNotMatch(byok, /fall through to plaintext|looksLikeLegacyPlaintext/)
  assert.match(byok, /byokHeaders\(enabled: boolean\)/)
  assert.match(byok, /if \(!enabled\) return \{\}/)
  assert.match(app, /byokHeaders\(byok\)/)
})

test("scanner exposes the backend's one-file contract", () => {
  const app = read("components/aegis/AegisApp.tsx")

  assert.match(app, /const SUPPORTED_EXTENSIONS = \["\.gguf", "\.safetensors", "\.pkl", "\.pickle", "\.pt", "\.pth"\]/)
  assert.match(app, /const \[file, setFile\]/)
  assert.doesNotMatch(app, /const \[files, setFiles\]/)
  assert.doesNotMatch(app, /<input[^>]+type="file"[^>]+multiple/)
})

test("scan progress has one connection owner and failure cannot load a report", () => {
  const page = read("app/scan/[id]/page.tsx")
  const progress = read("components/ScanProgress.tsx")
  const hook = read("hooks/useScanProgress.ts")

  assert.doesNotMatch(progress, /useScanProgress\(/)
  assert.match(progress, /progressData: ScanProgressData/)
  assert.match(page, /<ScanProgress progressData=\{progressData\}/)
  assert.match(page, /progressData\.stage === "complete"/)
  assert.match(hook, /status: failed \? "error" : "complete"/)
  assert.match(hook, /error: failed/)
})

test("unused browser auth stack is absent", () => {
  const root = new URL("../", import.meta.url)
  const pkg = JSON.parse(read("package.json"))

  assert.equal(pkg.dependencies["@auth/core"], undefined)
  assert.equal(pkg.dependencies["next-auth"], undefined)
  for (const path of ["auth.ts", "components/TokenSync.tsx", "components/Providers.tsx", "app/api/auth/[...nextauth]/route.ts"]) {
    assert.equal(existsSync(new URL(path, root)), false, `${path} should be removed`)
  }
})

test("framework dependencies use patched security releases", () => {
  const pkg = JSON.parse(read("package.json"))
  const workspace = read("pnpm-workspace.yaml")

  assert.equal(pkg.dependencies.next, "^15.5.21")
  assert.equal(pkg.devDependencies["eslint-config-next"], "^15.5.21")
  assert.equal(pkg.devDependencies.postcss, "^8.5.18")
  assert.equal(pkg.pnpm, undefined)
  assert.match(workspace, /overrides:\n  postcss: 8\.5\.18\n  sharp: 0\.35\.2/)
})

test("report export is local JSON and does not call the PDF endpoint", () => {
  const page = read("app/scan/[id]/page.tsx")

  assert.doesNotMatch(page, /\/api\/v1\/analytics\/report/)
  assert.doesNotMatch(page, /Download PDF|handleDownloadPdf/)
  assert.match(page, /type: "application\/json"/)
  assert.match(page, /AegisML_Report_\$\{id\}\.json/)
  assert.match(page, /handleDownloadJson/)
})

test("capability scan reports are never advertised to search engines", () => {
  const robots = read("app/robots.ts")
  const scanLayout = read("app/scan/[id]/layout.tsx")
  const manifest = read("public/manifest.json")
  const root = new URL("../", import.meta.url)

  assert.match(robots, /disallow:\s*\[[^\]]*["']\/scan\/["']/s)
  assert.match(scanLayout, /index:\s*false/)
  assert.match(scanLayout, /follow:\s*false/)
  assert.equal(existsSync(new URL("public/robots.txt", root)), false)
  assert.doesNotMatch(manifest, /hidden threats/i)
  assert.match(manifest, /static analysis/i)
})

test("the browser client and CSP share the same local-first API default", () => {
  const config = read("next.config.ts")
  const api = read("lib/api.ts")

  assert.match(config, /const DEFAULT_API_ORIGIN = "http:\/\/localhost:8000"/)
  assert.match(api, /NEXT_PUBLIC_API_URL \|\| "http:\/\/localhost:8000"/)
  assert.doesNotMatch(config, /web-production-[a-z0-9]+\.up\.railway\.app/)
  assert.match(config, /frame-ancestors 'none'/)
  assert.match(config, /object-src 'none'/)
  assert.match(config, /base-uri 'self'/)
  assert.match(config, /form-action 'self'/)
  assert.match(config, /browsing-topics=\(\)/)
})

test("the primary navigation and BYOK card stack on narrow screens", () => {
  const app = read("components/aegis/AegisApp.tsx")

  assert.match(app, /<nav className="[^"]*flex-wrap sm:flex-nowrap/)
  assert.match(app, /order-3 sm:order-none w-full sm:w-auto/)
  assert.match(app, /flex flex-col sm:flex-row sm:items-center justify-between gap-5/)
})

test("custom scanner controls expose keyboard and screen-reader semantics", () => {
  const app = read("components/aegis/AegisApp.tsx")

  assert.match(app, /role="switch"/)
  assert.match(app, /aria-checked=\{on\}/)
  assert.match(app, /aria-label=\{label\}/)
  assert.match(app, /role="button"/)
  assert.match(app, /tabIndex=\{0\}/)
  assert.match(app, /onKeyDown=\{\(event\)/)
  assert.match(app, /aria-label=\{t\.orUrl\}/)
  assert.match(app, /htmlFor="aegis-byok-key"/)

  const mutedTextOpacities = [...app.matchAll(/text-\[rgba\(237,234,227,0\.(\d+)\)\]/g)]
    .map((match) => Number(`0.${match[1]}`))
  assert.equal(mutedTextOpacities.some((opacity) => opacity < 0.55), false)
})
