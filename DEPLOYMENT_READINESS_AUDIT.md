# AegisML — Deployment-Readiness Audit

> [!WARNING]
> **Historical snapshot; not current deployment approval.** This report describes
> the repository as observed on 2026-06-30. Paths, dependencies, findings, and
> readiness statements may now be obsolete. Use [README.md](README.md) for the
> current product contract and [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md)
> for fresh verification evidence before deploying.

**Author:** Senior Software Architect review
**Date:** 2026-06-30
**Scope:** `apps/web` (Next.js 15 / NextAuth v5) ↔ `services/scan-engine` (FastAPI + PostgreSQL + Redis)
**Status of this document:** Audit only. No application code was modified. This tells you exactly what to *provide* (keys/config) and what to *build/wire* (code gaps).

---

## 0. Executive Summary

The backend is far more complete than a typical pre-launch repo: real OAuth, real JWT issuance, real Stripe checkout/portal/webhook, real DB models, real scan pipeline, and ~40 implemented endpoints that match what the frontend calls. The architecture is sound.

There are, however, **three launch-blocking gaps** that no amount of environment configuration will fix on its own:

1. **Auth token never reaches the browser's API calls.** NextAuth stores the backend JWT in the session, but every authenticated frontend call reads it from `localStorage["token"]`, which is *never written*. Result: billing, profile, developer console, and enterprise calls all send an empty `Bearer` token and get 401s.
2. **The `/api/scan` Next.js route returns fake, randomly-generated results** instead of calling the real scan engine. Whichever UI path uses it will look like it works but scans nothing.
3. **Several backend modules are still mock stubs** (GraphQL resolvers, HF monitor feed, Slack/Discord bots, webhook test). Most are non-critical, but the GraphQL endpoint is publicly advertised in the docs page.

Everything else is "provide the keys and set the env vars." Details below.

---

## 1. Authentication Audit

### 1.1 How it currently works

- **Frontend** (`apps/web/auth.ts`): NextAuth v5 with **GitHub** and **Google** providers. On sign-in, the `jwt` callback POSTs the user profile to the backend `/auth/sync` endpoint and stores the returned backend JWT as `token.backendToken`; the `session` callback copies it to `session.backendToken`.
- **Backend** (`services/scan-engine/auth/`): `/auth/sync` upserts the user (`sync_user`) and returns an HS256 access token signed with `SECRET_KEY`. Standalone OAuth (`/auth/github`, `/auth/google` + callbacks) also exists and works independently.
- **User identity** is keyed on email; an `api_key` is auto-generated per user.

### 1.2 The blocking gap (must build)

The browser obtains the backend JWT only inside the NextAuth **session object** (`session.backendToken`). But the data-fetching code reads it from **`localStorage["token"]`**:

| File | Line(s) | Reads token from |
|---|---|---|
| `app/billing/page.tsx` | 14, 21, 35 | `localStorage.getItem("token")` |
| `app/pricing/page.tsx` | 24 | `localStorage.getItem("token")` |
| `components/DeveloperConsoleClient.tsx` | 25, 36, 53 | `localStorage.getItem("token")` |
| `components/Navbar.tsx` | 52 | `localStorage.getItem("token")` |
| `lib/api.ts` → `authFetch()` | 32 | `localStorage.getItem("token")` |

A repo-wide search for `localStorage.setItem("token", …)` returns **nothing**. The token is never persisted to where these calls look for it.

**Fix required (code, not config):** after sign-in, write `session.backendToken` into `localStorage["token"]` (e.g. a small client effect that reads `useSession()` and syncs it), *or* refactor `authFetch`/pages to pull the token from the session instead of localStorage. Until then, every authenticated endpoint is effectively unreachable from the UI.

### 1.3 Secondary auth issues

- `auth/router.py` `/auth/refresh` is a **placeholder** — it returns a literal `"new_access_token"` string and ignores the `RefreshToken` table. Access tokens expire in **15 minutes** (`ACCESS_TOKEN_EXPIRE_MINUTES = 15`), so sessions will silently break after 15 min until refresh is implemented.
- `/auth/logout` is a **no-op** (does not revoke refresh tokens).
- `User` model has both `plan` and `current_plan` (`current_plan` is a self-described "duplicate just in case") — harmless but worth removing.

### 1.4 Database schema for users & sessions

**Ready.** Tables are defined and auto-created at startup:

- `auth/models.py`: `users`, `refresh_tokens`, `user_api_keys` (all on the shared `Base`).
- `database.py` `init_db()` runs `Base.metadata.create_all` on startup (lifespan), so tables are created automatically on first boot against `DATABASE_URL`. Alembic is also present (`alembic.ini`, `migrations/`) if you prefer managed migrations.
- One caveat: `User.id` is a `UUID`; the Stripe webhook and rate-limit middleware do `session.get(User, user_id)` with a **string** user_id from JWT/Stripe metadata. SQLAlchemy usually coerces this, but verify against your Postgres driver — a type mismatch here would silently fail plan upgrades.

### 1.5 Required environment variables — Authentication

**Frontend (Vercel):**

| Variable | Required | Notes |
|---|---|---|
| `NEXTAUTH_SECRET` (a.k.a. `AUTH_SECRET`) | ✅ | NextAuth v5 beta prefers `AUTH_SECRET`; set both to be safe. Generate with `openssl rand -base64 32`. |
| `NEXTAUTH_URL` (a.k.a. `AUTH_URL`) | ✅ | Your Vercel production URL, e.g. `https://aegisml.vercel.app`. |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | ✅ | GitHub OAuth App. Callback: `https://<your-domain>/api/auth/callback/github`. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | ✅ | Google OAuth client. Callback: `https://<your-domain>/api/auth/callback/google`. |
| `NEXT_PUBLIC_API_URL` | ✅ | Railway backend base, e.g. `https://web-production-a53a8.up.railway.app`. **No trailing `/api/v1`** — `auth.ts` derives `/auth/sync` from it. |
| `NEXT_PUBLIC_WS_URL` | ✅ | WebSocket base, e.g. `wss://web-production-a53a8.up.railway.app`. |

**Backend (Railway):** `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` (e.g. `https://<backend>/auth/google/callback`), and `SECRET_KEY` (signs the JWTs — **must be set**, the fallback is dev-only and insecure).

---

## 2. Payments / Billing Audit

### 2.1 Gateway

**Stripe** (`stripe==9.3.0`, `services/scan-engine/billing/router.py`). Three tiers: `free` / `pro` / `enterprise`.

### 2.2 What is implemented (real, not stubbed)

- `POST /api/v1/billing/checkout` — creates a Stripe Customer (persists `stripe_customer_id`) and a subscription Checkout Session. ✅
- `GET /api/v1/billing/portal` — Stripe billing portal session. ✅
- `GET /api/v1/billing/usage` — returns plan, scans used, limit, reset date. ✅
- `POST /api/v1/billing/cancel` — cancels the Stripe subscription and downgrades to free. ✅
- `POST /api/v1/billing/webhook` — verifies signature and handles `checkout.session.completed` (upgrade) and `customer.subscription.deleted` (downgrade). ✅

### 2.3 Gaps & risks

- **Defaults are mock values.** `STRIPE_SECRET_KEY` falls back to `"sk_test_mock"`, webhook secret to `"whsec_mock"`, and price IDs to `"price_pro_mock"` / `"price_ent_mock"`. With these defaults, checkout calls will fail against real Stripe. **You must provide all of them.**
- **Webhook coverage is partial.** Only two event types are handled. Recommended additions for production: `customer.subscription.updated` (plan changes/downgrades mid-cycle), `invoice.payment_failed` (dunning), and `invoice.paid`. Not strictly blocking, but you'll have drift between Stripe and your DB without them.
- **`billing/models.py` is intentionally empty** — billing fields live on `User` (`stripe_customer_id`, `stripe_subscription_id`, `plan`, `scans_this_month`). This is fine, but there is **no billing-history / invoice table**, so you cannot show past invoices in-app without adding one.
- **Usage metering is not wired to scans.** `usage` reads `User.scans_this_month`, but the scan pipeline (`main.py _process_scan`) never increments it, and nothing resets it monthly. Rate-limiting is enforced separately in Redis (`plan_rate_limit_middleware`), so quota *display* and quota *enforcement* are two different systems and the displayed "scans used" will always read 0. **Build needed** if usage numbers must be accurate.
- The checkout flow depends on a valid `Bearer` token (`get_current_user`), so it is **also blocked by the §1.2 token gap**.

### 2.4 Required environment variables — Payments (Backend / Railway)

| Variable | Required | Notes |
|---|---|---|
| `STRIPE_SECRET_KEY` | ✅ | `sk_live_…` (or `sk_test_…` while testing). |
| `STRIPE_WEBHOOK_SECRET` | ✅ | `whsec_…` from the Stripe webhook endpoint you register at `POST https://<backend>/api/v1/billing/webhook`. |
| `STRIPE_PRO_PRICE_ID` | ✅ | `price_…` for the Pro subscription. |
| `STRIPE_ENTERPRISE_PRICE_ID` | ✅ | `price_…` for the Enterprise subscription. |
| `FRONTEND_URL` | ✅ | Used to build Checkout `success_url` / `cancel_url`, e.g. `https://aegisml.vercel.app`. |

---

## 3. API Connectivity Audit (`apps/web` ↔ `services/scan-engine`)

### 3.1 Route mapping — overall: healthy

Cross-referencing every API path the frontend calls against the routers registered in `main.py`, **nearly every endpoint the frontend uses is implemented on the backend.** Prefixes line up (`analytics` → `/api/v1/analytics`, `developer` → `/api/v1/developer`, `billing` → `/api/v1/billing`, etc.).

Implemented and matched (sample): `/api/v1/scan/file`, `/api/v1/scan/url`, `/api/v1/scan/{id}`, `/api/v1/scans/recent`, `/api/v1/stats`, `/api/v1/threats/patterns`, `/api/v1/threats/query`, `/api/v1/ai/providers`, `/api/v1/ai/validate-key`, `/api/v1/billing/*`, `/api/v1/analytics/*`, `/api/v1/community/leaderboard`, `/api/v1/community/threat-reports`, `/api/v1/developer/webhooks(/logs)`, `/api/v1/enterprise/*`, `/api/v1/monitor/*`, `/api/v1/research/*`, `/api/v1/referral/*`, `/api/v1/newsletter/subscribe`, `/api/v1/user/api-keys`.

### 3.2 Issues found

1. **`apps/web/app/api/scan/route.ts` is a fake scanner.** This Next.js Route Handler sleeps 1.5s and returns a **randomly-generated** result based only on the file extension. It never contacts `services/scan-engine`. Any component POSTing to `/api/scan` (relative) is scanning nothing. The *real* flow is the browser calling the backend `/api/v1/scan/file` directly — confirm which one each UI surface uses and delete/replace the mock route.
2. **Duplicate route definitions in `main.py`.** `get_threat_patterns` is declared **twice** (≈line 1105 and ≈line 1196) on the same path `/api/v1/threats/patterns`, and `validate_key` is defined twice (API-key validate vs AI-key validate). With FastAPI, the **last registration wins** — so the first `/api/v1/threats/patterns` (the paginated `scanner.patterns` library version) is shadowed by the DB-backed one. Decide which you want; right now the paginated/filtered one is dead code.
3. **`user/api-keys` is defined in two places** — inline in `main.py` (`/api/v1/user/api-keys`) and in `routers/user_keys.py` (`/api/v1/user/api-keys` via the `/api/v1` prefix). They overlap; confirm precedence and remove the redundant one.
4. **GraphQL endpoint is a mock.** The docs page advertises a GraphQL Playground link, but `/graphql` is served by `graphql_schema.py`, whose resolvers return hardcoded `mock-123` data. A second, more real-looking `graphql_gateway/schema.py` is imported in `main.py` but **not mounted**. Either wire the gateway schema or stop advertising the endpoint.

### 3.3 Endpoints referenced but not implemented

After full cross-check, **no frontend-referenced REST path is entirely missing a backend handler.** The problems are *quality* (mocked data, duplicates) rather than *absence*. The one true "calls nothing real" case is the frontend-internal `/api/scan` mock in §3.2(1).

---

## 4. Developer Setup Checklist

### 4.1 Feature status

| Feature | Status | Required Configuration / Keys |
|---|---|---|
| Frontend build/deploy (Vercel) | ✅ Implemented (TS/ESLint errors currently bypassed in `next.config.ts`) | `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_WS_URL` |
| OAuth login (GitHub/Google) | ⚠️ Implemented but **token not wired to API calls** (§1.2) | `NEXTAUTH_SECRET`/`AUTH_SECRET`, `NEXTAUTH_URL`, `GITHUB_CLIENT_ID/SECRET`, `GOOGLE_CLIENT_ID/SECRET` (both FE+BE), `GOOGLE_REDIRECT_URI` (BE) |
| Token refresh / logout | ❌ Stubbed (`/auth/refresh` returns a literal string; 15-min expiry) | — (code work) |
| User/session DB schema | ✅ Implemented (auto-created at startup) | `DATABASE_URL` |
| Stripe checkout / portal / cancel | ✅ Implemented (blocked by token gap §1.2) | `STRIPE_SECRET_KEY`, `STRIPE_PRO_PRICE_ID`, `STRIPE_ENTERPRISE_PRICE_ID`, `FRONTEND_URL` |
| Stripe webhooks | ⚠️ Partial (2 events only) | `STRIPE_WEBHOOK_SECRET` |
| Usage metering (scans_this_month) | ❌ Not incremented/reset (display always 0) | — (code work) |
| Scan engine (file/URL) | ✅ Implemented (real pipeline) | `ANTHROPIC_API_KEY`, `HF_TOKEN` (for gated HF URLs) |
| Frontend `/api/scan` route | ❌ Fake/random results | — (delete/replace, code work) |
| AI analysis (multi-provider) | ✅ Implemented; users can supply own keys | `ANTHROPIC_API_KEY` (server default); per-user keys encrypted via `SECRET_KEY` |
| Realtime progress (WS/SSE) | ✅ Implemented | `NEXT_PUBLIC_WS_URL`, `REDIS_URL` |
| Background jobs (large scans) | ✅ Implemented (arq worker) — **requires a separate worker process** | `REDIS_URL`; run `arq worker.WorkerSettings` |
| Caching / rate limiting | ✅ Implemented (degrades gracefully without Redis) | `REDIS_URL` |
| CVE / threat-intel sync | ✅ Implemented (scheduler) | `NVD_API_KEY` (optional, higher rate limits) |
| Email notifications | ⚠️ Present, mock notifier in HF monitor | `RESEND_API_KEY`, `RESEND_FROM_EMAIL` |
| Slack bot | ❌ Mock endpoint | `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET` |
| Discord bot | ❌ Mock endpoint | — |
| GitHub Action scan gate | ✅ Implemented (real) | — |
| GraphQL API | ❌ Mock resolvers (gateway schema not mounted) | — (code work) |
| HF monitor feed | ⚠️ In-memory mock list + real scheduler status | — (code work) |
| Community reviews/leaderboard | ✅ Implemented (real DB queries) | — |
| Enterprise members/rules/audit | ✅ Implemented (real role checks) | — |

Legend: ✅ ready · ⚠️ works but incomplete/needs attention · ❌ stub or broken.

### 4.2 Every environment variable to set

**Vercel (frontend — `apps/web`):**

```
NEXT_PUBLIC_API_URL        = https://<your-railway-backend>          # no /api/v1 suffix
NEXT_PUBLIC_WS_URL         = wss://<your-railway-backend>
NEXTAUTH_URL               = https://<your-vercel-domain>
AUTH_URL                   = https://<your-vercel-domain>            # v5 alias, set both
NEXTAUTH_SECRET            = <openssl rand -base64 32>
AUTH_SECRET                = <same value as NEXTAUTH_SECRET>          # v5 alias, set both
GITHUB_CLIENT_ID           = <github oauth app id>
GITHUB_CLIENT_SECRET       = <github oauth app secret>
GOOGLE_CLIENT_ID           = <google oauth client id>
GOOGLE_CLIENT_SECRET       = <google oauth client secret>
```

**Railway (backend — `services/scan-engine`):**

```
# Core (required)
DATABASE_URL               = postgresql+asyncpg://...   # Railway Postgres reference; postgres:// is auto-rewritten
REDIS_URL                  = redis://...                # Railway Redis reference
SECRET_KEY                 = <strong random>            # signs JWTs AND derives API-key encryption
FRONTEND_URL               = https://<your-vercel-domain>
ENVIRONMENT                = production
PORT                       = 8000

# OAuth (required for login)
GITHUB_CLIENT_ID           = <...>
GITHUB_CLIENT_SECRET       = <...>
GOOGLE_CLIENT_ID           = <...>
GOOGLE_CLIENT_SECRET       = <...>
GOOGLE_REDIRECT_URI        = https://<backend>/auth/google/callback

# AI analysis (required for verdicts)
ANTHROPIC_API_KEY          = sk-ant-...

# Payments (required for billing)
STRIPE_SECRET_KEY          = sk_live_... (or sk_test_...)
STRIPE_WEBHOOK_SECRET      = whsec_...
STRIPE_PRO_PRICE_ID        = price_...
STRIPE_ENTERPRISE_PRICE_ID = price_...

# Optional / feature-specific
HF_TOKEN                   = hf_...        # gated HuggingFace model downloads
NVD_API_KEY                = <...>         # CVE sync rate limits
RESEND_API_KEY             = re_...        # email notifications
RESEND_FROM_EMAIL          = alerts@yourdomain
SLACK_BOT_TOKEN            = xoxb-...      # only if enabling Slack bot
SLACK_SIGNING_SECRET       = <...>         # only if enabling Slack bot
ENCRYPTION_KEY             = <fernet key>  # ONLY if you use auth/crypto.py; auth/encryption.py derives from SECRET_KEY instead
```

> Note on `ENCRYPTION_KEY`: there are **two** encryption helpers. `auth/encryption.py` (used by the live `/api/v1/user/api-keys` routes in `main.py`) derives its key from `SECRET_KEY` — no separate var needed. `auth/crypto.py` requires a standalone `ENCRYPTION_KEY` and warns if missing. Standardize on one to avoid confusion.

### 4.3 Process / infra reminders (not env vars)

- **Run the arq worker** as a second Railway process (`arq worker.WorkerSettings`) — scans >50 MB are enqueued to it; without it they will never complete.
- **Register the Stripe webhook** endpoint in the Stripe dashboard pointing at `https://<backend>/api/v1/billing/webhook`.
- **OAuth callback URLs** must be whitelisted in both the GitHub and Google consoles (frontend `/api/auth/callback/...` for NextAuth, backend `/auth/.../callback` for the standalone flow).
- **CORS**: backend allows `https://aegisml.vercel.app`, `localhost:4001`, and `$FRONTEND_URL` plus any `*VERCEL_URL*`. If your domain differs, set `FRONTEND_URL`.

---

## 5. Architecture Gaps — Stubbed / Mock Functions

Critical (fix before claiming the feature works):

1. **`apps/web/app/api/scan/route.ts`** — returns random fake scan results; never calls the engine. (§3.2)
2. **Auth token wiring** — `localStorage["token"]` never set; all authenticated calls 401. (§1.2)
3. **`auth/router.py::refresh_token`** — `# Very basic placeholder logic`; returns the literal `"new_access_token"`. Sessions break after 15 min.
4. **Usage metering** — `scans_this_month` never incremented or reset; billing usage display is always 0. (§2.3)

Non-critical but advertised / visible:

5. **`graphql_schema.py`** — all resolvers return hardcoded `mock-123` data; the real `graphql_gateway/schema.py` is imported but not mounted. Docs page links to this endpoint.
6. **`hf_monitor/router.py`** — `_recent_models` / `_subscriptions` are in-memory mock lists (`test/model1`, `hacker/malware_agent`); subscriptions are lost on restart and not persisted to DB.
7. **`integrations/router.py`** — `/slack/events` and `/discord/webhook` are mock handlers (`# Mock endpoint…`). `slack_bot.py` defaults to `xoxb-mock`. (The GitHub Action gate `/github/scan` **is** real.)
8. **`hf_monitor/notifications.py`** — `# Mocking email/alert notification`; no real email is sent.
9. **`webhooks.py`** test path uses `mock_url = https://httpbin.org/post` and `whsec_mock` — fine for a self-test, not for production.

Cleanliness (low priority):

10. Duplicate route handlers in `main.py` (`get_threat_patterns` ×2, `validate_key` ×2) and overlapping `user/api-keys` definitions (`main.py` vs `routers/user_keys.py`). (§3.2)
11. `User.current_plan` duplicates `User.plan`.
12. `next.config.ts` currently has `typescript.ignoreBuildErrors` and `eslint.ignoreDuringBuilds` **on** (set during the deploy-unblock task). Real type/lint errors are being hidden; plan to turn these back off and fix the underlying issues before this is "production hardened."

---

## 6. Recommended order of operations

1. Set all **required** env vars in Vercel + Railway (§4.2).
2. **Wire the auth token** to where the API calls read it (§1.2) — this single fix unblocks billing, profile, developer console, and enterprise simultaneously.
3. Provide real **Stripe** keys + price IDs and register the **webhook** (§2.4); add `subscription.updated` / `payment_failed` handling.
4. Replace/remove the **fake `/api/scan`** route and confirm the UI uses the real backend (§3.2).
5. Implement **token refresh** + **usage metering** (§5.3, §5.4).
6. Stand up the **arq worker** process and the **Stripe webhook** endpoint (§4.3).
7. Decide the fate of the **mock modules** (GraphQL, HF monitor, Slack/Discord) — implement or hide.
8. Re-enable strict TS/ESLint in `next.config.ts` and clear the real errors (§5.12).

---

*End of audit. No code was changed to produce this report.*
