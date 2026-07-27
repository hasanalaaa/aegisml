# Graph Report - aegisml  (2026-07-02)

## Corpus Check
- 132 files · ~71,250 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1117 nodes · 1946 edges · 90 communities (76 shown, 14 thin omitted)
- Extraction: 83% EXTRACTED · 17% INFERRED · 0% AMBIGUOUS · INFERRED: 334 edges (avg confidence: 0.53)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `681ca2c8`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 72|Community 72]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 76|Community 76]]
- [[_COMMUNITY_Community 77|Community 77]]
- [[_COMMUNITY_Community 87|Community 87]]

## God Nodes (most connected - your core abstractions)
1. `User` - 48 edges
2. `AIProviderManager` - 37 edges
3. `ScanRecord` - 30 edges
4. `AIProvider` - 22 edges
5. `Base` - 21 edges
6. `AIAnalysisResult` - 20 edges
7. `CircuitBreaker` - 20 edges
8. `FastAPI` - 20 edges
9. `ThreatPattern` - 18 edges
10. `AsyncSession` - 18 edges

## Surprising Connections (you probably didn't know these)
- `_AuthError` --uses--> `CircuitState`  [INFERRED]
  tests/test_resilience.py → services/scan-engine/ai_providers/circuit_breaker.py
- `_Clock` --uses--> `CircuitState`  [INFERRED]
  tests/test_resilience.py → services/scan-engine/ai_providers/circuit_breaker.py
- `_FakeProvider` --uses--> `CircuitState`  [INFERRED]
  tests/test_resilience.py → services/scan-engine/ai_providers/circuit_breaker.py
- `_Clock` --uses--> `CircuitOpenError`  [INFERRED]
  tests/test_resilience.py → services/scan-engine/ai_providers/circuit_breaker.py
- `_FakeProvider` --uses--> `CircuitOpenError`  [INFERRED]
  tests/test_resilience.py → services/scan-engine/ai_providers/circuit_breaker.py

## Import Cycles
- 1-file cycle: `services/scan-engine/main.py -> services/scan-engine/main.py`
- 1-file cycle: `services/scan-engine/auth/utils.py -> services/scan-engine/auth/utils.py`
- 2-file cycle: `services/scan-engine/enterprise/router.py -> services/scan-engine/main.py -> services/scan-engine/enterprise/router.py`
- 2-file cycle: `services/scan-engine/main.py -> services/scan-engine/routers/developer.py -> services/scan-engine/main.py`
- 2-file cycle: `services/scan-engine/auth/utils.py -> services/scan-engine/main.py -> services/scan-engine/auth/utils.py`
- 2-file cycle: `services/scan-engine/growth/router.py -> services/scan-engine/main.py -> services/scan-engine/growth/router.py`
- 2-file cycle: `services/scan-engine/integrations/router.py -> services/scan-engine/main.py -> services/scan-engine/integrations/router.py`
- 2-file cycle: `services/scan-engine/auth/router.py -> services/scan-engine/main.py -> services/scan-engine/auth/router.py`
- 3-file cycle: `services/scan-engine/auth/utils.py -> services/scan-engine/main.py -> services/scan-engine/enterprise/router.py -> services/scan-engine/auth/utils.py`
- 3-file cycle: `services/scan-engine/auth/utils.py -> services/scan-engine/main.py -> services/scan-engine/routers/developer.py -> services/scan-engine/auth/utils.py`
- 3-file cycle: `services/scan-engine/auth/router.py -> services/scan-engine/auth/utils.py -> services/scan-engine/main.py -> services/scan-engine/auth/router.py`
- 3-file cycle: `services/scan-engine/auth/utils.py -> services/scan-engine/main.py -> services/scan-engine/growth/router.py -> services/scan-engine/auth/utils.py`

## Communities (90 total, 14 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.06
Nodes (85): User, BaseModel, CommunityThreatReport, ModelBookmark, ModelReview, bookmark_model(), BookmarkCreate, BookmarkResponse (+77 more)

### Community 1 - "Community 1"
Cohesion: 0.06
Nodes (47): AegisApp(), DICT, DOC_TABS, Lang, RISK_TO_SEV, SETTINGS_DEFS, SEV_STYLE, StatCard() (+39 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (32): ChatMessage, ArchitectureCard(), formatBytes(), formatParams(), FormatSpecificMeta, rowStyle, ButtonProps, GhostButton() (+24 more)

### Community 3 - "Community 3"
Cohesion: 0.06
Nodes (43): calculate_cvss_v3(), AegisML Scan Engine — v3.2 (Phase 2: scalability & fault tolerance)  Real multi-, analyze(), _analyze_full(), _analyze_sampled(), calculate_entropy(), detect_encrypted_sections(), _entropy_from_counts() (+35 more)

### Community 4 - "Community 4"
Cohesion: 0.06
Nodes (32): Any, InspectorResult, Path, Any, InspectorResult, Path, InspectorResult, Path (+24 more)

### Community 5 - "Community 5"
Cohesion: 0.10
Nodes (35): # NOTE: The former UserAPIKey model (server-side storage of users', RefreshToken, get_github_user_info(), get_google_user_info(), get_me(), github_callback(), google_callback(), logout() (+27 more)

### Community 6 - "Community 6"
Cohesion: 0.06
Nodes (30): dependencies, @auth/core, framer-motion, lucide-react, next, next-auth, react, react-dom (+22 more)

### Community 7 - "Community 7"
Cohesion: 0.17
Nodes (7): format_result(), main(), AegisML, Path, ScanResult, Threat, ScanResult

### Community 8 - "Community 8"
Cohesion: 0.13
Nodes (15): CircuitOpenError, Raised by callers that cannot fall back when a circuit is OPEN., AIProviderManager, _is_auth_error(), _is_rate_limited(), Return the configured system API key for a provider, or None., Key to use for a provider, or None if the provider is unusable.          Ollama, Run AI analysis with graceful degradation.          Order of attempts: (+7 more)

### Community 9 - "Community 9"
Cohesion: 0.30
Nodes (21): AuditLog, CustomThreatRule, OrgMember, AuditLogResponse, create_threat_rule(), delete_member(), delete_threat_rule(), get_audit_logs() (+13 more)

### Community 10 - "Community 10"
Cohesion: 0.08
Nodes (23): 0. Executive Summary, 1.1 How it currently works, 1.2 The blocking gap (must build), 1.3 Secondary auth issues, 1.4 Database schema for users & sessions, 1.5 Required environment variables — Authentication, 1. Authentication Audit, 2.1 Gateway (+15 more)

### Community 11 - "Community 11"
Cohesion: 0.16
Nodes (13): AIAnalysisResult, AIProvider, build_analysis_prompt(), parse_ai_json_response(), Turn real scan engine output into a grounded prompt. Truncates the     threat li, Robustly extract a JSON object from a model response (handles models     that wr, AIAnalysisResult, AIAnalysisResult (+5 more)

### Community 12 - "Community 12"
Cohesion: 0.13
Nodes (22): delete_cache(), delete_pattern(), get_cache(), get_cached_stats(), _get_redis(), invalidate_scan(), AegisML Cache Module — Redis-backed caching with graceful fallback  Every functi, Remove a specific scan from cache and bust the stats cache. (+14 more)

### Community 13 - "Community 13"
Cohesion: 0.09
Nodes (22): 1. استهلاك ذاكرة كارثي في رفع الملفات, 1. استيلاء كامل على أي حساب عبر `/auth/sync` (حرجة — الأخطر في المنصة), 2. تجاوز سعة عمود `file_size` (خلل بيانات مؤكد), 2. قبول Refresh Token مكان Access Token (حرجة), 3. تسميم متبادل لذاكرة التخزين المؤقت للإحصائيات, 3. مفتاح توقيع JWT احتياطي ثابت ومعروف (حرجة), 4. حذف الكاش فور كتابته, 4. مسار `/auth/refresh` وهمي (خلل وظيفي + أمني) (+14 more)

### Community 14 - "Community 14"
Cohesion: 0.10
Nodes (19): compilerOptions, allowJs, esModuleInterop, incremental, isolatedModules, jsx, lib, module (+11 more)

### Community 15 - "Community 15"
Cohesion: 0.12
Nodes (19): Enum, Finding, HealthResponse, HFScanQueued, HFScanRequest, Pydantic models for the AegisML Scan Engine API., Response when a Hugging Face scan is queued., Health check response. (+11 more)

### Community 16 - "Community 16"
Cohesion: 0.13
Nodes (10): Single-pass Aho-Corasick byte-signature scan (streamed).          v3.0 ran ``pat, Regex scan over text-decodable portions (first 10MB max)., Format-specific deep scan, isolated so a scanner crash degrades         to an er, Remove duplicate findings by ID, keeping highest severity., Ensure all threats have CVSS scores and find highest., Determine overall verdict from CVSS score and entropy., Compute SHA-256 hash of the file., Multi-pass AI model security scanner.         Pass 1: Magic byte detection & fil (+2 more)

### Community 17 - "Community 17"
Cohesion: 0.17
Nodes (15): _Evil, _make_torch_zip(), AegisML — Phase 1 forensic-engine regression suite.  Covers the v3.1 upgrades:, Reduces to os.system(...) on unpickling — the canonical RCE gadget., Proto 4/5 embedded pickles were invisible to the old inline GLOBAL-only scan., test_benign_checkpoint_no_false_positive(), test_embedded_torch_zip_payload(), test_entropy_edge_cases() (+7 more)

### Community 18 - "Community 18"
Cohesion: 0.18
Nodes (17): _both_backends(), _breaker(), AegisML — Phase 2 resilience regression suite.  Covers the v3.2 (scalability & f, Build the matcher on every available backend (parity testing)., test_breaker_half_open_probe_failure_reopens(), test_breaker_half_open_probe_success_closes(), test_breaker_neutral_returns_trial_slot_without_judging(), test_breaker_snapshot_shape_and_counters() (+9 more)

### Community 19 - "Community 19"
Cohesion: 0.13
Nodes (13): BinaryIO, Pattern, _as_bytes(), BytePatternMatcher, get_threat_matcher(), AegisML Byte-Pattern Matcher — v3.2 (Phase 2: single-pass multi-pattern search), Indices of all patterns occurring in ``data``, minus ``exclude``.          ``exc, Single pass over a binary stream; returns all matched indices.          Memory i (+5 more)

### Community 20 - "Community 20"
Cohesion: 0.11
Nodes (18): 0. Honest scope note (read this first), 1.1 The scanner did not scan (highest severity), 1.2 `_process_scan` crashed on every normal scan (`UnboundLocalError`), 1.3 The product's main entry point did nothing, 1.4 Hardcoded `http://localhost:8000` across 13 files, 1.5 The enterprise API had a fake auth gate, 1.6 Dead/orphaned code paths in `main.py`, 1. Critical bugs fixed (+10 more)

### Community 21 - "Community 21"
Cohesion: 0.14
Nodes (16): _compute_file_hash(), generate_api_key(), get_scan_job_status(), _hash_key(), plan_rate_limit_middleware(), AegisML Scan Engine - FastAPI Backend v2.0.0  Production-grade API for scanning, SHA-256 hash of an API key for storage (never store plaintext)., Generate a new API key.  The raw key is shown only once. (+8 more)

### Community 22 - "Community 22"
Cohesion: 0.15
Nodes (4): ABC, GoogleProvider, MistralProvider, Shared prompt construction and response parsing for all AI providers.  Every pro

### Community 23 - "Community 23"
Cohesion: 0.14
Nodes (7): CircuitBreaker, CircuitState, Circuit breaker for outbound AI-provider calls — v3.2 (Phase 2).  Why: without a, Return a trial slot without judging provider health., Effective state (reports HALF_OPEN once an OPEN cooldown expires,         withou, True if a call may proceed. May consume a HALF_OPEN trial slot —         pair ev, test_breaker_rejects_invalid_configuration()

### Community 24 - "Community 24"
Cohesion: 0.17
Nodes (15): export_all_scans_csv(), export_scan_csv(), generate_pdf_report(), get_geography(), get_overview(), get_threat_distribution(), get_trends(), General overview statistics for the dashboard. (+7 more)

### Community 25 - "Community 25"
Cohesion: 0.21
Nodes (12): GitHubScanError, handle_github_scan(), AegisML GitHub Actions CI/CD Integration — Real Scan Pipeline  Previously `handl, Raised for any condition that should surface as a 4xx to the Action., Download a model from HuggingFace and run a real, synchronous scan     for use i, _validate_model_url(), github_scan(), GithubScanRequest (+4 more)

### Community 26 - "Community 26"
Cohesion: 0.21
Nodes (12): ResearchKeyRequest, _anonymized_rows(), get_aggregate_stats(), get_dataset(), Compute real aggregate statistics from the scan history table., Persist a research-key application to the real ResearchKeyRequest     table (pre, Strip all PII (no user IDs, IPs, filenames, source URLs, hashes) —     keep only, Return a real anonymized dataset built from actual scan history. (+4 more)

### Community 27 - "Community 27"
Cohesion: 0.20
Nodes (11): AdmissionController, ``async with controller.admit(size, scan_id):`` around heavy work.          Bloc, Observability snapshot (safe to expose on a health endpoint)., Size-class weighted admission for scan jobs., _config(), test_admission_classes_do_not_block_each_other(), test_admission_classify_boundaries(), test_admission_serializes_within_size_class() (+3 more)

### Community 28 - "Community 28"
Cohesion: 0.18
Nodes (14): compare_scans(), get_badge(), get_badge_json(), get_recent_scans(), Download a model from a URL and scan it for security threats.      BYOK: AI key, Generate an SVG badge for a scan result., Shields.io-compatible JSON badge endpoint., Compare two scan results side by side. (+6 more)

### Community 29 - "Community 29"
Cohesion: 0.19
Nodes (4): AnthropicProvider, _env_float(), _env_int(), OpenAIProvider

### Community 30 - "Community 30"
Cohesion: 0.17
Nodes (4): get_status(), subscribe(), SubscribeRequest, get_scheduler_status()

### Community 31 - "Community 31"
Cohesion: 0.17
Nodes (11): background_color, categories, description, display, icons, name, orientation, screenshots (+3 more)

### Community 32 - "Community 32"
Cohesion: 0.20
Nodes (10): fetch_and_store_ai_cves(), fetch_cves_for_keyword(), parse_cve_item(), Fetch CVEs from NVD for a specific keyword with exponential backoff., Extract relevant fields from the NVD JSON item., Main task to fetch AI CVEs and store them in the database., Initialise and start the background scheduler., Gracefully shutdown the scheduler. (+2 more)

### Community 33 - "Community 33"
Cohesion: 0.31
Nodes (9): NewsletterSubscriber, ReferralCode, create_referral_code(), generate_referral_code(), get_referral_stats(), subscribe_newsletter(), SubscribeRequest, AsyncSession (+1 more)

### Community 34 - "Community 34"
Cohesion: 0.24
Nodes (8): API, localStorage, log(), main(), out, results, test(), WEB

### Community 35 - "Community 35"
Cohesion: 0.27
Nodes (8): _find_related_patterns(), natural_language_query(), Natural-language threat search.  Previously this returned a single hardcoded can, Cheap keyword-overlap ranking over the real pattern library — used     both to g, FixSuggestionRequest, get_fix_suggestions(), NLPQueryRequest, query_threats()

### Community 36 - "Community 36"
Cohesion: 0.24
Nodes (6): Cache an individual scan result for 30 s., set_cached_scan(), ConnectionManager, _process_scan(), _process_url_scan(), websocket_scan_endpoint()

### Community 37 - "Community 37"
Cohesion: 0.29
Nodes (8): _FakeProvider, _manager(), Duck-typed provider: manager only calls .analyze()., test_manager_auth_errors_never_trip_the_breaker(), test_manager_no_fallback_raises_circuit_open_error(), test_manager_open_circuit_is_skipped_instantly(), test_manager_snapshots_cover_every_provider(), test_manager_static_fallback_when_everything_is_open()

### Community 38 - "Community 38"
Cohesion: 0.25
Nodes (8): Connection, do_run_migrations(), Run migrations in 'online' mode., Run migrations in 'offline' mode.      This configures the context with just a U, In this scenario we need to create an Engine     and associate a connection with, run_async_migrations(), run_migrations_offline(), run_migrations_online()

### Community 39 - "Community 39"
Cohesion: 0.33
Nodes (6): register_webhook(), sign_payload(), test_webhook(), trigger_webhook(), WebhookRegisterRequest, WebhookResponse

### Community 40 - "Community 40"
Cohesion: 0.31
Nodes (6): AdmissionConfig, _env_float(), _env_int(), get_admission_controller(), AegisML Scan Admission Control — v3.2 (Phase 2: load-aware scheduling)  Two coop, Process-wide admission controller (lazy; env read at first use).

### Community 41 - "Community 41"
Cohesion: 0.25
Nodes (7): 🛡️ AegisML, 🤝 Contributing, 📚 Documentation & API, 🌟 Features, 📄 License, 🚀 Quick Start (Self-Hosting), 🛠️ Technology Stack

### Community 42 - "Community 42"
Cohesion: 0.29
Nodes (8): Validate and parse a model-download URL.      Returns (url, filename, extension), Sanitize and validate an uploaded filename., Extract and validate file extension.  Raises HTTPException on invalid., Upload and scan a model file for security threats.      BYOK: the user's third-p, scan_file(), _validate_extension(), _validate_filename(), _validate_scan_url()

### Community 43 - "Community 43"
Cohesion: 0.29
Nodes (6): get_pass_semaphore(), _LoopBoundSemaphore, A bounded semaphore that survives event-loop replacement., Global bounded semaphore for ``asyncio.to_thread`` scan passes., Semaphore, test_loop_bound_semaphore_rebuilds_per_loop()

### Community 44 - "Community 44"
Cohesion: 0.25
Nodes (6): apiOrigin, connectSrc, contentSecurityPolicy, nextConfig, withBundleAnalyzer, wsOrigin

### Community 45 - "Community 45"
Cohesion: 0.29
Nodes (6): 1. HISTORICAL EXECUTION SUMMARY (PHASE 1 to 10), 2. SECURITY CERTIFICATIONS, 3. ARCHITECTURE SYNCHRONIZATION, 4. ENTERPRISE READINESS GRADE, 🛡️ AEGISML ENTERPRISE AUDIT REPORT 🛡️, Final Evaluation

### Community 46 - "Community 46"
Cohesion: 0.29
Nodes (6): Adding Threat Patterns, Code Standards, Contributing to AegisML, Development Setup, Pull Request Process, Ways to Contribute

### Community 47 - "Community 47"
Cohesion: 0.29
Nodes (5): RuntimeError, AdmissionTimeout, A scan waited longer than ADMISSION_TIMEOUT_SECONDS for a slot., _Clock, Deterministic monotonic clock for breaker tests.

### Community 48 - "Community 48"
Cohesion: 0.33
Nodes (6): fs, generate(), path, publicDir, sharp, svgBuffer

### Community 49 - "Community 49"
Cohesion: 0.33
Nodes (5): AegisML Development Report, New API Endpoints, New Files Created, New Frontend Pages, Phase Status

### Community 50 - "Community 50"
Cohesion: 0.33
Nodes (6): get_cached_scan(), Get a cached individual scan result., get_scan(), Retrieve a scan result by its ID., SSE Fallback for streaming progress.      Fixes vs. previous version: if the sca, scan_stream()

### Community 51 - "Community 51"
Cohesion: 0.33
Nodes (6): get_cached_threats(), Get cached /threats/patterns response., Cache /threats/patterns response for 300 s., set_cached_threats(), get_threat_patterns(), List all active threat patterns.  Cached for 300 s.

### Community 52 - "Community 52"
Cohesion: 0.33
Nodes (6): check_db_health(), check_redis_health(), Non-throwing health-check for Redis., Non-throwing health-check for the database., health(), Health check with database and Redis status.

### Community 56 - "Community 56"
Cohesion: 0.40
Nodes (4): build, builder, dockerfilePath, $schema

### Community 57 - "Community 57"
Cohesion: 0.40
Nodes (4): Reporting a Vulnerability, Scope, Security Policy, Supported Versions

### Community 58 - "Community 58"
Cohesion: 0.40
Nodes (4): compat, __dirname, eslintConfig, __filename

### Community 59 - "Community 59"
Cohesion: 0.50
Nodes (3): AegisML GGUF Format Scanner Validates GGUF magic bytes, version, metadata struct, scan(), Any

### Community 60 - "Community 60"
Cohesion: 0.50
Nodes (3): AegisML ONNX Format Scanner ONNX files are Protocol Buffer (protobuf) serialized, scan(), Any

### Community 61 - "Community 61"
Cohesion: 0.50
Nodes (3): Deploy on Vercel, Getting Started, Learn More

## Knowledge Gaps
- **205 isolated node(s):** `SeverityLevel`, `cormorant`, `manrope`, `jetbrains`, `cairo` (+200 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **14 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AIProviderManager` connect `Community 8` to `Community 0`, `Community 36`, `Community 37`, `Community 11`, `Community 47`, `Community 23`, `Community 55`, `Community 54`, `Community 22`, `Community 21`, `Community 28`, `Community 29`?**
  _High betweenness centrality (0.081) - this node is a cross-community bridge._
- **Why does `FastAPI` connect `Community 0` to `Community 33`, `Community 35`, `Community 5`, `Community 39`, `Community 8`, `Community 9`, `Community 21`, `Community 24`, `Community 25`, `Community 26`, `Community 30`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Why does `resilience_snapshot()` connect `Community 28` to `Community 40`, `Community 19`, `Community 21`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **Are the 47 inferred relationships involving `User` (e.g. with `Base` and `NextAuthSyncRequest`) actually correct?**
  _`User` has 47 INFERRED edges - model-reasoned connections that need verification._
- **Are the 24 inferred relationships involving `AIProviderManager` (e.g. with `AnthropicProvider` and `AIAnalysisResult`) actually correct?**
  _`AIProviderManager` has 24 INFERRED edges - model-reasoned connections that need verification._
- **Are the 28 inferred relationships involving `ScanRecord` (e.g. with `BookmarkCreate` and `BookmarkResponse`) actually correct?**
  _`ScanRecord` has 28 INFERRED edges - model-reasoned connections that need verification._
- **Are the 15 inferred relationships involving `AIProvider` (e.g. with `AnthropicProvider` and `GoogleProvider`) actually correct?**
  _`AIProvider` has 15 INFERRED edges - model-reasoned connections that need verification._