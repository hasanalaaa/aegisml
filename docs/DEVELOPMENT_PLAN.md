# AegisML production-development plan

Status: completed (release gate passed; environment limitations recorded below)  
Date: 2026-07-26  
Scope: local scanner, CLI, package, service integration, web experience, and verification

## Product objective

AegisML must provide a deterministic, no-execution security scan for AI model
artifacts on a developer's own machine. The primary path must work offline,
without an account or API key, and keep memory usage bounded independently of
artifact size. Hosted services and AI enrichment are optional layers; they must
never be required for the static verdict.

## Audit baseline

The following bullets record the pre-2.0 state found at intake; they are not a
description of the current implementation.

- The installed-package path in `aegisml/scanner.py` reads only the first 10 MiB,
  silently swallows read failures, and does not use the repository's format
  inspectors. It cannot honestly claim a complete local scan.
- The service scanner contains stronger components (streamed byte matching,
  pickle opcode forensics, bounded entropy analysis, admission control), but
  those components are not the local SDK/CLI execution path.
- Local installation currently pulls HTTP and Anthropic SDKs even though an
  offline scan should need only the Python standard library.
- The CLI's `--fail-on-critical` flag is always enabled and cannot be disabled;
  output and error contracts are not stable enough for automation.
- Package metadata says AGPL-3.0 while the checked-in `LICENSE` and README say
  MIT.
- The checkout has no `.git` directory. Change attribution, clean-worktree
  checks, commits, and comparisons against `graphify-out` commit `681ca2c8`
  therefore cannot be performed here.
- `graphify-out/graph.json` exists, but the `graphify` executable is unavailable.
  The generated graph report was used as the documented fallback.
- The active Python has no `pytest`; new core checks will therefore also be
  runnable with the standard-library `unittest` runner.

## Explicit guarantees

1. The generic byte-signature pass reads every byte once unless the OS reports a
   read error or the user cancels it.
2. Memory is `O(chunk_size + rules + findings)`, not `O(file_size)`.
3. The scanner never imports, unpickles, executes, or extracts model content.
4. SHA-256, entropy statistics, signature matching, and byte offsets are produced
   during the same streaming pass.
5. Format parsers are defensive and separately report their coverage and any
   resource cap. A partial deep-format pass cannot be presented as a complete
   semantic analysis.
6. Results are deterministic for the same bytes and rule set. Volatile fields
   such as duration and scan ID are kept separate from evidence.

## Non-goals and honest limits

- No static scanner can prove an arbitrary model safe or detect every future
  exploit. A "safe" verdict means no enabled rule matched and all reported
  passes completed; it is not a mathematical guarantee of harmlessness.
- A 1 TiB full byte scan is supported with bounded memory, but still requires
  reading 1 TiB from storage. Runtime is bounded below by disk throughput.
- Tensor-value backdoors require model- and task-specific behavioral evaluation.
  This iteration detects artifact, serialization, metadata, archive, and supply-
  chain risks; it does not claim universal neural-backdoor detection.
- Remote downloading, cloud orchestration, and AI opinions are not part of the
  trusted local verdict.

## Definition of done

- [x] A payload after the old 10 MiB boundary and a payload spanning two chunks
      are both detected with exact byte offsets.
- [x] Unknown model/file extensions receive a generic scan instead of a false
      "unsupported" result.
- [x] Disguised executable headers are critical findings.
- [x] Scan results expose bytes read, total bytes, full/partial coverage, SHA-256,
      rule-set version, duration, and format evidence.
- [x] SafeTensors and GGUF headers are parsed with strict length/count bounds;
      Pickle/PyTorch are never deserialized and suspicious opcodes/globals are
      surfaced when within the format pass's declared bounds.
- [x] `aegisml scan`, `aegisml rules`, and `aegisml doctor` work offline with
      human and stable machine-readable output.
- [x] Exit code 0 means the command completed below the chosen threshold; 1 means
      a finding met the threshold; 2 means invalid input or incomplete scan.
- [x] The core package has no mandatory third-party runtime dependency.
- [x] Package version/license metadata and README commands agree with reality.
- [x] Focused tests, full available tests, package build/install smoke test, CLI
      smoke test from outside the repository, Python compilation, and web lint/
      build are run and their actual results recorded.

## Iteration 1 — trustworthy local engine

1. Add failing behavior tests for full-file coverage, chunk boundaries, exact
   offsets, arbitrary formats, disguised binaries, deterministic evidence, and
   bounded reads.
2. Replace the 10 MiB local substring scan with one-pass streaming analysis.
3. Connect defensive format inspectors and normalize findings into one schema.
4. Add explicit coverage/error state; remove swallowed exceptions.
5. Re-run focused and regression checks, then refactor only while green.

## Iteration 2 — distribution and operator experience

1. Stabilize the CLI command, output, threshold, progress, and exit-code contract.
2. Make network and AI integrations optional extras; correct package metadata.
3. Add `doctor` and `rules` discovery commands and local install documentation.
4. Apply the highest-impact web fixes found by lint/build and accessibility audit;
   avoid a visual rewrite that is not validated by real scan behavior.
5. Verify installation from an isolated environment and invocation from `/tmp`.

## Iteration 3 — service, web, and release hardening

1. Make the FastAPI engine an adapter over the same trusted local scanner so
   hosted scans do not repeat full-file hashing or use a weaker rule path.
2. Stream uploads and downloads to disk with caps, validate Hugging Face URLs
   against SSRF and redirect abuse, keep scans private by default, and ensure
   BYOK secrets never enter Redis or persistent storage.
3. Remove dead mock routes, synthetic analytics, redundant scanners, unused
   dependencies, unsafe deployment examples, and duplicate OpenAPI routes.
4. Align the Next.js client with the real one-file API contract; fix terminal
   progress ownership, narrow-screen layout, keyboard semantics, accessible
   names, CSP, indexing policy, and local-first endpoint defaults.
5. Exercise a clean wheel, a real SQLite/Redis-free API upload, the production
   web build, vulnerability audits, static security analysis, accessibility,
   and a peak-memory benchmark.

## Decision log

| Decision | Alternatives considered | Reason |
| --- | --- | --- |
| Local-first deterministic verdict | Hosted-only or AI-first verdict | Offline privacy, reproducibility, and failure isolation |
| Python standard library core | Rust rewrite; mandatory native matcher | Reuses the existing package, minimizes installation friction; native acceleration can remain optional |
| Single streamed evidence pass | Separate full-file passes | Reduces 1 TiB I/O amplification and keeps memory bounded |
| Honest pass-level coverage | One binary "scan complete" flag | Format-specific caps must not be hidden behind a generic success label |
| Stable JSON/JSONL/SARIF | Human-only terminal report | Enables CI, automation, and security tooling without scraping text |
| Two implementation rounds | Indefinite feature loop | Completion must be testable; endless additions reduce reliability and violate YAGNI |

## Risk register

| Risk | Mitigation / acceptance test |
| --- | --- |
| Chunk-boundary false negatives | Boundary-focused regression test at several chunk sizes |
| Memory growth with artifact size | Sparse-file test plus peak-memory benchmark on a representative artifact |
| Parser bombs / malicious lengths | Checked arithmetic, hard metadata limits, no extraction or deserialization |
| False confidence from partial deep scan | Per-pass status and coverage in every result and output format |
| Excessive false positives in random weights | Context-specific severity, structural evidence, and benign fixtures |
| CLI output breaks CI | Golden shape assertions and documented exit-code policy |

## Verification ledger

This ledger records fresh evidence from the completed implementation round. A
failed or unavailable check remains visible rather than being rewritten as
success.

| Check | Command | Result |
| --- | --- | --- |
| Full Python contracts | Python 3.12 venv with project + service test dependencies; `python -m pytest -q` | pass: 80 tests and 11 subtests on 2026-07-26 |
| Python syntax/import bytecode | `python3 -m compileall -q aegisml_scanner services/scan-engine` | pass on 2026-07-26 |
| Critical Python lint | `ruff check ... --select E9,F63,F7,F82` | pass on 2026-07-26 |
| Static security scan | `bandit -q -r aegisml_scanner services/scan-engine ... -ll` | pass: zero medium/high findings |
| Service dependency audit | `pip-audit -r services/scan-engine/requirements.txt` | pass: no known vulnerabilities |
| Web dependency audit | `pnpm audit --prod --audit-level=high` | pass: no known vulnerabilities |
| Distribution build | `python -m build` in an isolated builder | pass: sdist and `aegisml_scanner-2.0.0-py3-none-any.whl` |
| Isolated install and identity | install wheel with `--no-deps` in a fresh Python 3.12 venv; run `doctor`, scan from `/tmp`, and `pip check` | pass: offline command, distribution/import identity, clean scan, and dependency integrity |
| Local API end-to-end | SQLite, Redis deliberately unavailable; start Uvicorn, read OpenAPI, upload Pickle, poll result | pass: healthy `inline-only` mode, full byte/SHA-256/deep-format coverage, clean startup log |
| Web contracts and production build | `pnpm test`; `pnpm lint`; `pnpm typecheck`; `pnpm build` | pass: 11 tests, lint, TypeScript, and Next.js 15.5.21 production build |
| Accessibility and narrow viewport | Axe 4.12.1 on default/BYOK states; keyboard pass; 320 px overflow check | pass: zero Axe violations, logical visible focus order, no horizontal overflow or unnamed buttons |
| Peak-memory benchmark | full-entropy scan of a 256 MiB sparse artifact with `/usr/bin/time -l` | pass: 4.84 s, 58,507,264-byte maximum RSS; all 256 MiB read |
| Compose YAML/graph shape | parse `docker-compose.yml`; assert API build target and worker dependencies | pass (static structure only) |
| Docker build / Compose normalization | `docker compose config --quiet` and image builds | unavailable: `docker` executable is not installed; not claimed as verified |
| Graph query/update | `graphify query ...`; `graphify update .` | unavailable: `graphify` executable is not installed; report/wiki fallback used |
| Git worktree review | `git status --short` | unavailable: this checkout has no `.git` directory |
