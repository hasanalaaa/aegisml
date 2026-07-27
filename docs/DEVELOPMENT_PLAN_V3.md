# AegisML v3 — "Every Atom" Engine Plan

Status: in progress (started 2026-07-27)
Predecessor: `docs/DEVELOPMENT_PLAN.md` (v2, delivered a single streaming engine + CLI)

## 1. What v2 actually delivered (audit)

Verified by reading the tree, not the changelog:

- One streaming engine (`aegisml_scanner/scanner.py`) reading every byte once:
  SHA-256 + literal signatures + entropy in a single pass, memory flat.
- 18 literal rules / 55 signatures. Linear `bytes.find` per pattern per chunk.
- Format inspectors for SafeTensors, GGUF, raw Pickle, PyTorch ZIP only.
- CLI (`scan`, `rules`, `doctor`, `version`), JSON/JSONL/SARIF, exit codes 0/1/2.
- FastAPI service + web UI reusing the same engine.

## 2. Honest gap list (why v2 is not "every atom")

| # | Gap | Impact |
|---|-----|--------|
| G1 | 18 rules, no regex, no custom rule packs, no ATT&CK/CWE mapping | Detection surface far below the real threat corpus |
| G2 | Matching is O(patterns) `find` per chunk | Cannot grow the ruleset without losing throughput |
| G3 | No Keras `.h5` / `.keras` support | Misses Lambda-layer RCE (CVE-2024-3660, CVE-2025-1550, CVE-2025-9905) |
| G4 | No ONNX / TFLite / TF SavedModel support | Misses custom-op + `PyFunc` + external-data path traversal |
| G5 | No `.npy` / `.npz` object-array handling | Misses `allow_pickle` RCE |
| G6 | No TorchScript `code/*.py` extraction | Misses arbitrary Python shipped inside `.pt` |
| G7 | GGUF metadata values are parsed then discarded | Misses `tokenizer.chat_template` Jinja SSTI (CVE-2024-34359) |
| G8 | No repo-level analysis | Misses `auto_map` / `trust_remote_code`, malicious `requirements.txt`, sidecar `.py` |
| G9 | No tensor-level forensics | Misses steganography, NaN/Inf poisoning, unclaimed slack payloads |
| G10 | Findings have file offsets but no semantic location | "byte 4192731" is not actionable; it must say *which tensor / which archive member* |
| G11 | No recursion into nested containers | zip-in-zip, tar.gz, `.pyc` hide payloads |
| G12 | No IOC/known-bad hash matching, no baseline/diff | No supply-chain memory between scans |
| G13 | Pickle analysis is a flat opcode list | No call-graph: cannot say *what* REDUCE actually calls |
| G14 | No local UI; the hosted site is the only visual path | Contradicts "local-first" |

## 3. v3 architecture

```
                  ┌──────────── inventory pass (cheap, structural) ────────────┐
  artifact  ──▶   │ format directory: safetensors hdr / gguf dir / zip CD /    │
                  │ onnx index / npy hdr → REGION MAP (name, span, kind)       │
                  └───────────────────────────────────────────────────────────┘
                                        │
                  ┌──────────── evidence pass (one sequential read) ───────────┐
                  │ sha256+blake2b │ atom-prefiltered multi-pattern matcher    │
                  │ printable-string harvester → regex rules                   │
                  │ block entropy profile │ LSB chi-square │ printable ratio   │
                  └───────────────────────────────────────────────────────────┘
                                        │
                  ┌──────────── deep pass (bounded, no execution) ─────────────┐
                  │ pickle symbolic VM │ archive members (recursive, depth-cap)│
                  │ graph/protobuf ops │ HDF5 objects │ config semantics       │
                  └───────────────────────────────────────────────────────────┘
                                        │
                  correlate offsets → regions → explainable risk → report
```

### Design rules (kept from Ponytail)
- Never execute, import, unpickle, decompress-to-disk, or network anything by default.
- Every limit that is hit downgrades coverage; coverage is never silently "complete".
- Memory is O(chunk + directory), never O(file). 1 TiB must work on a laptop.
- stdlib only for the scanner package. Accelerators are optional, never required.

### Performance strategy (G2)
Atom prefilter: every literal signature registers a rare substring ("atom").
The chunk is scanned once per *distinct atom* (C-level `bytes.find`), not once
per signature. 500 signatures collapse to ~60 atom scans → the ruleset can grow
~10x with no throughput loss. Exactness is preserved: an atom is by construction
a substring of its signature, so stage 2 re-verifies the full signature.

## 4. Work packages

- **WP1** `rules.py` — rule catalog (literal + regex), atoms, ATT&CK/CWE/CVE refs, custom packs.
- **WP2** `matcher.py` — atom filter, streaming matcher, string harvester, entropy/LSB analyzers.
- **WP3** `formats/` — pickle VM, containers, tensor formats, graph formats, HDF5, configs.
- **WP4** `tensors.py` — region map + per-region forensics.
- **WP5** `scanner.py` — orchestrator, repo scanning, correlation, scoring.
- **WP6** `cli.py` + `serve.py` — full local UX, local zero-dependency web UI.
- **WP7** service + DB + web wiring on the same engine.
- **WP8** adversarial test corpus (one synthetic malicious sample per vector) + benchmarks.

## 5. Acceptance criteria

1. A synthetic malicious sample for **every** supported format is detected, with the
   finding carrying a semantic location (tensor name / archive member / opcode offset).
2. Clean reference artifacts for every format produce zero findings above `low`.
3. Peak RSS stays flat (< 200 MB) from 1 MiB to 256 MiB inputs; throughput measured.
4. `pip install` → `aegisml scan` works with zero non-stdlib dependencies.
5. `aegisml serve` gives a working local UI with no network egress.
6. Hosted API returns the same verdict as the CLI for the same bytes.

---

## 6. Evidence log (status: **complete**, 2026-07-27)

### Delivered

| WP | Module | Result |
|----|--------|--------|
| WP1 | `rules.py` | 65 rules / 327 signatures, regex family, ATT&CK+CWE+CVE metadata, JSON rule packs |
| WP2 | `matcher.py` | anchor cover (37 anchors for 327 signatures), two scan tiers, block profiler, text-run gate |
| WP3 | `formats/` | pickle VM, containers (zip/tar/gzip), safetensors, gguf, npy, keras (h5 + v3), onnx, savedmodel, tflite, configs, python, notebooks, requirements |
| WP4 | `tensors.py` | per-tensor text/zero/NaN-Inf/LSB forensics with bit-parallel counting |
| WP5 | `scanner.py`, `parallel.py` | four-pass orchestrator, region correlation, repository correlation, segment-parallel evidence |
| WP6 | `cli.py`, `report.py`, `serve.py` | 7 commands, 7 output formats, zero-dependency local web UI |
| WP7 | service + web | adapter publishes v3 evidence; scan page renders per-finding evidence and an engine-evidence panel |
| WP8 | `tests/corpus.py`, `tests/test_engine_v3.py` | 32 synthetic artifacts, 55 new assertions, all keyed to named rule ids |

### Measured

- **Detection.** Every malicious corpus sample is detected; every clean control
  produces zero findings above `low` (a clean pickle scores 35 — pickle is never
  reported as safe, by design).
- **Throughput** (2-core container, 256 MiB artifact): adaptive 44.5 MiB/s,
  full 20.5 MiB/s, full with 2 jobs 36.3 MiB/s.  On a 1 GiB artifact, full with
  2 jobs reached 123.8 MiB/s.
- **Memory.** Peak RSS 54–57 MB, identical at 256 MiB and 1 GiB — flat, as designed.
- **Quality gates.** 130 tests + 11 subtests pass, 5 skipped (optional SDKs);
  ruff critical rules clean; bandit reports zero medium/high; web `pnpm test`,
  `lint` and `tsc --noEmit` pass.
- **Packaging.** `aegisml_scanner-3.0.0` wheel installs with `--no-deps` into a
  clean venv and scans correctly from outside the repository.
- **UI.** Local `aegisml serve` verified end to end in a headless browser
  (page, path scan, upload scan, path-traversal rejection).

### Known gaps, deliberately left open

1. **Web production build** could not be executed in this environment: `next/font`
   fetches Google Fonts at build time and the sandbox blocks that host. Lint,
   types and unit tests pass, and no font configuration was changed.
2. **Docker images** were not built here (no daemon available).
3. **Adaptive-tier residual risk**: an isolated signature with no printable run of
   ≥24 bytes nearby is only found by `--signatures full`. Documented in README and
   reported per scan in `coverage.signatures`.
4. **`--entropy full`** costs 256 `memchr` passes per byte (~4 MiB/s). It is opt-in
   and only worth it for small artifacts.

### Breaking changes from v2

- Structural rule ids were flattened: `AML.FORMAT.SAFETENSORS.*` → `AML.SAFETENSORS.*`,
  `AML.FORMAT.GGUF.*` → `AML.GGUF.*`, `AML.FORMAT.PICKLE.*` → `AML.PICKLE.*`,
  `AML.FORMAT.ZIP.*` → `AML.ARCHIVE.*`.
- `AML.PICKLE.DANGEROUS_GLOBAL` split into `AML.PICKLE.GLOBAL.{EXEC,GADGET,IMPORT,…}`
  plus the new `AML.PICKLE.EXEC_CALL`, which names the reconstructed call.
- `entropy_mode="auto"` now always means block sampling; `entropy_full_limit` and
  `entropy_sample_bytes` are accepted but no longer change the tier.
- `Threat` gained `region`, `evidence`, `attack`, `cwe`, `references`, `confidence`
  and `source`. Existing fields are unchanged.
