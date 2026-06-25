<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)
![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-C9A84C?style=flat-square)
![Security](https://img.shields.io/badge/Security-Responsible%20Disclosure-E74C3C?style=flat-square)

# AegisML

**AI Model Malware Inspector**

Scan AI model files for backdoors, trojans, and malicious code — before they reach production.

[Getting Started](#installation) · [How It Works](#how-it-works) · [API Docs](#api-endpoints) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

---

## Why This Matters

AI supply chain attacks are not theoretical — they are happening right now.

> **In 2024, poisoned models were downloaded 244,000 times in just 18 hours** before being detected and removed from Hugging Face. The malicious payloads executed arbitrary code on victims' machines through Python's `pickle` deserialization.

The AI ecosystem has a trust problem:

- **Pickle files execute arbitrary code** on load. A single `torch.load()` call can compromise an entire system.
- **GGUF chat templates** can embed hidden JavaScript or shell commands that execute during inference.
- **Model metadata** can carry C2 (command & control) URLs, base64-encoded payloads, and data exfiltration hooks.
- **Supply chain impersonation** — attackers upload models with names similar to popular ones, hoping users download the wrong version.

AegisML exists to make this class of attack detectable **before** a model is loaded into memory.

---

## Installation

```bash
pip install -e .
```

## Usage

### CLI

```bash
# Scan a model file
aegisml scan model.gguf

# Check supported formats
aegisml help-formats

# Version info
aegisml version
```

### API

```bash
# Start the scan engine
cd services/scan-engine
uvicorn main:app --reload

# Scan a file via API
curl -X POST http://localhost:8000/api/v1/scan/file \
  -F "file=@model.pkl"
```

### Web UI

```bash
cd apps/web
npm install && npm run dev
# Open http://localhost:3000
```

---

## How It Works

AegisML performs deep inspection of AI model files through a multi-stage pipeline:

```
┌─────────────┐    ┌──────────────┐    ┌───────────────┐    ┌────────────┐
│  1. Upload   │───▶│ 2. Static    │───▶│ 3. Behavioral │───▶│ 4. Risk    │
│  Model File  │    │  Analysis    │    │  Check        │    │  Score     │
└─────────────┘    └──────────────┘    └───────────────┘    └────────────┘
                    Magic bytes         __reduce__ hooks     0-100 score
                    Pattern scan        Deserialization       Severity
                    Metadata parse      Template injection    Findings
```

| Stage | What It Does |
|-------|-------------|
| **Magic Bytes Validation** | Verifies file format integrity and detects mismatched extensions |
| **Static Pattern Scan** | Searches for 14+ dangerous patterns: `os.system`, `exec`, `eval`, `subprocess`, `__import__`, `socket`, etc. |
| **Metadata Analysis** | Parses format-specific metadata for URLs, base64 blobs, and suspicious fields |
| **Template Injection** | Checks GGUF chat templates for embedded code injection |
| **Deserialization Hooks** | Detects `__reduce__` / `__reduce_ex__` which enable arbitrary code execution in Pickle files |

---

## Supported Formats

| Format | Extension(s) | Risk Level | Status |
|--------|-------------|-----------|--------|
| GGUF | `.gguf` | Medium | ✅ Supported |
| Python Pickle | `.pkl`, `.pickle` | 🔴 High | ✅ Supported |
| PyTorch | `.pt`, `.pth` | 🔴 High | ✅ Supported |
| SafeTensors | `.safetensors` | 🟢 Low | ✅ Supported |
| ONNX | `.onnx` | Medium | 🔜 Coming Soon |
| TensorFlow | `.pb`, `.h5` | Medium | 🔜 Coming Soon |

## Risk Scoring

| Score Range | Severity | Description |
|-------------|----------|-------------|
| 0–10 | 🟢 Clean | No threats detected |
| 11–40 | 🟡 Suspicious | Minor anomalies found |
| 41–70 | 🟠 Malicious | Dangerous patterns detected |
| 71–100 | 🔴 Critical | Active malware payload found |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service health check |
| `POST` | `/api/v1/scan/file` | Upload and scan a model file |
| `POST` | `/api/v1/scan/hf` | Queue a Hugging Face repo scan |
| `GET` | `/api/v1/scan/{scan_id}` | Retrieve scan result by ID |

---

## How Claude Powers AegisML

AegisML uses **Claude as an LLM Judge** to provide a second layer of intelligent analysis beyond static pattern matching:

### The LLM Judge Pipeline

```
Static Analysis Results ──▶ Claude API ──▶ Enhanced Risk Assessment
```

1. **Context-Aware Analysis**: After the static inspectors identify suspicious patterns, the findings are sent to Claude for contextual evaluation. Claude understands whether a pattern like `open()` is genuinely dangerous (opening `/etc/passwd`) or benign (a Jinja2 template rendering a chat bubble).

2. **Chat Template Reasoning**: GGUF chat templates can contain complex Jinja2 logic. Static regex matching produces false positives on legitimate templates. Claude analyzes the template's actual intent and determines if the code is malicious injection or standard formatting.

3. **Severity Calibration**: Claude adjusts the risk score based on the combination of findings. A single `eval()` in isolation might be suspicious, but `eval()` + `base64` + `socket` together is almost certainly malicious. Claude understands these compound threat patterns.

4. **Natural Language Reports**: Claude generates human-readable explanations of why a model is flagged, making it easier for non-security-experts to understand the threat.

> **Note**: The LLM Judge is an optional enhancement. AegisML's core static analysis works fully offline without any API calls.

---

## Roadmap

### v0.2.0 — Inspector Expansion
- [ ] ONNX inspector (custom operator detection)
- [ ] TensorFlow SavedModel inspector
- [ ] HDF5 / Keras `.h5` inspector
- [ ] Core ML `.mlmodel` inspector

### v0.3.0 — Intelligence Layer
- [ ] Claude LLM Judge integration for contextual analysis
- [ ] Hugging Face Hub integration (auto-download & scan)
- [ ] Community threat signature database
- [ ] YARA rule support for custom pattern matching

### v0.4.0 — Enterprise Features
- [ ] PostgreSQL persistent scan storage
- [ ] Redis job queue for async scanning
- [ ] Webhook notifications (Slack, Discord, email)
- [ ] GitHub Action for CI/CD model scanning
- [ ] SBOM (Software Bill of Materials) generation for models

### v0.5.0 — Ecosystem
- [ ] VS Code extension
- [ ] PyPI package (`pip install aegisml`)
- [ ] Docker Hub published images
- [ ] Grafana dashboard for scan metrics
- [ ] Public API for community model scanning

---

## Project Structure

```
aegisml/
├── aegisml/                  # Python package (CLI + inspectors)
│   ├── cli.py                # Click CLI with Rich output
│   └── inspectors/           # Format-specific inspectors
│       ├── base.py           # InspectorResult dataclass
│       ├── gguf_inspector.py # GGUF format inspector
│       ├── static_inspector.py    # Pickle/PyTorch inspector
│       └── safetensors_inspector.py # SafeTensors inspector
├── services/
│   └── scan-engine/          # FastAPI backend
│       ├── main.py           # API endpoints
│       ├── models.py         # Pydantic models
│       └── Dockerfile
├── apps/
│   └── web/                  # Next.js 15 frontend
│       └── app/page.tsx      # Landing page + scan UI
├── SECURITY.md               # Vulnerability reporting policy
├── CONTRIBUTING.md           # Contributor guide
└── docker-compose.yml        # Container orchestration
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- How to set up your development environment
- How to add new inspectors
- How to add new threat patterns
- PR guidelines and code style

## Security

If you discover a vulnerability in AegisML itself, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for our responsible disclosure policy.

If you've found a malicious AI model in the wild, please use our [Threat Report](https://github.com/aegisml/aegisml/issues/new?template=threat_report.yml) template.

## License

MIT License — see [LICENSE](LICENSE) for details.
