# ◆ AegisML — AI Model Security Scanner

<div align="center">

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Next.js 15](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org)
[![Claude API](https://img.shields.io/badge/Powered%20by-Claude%20API-orange.svg)](https://anthropic.com)

**Detect backdoors, trojans & malicious code in AI models before running them in production.**

[🌐 Website](https://aegisml.vercel.app) · [📖 API Docs](https://aegisml.vercel.app/docs) · [📊 Dashboard](https://aegisml.vercel.app/dashboard) · [🐛 Issues](https://github.com/hasanalaaa/aegisml/issues)

</div>

---

## 🛡️ What is AegisML?

AegisML is an open-source security scanner for AI model files. It analyzes `.gguf`, `.safetensors`, `.pkl`, `.pt`, and `.pth` files for **14+ known threat patterns** including:

- 🔴 **Critical**: `os.system`, `eval`, `exec`, `__reduce__`, `ctypes`
- 🟠 **High**: `subprocess`, `pickle.loads`, `socket`, `__import__`
- 🟡 **Medium**: `base64`, `requests`, `urllib`, `shutil`

After static analysis, **Claude AI** provides a comprehensive bilingual (Arabic/English) security assessment.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Deep Static Scan** | Byte-level analysis of model files |
| 🤖 **Claude AI Judge** | Intelligent security assessment via Claude API |
| 🔗 **HuggingFace URL Scan** | Scan models directly from HuggingFace URLs |
| 📊 **Public Dashboard** | Live statistics and recent scan history |
| ⚡ **Threat Database** | Open database of 14+ threat patterns |
| 🏷️ **Badge Generator** | Add security badges to your README |
| ⚖️ **Model Comparison** | Compare security of two models side-by-side |
| 🌍 **Bilingual** | Full Arabic and English support |
| 📖 **REST API** | Public API with free API keys |
| 🐍 **Python SDK** | `pip install aegisml` |
| 🔄 **GitHub Action** | CI/CD integration |

## 🚀 Quick Start

### Web Interface
Visit [aegisml.vercel.app](https://aegisml.vercel.app) — no installation required.

### Python Package

```bash
pip install aegisml
```

```python
from aegisml import AegisML

scanner = AegisML()
result = scanner.scan("model.gguf")

print(f"Risk Score: {result.risk_score}/100")
print(f"Verdict:    {result.verdict}")
print(f"Threats:    {len(result.threats)}")

for threat in result.threats:
    print(f"  [{threat.severity}] {threat.pattern}: {threat.description}")
```

### CLI

```bash
# Scan a file
aegisml scan model.pkl

# Output as JSON
aegisml scan model.gguf --format json

# Scan directory
aegisml scan ./models/

# With AI analysis
ANTHROPIC_API_KEY=sk-ant-... aegisml scan model.pkl
```

### GitHub Action

```yaml
- name: Scan AI Models
  uses: hasanalaaa/aegisml@v1
  with:
    model_path: ./models/
    fail_on_critical: "true"
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### REST API

```bash
# Scan a file
curl -X POST https://your-backend.railway.app/api/v1/scan/file \
  -F "file=@model.gguf"

# Scan from HuggingFace URL
curl -X POST https://your-backend.railway.app/api/v1/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://huggingface.co/.../model.gguf"}'

# Get results
curl https://your-backend.railway.app/api/v1/scan/{scan_id}
```

## 🏗️ Project Structure

```
aegisml/
├── aegisml/               ← Python package (pip install aegisml)
│   ├── scanner.py         ← Core scanning engine
│   └── cli.py             ← CLI interface
├── apps/
│   └── web/               ← Next.js 15 frontend
│       └── app/
│           ├── page.tsx           ← Home (scan UI)
│           ├── scan/[id]/         ← Scan results
│           ├── dashboard/         ← Public dashboard
│           ├── docs/              ← API documentation
│           ├── threats/           ← Threat database
│           ├── compare/           ← Model comparison
│           └── badge/[id]/        ← Badge generator
└── services/
    └── scan-engine/       ← FastAPI backend
        ├── main.py        ← API endpoints
        └── database.py    ← SQLAlchemy models
```

## 🔧 Self-Hosting

```bash
# Clone
git clone https://github.com/hasanalaaa/aegisml
cd aegisml

# Backend
cd services/scan-engine
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --host 0.0.0.0 --port 8000

# Frontend
cd apps/web
pnpm install
cp .env.example .env.local
pnpm dev
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🔒 Security

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## 📄 License

AGPL-3.0 — See [LICENSE](LICENSE).

---

<div align="center">
Built with ◆ Claude API · Submitted to Anthropic Open Source Grant 2026
</div>
