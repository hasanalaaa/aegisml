# 🛡️ AegisML

[![License: MIT](https://img.shields.io/badge/License-MIT-gold.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Version](https://img.shields.io/badge/Version-1.0.0-cyan.svg)]()

> **Trust No Model.** The world's most advanced open-source AI model security scanner.

AegisML intercepts, decompiles, and statically analyzes machine learning models (Pickle, GGUF, Safetensors, ONNX, PyTorch) to detect hidden backdoors, ransomware, and remote code execution payloads *before* they are loaded into memory.

![AegisML UI Dashboard](https://aegisml.vercel.app/og-image.png)

## 🌟 Features

- **Deep AST Scanning**: Decompiles Python pickle operations and inspects the abstract syntax tree for malicious bytecode execution (`eval()`, `exec()`, `os.system`).
- **250+ Threat Patterns**: Utilizes a combination of YARA rules, Shannon entropy scoring, and heuristic signatures to detect obfuscated malware.
- **AI-Powered Diagnostics**: Natural language querying and automated remediation steps powered by Claude AI.
- **Continuous Monitoring**: Automatically intercepts and scans new models uploaded to the HuggingFace Hub.
- **Enterprise Ready**: Role-Based Access Control (RBAC), custom threat signatures, audit logs, and SOC2 compliance tools.
- **CI/CD Integrations**: GitHub Actions, Slack Webhooks, Discord bots, and a fully featured GraphQL v2 API.

## 🛠️ Technology Stack

- **Frontend**: Next.js 15 (App Router), React 19, Framer Motion, Tailwind CSS, Recharts.
- **Backend**: FastAPI, Python 3.11, PostgreSQL, SQLAlchemy, Redis, ARQ Background Tasks.
- **Infrastructure**: Docker, Kubernetes auto-scaling, GitHub Actions CI/CD.
- **Integrations**: Stripe (Billing), Resend (Transactional Email), HuggingFace API, Claude AI.

## 🚀 Quick Start (Self-Hosting)

AegisML is designed to be easily self-hosted using Docker Compose.

```bash
# Clone the repository
git clone https://github.com/hasanalaaa/aegisml.git
cd aegisml

# Start the PostgreSQL and Redis databases
docker-compose up -d db redis

# Start the Scan Engine (Backend)
cd services/scan-engine
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Start the Web App (Frontend)
cd ../../apps/web
pnpm install
pnpm dev
```

The web dashboard will be available at `http://localhost:3000` and the API documentation at `http://localhost:8000/docs`.

## 📚 Documentation & API

Full API documentation, integration guides, and GraphQL schemas are available on the [AegisML Documentation Site](https://aegisml.vercel.app/docs).

## 🤝 Contributing

We welcome contributions from security researchers and developers! Please read our [Contributing Guidelines](CONTRIBUTING.md) and join our [Community Leaderboard](https://aegisml.vercel.app/community) to help rank the safest models.

## 📄 License

AegisML is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
