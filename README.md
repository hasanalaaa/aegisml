<div align="center">
  <img src="https://raw.githubusercontent.com/hasanalaaa/aegisml/main/apps/web/public/favicon.ico" width="80" alt="AegisML Logo" />
  <h1>AegisML</h1>
  <p><strong>Advanced AI Model Security & Threat Intelligence Platform</strong></p>
  
  [![License](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
  [![FastAPI](https://img.shields.io/badge/FastAPI-0.103.0-009688?logo=fastapi)](https://fastapi.tiangolo.com)
  [![Next.js](https://img.shields.io/badge/Next.js-14.0-black?logo=next.js)](https://nextjs.org)
  [![GraphQL](https://img.shields.io/badge/GraphQL-Strawberry-E10098?logo=graphql)](https://strawberry.rocks/)
</div>

<br />

## Project Overview
**AegisML** is a next-generation, open-source security scanner tailored specifically for Artificial Intelligence models. As the deployment of AI scales globally, malicious actors exploit serialization formats (like `Pickle`, `ONNX`, and `GGUF`) to embed zero-day trojans, backdoors, and ransomware directly inside model metadata and computational graphs. 

AegisML protects the machine learning supply chain by performing **Deep Structural Scanning** at the byte-level before a model ever reaches memory, preventing catastrophic Remote Code Execution (RCE) and local data exfiltration.

---

## Key Architecture

Our robust microservices architecture was incrementally engineered across 10 structured phases:

### 1. Real-Time Scan Engine
A highly concurrent asynchronous backend utilizing **WebSockets** and **Server-Sent Events (SSE)** fallbacks to broadcast multi-stage file analysis logs in real-time, delivering sub-millisecond status updates to the frontend dashboard.

### 2. Multi-AI Judge Engine (Provider Hub)
A flexible AI integration layer securely mediating between `Anthropic`, `OpenAI`, `Google Gemini`, and `Ollama`. User API keys are stored securely in PostgreSQL encrypted with **AES-256 (Fernet)** cryptography. The AI Judge reads the scan results and generates human-readable forensic reports and remediation strategies.

### 3. Deep Structural Scanner
A heavy-duty forensic module equipped with over **200+ signatures** to detect evasion techniques:
- **Pickle Opcode Tracing**: Simulates Python serialization using custom state machines without executing `__reduce__` hooks.
- **GGUF AST Parsing**: Parses Jinja2 chat templates without triggering sandbox escapes.
- **ONNX Protobuf**: Checks layer weights for embedded arbitrary code nodes.
- **Mathematical Threat Analysis**: Employs **Shannon Entropy** to detect obfuscated byte arrays (Entropy > 7.5 triggers alerts) and calculates automated CVSS v3.1 severity scores.

### 4. Threat Intelligence & CVE Sync
A continuous threat-hunting system running via `APScheduler`. It fetches AI-specific CVEs directly from the **NVD API (National Vulnerability Database)** using Exponential Backoff algorithms to avoid rate-limiting, and matches model hashes against an internal **IOC (Indicators of Compromise) Blacklist**.

### 5. Analytics Hub & Geography
A full-fledged analytical dashboard plotting malicious trends globally. Featuring interactive `Recharts` data visualization, a dynamic `React-Leaflet` GeoMap, and a server-side **PDF Report Generator** using `xhtml2pdf` (zero system-dependencies) and `Jinja2` templating.

### 6. Developer Ecosystem & Webhooks
An enterprise-grade Developer Console empowering organizations to weave AegisML directly into their CI/CD pipelines (e.g., Jenkins, GitHub Actions):
- **GraphQL Gateway**: Built with `Strawberry GraphQL`, providing type-safe and deeply nested queries for threats, scans, and CVE records.
- **Secure Webhooks**: An asynchronous HTTP orchestrator that blasts immediate notifications (`scan.completed`, `threat.critical`) to developer servers, cryptographically signed with **HMAC-SHA256**.

---

## Tech Stack

### Frontend (User Interface)
- **Framework**: Next.js 14 / 15 (App Router)
- **Styling**: Tailwind CSS (Obsidian Black & Gold Aesthetic)
- **Visualization**: Recharts, React-Leaflet
- **Language**: TypeScript (Strict Mode)

### Backend (Scan Engine)
- **Framework**: FastAPI (Python 3.10+)
- **Database**: PostgreSQL with asyncpg & Alembic
- **Caching**: Redis
- **APIs**: Strawberry GraphQL
- **Security**: Cryptography (Fernet AES-256), HMAC-SHA256
- **PDF Generation**: xhtml2pdf & Jinja2

---

## Production Setup

To run AegisML locally or push to a production cloud server (like Vercel and Railway):

### 1. Requirements
- Node.js 18+ and `pnpm`
- Python 3.10+
- PostgreSQL
- Redis Server

### 2. Backend Initialization
```bash
cd services/scan-engine
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Set up environment variables (.env)
cp .env.example .env

# Run database migrations
alembic upgrade head

# Start the FastAPI engine
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 3. Frontend Initialization
```bash
cd apps/web
pnpm install

# Set up environment variables (.env.local)
cp .env.local.example .env.local

# Build the frontend application
pnpm build

# Start Next.js production server
pnpm start
```

## License
AegisML is licensed under the [AGPL 3.0 License](LICENSE).
