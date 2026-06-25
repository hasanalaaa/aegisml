# 🛡️ AegisML

**AI Model Malware Inspector**

AegisML inspects AI model files (GGUF, SafeTensors, ONNX, etc.) for embedded malware, malicious payloads, and suspicious patterns.

## Installation

```bash
pip install -e .
```

## Usage

```bash
aegisml scan <model_file_path>
```

## Supported Formats

| Format | Status |
|--------|--------|
| GGUF   | ✅ Supported |
| SafeTensors | 🔜 Coming Soon |
| ONNX | 🔜 Coming Soon |
| Pickle (.pt, .pkl) | 🔜 Coming Soon |

## How It Works

AegisML performs deep inspection of AI model files by:

1. **Magic Bytes Validation** — Verifies file format integrity
2. **Metadata Analysis** — Scans metadata fields for suspicious content
3. **Template Injection Detection** — Checks chat templates for code injection
4. **Payload Scanning** — Searches for dangerous function calls and shell commands

## Risk Scoring

| Score Range | Severity | Description |
|-------------|----------|-------------|
| 0–10        | 🟢 Clean | No threats detected |
| 11–40       | 🟡 Suspicious | Minor anomalies found |
| 41–70       | 🟠 Malicious | Dangerous patterns detected |
| 71–100      | 🔴 Critical | Active malware payload found |

## License

MIT License — see [LICENSE](LICENSE) for details.
