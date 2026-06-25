# Contributing to AegisML

Thank you for your interest in making AI models safer! This guide will help you get started with contributing to AegisML.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Adding a New Inspector](#adding-a-new-inspector)
- [Adding New Threat Patterns](#adding-new-threat-patterns)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Reporting Malicious Models](#reporting-malicious-models)

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/aegisml.git
   cd aegisml
   ```
3. **Create a branch** for your work:
   ```bash
   git checkout -b feat/my-new-inspector
   ```

## Development Setup

### Python CLI & Inspectors

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Install in editable mode
pip install -e .

# Verify installation
aegisml --version
```

### Backend (Scan Engine)

```bash
cd services/scan-engine
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend (Web App)

```bash
cd apps/web
npm install
npm run dev
```

---

## Adding a New Inspector

AegisML's architecture makes it easy to add inspectors for new model formats. Here's the step-by-step process:

### Step 1: Create the Inspector File

Create a new file in `aegisml/inspectors/`:

```
aegisml/inspectors/your_format_inspector.py
```

### Step 2: Implement the Inspector Class

Follow this template:

```python
"""YourFormat Model File Inspector."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegisml.inspectors.base import InspectorResult


class YourFormatInspector:
    """Inspector for .yourformat model files.
    
    Describe what this format is, why it may be dangerous,
    and what this inspector checks for.
    """

    SUPPORTED_EXTENSIONS = {".yourformat", ".yf"}

    def inspect(self, file_path: str | Path) -> InspectorResult:
        """Inspect a YourFormat model file and return risk assessment.

        Args:
            file_path: Path to the model file to inspect.

        Returns:
            An InspectorResult with risk score, findings, and severity.
        """
        file_path = Path(file_path)
        findings: list[dict[str, Any]] = []
        risk_score: float = 0.0

        # 1. Validate file exists
        if not file_path.exists():
            findings.append({
                "type": "file_error",
                "detail": f"File not found: {file_path}",
                "severity": "critical",
            })
            return InspectorResult(risk_score=0.0, findings=findings, severity="clean")

        # 2. Validate magic bytes / file header
        # 3. Parse metadata
        # 4. Scan for dangerous patterns
        # 5. Calculate risk score

        clamped = max(0.0, min(100.0, risk_score))
        return InspectorResult(
            risk_score=clamped,
            findings=findings,
            severity=InspectorResult.severity_from_score(clamped),
        )
```

### Step 3: Register the Inspector

1. **Add to `aegisml/inspectors/__init__.py`**:
   ```python
   from aegisml.inspectors.your_format_inspector import YourFormatInspector
   ```

2. **Add to the CLI registry in `aegisml/cli.py`**:
   ```python
   FORMAT_REGISTRY[".yourformat"] = {
       "inspector_cls": YourFormatInspector,
       "label": "YourFormat Description",
       "status": "[green]Supported[/green]",
       "risk_note": "[yellow]Medium[/yellow] -- explain risk",
   }
   ```

3. **Add to the API registry in `services/scan-engine/main.py`**:
   ```python
   _FORMAT_MAP[".yourformat"] = {"cls": YourFormatInspector, "label": "yourformat"}
   ```

### Step 4: Write Tests

Create `tests/test_your_format_inspector.py` with at minimum:

- A test with a valid file (clean result expected)
- A test with a malicious file (findings expected)
- A test with a non-existent file (graceful handling)
- A test with a corrupted file (graceful handling)

### Step 5: Update Documentation

- Add the format to the table in `README.md`
- Update `aegisml help-formats` output if needed

---

## Adding New Threat Patterns

If you've discovered a new attack vector or dangerous pattern, here's how to add it:

### In an Existing Inspector

1. Open the relevant inspector file (e.g., `gguf_inspector.py`)
2. Add your pattern to the `DANGEROUS_PATTERNS` list:

```python
{
    "pattern": r"your_regex_pattern",
    "label": "short_label",
    "description": "Human-readable description of why this is dangerous",
    "weight": 15.0,  # Risk score contribution (use 15 for standard, 40 for critical)
}
```

3. Test with a file that contains the pattern
4. Submit a PR with:
   - The pattern addition
   - A test case
   - A brief explanation of the attack vector

### Risk Weight Guidelines

| Weight | When to Use |
|--------|-------------|
| **5–10** | Informational / minor anomaly |
| **15** | Standard dangerous pattern (e.g., `eval`, `socket`) |
| **20–25** | Code injection / template injection |
| **40** | Arbitrary code execution (e.g., `__reduce__`, deserialization) |

---

## Submitting Changes

### Pull Request Process

1. Ensure your code passes all existing tests
2. Add tests for any new functionality
3. Update documentation as needed
4. Submit a PR with a clear title and description:
   - **feat:** for new features (`feat: add ONNX inspector`)
   - **fix:** for bug fixes (`fix: handle truncated GGUF headers`)
   - **docs:** for documentation (`docs: add SafeTensors format details`)
   - **security:** for detection improvements (`security: add pickle RCE pattern`)

### PR Checklist

- [ ] Code follows the project's style guidelines
- [ ] Tests pass locally
- [ ] New functionality includes tests
- [ ] Documentation is updated
- [ ] Commit messages follow conventional format

---

## Code Style

- **Python**: Follow PEP 8. Use type hints. Docstrings on all public methods.
- **TypeScript**: Follow the existing Next.js conventions.
- **Commits**: Use [Conventional Commits](https://www.conventionalcommits.org/).

---

## Reporting Malicious Models

If you've found a malicious AI model in the wild, please report it using our [Threat Report](https://github.com/aegisml/aegisml/issues/new?template=threat_report.yml) issue template. This helps the community stay safe and improves AegisML's detection capabilities.

---

## Questions?

Open a [Discussion](https://github.com/aegisml/aegisml/discussions) on GitHub or reach out to the maintainers. We're happy to help!
