"""
Shared prompt construction and response parsing for all AI providers.

Every provider's analyze() previously returned a hardcoded canned
AIAnalysisResult regardless of the actual scan findings (e.g. explanation
was the literal string "Analyzed via Anthropic" / "Analyzed via OpenAI" /
etc., with empty threats and a single generic recommendation). This module
gives every provider a single, consistent way to (1) turn real scan
findings into a grounded prompt, and (2) parse a model's free-form or
JSON-mode response back into a structured AIAnalysisResult, so the "Multi-
AI Engine" feature actually reflects what each provider says about the
specific file being scanned.
"""
import json
import re
from .base import AIAnalysisResult

ALLOWED_VERDICTS = {"safe", "suspicious", "dangerous", "critical"}

SYSTEM_INSTRUCTIONS = (
    "You are a senior AI/ML security analyst reviewing the output of an "
    "automated static scanner that just inspected an AI model file (pickle "
    "opcodes, GGUF chat templates, safetensors metadata, ONNX graphs, "
    "PyTorch checkpoints, byte-level threat signatures, and Shannon "
    "entropy). You are given the scanner's raw findings and must produce a "
    "concise expert verdict for the end user. "
    "Respond with ONLY a single JSON object — no markdown fences, no prose "
    "outside the JSON — matching exactly this shape:\n"
    '{"verdict": "safe|suspicious|dangerous|critical", '
    '"confidence": <integer 0-100>, '
    '"explanation": "<2-4 sentence plain-English summary of the real risk, '
    'referencing the specific findings>", '
    '"recommendations": ["<actionable step 1>", "<actionable step 2>"]}\n'
    "The verdict must be consistent with severity: if any critical-severity "
    "finding is present, verdict should usually be 'critical' or "
    "'dangerous'; if no findings exist, verdict should be 'safe'."
)


def build_analysis_prompt(file_info: dict, scan_results: dict) -> str:
    """Turn real scan engine output into a grounded prompt. Truncates the
    threat list to the 15 highest-severity findings so the prompt stays a
    reasonable size even for files with hundreds of matches."""
    filename = file_info.get("filename", "unknown")
    size = file_info.get("size", 0)
    threats = scan_results.get("threats", []) or []
    verdict = scan_results.get("verdict") or scan_results.get("risk_level", "unknown")
    format_detected = scan_results.get("format_detected", "unknown")
    entropy = scan_results.get("entropy") or scan_results.get("entropy_analysis") or {}

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_threats = sorted(
        threats, key=lambda t: severity_rank.get(str(t.get("severity", "")).lower(), 0), reverse=True
    )[:15]

    threat_lines = []
    for t in top_threats:
        threat_lines.append(
            f"- [{t.get('severity', '?').upper()}] {t.get('id', t.get('pattern', '?'))} "
            f"\"{t.get('name', t.get('pattern', 'unnamed'))}\" "
            f"(CVSS {t.get('cvss', '?')}, category={t.get('category', '?')}): "
            f"{t.get('description', 'no description')}"
        )
    threats_block = "\n".join(threat_lines) if threat_lines else "(no threats matched by static scan)"

    return (
        f"{SYSTEM_INSTRUCTIONS}\n\n"
        f"--- SCAN CONTEXT ---\n"
        f"Filename: {filename}\n"
        f"File size: {size} bytes\n"
        f"Detected format: {format_detected}\n"
        f"Static engine verdict: {verdict}\n"
        f"Total findings: {len(threats)}\n"
        f"Shannon entropy: {entropy.get('overall_entropy', 'n/a')} "
        f"(risk level: {entropy.get('risk_level', 'n/a')})\n\n"
        f"Top findings:\n{threats_block}\n"
    )


def parse_ai_json_response(raw_text: str, provider: str, model: str) -> AIAnalysisResult:
    """Robustly extract a JSON object from a model response (handles models
    that wrap JSON in ```json fences despite instructions) and convert it
    into an AIAnalysisResult, clamping/validating fields so a malformed or
    partially-wrong response degrades gracefully instead of crashing the
    whole scan pipeline."""
    text = (raw_text or "").strip()

    # Strip markdown code fences if present
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1)
    else:
        # Fall back to grabbing the first {...} block in the text
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            text = brace_match.group(0)

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return AIAnalysisResult(
            verdict="suspicious",
            confidence=0,
            explanation=(
                f"{provider} returned a response that could not be parsed as "
                f"structured JSON. Raw response (truncated): {raw_text[:300]!r}"
            ),
            threats=[],
            recommendations=["Manual review recommended — AI response was malformed."],
            provider=f"{provider}-parse-error",
            model=model,
        )

    verdict = str(data.get("verdict", "suspicious")).lower()
    if verdict not in ALLOWED_VERDICTS:
        verdict = "suspicious"

    try:
        confidence = int(data.get("confidence", 50))
    except (TypeError, ValueError):
        confidence = 50
    confidence = max(0, min(100, confidence))

    explanation = str(data.get("explanation", "")).strip() or "No explanation provided by model."
    recommendations = data.get("recommendations", [])
    if not isinstance(recommendations, list):
        recommendations = [str(recommendations)]
    recommendations = [str(r) for r in recommendations][:10]

    return AIAnalysisResult(
        verdict=verdict,
        confidence=confidence,
        explanation=explanation,
        threats=[],
        recommendations=recommendations or ["No specific recommendations provided."],
        provider=provider,
        model=model,
    )
