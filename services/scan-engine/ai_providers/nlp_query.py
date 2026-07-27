"""
Natural-language threat search.

Ground answers in the same deterministic rule inventory used by the local
scanner. Optional provider output is explanatory and falls back to keyword
matching without fabricating an answer.
"""
import json
import os
import re


def _find_related_patterns(question: str, patterns: list[dict] | None, limit: int = 6) -> list[dict]:
    """Cheap keyword-overlap ranking over the real pattern library — used
    both to ground the prompt and as a safe fallback if the AI call fails."""
    if not patterns:
        from aegisml_scanner import AegisML
        patterns = AegisML.rules()

    question_words = set(re.findall(r"[a-zA-Z]{3,}", question.lower()))
    if not question_words:
        return patterns[:limit]

    scored = []
    for p in patterns:
        haystack = f"{p.get('name', '')} {p.get('description', '')} {p.get('category', '')}".lower()
        score = sum(1 for w in question_words if w in haystack)
        if score > 0:
            scored.append((score, p))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in scored[:limit]] or patterns[:limit]


async def natural_language_query(question: str, patterns: list[dict] | None = None) -> dict:
    related = _find_related_patterns(question, patterns)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        # Graceful, honest degradation — no fabricated answer text.
        names = ", ".join(p.get("name", p.get("id", "?")) for p in related[:3]) or "no close matches"
        return {
            "question": question,
            "answer": (
                "AI-powered answers are not configured on this server "
                "(ANTHROPIC_API_KEY missing). Based on keyword matching against "
                f"the pattern library, the closest related entries are: {names}."
            ),
            "related_patterns": [p.get("id") for p in related if p.get("id")],
            "confidence": 0,
        }

    context_lines = "\n".join(
        f"- {p.get('id')}: {p.get('name') or p.get('id')} [{p.get('severity')}, CVSS {p.get('cvss')}] — {p.get('description')}"
        for p in related
    )
    prompt = (
        "You are AegisML's threat-intelligence assistant. A user is browsing "
        "our library of AI model security threat patterns and asked a "
        "question. Answer using ONLY the pattern excerpts below as ground "
        "truth — do not invent CVEs, pattern IDs, or details not present "
        "here. If nothing below is relevant, say so plainly.\n\n"
        f"Relevant pattern library excerpts:\n{context_lines}\n\n"
        f"User question: {question}\n\n"
        "Respond with ONLY a JSON object: "
        '{"answer": "<2-4 sentence answer>", "related_pattern_ids": ["<id>", ...]}'
    )

    try:
        import anthropic as anthropic_sdk
        client = anthropic_sdk.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_text = "".join(b.text for b in response.content if getattr(b, "type", None) == "text")

        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
        json_text = fence_match.group(1) if fence_match else raw_text
        brace_match = re.search(r"\{.*\}", json_text, re.DOTALL)
        if brace_match:
            json_text = brace_match.group(0)

        data = json.loads(json_text)
        return {
            "question": question,
            "answer": str(data.get("answer", "")).strip() or "No answer returned.",
            "related_patterns": data.get("related_pattern_ids") or [p.get("id") for p in related if p.get("id")],
            "confidence": 85,
        }
    except Exception:
        names = [p.get("id") for p in related if p.get("id")]
        return {
            "question": question,
            "answer": (
                "AI analysis failed. Based on keyword matching, "
                f"the closest related patterns are: {', '.join(names) or 'none found'}."
            ),
            "related_patterns": names,
            "confidence": 0,
        }
