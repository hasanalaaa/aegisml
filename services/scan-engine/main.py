import anthropic
import uuid
import json
import os
import subprocess
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="AegisML Scan Engine", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://aegisml.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_results = {}

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}

@app.post("/api/v1/scan/file")
async def scan_file(file: UploadFile = File(...)):
    scan_id = str(uuid.uuid4())
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        temp_path = tmp.name
    try:
        result = await run_inspector(temp_path, file.filename, scan_id)
        result["ai_analysis"] = await claude_judge(result)
        scan_results[scan_id] = result
        return {"scan_id": scan_id, "status": "complete", "result": result}
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.get("/api/v1/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_results[scan_id]

async def run_inspector(file_path: str, filename: str, scan_id: str) -> dict:
    try:
        proc = subprocess.run(
            ["python", "-m", "aegisml", "scan", file_path, "--format", "json"],
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(proc.stdout)
        data["scan_id"] = scan_id
        data["filename"] = filename
        return data
    except Exception as e:
        ext = os.path.splitext(filename)[1].lower()
        risk = 0
        threats = []
        if ext in [".pkl", ".pickle", ".pt", ".pth"]:
            risk = 75
            threats = [{"pattern": "pickle_file", "severity": "high", "description": "Pickle files can execute arbitrary code on load", "location": filename}]
        elif ext == ".gguf":
            risk = 10
        elif ext == ".safetensors":
            risk = 5
        else:
            risk = 50
            threats = [{"pattern": "unknown_format", "severity": "medium", "description": "Unknown file format", "location": filename}]
        return {
            "scan_id": scan_id,
            "filename": filename,
            "risk_score": risk,
            "risk_level": "clean" if risk < 30 else "suspicious" if risk < 60 else "malicious" if risk < 85 else "critical",
            "threats": threats,
            "metadata": {"file_size": os.path.getsize(file_path), "extension": ext},
        }

async def claude_judge(scan_data: dict) -> dict:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "verdict": "UNKNOWN", "confidence": 0,
            "summary_en": "API key not configured.",
            "summary_ar": "مفتاح API غير مضبوط.",
            "key_risks": [],
            "recommendation": "Set ANTHROPIC_API_KEY.",
            "recommendation_ar": "اضبط متغير ANTHROPIC_API_KEY."
        }
    try:
        client = anthropic.Anthropic(api_key=api_key)
        prompt = f"""You are AegisML's AI security analyst.

Scan Results:
- Filename: {scan_data.get('filename')}
- Risk Score: {scan_data.get('risk_score')}/100
- Risk Level: {scan_data.get('risk_level')}
- Threats: {json.dumps(scan_data.get('threats', []))}
- Metadata: {json.dumps(scan_data.get('metadata', {}))}

Respond ONLY with valid JSON, no markdown:
{{
  "verdict": "SAFE or SUSPICIOUS or DANGEROUS or CRITICAL",
  "confidence": 0-100,
  "summary_en": "2-3 sentences in English",
  "summary_ar": "2-3 جمل بالعربية",
  "key_risks": ["risk1", "risk2"],
  "recommendation": "next steps in English",
  "recommendation_ar": "الخطوات التالية بالعربية"
}}"""
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        text = message.content[0].text.replace("```json","").replace("```","").strip()
        return json.loads(text)
    except Exception as e:
        return {
            "verdict": "UNKNOWN", "confidence": 0,
            "summary_en": f"Analysis failed: {str(e)}",
            "summary_ar": f"فشل التحليل: {str(e)}",
            "key_risks": [],
            "recommendation": "Manual review required.",
            "recommendation_ar": "يلزم المراجعة اليدوية."
        }
