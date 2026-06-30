"""
AegisML Scan Engine — v3.0
Real multi-pass threat detection with format-specific scanning,
entropy analysis, regex matching, and CVSS scoring.
"""
from typing import Any, Optional
import os
import re
import struct
import hashlib
import math

from . import gguf_scanner, safetensors_scanner, pkl_scanner, pt_scanner, onnx_scanner
from .patterns import THREAT_PATTERNS, PATTERN_COUNT
from .entropy import analyze as entropy_analyze
from .cvss import calculate_cvss_v3


class ScanEngine:
    SUPPORTED_FORMATS = {
        ".gguf":        gguf_scanner,
        ".safetensors": safetensors_scanner,
        ".pkl":         pkl_scanner,
        ".pickle":      pkl_scanner,
        ".pt":          pt_scanner,
        ".pth":         pt_scanner,
        ".bin":         pt_scanner,
        ".onnx":        onnx_scanner,
        ".h5":          None,
        ".keras":       None,
        ".npz":         None,
        ".npy":         None,
        ".joblib":      pkl_scanner,
    }

    # Magic byte → format
    MAGIC_BYTES = {
        b"GGUF":                 "gguf",
        b"\x80\x02":             "pickle",
        b"\x80\x03":             "pickle",
        b"\x80\x04":             "pickle",
        b"\x80\x05":             "pickle",
        b"PK\x03\x04":           "zip",
        b"\x1f\x8b":             "gzip",
        b"\x7fELF":              "elf_binary",
        b"MZ":                   "pe_binary",
        b"\xca\xfe\xba\xbe":     "macho_binary",
        b"\x89PNG":              "png",
        b"\xff\xd8\xff":         "jpeg",
        b"%PDF":                 "pdf",
        b"\x52\x61\x72\x21":     "rar",
    }

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    async def scan(
        self,
        file_path: str,
        scan_id: str,
        manager_ws: Optional[Any] = None,
        chunk_size: int = 64 * 1024 * 1024,  # 64MB chunks
    ) -> dict[str, Any]:
        """
        Multi-pass AI model security scanner.
        Pass 1: Magic byte detection & file type validation
        Pass 2: Pattern matching (byte signatures)
        Pass 3: Regex scanning (text-mode patterns)
        Pass 4: Format-specific deep inspection
        Pass 5: Shannon entropy analysis
        Pass 6: CVSS scoring & verdict determination
        """
        ext = os.path.splitext(file_path)[1].lower()
        file_size = os.path.getsize(file_path)
        threats_found: list[dict] = []

        # ── Pass 1: Magic bytes & file metadata ──────────────────────
        await self._emit(manager_ws, scan_id, "header_check", 10,
                         "Validating file headers and magic bytes...", 0)

        file_meta = self._read_header(file_path, file_size)

        # Detect if file extension matches actual format
        if file_meta["detected_format"] in ("elf_binary", "pe_binary", "macho_binary"):
            threats_found.append({
                "id": "FA-EXE-001",
                "name": "Executable Binary Disguised as Model",
                "category": "format_anomaly",
                "severity": "critical",
                "cvss": 9.9,
                "description": f"File has executable binary magic bytes ({file_meta['detected_format']}) but is named as an AI model. Immediate red flag.",
                "remediation": "Do not execute this file. Report to security team immediately.",
                "references": []
            })

        # ── Pass 2: Byte-pattern matching ─────────────────────────────
        await self._emit(manager_ws, scan_id, "signature_scan", 25,
                         f"Running {PATTERN_COUNT}+ byte-signature pattern scan...", 0)

        byte_threats = self._scan_bytes(file_path, file_size, chunk_size)
        threats_found.extend(byte_threats)

        await self._emit(manager_ws, scan_id, "signature_scan", 45,
                         f"Byte scan complete: {len(byte_threats)} potential threats found.", len(threats_found))

        # ── Pass 3: Regex pattern matching (text patterns) ────────────
        await self._emit(manager_ws, scan_id, "regex_scan", 50,
                         "Running regex pattern analysis...", len(threats_found))

        regex_threats = self._scan_regex(file_path, file_size)
        threats_found.extend(regex_threats)

        # ── Pass 4: Format-specific deep scanning ─────────────────────
        await self._emit(manager_ws, scan_id, "structure_scan", 60,
                         "Deep file structure analysis...", len(threats_found))

        scanner_module = self.SUPPORTED_FORMATS.get(ext)
        format_result = {}
        if scanner_module:
            try:
                format_result = scanner_module.scan(file_path)
                if format_result.get("threats_found"):
                    threats_found.extend(format_result["threats_found"])
            except Exception as e:
                format_result = {"error": str(e), "threats_found": []}

        # ── Pass 5: Entropy analysis ───────────────────────────────────
        await self._emit(manager_ws, scan_id, "entropy_scan", 75,
                         "Shannon entropy & obfuscation analysis...", len(threats_found))

        entropy_res = entropy_analyze(file_path)

        # High entropy sections may indicate encrypted payloads
        if entropy_res.get("risk_level") == "critical":
            threats_found.append({
                "id": "ENT-001",
                "name": "Extremely High Entropy Detected",
                "category": "obfuscation",
                "severity": "high",
                "cvss": 7.5,
                "description": f"Shannon entropy {entropy_res.get('overall_entropy', 0):.2f}/8.0 — strongly suggests encrypted or compressed payload hidden in the model.",
                "remediation": "Investigate high-entropy sections. Could be compressed weights (normal) or encrypted malicious payload.",
                "references": []
            })
        elif entropy_res.get("risk_level") == "high":
            threats_found.append({
                "id": "ENT-002",
                "name": "High Entropy Section Detected",
                "category": "obfuscation",
                "severity": "medium",
                "cvss": 5.0,
                "description": f"Shannon entropy {entropy_res.get('overall_entropy', 0):.2f}/8.0 — elevated entropy in model sections. May be normal for compressed weights.",
                "remediation": "Cross-check with model architecture documentation to confirm entropy is expected.",
                "references": []
            })

        # ── Pass 6: File hash ──────────────────────────────────────────
        await self._emit(manager_ws, scan_id, "ai_analysis", 85,
                         "Finalizing analysis and computing file hash...", len(threats_found))

        file_hash = self._hash_file(file_path)

        # ── Pass 7: Deduplicate & score ────────────────────────────────
        unique_threats = self._deduplicate(threats_found)
        scored_threats, highest_cvss = self._score_threats(unique_threats)

        # ── Pass 8: Verdict determination ─────────────────────────────
        verdict = self._determine_verdict(highest_cvss, entropy_res, scored_threats)

        await self._emit(manager_ws, scan_id, "complete", 100,
                         f"Scan complete. Verdict: {verdict.upper()}", len(scored_threats))

        return {
            "verdict": verdict,
            "threat_count": len(scored_threats),
            "threats": scored_threats,
            "entropy_analysis": entropy_res,
            "format_detected": file_meta["detected_format"] or ext[1:],
            "highest_cvss": highest_cvss,
            "file_hash": file_hash,
            "file_size": file_size,
            "patterns_checked": PATTERN_COUNT,
            "format_specific": format_result.get("metadata", {}),
            "scan_passes": ["header_check", "byte_pattern", "regex_pattern",
                            "format_specific", "entropy", "scoring"],
        }

    # ── Private helpers ────────────────────────────────────────────────

    async def _emit(self, manager_ws, scan_id, stage, progress, message, threat_count):
        if manager_ws:
            try:
                await manager_ws.send_progress(scan_id, {
                    "stage": stage,
                    "progress": progress,
                    "message": message,
                    "threat_count": threat_count,
                })
            except Exception:
                pass

    def _read_header(self, file_path: str, file_size: int) -> dict:
        header = b""
        detected_format = "unknown"
        try:
            with open(file_path, "rb") as f:
                header = f.read(min(64, file_size))
            for magic, fmt in self.MAGIC_BYTES.items():
                if header.startswith(magic):
                    detected_format = fmt
                    break
        except Exception:
            pass
        return {"header": header, "detected_format": detected_format, "file_size": file_size}

    def _scan_bytes(self, file_path: str, file_size: int, chunk_size: int) -> list[dict]:
        """Multi-chunk byte-pattern scanning. Handles files larger than RAM."""
        found = []
        matched_ids = set()
        try:
            # Filter to byte patterns only
            byte_patterns = [p for p in THREAT_PATTERNS if p["pattern_type"] == "bytes"]
            with open(file_path, "rb") as f:
                # Overlap window ensures we don't miss patterns that span chunk boundaries
                overlap = 512
                leftover = b""
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    search_space = leftover + chunk
                    for p in byte_patterns:
                        pid = p["id"]
                        if pid in matched_ids:
                            continue
                        try:
                            if p["pattern"] in search_space:
                                matched_ids.add(pid)
                                found.append({
                                    "id": p["id"],
                                    "name": p["name"],
                                    "category": p["category"],
                                    "severity": p["severity"],
                                    "cvss": p["cvss"],
                                    "description": p["description"],
                                    "remediation": p["remediation"],
                                    "references": p.get("references", []),
                                })
                        except Exception:
                            continue
                    leftover = search_space[-overlap:] if len(search_space) > overlap else search_space
        except Exception:
            pass
        return found

    def _scan_regex(self, file_path: str, file_size: int) -> list[dict]:
        """Regex scan over text-decodable portions (first 10MB max)."""
        found = []
        matched_ids = set()
        regex_patterns = [p for p in THREAT_PATTERNS if p["pattern_type"] == "regex"]
        if not regex_patterns:
            return found
        try:
            with open(file_path, "rb") as f:
                raw = f.read(min(10 * 1024 * 1024, file_size))
            # Attempt UTF-8 decode with error replacement
            text = raw.decode("utf-8", errors="replace")
            for p in regex_patterns:
                pid = p["id"]
                if pid in matched_ids:
                    continue
                try:
                    if re.search(p["pattern"], text, re.IGNORECASE | re.DOTALL):
                        matched_ids.add(pid)
                        found.append({
                            "id": p["id"],
                            "name": p["name"],
                            "category": p["category"],
                            "severity": p["severity"],
                            "cvss": p["cvss"],
                            "description": p["description"],
                            "remediation": p["remediation"],
                            "references": p.get("references", []),
                        })
                except re.error:
                    continue
        except Exception:
            pass
        return found

    def _deduplicate(self, threats: list[dict]) -> list[dict]:
        """Remove duplicate findings by ID, keeping highest severity."""
        seen: dict[str, dict] = {}
        for t in threats:
            tid = t.get("id", t.get("name", ""))
            if tid not in seen:
                seen[tid] = t
            else:
                # Keep higher CVSS
                if t.get("cvss", 0) > seen[tid].get("cvss", 0):
                    seen[tid] = t
        return list(seen.values())

    def _score_threats(self, threats: list[dict]) -> tuple[list[dict], float]:
        """Ensure all threats have CVSS scores and find highest."""
        highest = 0.0
        scored = []
        for t in threats:
            cvss = float(t.get("cvss", 0.0))
            highest = max(highest, cvss)
            scored.append({**t, "cvss": round(cvss, 1)})
        # Sort by severity order then CVSS
        scored.sort(
            key=lambda x: (self.SEVERITY_ORDER.get(x.get("severity", "low"), 0), x.get("cvss", 0)),
            reverse=True
        )
        return scored, highest

    def _determine_verdict(self, highest_cvss: float, entropy_res: dict,
                           threats: list[dict]) -> str:
        """Determine overall verdict from CVSS score and entropy."""
        # Any critical severity pattern → at minimum dangerous
        has_critical = any(t.get("severity") == "critical" for t in threats)
        has_high = any(t.get("severity") == "high" for t in threats)

        if highest_cvss >= 9.0 or has_critical:
            return "critical"
        elif highest_cvss >= 7.0 or has_high:
            return "dangerous"
        elif highest_cvss >= 4.0:
            return "suspicious"
        else:
            # Fallback: entropy-based
            entropy_risk = entropy_res.get("risk_level", "low")
            if entropy_risk == "critical":
                return "suspicious"
            return "safe"

    def _hash_file(self, file_path: str) -> str:
        """Compute SHA-256 hash of the file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
        except Exception:
            return "hash_error"
        return sha256.hexdigest()


engine = ScanEngine()
