"""Archive containers: ZIP (PyTorch / Keras v3 / NPZ), TAR and GZIP.

Members are listed and read into a bounded buffer; nothing is ever written to
disk and no member is executed.  Every member becomes either a finding (unsafe
name, unsafe type, decompression bomb) or an :class:`Embedded` payload that the
orchestrator scans with the full engine, which is what makes zip-in-zip and
"pickle hidden three levels down" detectable.
"""

from __future__ import annotations

import posixpath
import stat
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from .common import (
    MAX_ARCHIVE_ENTRIES,
    MAX_EMBEDDED_BYTES,
    MAX_EMBEDDED_ITEMS,
    MAX_TOTAL_EMBEDDED_BYTES,
    MAX_COMPRESSION_RATIO,
    Embedded,
    FormatReport,
    KIND_MEMBER,
    Region,
    finding,
    printable,
)


#: Extensions that have no business inside a model archive.
_EXECUTABLE_MEMBERS = {
    ".exe": ("critical", 9.0, "Windows executable"),
    ".dll": ("critical", 9.0, "Windows dynamic library"),
    ".so": ("critical", 8.8, "ELF shared object"),
    ".dylib": ("critical", 8.8, "Mach-O shared library"),
    ".sh": ("high", 8.2, "shell script"),
    ".bash": ("high", 8.2, "shell script"),
    ".bat": ("high", 8.2, "Windows batch script"),
    ".cmd": ("high", 8.2, "Windows batch script"),
    ".ps1": ("high", 8.4, "PowerShell script"),
    ".vbs": ("high", 8.4, "Visual Basic script"),
    ".jar": ("high", 8.0, "Java archive"),
    ".msi": ("critical", 9.0, "Windows installer"),
    ".scr": ("critical", 9.0, "Windows screensaver executable"),
    ".apk": ("high", 8.0, "Android package"),
    ".deb": ("high", 8.0, "Debian package"),
    ".rpm": ("high", 8.0, "RPM package"),
}

_CODE_MEMBERS = {".py", ".pyc", ".pyo", ".pyw", ".pyx", ".ipynb", ".js", ".mjs", ".rb", ".pl", ".php", ".lua"}
_PICKLE_MEMBERS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".dat", ".data", ".model"}
_NESTED_ARCHIVES = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".whl", ".npz", ".keras", ".h5", ".onnx", ".safetensors", ".gguf", ".pb", ".tflite", ".npy", ".msgpack", ".json", ".yaml", ".yml", ".txt", ".md", ".cfg", ".ini", ".toml"}


def zip_report(path: Path, *, hint: str = "zip") -> FormatReport:
    report = FormatReport(status="complete", format=hint)
    metadata: dict[str, Any] = {"container": hint}
    report.metadata = metadata

    declared_entries, directory_size = _eocd_limits(path)
    metadata["declared_entries"] = declared_entries
    metadata["central_directory_bytes"] = directory_size
    if declared_entries is not None and declared_entries > MAX_ARCHIVE_ENTRIES:
        report.cap(f"archive declares {declared_entries:,} entries")
        return report

    total_embedded = 0
    seen_names: dict[str, int] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            metadata["entries"] = len(infos)
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                report.cap(f"archive contains {len(infos):,} entries")
                return report
            uncompressed = sum(info.file_size for info in infos)
            compressed = sum(info.compress_size for info in infos) or 1
            metadata["uncompressed_bytes"] = uncompressed
            metadata["compression_ratio"] = round(uncompressed / compressed, 2)
            if uncompressed / compressed > MAX_COMPRESSION_RATIO and uncompressed > 64 * 1024 * 1024:
                report.add(
                    finding(
                        "AML.ARCHIVE.BOMB", "high", 7.8,
                        f"Archive expands {uncompressed / compressed:.0f}x to "
                        f"{uncompressed:,} bytes, consistent with a decompression bomb.",
                        category="impact",
                        remediation="Do not extract; the archive can exhaust host storage.",
                        cwe=("CWE-409",),
                    )
                )

            for info in infos:
                name = info.filename
                normalized = name.replace("\\", "/")
                seen_names[normalized] = seen_names.get(normalized, 0) + 1
                report.regions.append(
                    Region(
                        name=normalized,
                        start=info.header_offset,
                        end=info.header_offset + info.compress_size,
                        kind=KIND_MEMBER,
                        detail={
                            "compressed": info.compress_size,
                            "uncompressed": info.file_size,
                            "crc": f"{info.CRC:08x}",
                        },
                    )
                )
                _check_member_name(report, normalized)
                mode = info.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    report.add(
                        finding(
                            "AML.ARCHIVE.SYMLINK", "high", 8.0,
                            f"Archive member {printable(normalized)!r} is a symbolic link; "
                            "extraction can redirect writes outside the target directory.",
                            category="format_anomaly", location=normalized,
                            cwe=("CWE-59",),
                        )
                    )
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    report.add(
                        finding(
                            "AML.ARCHIVE.SETUID", "high", 8.2,
                            f"Archive member {printable(normalized)!r} carries a setuid/setgid bit.",
                            category="privilege_escalation", location=normalized,
                            cwe=("CWE-732",),
                        )
                    )
                suffix = posixpath.splitext(normalized)[1].lower()
                classification = _EXECUTABLE_MEMBERS.get(suffix)
                if classification:
                    severity, cvss, label = classification
                    report.add(
                        finding(
                            "AML.ARCHIVE.EXECUTABLE_MEMBER", severity, cvss,
                            f"Model archive ships a {label}: {printable(normalized)!r}.",
                            category="native_code", location=normalized,
                            remediation="Weights archives must contain only tensor data and metadata.",
                            attack=("T1195",), cwe=("CWE-506",),
                        )
                    )
                if (
                    len(report.embedded) < MAX_EMBEDDED_ITEMS
                    and total_embedded < MAX_TOTAL_EMBEDDED_BYTES
                    and info.file_size > 0
                    and _worth_reading(normalized, suffix, info.file_size)
                ):
                    if info.file_size > MAX_EMBEDDED_BYTES:
                        report.add(
                            finding(
                                "AML.ARCHIVE.MEMBER_TOO_LARGE", "medium", 5.0,
                                f"Member {printable(normalized)!r} is {info.file_size:,} bytes; "
                                "deep analysis of this member was skipped.",
                                category="coverage", location=normalized,
                                remediation="Extract the member in isolation and scan it directly.",
                            )
                        )
                        report.status = "capped" if report.status == "complete" else report.status
                        continue
                    try:
                        with archive.open(info) as member:
                            data = member.read(MAX_EMBEDDED_BYTES + 1)
                    except (RuntimeError, zipfile.BadZipFile, OSError, EOFError) as error:
                        report.add(
                            finding(
                                "AML.ARCHIVE.MEMBER_UNREADABLE", "high", 7.0,
                                f"Member {printable(normalized)!r} cannot be read: {str(error)[:120]}.",
                                category="coverage", location=normalized,
                            )
                        )
                        report.status = "capped" if report.status == "complete" else report.status
                        continue
                    if len(data) > MAX_EMBEDDED_BYTES:
                        report.status = "capped" if report.status == "complete" else report.status
                        continue
                    total_embedded += len(data)
                    report.embedded.append(
                        Embedded(
                            path=normalized,
                            data=data,
                            kind="zip_member",
                            declared_size=info.file_size,
                            detail={"offset": info.header_offset},
                        )
                    )

            duplicates = [name for name, count in seen_names.items() if count > 1]
            if duplicates:
                report.add(
                    finding(
                        "AML.ARCHIVE.DUPLICATE_ENTRY", "high", 7.6,
                        f"Archive declares {len(duplicates)} duplicated member name(s) "
                        f"(first: {printable(duplicates[0])!r}); different readers may "
                        "resolve different content for the same path.",
                        category="evasion",
                        remediation="Reject ambiguous archives; rebuild from a trusted source.",
                        cwe=("CWE-706",),
                    )
                )
            _pytorch_expectations(report, hint, [info.filename for info in infos])
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        report.status = "error"
        report.add(
            finding(
                "AML.ARCHIVE.INVALID", "high", 7.0,
                f"Invalid ZIP container: {str(error)[:160]}.",
                category="format_anomaly",
            )
        )
    metadata["embedded_analyzed"] = len(report.embedded)
    return report


def _worth_reading(name: str, suffix: str, size: int) -> bool:
    lowered = name.lower()
    if suffix in _PICKLE_MEMBERS or suffix in _CODE_MEMBERS or suffix in _NESTED_ARCHIVES:
        return True
    if suffix in _EXECUTABLE_MEMBERS:
        return True
    base = posixpath.basename(lowered)
    if base in {"data.pkl", "constants.pkl", "config.json", "metadata.json", "version"}:
        return True
    if lowered.startswith("code/") or "/code/" in lowered:
        return True
    # Unknown extension: small members are cheap to inspect and are exactly
    # where smuggled payloads hide.
    return suffix == "" and size <= 4 * 1024 * 1024


def _check_member_name(report: FormatReport, normalized: str) -> None:
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        report.add(
            finding(
                "AML.ARCHIVE.ABSOLUTE_PATH", "critical", 8.8,
                f"Archive member uses an absolute path: {printable(normalized)!r}.",
                category="format_anomaly", location=normalized, cwe=("CWE-22",),
            )
        )
    if ".." in normalized.split("/"):
        report.add(
            finding(
                "AML.ARCHIVE.PATH_TRAVERSAL", "critical", 9.0,
                f"Archive member escapes the extraction directory: {printable(normalized)!r}.",
                category="format_anomaly", location=normalized,
                remediation="Reject the archive; extraction would overwrite files outside the target.",
                attack=("T1574",), cwe=("CWE-22",),
            )
        )
    if "\x00" in normalized or any(ord(ch) < 0x20 for ch in normalized):
        report.add(
            finding(
                "AML.ARCHIVE.CONTROL_CHARACTER", "high", 7.4,
                "Archive member name contains control characters, which hides its real path.",
                category="evasion", location=printable(normalized), cwe=("CWE-116",),
            )
        )


def _pytorch_expectations(report: FormatReport, hint: str, names: list[str]) -> None:
    if hint != "pytorch":
        return
    lowered = [name.lower().replace("\\", "/") for name in names]
    if not any(name.endswith("data.pkl") or name.endswith(".pkl") for name in lowered):
        report.add(
            finding(
                "AML.PYTORCH.MISSING_PICKLE", "medium", 5.5,
                "PyTorch archive contains no pickle entry; the container may be repacked.",
                category="format_anomaly",
                remediation="Verify the artifact was produced by torch.save.",
                confidence="medium",
            )
        )
    script_members = [name for name in lowered if name.startswith(("code/",)) or "/code/" in name]
    if script_members:
        report.add(
            finding(
                "AML.PYTORCH.TORCHSCRIPT_CODE", "high", 8.0,
                f"Archive ships {len(script_members)} TorchScript source member(s) under code/; "
                "this is executable Python carried inside the weights file.",
                category="code_execution",
                location=script_members[0],
                remediation="Review every code/ member before calling torch.jit.load.",
                attack=("AML.T0010",), cwe=("CWE-506",),
            )
        )


def _eocd_limits(path: Path) -> tuple[int | None, int | None]:
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - (65_535 + 22)))
        tail = stream.read()
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or len(tail) - position < 22:
        return None, None
    fields = struct.unpack("<4s4H2LH", tail[position: position + 22])
    entries, directory_size = fields[4], fields[5]
    if entries == 0xFFFF or directory_size == 0xFFFFFFFF:
        return None, None
    return entries, directory_size


# ---------------------------------------------------------------------------
# TAR
# ---------------------------------------------------------------------------
def tar_report(path: Path) -> FormatReport:
    report = FormatReport(status="complete", format="tar")
    metadata: dict[str, Any] = {"container": "tar"}
    report.metadata = metadata
    total_embedded = 0
    try:
        with tarfile.open(path, mode="r:*") as archive:
            count = 0
            for member in archive:
                count += 1
                if count > MAX_ARCHIVE_ENTRIES:
                    report.cap(f"tar archive exceeds {MAX_ARCHIVE_ENTRIES:,} members")
                    break
                name = member.name.replace("\\", "/")
                report.regions.append(
                    Region(
                        name=name,
                        start=member.offset_data,
                        end=member.offset_data + max(0, member.size),
                        kind=KIND_MEMBER,
                        detail={"size": member.size, "mode": oct(member.mode)},
                    )
                )
                _check_member_name(report, name)
                if member.issym() or member.islnk():
                    report.add(
                        finding(
                            "AML.ARCHIVE.SYMLINK", "high", 8.0,
                            f"Tar member {printable(name)!r} is a link to "
                            f"{printable(member.linkname)!r}.",
                            category="format_anomaly", location=name, cwe=("CWE-59",),
                        )
                    )
                if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                    report.add(
                        finding(
                            "AML.ARCHIVE.DEVICE_NODE", "high", 7.8,
                            f"Tar member {printable(name)!r} is a device or FIFO node.",
                            category="format_anomaly", location=name, cwe=("CWE-732",),
                        )
                    )
                if member.mode & (stat.S_ISUID | stat.S_ISGID):
                    report.add(
                        finding(
                            "AML.ARCHIVE.SETUID", "high", 8.2,
                            f"Tar member {printable(name)!r} carries a setuid/setgid bit.",
                            category="privilege_escalation", location=name, cwe=("CWE-732",),
                        )
                    )
                suffix = posixpath.splitext(name)[1].lower()
                classification = _EXECUTABLE_MEMBERS.get(suffix)
                if classification:
                    severity, cvss, label = classification
                    report.add(
                        finding(
                            "AML.ARCHIVE.EXECUTABLE_MEMBER", severity, cvss,
                            f"Model archive ships a {label}: {printable(name)!r}.",
                            category="native_code", location=name, cwe=("CWE-506",),
                        )
                    )
                if (
                    member.isfile()
                    and len(report.embedded) < MAX_EMBEDDED_ITEMS
                    and total_embedded < MAX_TOTAL_EMBEDDED_BYTES
                    and 0 < member.size <= MAX_EMBEDDED_BYTES
                    and _worth_reading(name, suffix, member.size)
                ):
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    data = handle.read(MAX_EMBEDDED_BYTES)
                    total_embedded += len(data)
                    report.embedded.append(
                        Embedded(path=name, data=data, kind="tar_member", declared_size=member.size)
                    )
            metadata["entries"] = count
    except (OSError, tarfile.TarError, EOFError) as error:
        report.status = "error"
        report.add(
            finding(
                "AML.ARCHIVE.INVALID", "high", 7.0,
                f"Invalid TAR container: {str(error)[:160]}.",
                category="format_anomaly",
            )
        )
    metadata["embedded_analyzed"] = len(report.embedded)
    return report


# ---------------------------------------------------------------------------
# GZIP
# ---------------------------------------------------------------------------
def gzip_report(path: Path) -> FormatReport:
    import gzip

    report = FormatReport(status="complete", format="gzip")
    metadata: dict[str, Any] = {"container": "gzip"}
    report.metadata = metadata
    try:
        with path.open("rb") as raw:
            header = raw.read(10)
            if len(header) < 10 or header[:2] != b"\x1f\x8b":
                raise OSError("missing gzip magic")
            flags = header[3]
            original_name = ""
            if flags & 0x08:
                raw.seek(10)
                name_bytes = bytearray()
                while len(name_bytes) < 1024:
                    byte = raw.read(1)
                    if not byte or byte == b"\x00":
                        break
                    name_bytes += byte
                original_name = name_bytes.decode("utf-8", "replace")
                metadata["original_name"] = original_name
                if "/" in original_name or ".." in original_name:
                    report.add(
                        finding(
                            "AML.ARCHIVE.PATH_TRAVERSAL", "high", 7.6,
                            f"Gzip header stores a path-bearing original name: "
                            f"{printable(original_name)!r}.",
                            category="format_anomaly", cwe=("CWE-22",),
                        )
                    )
        with gzip.open(path, "rb") as stream:
            data = stream.read(MAX_EMBEDDED_BYTES + 1)
        if len(data) > MAX_EMBEDDED_BYTES:
            report.status = "capped"
            report.add(
                finding(
                    "AML.ARCHIVE.MEMBER_TOO_LARGE", "medium", 5.0,
                    "Decompressed gzip stream exceeds the in-memory analysis budget.",
                    category="coverage",
                    remediation="Decompress in isolation and scan the result directly.",
                )
            )
            data = data[:MAX_EMBEDDED_BYTES]
        compressed = path.stat().st_size or 1
        ratio = len(data) / compressed
        metadata["uncompressed_bytes"] = len(data)
        metadata["compression_ratio"] = round(ratio, 2)
        if ratio > MAX_COMPRESSION_RATIO and len(data) > 16 * 1024 * 1024:
            report.add(
                finding(
                    "AML.ARCHIVE.BOMB", "high", 7.8,
                    f"Gzip stream expands {ratio:.0f}x, consistent with a decompression bomb.",
                    category="impact", cwe=("CWE-409",),
                )
            )
        report.embedded.append(
            Embedded(
                path=original_name or f"{path.name}#inflated",
                data=data,
                kind="gzip_stream",
                declared_size=len(data),
            )
        )
    except (OSError, EOFError) as error:
        report.status = "error"
        report.add(
            finding(
                "AML.ARCHIVE.INVALID", "high", 7.0,
                f"Invalid gzip stream: {str(error)[:160]}.",
                category="format_anomaly",
            )
        )
    return report
