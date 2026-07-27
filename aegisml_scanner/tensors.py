"""Weight-level forensics — the pass that looks *inside* the numbers.

Structural parsers prove the tensor directory is consistent.  They cannot tell
whether the values themselves were tampered with.  This module samples the
tensor payload and answers three questions that matter operationally:

1. **Is there non-numeric content in a numeric region?**  A dense run of
   printable bytes inside a float tensor is source code or a command line, not
   weights.
2. **Are the values themselves broken?**  NaN/Inf payloads and all-zero tensors
   break or silently disable parts of a network.
3. **Is a covert channel present?**  Steganography in the least-significant bit
   of float mantissas leaves a measurable bias; a chi-square test over a bounded
   sample detects it without reading the whole tensor.

Everything is sampled under a fixed budget, so a 1 TiB model costs the same as a
1 GiB one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from pathlib import Path
from typing import Any, Sequence

from .formats.common import KIND_TENSOR, Region, finding


DEFAULT_SAMPLE_PER_TENSOR = 512 * 1024
DEFAULT_TOTAL_BUDGET = 64 * 1024 * 1024
MAX_TENSORS_SAMPLED = 512
MIN_SAMPLE_FOR_STATS = 4096

_PRINTABLE = bytes(1 if (0x20 <= value <= 0x7E) else 0 for value in range(256))
_ODD = bytes(value & 1 for value in range(256))
_ZERO = bytes(1 if value == 0 else 0 for value in range(256))

# 99.999% critical value for chi-square with one degree of freedom.
_CHI2_CRITICAL = 19.5


@dataclass
class TensorStat:
    name: str
    start: int
    length: int
    sampled: int
    dtype: str = ""
    printable_ratio: float = 0.0
    zero_ratio: float = 0.0
    lsb_ratio: float = 0.5
    lsb_chi2: float = 0.0
    nan_count: int = 0
    inf_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "start": self.start,
            "length": self.length,
            "sampled": self.sampled,
            "dtype": self.dtype,
            "printable_ratio": round(self.printable_ratio, 4),
            "zero_ratio": round(self.zero_ratio, 4),
            "lsb_ratio": round(self.lsb_ratio, 5),
            "lsb_chi2": round(self.lsb_chi2, 2),
            "nan_count": self.nan_count,
            "inf_count": self.inf_count,
        }


@dataclass
class TensorForensics:
    stats: list[TensorStat] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    sampled_bytes: int = 0
    tensors_examined: int = 0
    truncated: bool = False

    def metadata(self) -> dict[str, Any]:
        ranked = sorted(self.stats, key=lambda item: -item.printable_ratio)[:8]
        return {
            "tensors_examined": self.tensors_examined,
            "sampled_bytes": self.sampled_bytes,
            "truncated": self.truncated,
            "most_text_like": [item.to_dict() for item in ranked if item.printable_ratio > 0.3],
        }


def analyze(
    path: Path,
    regions: Sequence[Region],
    *,
    sample_per_tensor: int = DEFAULT_SAMPLE_PER_TENSOR,
    total_budget: int = DEFAULT_TOTAL_BUDGET,
) -> TensorForensics:
    """Sample tensor regions and report value-level anomalies."""
    result = TensorForensics()
    tensors = [region for region in regions if region.kind == KIND_TENSOR and region.length > 0]
    if not tensors:
        return result
    if len(tensors) > MAX_TENSORS_SAMPLED:
        # Sample a deterministic spread rather than the first N, so a payload
        # placed late in a large model is still reachable.
        step = len(tensors) / MAX_TENSORS_SAMPLED
        tensors = [tensors[int(index * step)] for index in range(MAX_TENSORS_SAMPLED)]
        result.truncated = True

    try:
        with path.open("rb") as stream:
            for region in tensors:
                if result.sampled_bytes >= total_budget:
                    result.truncated = True
                    break
                count = min(sample_per_tensor, region.length, total_budget - result.sampled_bytes)
                stream.seek(region.start)
                data = stream.read(count)
                if not data:
                    continue
                result.sampled_bytes += len(data)
                result.tensors_examined += 1
                stat = _measure(region, data)
                result.stats.append(stat)
                _judge(stat, region, result)
    except OSError:
        result.truncated = True
    return result


def _measure(region: Region, data: bytes) -> TensorStat:
    dtype = str(region.detail.get("dtype", ""))
    stat = TensorStat(
        name=region.name,
        start=region.start,
        length=region.length,
        sampled=len(data),
        dtype=dtype,
    )
    total = len(data)
    stat.printable_ratio = data.translate(_PRINTABLE).count(1) / total
    stat.zero_ratio = data.translate(_ZERO).count(1) / total
    odd = data.translate(_ODD).count(1)
    stat.lsb_ratio = odd / total
    # Chi-square for a fair-coin null hypothesis over the low bit.
    expected = total / 2
    stat.lsb_chi2 = ((odd - expected) ** 2 + ((total - odd) - expected) ** 2) / expected if expected else 0.0
    if dtype in {"F32", "F64", "F16", "BF16"} or region.detail.get("float"):
        stat.nan_count, stat.inf_count = _count_special(data, dtype)
    return stat


def _mask(data: bytes, table: bytes) -> int:
    """Map bytes to 0/1 with ``translate`` and return them as one big integer.

    Combining the per-byte predicates with integer bit operations keeps the
    whole test at C speed: no Python-level loop ever touches tensor bytes.
    """
    return int.from_bytes(data.translate(table), "big")


def _table(predicate) -> bytes:
    return bytes(1 if predicate(value) else 0 for value in range(256))


_EXP_ALL_ONES_HIGH = _table(lambda v: (v & 0x7F) == 0x7F)      # F32/BF16 top byte
_HIGH_BIT = _table(lambda v: v >= 0x80)                        # F32 next byte
_EQ_80 = _table(lambda v: v == 0x80)
_EQ_00 = _table(lambda v: v == 0)
_F16_EXP = _table(lambda v: (v & 0x7C) == 0x7C)
_F16_MANTISSA_HIGH = _table(lambda v: (v & 0x03) != 0)


def _count_special(data: bytes, dtype: str) -> tuple[int, int]:
    """Count NaN/Inf encodings without materialising float objects."""
    width = {"F16": 2, "BF16": 2, "F32": 4, "F64": 8}.get(dtype, 4)
    if len(data) < width * 8:
        return 0, 0
    usable = len(data) - (len(data) % width)
    view = data[:usable]
    if width == 4:
        # Little-endian F32: non-finite iff the 8 exponent bits are all ones,
        # i.e. (b3 & 0x7f) == 0x7f and b2 >= 0x80.  Infinity additionally has a
        # zero mantissa: b2 == 0x80 and b1 == b0 == 0.
        exponent = _mask(view[3::4], _EXP_ALL_ONES_HIGH) & _mask(view[2::4], _HIGH_BIT)
        non_finite = exponent.bit_count()
        infinite = (
            exponent
            & _mask(view[2::4], _EQ_80)
            & _mask(view[1::4], _EQ_00)
            & _mask(view[0::4], _EQ_00)
        ).bit_count()
        return non_finite - infinite, infinite
    if width == 2:
        high = view[1::2]
        low = view[0::2]
        if dtype == "F16":
            exponent = _mask(high, _F16_EXP)
            non_finite = exponent.bit_count()
            infinite = (exponent & ~_mask(high, _F16_MANTISSA_HIGH) & _mask(low, _EQ_00)).bit_count()
            return max(0, non_finite - infinite), infinite
        exponent = _mask(high, _EXP_ALL_ONES_HIGH) & _mask(low, _HIGH_BIT)
        non_finite = exponent.bit_count()
        infinite = (exponent & _mask(low, _EQ_80)).bit_count()
        return non_finite - infinite, infinite
    return 0, 0


def _judge(stat: TensorStat, region: Region, result: TensorForensics) -> None:
    if stat.sampled < MIN_SAMPLE_FOR_STATS:
        return
    if stat.printable_ratio > 0.9:
        result.findings.append(
            finding(
                "AML.TENSOR.TEXT_PAYLOAD", "high", 8.2,
                f"Tensor {region.name!r} is {stat.printable_ratio:.0%} printable text over "
                f"{stat.sampled:,} sampled bytes; numeric weights are not text.",
                category="evasion", location=region.name, byte_offsets=[region.start],
                remediation="Extract the region and review it as a file; the model was repacked.",
                cwe=("CWE-506",),
            )
        )
    elif stat.printable_ratio > 0.6:
        result.findings.append(
            finding(
                "AML.TENSOR.TEXT_DENSE", "medium", 5.5,
                f"Tensor {region.name!r} is {stat.printable_ratio:.0%} printable over "
                f"{stat.sampled:,} sampled bytes, which is unusual for numeric data.",
                category="evasion", location=region.name, byte_offsets=[region.start],
                remediation="Confirm the tensor holds weights and not embedded text.",
                confidence="medium",
            )
        )
    if stat.zero_ratio > 0.995 and stat.length > 65536:
        result.findings.append(
            finding(
                "AML.TENSOR.ZERO_FILLED", "low", 3.0,
                f"Tensor {region.name!r} is {stat.zero_ratio:.1%} zero bytes; the layer is "
                "effectively disabled or the checkpoint is incomplete.",
                category="integrity", location=region.name, byte_offsets=[region.start],
                remediation="Verify the export completed; compare against the publisher's file.",
                confidence="medium",
            )
        )
    if stat.nan_count or stat.inf_count:
        share = (stat.nan_count + stat.inf_count) / max(1, stat.sampled // 4)
        severity = "high" if share > 0.01 else "medium"
        result.findings.append(
            finding(
                "AML.TENSOR.NAN_INF", severity, 7.0 if severity == "high" else 5.0,
                f"Tensor {region.name!r} contains {stat.nan_count:,} NaN and "
                f"{stat.inf_count:,} Inf value(s) in the sampled window; these propagate through "
                "the network and can silently destroy or gate outputs.",
                category="integrity", location=region.name, byte_offsets=[region.start],
                remediation="Reject the checkpoint; a trained model does not ship NaN weights.",
                cwe=("CWE-682",),
            )
        )
    # A deliberate LSB channel shows up as an extreme chi-square on bit 0.
    if stat.lsb_chi2 > _CHI2_CRITICAL and stat.dtype in {"F32", "F64"} and stat.sampled >= 65536:
        result.findings.append(
            finding(
                "AML.TENSOR.LSB_ANOMALY", "medium", 6.5,
                f"Tensor {region.name!r} has a skewed least-significant-bit distribution "
                f"(ratio {stat.lsb_ratio:.4f}, chi2 {stat.lsb_chi2:,.0f} over {stat.sampled:,} "
                "bytes), which is consistent with data hidden in the mantissa.",
                category="steganography", location=region.name, byte_offsets=[region.start],
                remediation="Compare the tensor against the publisher's checkpoint byte for byte.",
                cwe=("CWE-506",), confidence="low",
            )
        )


def entropy_of(counts: Sequence[int], total: int) -> float:  # pragma: no cover - helper
    if total <= 0:
        return 0.0
    result = 0.0
    for count in counts:
        if count:
            probability = count / total
            result -= probability * math.log2(probability)
    return result
