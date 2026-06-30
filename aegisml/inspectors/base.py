"""Base data structures for inspection results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


SeverityLevel = Literal["clean", "suspicious", "malicious", "critical"]


@dataclass
class InspectorResult:
    """Represents the outcome of inspecting an AI model file.

    Attributes:
        risk_score: A value from 0 (safe) to 100 (critical threat).
        findings: A list of dictionaries, each describing a single finding.
            Each dict should contain at minimum:
                - "type": short identifier (e.g. "dangerous_call")
                - "detail": human-readable description
                - "severity": one of the SeverityLevel values
        severity: Overall severity classification derived from risk_score.
    """

    risk_score: float = 0.0
    findings: list[dict] = field(default_factory=list)
    severity: SeverityLevel = "clean"

    def __post_init__(self) -> None:
        """Clamp risk_score to [0, 100] and derive severity if not explicitly set."""
        self.risk_score = max(0.0, min(100.0, self.risk_score))

    @staticmethod
    def severity_from_score(score: float) -> SeverityLevel:
        """Derive a severity label from a numeric risk score.

        Args:
            score: Risk score in the range [0, 100].

        Returns:
            The corresponding severity level string.
        """
        if score <= 10:
            return "clean"
        elif score <= 40:
            return "suspicious"
        elif score <= 70:
            return "malicious"
        else:
            return "critical"
