"""Public Python API for the AegisML artifact scanner."""

from .scanner import AegisML, ScanResult, Threat, ENGINE_VERSION
from .rules import RULESET_VERSION

__version__ = "3.0.0"
__author__ = "AegisML Contributors"
__license__ = "MIT"
__all__ = ["AegisML", "ScanResult", "Threat", "ENGINE_VERSION", "RULESET_VERSION"]
