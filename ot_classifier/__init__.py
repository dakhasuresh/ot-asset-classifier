"""
ot-asset-classifier
===================
Deterministic IEC 62443-aligned OT asset classification and risk scoring.

Classifies industrial assets into Purdue Model levels, IEC 62443 security
zones, and asset categories using a deterministic rules engine covering 35+
OT device types. Scores each asset using a T × V × I risk model with 14
threat-actor patterns.

Designed for air-gapped OT environments — zero network calls, zero LLM
dependency, zero external services.

Quick start
-----------
>>> from ot_classifier import OTAssetClassifier, OTRiskScorer
>>> clf = OTAssetClassifier()
>>> scorer = OTRiskScorer()
>>>
>>> result = clf.classify(
...     device_type="PLC",
...     manufacturer="Siemens",
...     model="SIMATIC S7-1500",
... )
>>> risk = scorer.score(result)
>>> print(result.purdue_level, result.iec62443_zone, risk.risk_band)
L1 Critical OT High

Author
------
Suresh Dakha — https://github.com/suresh-dakha
"""

from .classifier import (
    AssetCategory,
    ClassificationResult,
    IEC62443Zone,
    OTAssetClassifier,
    PurdueLevel,
)
from .risk import OTRiskScorer, RiskScore

__all__ = [
    "OTAssetClassifier",
    "OTRiskScorer",
    "ClassificationResult",
    "RiskScore",
    "PurdueLevel",
    "IEC62443Zone",
    "AssetCategory",
]

__version__ = "1.0.0"
__author__ = "Suresh Dakha"
__licence__ = "MIT"
