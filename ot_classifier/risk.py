"""
ot_classifier.risk
==================
IEC 62443-aligned OT asset risk scoring model.

Implements a T × V × I (Threat × Vulnerability × Impact) scoring
framework producing a risk score per asset on a 0–125 scale.
14 threat-actor patterns are matched to asset zone and device category
to generate context-aware risk scenarios.

Author: Suresh Dakha
Licence: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .classifier import (
    AssetCategory,
    ClassificationResult,
    IEC62443Zone,
    PurdueLevel,
)


# ---------------------------------------------------------------------------
# Risk score dataclass
# ---------------------------------------------------------------------------

@dataclass
class RiskScore:
    """
    T × V × I risk score for a single OT asset.

    Attributes
    ----------
    threat_score : int
        Threat likelihood score (1–5). Based on zone exposure,
        device category, and applicable threat-actor patterns.
    vulnerability_score : int
        Vulnerability score (1–5). Based on Purdue level, device
        category, and unmatched classification flag.
    impact_score : int
        Impact score (1–5). Based on zone criticality and safety
        classification.
    risk_score : int
        Composite score: threat × vulnerability × impact. Max 125.
    risk_band : str
        Qualitative band: Critical (≥75), High (≥40), Medium (≥15),
        Low (<15).
    applicable_threat_patterns : list[str]
        Threat-actor scenario labels applicable to this asset.
    risk_rationale : str
        One-sentence human-readable rationale for the score.
    recommended_controls : list[str]
        IEC 62443 control recommendations mapped to this asset's
        zone and risk band.
    """
    threat_score: int
    vulnerability_score: int
    impact_score: int
    risk_score: int
    risk_band: str
    applicable_threat_patterns: list[str]
    risk_rationale: str
    recommended_controls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "threat_score": self.threat_score,
            "vulnerability_score": self.vulnerability_score,
            "impact_score": self.impact_score,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "applicable_threat_patterns": self.applicable_threat_patterns,
            "risk_rationale": self.risk_rationale,
            "recommended_controls": self.recommended_controls,
        }


# ---------------------------------------------------------------------------
# 14 threat-actor patterns
# ---------------------------------------------------------------------------
# Each pattern defines:
#   applicable_zones   — IEC62443Zone values where this threat is relevant
#   applicable_categories — AssetCategory values where this threat is relevant
#   threat_increment   — added to base threat score when pattern matches
#   label              — human-readable scenario name

_THREAT_PATTERNS: list[dict] = [
    {
        "id": "TP-01",
        "label": "Nation-State APT — Critical Infrastructure Targeting",
        "applicable_zones": {
            IEC62443Zone.SAFETY,
            IEC62443Zone.CRITICAL_OT,
        },
        "applicable_categories": {
            AssetCategory.CONTROL_SYSTEM,
            AssetCategory.SAFETY_SYSTEM,
            AssetCategory.SUPERVISORY,
        },
        "threat_increment": 2,
        "notes": "Nation-state actors (TRITON/TRISIS precedent) actively target SIS and PLC assets in CNI.",
    },
    {
        "id": "TP-02",
        "label": "Ransomware — IT/OT Lateral Movement",
        "applicable_zones": {
            IEC62443Zone.GENERAL_OT,
            IEC62443Zone.IT_OT_BOUNDARY,
            IEC62443Zone.ENTERPRISE,
        },
        "applicable_categories": {
            AssetCategory.HISTORIAN,
            AssetCategory.IT_INFRASTRUCTURE,
            AssetCategory.SUPERVISORY,
        },
        "threat_increment": 2,
        "notes": "Ransomware crossing IT/OT boundary via historian or MES (Colonial Pipeline model).",
    },
    {
        "id": "TP-03",
        "label": "Insider Threat — Privileged OT Access Abuse",
        "applicable_zones": {
            IEC62443Zone.CRITICAL_OT,
            IEC62443Zone.IT_OT_BOUNDARY,
        },
        "applicable_categories": {
            AssetCategory.REMOTE_ACCESS,
            AssetCategory.SUPERVISORY,
            AssetCategory.CONTROL_SYSTEM,
        },
        "threat_increment": 1,
        "notes": "Privileged insider or contractor misuse of engineering workstation or remote access.",
    },
    {
        "id": "TP-04",
        "label": "Supply Chain Compromise — Vendor Software / Firmware",
        "applicable_zones": {
            IEC62443Zone.CRITICAL_OT,
            IEC62443Zone.GENERAL_OT,
        },
        "applicable_categories": {
            AssetCategory.CONTROL_SYSTEM,
            AssetCategory.NETWORKING,
            AssetCategory.FIELD_DEVICE,
        },
        "threat_increment": 1,
        "notes": "Compromised firmware or software delivered via vendor update (SolarWinds / XZ Utils model).",
    },
    {
        "id": "TP-05",
        "label": "Unauthenticated Protocol Exploitation — Legacy OT",
        "applicable_zones": {
            IEC62443Zone.CRITICAL_OT,
            IEC62443Zone.GENERAL_OT,
        },
        "applicable_categories": {
            AssetCategory.CONTROL_SYSTEM,
            AssetCategory.FIELD_DEVICE,
            AssetCategory.NETWORKING,
        },
        "threat_increment": 2,
        "notes": "Exploitation of unauthenticated protocols (Modbus, DNP3, EtherNet/IP) on reachable assets.",
    },
    {
        "id": "TP-06",
        "label": "Remote Access Abuse — Vendor / Third-Party Session",
        "applicable_zones": {
            IEC62443Zone.IT_OT_BOUNDARY,
            IEC62443Zone.OT_DMZ,
        },
        "applicable_categories": {
            AssetCategory.REMOTE_ACCESS,
            AssetCategory.NETWORKING,
        },
        "threat_increment": 2,
        "notes": "Compromised or abused vendor remote access credential used to pivot into OT.",
    },
    {
        "id": "TP-07",
        "label": "Denial of Service — Process Control Network",
        "applicable_zones": {
            IEC62443Zone.CRITICAL_OT,
        },
        "applicable_categories": {
            AssetCategory.NETWORKING,
            AssetCategory.CONTROL_SYSTEM,
            AssetCategory.SUPERVISORY,
        },
        "threat_increment": 1,
        "notes": "Network flood or protocol-specific DoS disrupting real-time control communications.",
    },
    {
        "id": "TP-08",
        "label": "Safety System Bypass — Zone Boundary Violation",
        "applicable_zones": {
            IEC62443Zone.SAFETY,
        },
        "applicable_categories": {
            AssetCategory.SAFETY_SYSTEM,
        },
        "threat_increment": 2,
        "notes": "Direct or indirect attack on SIS bypassing protective functions (TRITON precedent).",
    },
    {
        "id": "TP-09",
        "label": "USB / Removable Media Introduction",
        "applicable_zones": {
            IEC62443Zone.CRITICAL_OT,
            IEC62443Zone.GENERAL_OT,
        },
        "applicable_categories": {
            AssetCategory.SUPERVISORY,
            AssetCategory.CONTROL_SYSTEM,
        },
        "threat_increment": 1,
        "notes": "Malware introduced via removable media on air-gapped or poorly monitored OT assets (Stuxnet model).",
    },
    {
        "id": "TP-10",
        "label": "Historian / DMZ Compromise — Bidirectional Data Flow",
        "applicable_zones": {
            IEC62443Zone.OT_DMZ,
            IEC62443Zone.GENERAL_OT,
        },
        "applicable_categories": {
            AssetCategory.HISTORIAN,
            AssetCategory.IT_INFRASTRUCTURE,
        },
        "threat_increment": 1,
        "notes": "Bidirectional data flow through historian or DMZ used as pivot from enterprise to OT.",
    },
    {
        "id": "TP-11",
        "label": "Physical Access — Unsecured Field Device Tampering",
        "applicable_zones": {
            IEC62443Zone.CRITICAL_OT,
        },
        "applicable_categories": {
            AssetCategory.FIELD_DEVICE,
            AssetCategory.CONTROL_SYSTEM,
        },
        "threat_increment": 1,
        "notes": "Physical access to field devices or PLCs used to install malicious firmware or extract data.",
    },
    {
        "id": "TP-12",
        "label": "Credential Theft — OT Domain / Local Account",
        "applicable_zones": {
            IEC62443Zone.ENTERPRISE,
            IEC62443Zone.IT_OT_BOUNDARY,
        },
        "applicable_categories": {
            AssetCategory.IT_INFRASTRUCTURE,
            AssetCategory.SECURITY,
        },
        "threat_increment": 1,
        "notes": "Stolen AD or local credentials enabling lateral movement into OT-adjacent systems.",
    },
    {
        "id": "TP-13",
        "label": "Zero-Day Exploitation — SCADA / HMI Software",
        "applicable_zones": {
            IEC62443Zone.CRITICAL_OT,
            IEC62443Zone.GENERAL_OT,
        },
        "applicable_categories": {
            AssetCategory.SUPERVISORY,
        },
        "threat_increment": 1,
        "notes": "Zero-day or N-day exploitation of SCADA/HMI software — OT patching cadence typically months to years.",
    },
    {
        "id": "TP-14",
        "label": "Wireless Attack — Rogue AP / Protocol Intercept",
        "applicable_zones": {
            IEC62443Zone.CRITICAL_OT,
            IEC62443Zone.GENERAL_OT,
        },
        "applicable_categories": {
            AssetCategory.NETWORKING,
        },
        "threat_increment": 1,
        "notes": "Rogue access point or protocol interception on industrial wireless infrastructure.",
    },
]


# ---------------------------------------------------------------------------
# Zone and category lookup tables for base scores
# ---------------------------------------------------------------------------

_ZONE_IMPACT: dict[IEC62443Zone, int] = {
    IEC62443Zone.SAFETY:          5,
    IEC62443Zone.CRITICAL_OT:     4,
    IEC62443Zone.GENERAL_OT:      3,
    IEC62443Zone.OT_DMZ:          3,
    IEC62443Zone.IT_OT_BOUNDARY:  2,
    IEC62443Zone.ENTERPRISE:      2,
    IEC62443Zone.UNKNOWN:         3,
}

_ZONE_THREAT_BASE: dict[IEC62443Zone, int] = {
    IEC62443Zone.SAFETY:          2,
    IEC62443Zone.CRITICAL_OT:     3,
    IEC62443Zone.GENERAL_OT:      2,
    IEC62443Zone.OT_DMZ:          3,
    IEC62443Zone.IT_OT_BOUNDARY:  4,
    IEC62443Zone.ENTERPRISE:      3,
    IEC62443Zone.UNKNOWN:         2,
}

_PURDUE_VULNERABILITY: dict[PurdueLevel, int] = {
    PurdueLevel.L0:   4,   # Fieldbus — rarely patchable, no auth
    PurdueLevel.L1:   4,   # PLCs / RTUs — long patch cycles
    PurdueLevel.L2:   3,   # HMI / SCADA — patching constrained
    PurdueLevel.L3:   3,   # Historians / MES — better but OT-constrained
    PurdueLevel.L35:  2,   # DMZ — typically hardened
    PurdueLevel.L4:   2,   # Enterprise — IT patch cadence
}

_RISK_BANDS = [
    (75, "Critical"),
    (40, "High"),
    (15, "Medium"),
    (0,  "Low"),
]

_ZONE_CONTROLS: dict[IEC62443Zone, list[str]] = {
    IEC62443Zone.SAFETY: [
        "IEC 62443-3-2 §6.2: Define Safety zone with highest SL target (SL3–SL4).",
        "IEC 61511 alignment: verify SIL assessment and functional safety lifecycle.",
        "Enforce air-gap or unidirectional gateway between Safety zone and BPCS.",
        "No remote access to SIS without dual-authorisation and session recording.",
    ],
    IEC62443Zone.CRITICAL_OT: [
        "IEC 62443-3-2 §6.2: Assign SL target SL2 minimum; SL3 for critical assets.",
        "IEC 62443-3-3 SR 1.1: Enforce account lockout and unique credentials per asset.",
        "Restrict inbound conduits to named source zones only — deny-all-except.",
        "USB port controls: disable or enforce approved-device whitelist.",
        "Firmware version tracking and vendor advisory monitoring.",
    ],
    IEC62443Zone.GENERAL_OT: [
        "IEC 62443-3-2 §6.2: Assign SL target SL1–SL2.",
        "Restrict bidirectional data flows to read-only where possible.",
        "Enforce patching schedule: OT-specific test-before-deploy process.",
        "Log all access to General OT assets — forward to SIEM via syslog.",
    ],
    IEC62443Zone.OT_DMZ: [
        "IEC 62443-3-2 §6.2.5: DMZ must not allow direct traffic between OT and IT zones.",
        "Enforce data diode or application-layer proxy for all cross-zone flows.",
        "Jump server in DMZ: MFA required, session recording mandatory.",
        "Quarterly firewall rule review — remove any permit-any rules.",
    ],
    IEC62443Zone.IT_OT_BOUNDARY: [
        "MFA on all remote access sessions crossing this boundary.",
        "Vendor remote access: time-limited sessions, dual approval, full recording.",
        "Network Access Control (NAC) for all devices at this boundary.",
        "Deny split-tunnelling on all VPN connections into OT scope.",
    ],
    IEC62443Zone.ENTERPRISE: [
        "Apply IT patching cadence — monthly minimum.",
        "Ensure enterprise assets are not connected to OT VLANs.",
        "Active Directory: OT-specific OU with restricted GPO.",
    ],
    IEC62443Zone.UNKNOWN: [
        "Manual classification required before zone controls can be applied.",
        "Isolate asset on dedicated VLAN pending classification.",
    ],
}


# ---------------------------------------------------------------------------
# Risk scorer
# ---------------------------------------------------------------------------

class OTRiskScorer:
    """
    IEC 62443-aligned T × V × I risk scorer for OT assets.

    Accepts a :class:`~ot_classifier.classifier.ClassificationResult`
    and returns a :class:`RiskScore`.

    Parameters
    ----------
    threat_cap : int
        Maximum threat score before capping (default 5).
    vulnerability_cap : int
        Maximum vulnerability score before capping (default 5).
    impact_cap : int
        Maximum impact score before capping (default 5).

    Examples
    --------
    >>> from ot_classifier import OTAssetClassifier, OTRiskScorer
    >>> clf = OTAssetClassifier()
    >>> scorer = OTRiskScorer()
    >>> result = clf.classify(device_type="SIS", manufacturer="Triconex")
    >>> risk = scorer.score(result)
    >>> risk.risk_band
    'Critical'
    >>> risk.risk_score
    100
    """

    def __init__(
        self,
        threat_cap: int = 5,
        vulnerability_cap: int = 5,
        impact_cap: int = 5,
    ) -> None:
        self._threat_cap = threat_cap
        self._vulnerability_cap = vulnerability_cap
        self._impact_cap = impact_cap

    def score(self, classification: ClassificationResult) -> RiskScore:
        """
        Score a classified OT asset.

        Parameters
        ----------
        classification : ClassificationResult
            Output of :meth:`OTAssetClassifier.classify`.

        Returns
        -------
        RiskScore
        """
        zone = classification.iec62443_zone
        purdue = classification.purdue_level
        category = classification.asset_category

        # ── Threat score ─────────────────────────────────────────────────
        threat = _ZONE_THREAT_BASE.get(zone, 2)
        matched_patterns: list[str] = []

        for pattern in _THREAT_PATTERNS:
            zone_match = zone in pattern["applicable_zones"]
            cat_match = category in pattern["applicable_categories"]
            if zone_match and cat_match:
                threat += pattern["threat_increment"]
                matched_patterns.append(
                    f"{pattern['id']}: {pattern['label']}"
                )

        threat = min(threat, self._threat_cap)

        # ── Vulnerability score ──────────────────────────────────────────
        vulnerability = _PURDUE_VULNERABILITY.get(purdue, 3)

        # Unmatched assets get +1 vulnerability — unknown = uncontrolled
        if classification.classification_path == "unmatched":
            vulnerability = min(vulnerability + 1, self._vulnerability_cap)

        vulnerability = min(vulnerability, self._vulnerability_cap)

        # ── Impact score ─────────────────────────────────────────────────
        impact = _ZONE_IMPACT.get(zone, 3)
        impact = min(impact, self._impact_cap)

        # ── Composite ────────────────────────────────────────────────────
        risk = threat * vulnerability * impact
        band = next(
            label for threshold, label in _RISK_BANDS if risk >= threshold
        )

        # ── Controls ─────────────────────────────────────────────────────
        controls = list(_ZONE_CONTROLS.get(zone, []))

        # ── Rationale ────────────────────────────────────────────────────
        rationale = (
            f"{classification.device_type_matched} in {zone.value} zone "
            f"(Purdue {purdue.value}): T={threat} × V={vulnerability} × I={impact} "
            f"= {risk} ({band}). "
            f"{len(matched_patterns)} threat pattern(s) applicable."
        )

        return RiskScore(
            threat_score=threat,
            vulnerability_score=vulnerability,
            impact_score=impact,
            risk_score=risk,
            risk_band=band,
            applicable_threat_patterns=matched_patterns,
            risk_rationale=rationale,
            recommended_controls=controls,
        )

    def score_batch(
        self, classifications: list[ClassificationResult]
    ) -> list[RiskScore]:
        """
        Score a list of :class:`ClassificationResult` objects.

        Parameters
        ----------
        classifications : list[ClassificationResult]

        Returns
        -------
        list[RiskScore]
        """
        return [self.score(c) for c in classifications]
