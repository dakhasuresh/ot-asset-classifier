"""
ot_classifier.classifier
========================
Deterministic IEC 62443-aligned OT asset classifier.

Classifies industrial assets into Purdue Model levels, IEC 62443 security zones,
and asset categories based on device-type rules. Designed for air-gapped
environments — zero network calls, zero LLM dependency.

Author: Suresh Dakha
Licence: MIT
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class PurdueLevel(str, Enum):
    """Purdue Model levels as defined in IEC 62443-1-1."""
    L0 = "L0"   # Field devices — sensors, actuators
    L1 = "L1"   # Basic control — PLCs, RTUs, drives
    L2 = "L2"   # Supervisory control — SCADA, DCS, HMI
    L3 = "L3"   # Site operations — historians, OT servers
    L35 = "L3.5"  # DMZ / industrial demilitarised zone
    L4 = "L4"   # Enterprise — IT network boundary


class IEC62443Zone(str, Enum):
    """
    IEC 62443-aligned security zone classification.

    Zone assignments drive conduit design, patch cadence, and access
    control requirements under IEC 62443-3-2.
    """
    SAFETY          = "Safety"           # SIS / safety-instrumented systems
    CRITICAL_OT     = "Critical OT"      # L1–L2 process control
    GENERAL_OT      = "General OT"       # L2–L3 supervisory / monitoring
    OT_DMZ          = "OT DMZ"           # L3.5 buffer / data diode zone
    IT_OT_BOUNDARY  = "IT/OT Boundary"   # Firewall, jump server, NAC
    ENTERPRISE      = "Enterprise"       # L4 IT assets in OT scope
    UNKNOWN         = "Unknown"          # Requires manual review


class AssetCategory(str, Enum):
    """Broad functional category used for gap-analysis grouping."""
    FIELD_DEVICE        = "Field Device"
    CONTROL_SYSTEM      = "Control System"
    SAFETY_SYSTEM       = "Safety System"
    NETWORKING          = "Networking"
    SUPERVISORY         = "Supervisory"
    HISTORIAN           = "Historian / Data"
    SECURITY            = "Security"
    REMOTE_ACCESS       = "Remote Access"
    IT_INFRASTRUCTURE   = "IT Infrastructure"
    UNKNOWN             = "Unknown"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    """
    Output of the deterministic classifier for a single asset.

    Attributes
    ----------
    device_type_matched : str
        The canonical device-type label matched by the rules engine,
        or 'Unknown' if no rule fired.
    purdue_level : PurdueLevel
        Assigned Purdue Model level.
    iec62443_zone : IEC62443Zone
        Assigned IEC 62443 security zone.
    asset_category : AssetCategory
        Functional category.
    classification_path : str
        'deterministic' — rule matched; 'unmatched' — no rule fired.
    confidence : float
        1.0 for deterministic matches; 0.0 for unmatched.
    matched_rule : Optional[str]
        The rule key that fired, for audit traceability.
    observations : list[str]
        Human-readable notes appended during classification.
    """
    device_type_matched: str
    purdue_level: PurdueLevel
    iec62443_zone: IEC62443Zone
    asset_category: AssetCategory
    classification_path: str
    confidence: float
    matched_rule: Optional[str] = None
    observations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "device_type_matched": self.device_type_matched,
            "purdue_level": self.purdue_level.value,
            "iec62443_zone": self.iec62443_zone.value,
            "asset_category": self.asset_category.value,
            "classification_path": self.classification_path,
            "confidence": self.confidence,
            "matched_rule": self.matched_rule,
            "observations": self.observations,
        }


# ---------------------------------------------------------------------------
# Device-type rule definitions
# ---------------------------------------------------------------------------
# Each rule is keyed by a canonical device-type label.
# 'patterns' are matched (case-insensitive) against the concatenated
# device_type + manufacturer + model string supplied by the caller.
# Rules fire on ANY pattern match — first match wins.

_DEVICE_RULES: list[dict] = [

    # ── Safety systems ──────────────────────────────────────────────────────
    {
        "key": "SIS",
        "label": "Safety Instrumented System (SIS)",
        "patterns": [
            r"\bsis\b", r"safety.*instrument", r"safety.*controller",
            r"\btrip\b.*system", r"emergency.*shutdown", r"\besd\b",
            r"safety.*plc", r"triconex", r"hima", r"pilz",
        ],
        "purdue_level": PurdueLevel.L1,
        "zone": IEC62443Zone.SAFETY,
        "category": AssetCategory.SAFETY_SYSTEM,
        "observations": [
            "SIS assets require IEC 61511 alignment in addition to IEC 62443.",
            "Verify air-gap or unidirectional gateway between SIS and Basic Process Control.",
        ],
    },
    {
        "key": "FIRE_GAS",
        "label": "Fire and Gas System",
        "patterns": [
            r"fire.*gas", r"\bfgs\b", r"fire.*detection",
            r"gas.*detection", r"flame.*detector",
        ],
        "purdue_level": PurdueLevel.L1,
        "zone": IEC62443Zone.SAFETY,
        "category": AssetCategory.SAFETY_SYSTEM,
        "observations": [
            "Fire and Gas systems are Safety zone assets — confirm conduit controls to adjacent zones.",
        ],
    },

    # ── Field devices (L0) ──────────────────────────────────────────────────
    {
        "key": "SENSOR",
        "label": "Field Sensor / Transmitter",
        "patterns": [
            r"\bsensor\b", r"transmitter", r"\bflow\b.*meter",
            r"pressure.*transmit", r"temperature.*transmit",
            r"\blevel\b.*transmit", r"\bpt\b\d", r"\bft\b\d", r"\btt\b\d",
        ],
        "purdue_level": PurdueLevel.L0,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.FIELD_DEVICE,
        "observations": [],
    },
    {
        "key": "ACTUATOR",
        "label": "Actuator / Final Control Element",
        "patterns": [
            r"\bactuator\b", r"control.*valve", r"\bvalve\b.*position",
            r"\bvfd\b", r"variable.*freq", r"motor.*control",
            r"\bpositioner\b",
        ],
        "purdue_level": PurdueLevel.L0,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.FIELD_DEVICE,
        "observations": [],
    },

    # ── PLCs / RTUs / Controllers (L1) ──────────────────────────────────────
    {
        "key": "PLC",
        "label": "Programmable Logic Controller (PLC)",
        "patterns": [
            r"\bplc\b", r"programmable.*logic",
            r"simatic\s*s7", r"controllogix", r"compactlogix",
            r"micrologix", r"modicon", r"schneider.*m\d{3}",
            r"omron.*cj", r"omron.*cs", r"ge.*rx3i", r"ge.*rx7i",
            r"beckhoff", r"codesys.*runtime",
        ],
        "purdue_level": PurdueLevel.L1,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.CONTROL_SYSTEM,
        "observations": [
            "Confirm firmware version and patch status against vendor security advisories.",
            "Verify no direct IT network connectivity — conduit through L2 only.",
        ],
    },
    {
        "key": "RTU",
        "label": "Remote Terminal Unit (RTU)",
        "patterns": [
            r"\brtu\b", r"remote.*terminal",
            r"sixnet", r"bristol.*babcock", r"emerson.*roc",
            r"totalflow", r"moxa.*nport.*server",
        ],
        "purdue_level": PurdueLevel.L1,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.CONTROL_SYSTEM,
        "observations": [
            "RTUs frequently use legacy protocols (Modbus, DNP3) — confirm protocol gateway controls.",
        ],
    },
    {
        "key": "DCS_CONTROLLER",
        "label": "DCS Controller / Process Controller",
        "patterns": [
            r"\bdcs\b.*controller", r"process.*controller",
            r"delta.*v.*controller", r"centum", r"experion.*controller",
            r"ovation.*controller", r"system\s*800xa",
        ],
        "purdue_level": PurdueLevel.L1,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.CONTROL_SYSTEM,
        "observations": [],
    },
    {
        "key": "DRIVE",
        "label": "Variable Speed Drive / Inverter",
        "patterns": [
            r"\bdrive\b", r"inverter", r"frequency.*converter",
            r"abb.*acs\d", r"sinamics", r"powerflex",
            r"altivar", r"danfoss.*fc",
        ],
        "purdue_level": PurdueLevel.L1,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.FIELD_DEVICE,
        "observations": [],
    },

    # ── SCADA / DCS / HMI (L2) ──────────────────────────────────────────────
    {
        "key": "SCADA_SERVER",
        "label": "SCADA Server",
        "patterns": [
            r"scada.*server", r"\bscada\b",
            r"wonderware", r"intouch", r"ignition.*server",
            r"wincc.*server", r"factorytalk.*view",
            r"genesis64", r"citect.*server",
        ],
        "purdue_level": PurdueLevel.L2,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.SUPERVISORY,
        "observations": [
            "SCADA servers are high-value targets — verify account lockout, MFA on remote access, and backup integrity.",
        ],
    },
    {
        "key": "DCS_WORKSTATION",
        "label": "DCS Engineering / Operator Workstation",
        "patterns": [
            r"dcs.*workstation", r"engineer.*station",
            r"operator.*station", r"dcs.*hmi",
            r"delta.*v.*workstation", r"experion.*workstation",
        ],
        "purdue_level": PurdueLevel.L2,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.SUPERVISORY,
        "observations": [
            "Engineering workstations carry full DCS access — apply least-privilege and USB port controls.",
        ],
    },
    {
        "key": "HMI",
        "label": "Human-Machine Interface (HMI)",
        "patterns": [
            r"\bhmi\b", r"human.*machine",
            r"panel.*pc", r"operator.*panel",
            r"proface", r"weintek", r"simatic.*hmi",
            r"rsview", r"kepware.*hmi",
        ],
        "purdue_level": PurdueLevel.L2,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.SUPERVISORY,
        "observations": [
            "Confirm OS patch status — embedded Windows HMIs are frequently unpatched.",
        ],
    },
    {
        "key": "EWS",
        "label": "Engineering Workstation (OT)",
        "patterns": [
            r"engineering.*workstation", r"\bews\b",
            r"programming.*station", r"ladder.*logic.*pc",
        ],
        "purdue_level": PurdueLevel.L2,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.SUPERVISORY,
        "observations": [
            "EWS typically holds PLC program backups — classify as Critical OT and restrict physical access.",
        ],
    },

    # ── Historians / OT servers (L3) ─────────────────────────────────────────
    {
        "key": "HISTORIAN",
        "label": "Process Historian",
        "patterns": [
            r"historian", r"osisoft", r"\bpi\b.*server",
            r"aspentech", r"ip21", r"planthistorian",
            r"wonderware.*historian", r"inductive.*historian",
        ],
        "purdue_level": PurdueLevel.L3,
        "zone": IEC62443Zone.GENERAL_OT,
        "category": AssetCategory.HISTORIAN,
        "observations": [
            "Historian is a key IT/OT integration point — verify read-only conduit from L2 and restrict write-back paths.",
        ],
    },
    {
        "key": "MES",
        "label": "Manufacturing Execution System (MES)",
        "patterns": [
            r"\bmes\b", r"manufacturing.*execut",
            r"wonderware.*mes", r"simatic.*it", r"rockwell.*ft.*production",
            r"apriso", r"camstar",
        ],
        "purdue_level": PurdueLevel.L3,
        "zone": IEC62443Zone.GENERAL_OT,
        "category": AssetCategory.SUPERVISORY,
        "observations": [
            "MES interfaces to both L2 OT and L4 ERP — conduit design must define trust boundaries explicitly.",
        ],
    },
    {
        "key": "OT_FILE_SERVER",
        "label": "OT File / Application Server",
        "patterns": [
            r"ot.*server", r"plant.*server",
            r"ot.*file", r"industrial.*application.*server",
        ],
        "purdue_level": PurdueLevel.L3,
        "zone": IEC62443Zone.GENERAL_OT,
        "category": AssetCategory.IT_INFRASTRUCTURE,
        "observations": [],
    },

    # ── OT networking ────────────────────────────────────────────────────────
    {
        "key": "OT_SWITCH",
        "label": "OT / Industrial Network Switch",
        "patterns": [
            r"industrial.*switch", r"managed.*switch",
            r"stratix", r"scalance", r"hirschmann",
            r"moxa.*switch", r"phoenix.*fl.*switch",
            r"ruggedcom",
        ],
        "purdue_level": PurdueLevel.L2,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.NETWORKING,
        "observations": [
            "Confirm VLAN segmentation aligns with proposed zone and conduit model.",
            "Check for unused ports — disable and document.",
        ],
    },
    {
        "key": "OT_FIREWALL",
        "label": "OT Firewall / Industrial Demilitarised Zone",
        "patterns": [
            r"ot.*firewall", r"industrial.*firewall",
            r"tofino", r"fortinet.*ot", r"checkpoint.*ot",
            r"palo.*alto.*ot", r"claroty.*firewall",
            r"idmz", r"industrial.*dmz",
        ],
        "purdue_level": PurdueLevel.L35,
        "zone": IEC62443Zone.OT_DMZ,
        "category": AssetCategory.NETWORKING,
        "observations": [
            "Firewall rule review required — verify deny-all-except approach for zone boundary conduits.",
        ],
    },
    {
        "key": "DATA_DIODE",
        "label": "Data Diode / Unidirectional Gateway",
        "patterns": [
            r"data.*diode", r"unidirectional.*gateway",
            r"waterfall.*security", r"owl.*cyber",
            r"foxtech.*diode",
        ],
        "purdue_level": PurdueLevel.L35,
        "zone": IEC62443Zone.OT_DMZ,
        "category": AssetCategory.NETWORKING,
        "observations": [
            "Data diode enforces hardware-level unidirectionality — confirm data flow direction aligns with security design.",
        ],
    },
    {
        "key": "PROTOCOL_GATEWAY",
        "label": "Protocol Gateway / Converter",
        "patterns": [
            r"protocol.*gateway", r"protocol.*converter",
            r"modbus.*gateway", r"dnp3.*gateway",
            r"opc.*gateway", r"kepserver", r"matrikon",
            r"moxa.*nport", r"anybus",
        ],
        "purdue_level": PurdueLevel.L2,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.NETWORKING,
        "observations": [
            "Protocol gateways are conduit devices — apply IEC 62443-3-2 conduit controls and restrict management access.",
        ],
    },
    {
        "key": "WIRELESS_AP",
        "label": "Industrial Wireless Access Point",
        "patterns": [
            r"wireless.*ap", r"industrial.*wifi",
            r"cisco.*1530", r"cisco.*1560",
            r"moxa.*wap", r"prosoft.*wireless",
            r"\biwap\b",
        ],
        "purdue_level": PurdueLevel.L2,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.NETWORKING,
        "observations": [
            "Wireless in OT requires WPA3 or WPA2-Enterprise minimum — verify rogue AP detection is active.",
        ],
    },

    # ── Remote access ────────────────────────────────────────────────────────
    {
        "key": "JUMP_SERVER",
        "label": "OT Jump Server / Privileged Access Workstation",
        "patterns": [
            r"jump.*server", r"jump.*host", r"bastion.*host",
            r"paw\b", r"privileged.*access.*workstation",
            r"secure.*access.*server",
        ],
        "purdue_level": PurdueLevel.L35,
        "zone": IEC62443Zone.IT_OT_BOUNDARY,
        "category": AssetCategory.REMOTE_ACCESS,
        "observations": [
            "Jump server must enforce MFA and session recording — verify PAM tooling.",
            "Confirm no split-tunnelling on vendor remote access sessions.",
        ],
    },
    {
        "key": "VPN_CONCENTRATOR",
        "label": "VPN Concentrator / Remote Access Gateway",
        "patterns": [
            r"vpn.*concentrat", r"remote.*access.*gateway",
            r"cisco.*asa", r"palo.*alto.*gateway",
            r"fortinet.*vpn", r"globalprotect",
        ],
        "purdue_level": PurdueLevel.L35,
        "zone": IEC62443Zone.IT_OT_BOUNDARY,
        "category": AssetCategory.REMOTE_ACCESS,
        "observations": [
            "All remote access to OT must traverse jump server — VPN termination at IT/OT boundary only.",
        ],
    },
    {
        "key": "VENDOR_REMOTE",
        "label": "Vendor Remote Access System",
        "patterns": [
            r"vendor.*remote", r"third.*party.*remote",
            r"team.*viewer.*ot", r"secomea",
            r"tosibox", r"ewon.*flexy",
            r"netbiter", r"mbconnect",
        ],
        "purdue_level": PurdueLevel.L35,
        "zone": IEC62443Zone.IT_OT_BOUNDARY,
        "category": AssetCategory.REMOTE_ACCESS,
        "observations": [
            "Vendor remote access requires time-limited sessions, dual approval, and session recording — confirm controls.",
        ],
    },

    # ── OT security tools ────────────────────────────────────────────────────
    {
        "key": "OT_IDS",
        "label": "OT Intrusion Detection System (IDS)",
        "patterns": [
            r"ot.*ids", r"ot.*intrusion",
            r"claroty", r"nozomi", r"dragos",
            r"armis.*ot", r"forescout.*ot",
            r"tenable.*ot", r"cisco.*cyber.*vision",
            r"radiflow", r"securitymatters",
        ],
        "purdue_level": PurdueLevel.L3,
        "zone": IEC62443Zone.GENERAL_OT,
        "category": AssetCategory.SECURITY,
        "observations": [
            "Passive OT IDS — confirm span port configuration and that no active probing is enabled.",
        ],
    },
    {
        "key": "PATCH_MGT",
        "label": "OT Patch Management System",
        "patterns": [
            r"patch.*management", r"wsus.*ot",
            r"sccm.*ot", r"tpam",
            r"ot.*patch", r"industrial.*patch",
        ],
        "purdue_level": PurdueLevel.L3,
        "zone": IEC62443Zone.GENERAL_OT,
        "category": AssetCategory.SECURITY,
        "observations": [
            "OT patch management requires vendor pre-approval — confirm patch test process before deployment.",
        ],
    },

    # ── IT/OT boundary assets ────────────────────────────────────────────────
    {
        "key": "DOMAIN_CONTROLLER",
        "label": "Active Directory Domain Controller",
        "patterns": [
            r"domain.*controller", r"\badc\b", r"\bdc\b.*windows",
            r"active.*directory",
        ],
        "purdue_level": PurdueLevel.L4,
        "zone": IEC62443Zone.ENTERPRISE,
        "category": AssetCategory.IT_INFRASTRUCTURE,
        "observations": [
            "AD in OT scope — confirm OT-specific OU with restricted GPO and no internet-facing exposure.",
        ],
    },
    {
        "key": "SIEM",
        "label": "SIEM / Log Aggregation",
        "patterns": [
            r"\bsiem\b", r"security.*information.*event",
            r"splunk", r"qradar", r"sentinel.*siem",
            r"logrhythm", r"arcsight",
        ],
        "purdue_level": PurdueLevel.L4,
        "zone": IEC62443Zone.ENTERPRISE,
        "category": AssetCategory.SECURITY,
        "observations": [
            "Confirm OT log sources are forwarded via syslog — no direct SIEM agent on L1/L2 assets.",
        ],
    },
    {
        "key": "IT_SERVER",
        "label": "IT Server (in OT scope)",
        "patterns": [
            r"windows.*server", r"linux.*server",
            r"\bvm\b.*server", r"vmware.*esxi",
            r"hypervisor",
        ],
        "purdue_level": PurdueLevel.L4,
        "zone": IEC62443Zone.ENTERPRISE,
        "category": AssetCategory.IT_INFRASTRUCTURE,
        "observations": [],
    },

    # ── OT-specific protocols and field bus ──────────────────────────────────
    {
        "key": "FIELDBUS_DEVICE",
        "label": "Fieldbus Device (PROFIBUS / FOUNDATION Fieldbus / DeviceNet)",
        "patterns": [
            r"profibus", r"foundation.*fieldbus",
            r"devicenet", r"controlnet",
            r"fieldbus.*device", r"ff.*device",
        ],
        "purdue_level": PurdueLevel.L0,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.FIELD_DEVICE,
        "observations": [
            "Legacy fieldbus protocols have no authentication — physical access controls are primary mitigation.",
        ],
    },
    {
        "key": "OPC_SERVER",
        "label": "OPC Server / OPC-UA Gateway",
        "patterns": [
            r"opc.*server", r"opc.*ua",
            r"opc.*da", r"kepserver.*ex",
            r"matrikon.*opc", r"softing.*opc",
        ],
        "purdue_level": PurdueLevel.L2,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.NETWORKING,
        "observations": [
            "OPC-UA: confirm certificate-based authentication is enabled — anonymous access must be disabled.",
            "OPC-DA (DCOM): legacy, high risk — plan migration to OPC-UA.",
        ],
    },

    # ── Telemetry and communications ─────────────────────────────────────────
    {
        "key": "TELEMETRY_UNIT",
        "label": "Telemetry Unit / Outstations",
        "patterns": [
            r"telemetry", r"outstation",
            r"abriox", r"technolog",
            r"gsm.*telemetry", r"4g.*telemetry",
            r"radio.*telemetry",
        ],
        "purdue_level": PurdueLevel.L1,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.CONTROL_SYSTEM,
        "observations": [
            "Remote telemetry units — confirm encryption on communications channel and restrict inbound access.",
        ],
    },
    {
        "key": "IED",
        "label": "Intelligent Electronic Device (IED)",
        "patterns": [
            r"\bied\b", r"intelligent.*electronic",
            r"relay.*protection", r"protection.*relay",
            r"schweitzer", r"\bsel\b.*relay",
            r"ge.*multilin", r"siprotec",
        ],
        "purdue_level": PurdueLevel.L1,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.CONTROL_SYSTEM,
        "observations": [
            "IEDs in substation environments — confirm IEC 61850 GOOSE message authentication where supported.",
        ],
    },
    {
        "key": "POWER_METER",
        "label": "Power Meter / Energy Management Device",
        "patterns": [
            r"power.*meter", r"energy.*meter",
            r"pmc\b", r"powerlogic",
            r"ion.*meter", r"socomec",
            r"janitza",
        ],
        "purdue_level": PurdueLevel.L0,
        "zone": IEC62443Zone.CRITICAL_OT,
        "category": AssetCategory.FIELD_DEVICE,
        "observations": [],
    },

    # ── Catch-all for known safe IT assets ──────────────────────────────────
    {
        "key": "PRINTER",
        "label": "Printer / Peripheral",
        "patterns": [r"\bprinter\b", r"\bscanner\b", r"multifunction.*device"],
        "purdue_level": PurdueLevel.L4,
        "zone": IEC62443Zone.ENTERPRISE,
        "category": AssetCategory.IT_INFRASTRUCTURE,
        "observations": [
            "Printers in OT environments — ensure not connected to OT VLAN; should sit on enterprise network only.",
        ],
    },
    {
        "key": "WORKSTATION_IT",
        "label": "IT Workstation / Desktop",
        "patterns": [
            r"desktop.*pc", r"workstation.*it",
            r"office.*pc", r"laptop",
        ],
        "purdue_level": PurdueLevel.L4,
        "zone": IEC62443Zone.ENTERPRISE,
        "category": AssetCategory.IT_INFRASTRUCTURE,
        "observations": [],
    },
]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class OTAssetClassifier:
    """
    Deterministic IEC 62443-aligned OT asset classifier.

    Instantiate once and call :meth:`classify` for each asset.
    The classifier is stateless and thread-safe.

    Parameters
    ----------
    strict : bool
        If True, :meth:`classify` raises ``ValueError`` when the
        combined lookup string is empty. Default False.

    Examples
    --------
    >>> clf = OTAssetClassifier()
    >>> result = clf.classify(
    ...     device_type="PLC",
    ...     manufacturer="Siemens",
    ...     model="SIMATIC S7-1500",
    ... )
    >>> result.purdue_level
    <PurdueLevel.L1: 'L1'>
    >>> result.iec62443_zone
    <IEC62443Zone.CRITICAL_OT: 'Critical OT'>
    >>> result.confidence
    1.0
    """

    def __init__(self, strict: bool = False) -> None:
        self._strict = strict
        # Pre-compile all patterns for performance
        self._compiled: list[tuple[dict, list[re.Pattern]]] = [
            (rule, [re.compile(p, re.IGNORECASE) for p in rule["patterns"]])
            for rule in _DEVICE_RULES
        ]

    def classify(
        self,
        device_type: str = "",
        manufacturer: str = "",
        model: str = "",
        description: str = "",
    ) -> ClassificationResult:
        """
        Classify a single OT asset.

        The classifier concatenates all provided fields into a single
        lookup string and tests each rule's patterns against it.
        The first rule that fires is used; remaining rules are skipped.

        Parameters
        ----------
        device_type : str
            Primary device type label (e.g., "PLC", "HMI").
        manufacturer : str
            Vendor / manufacturer name (e.g., "Siemens", "Rockwell").
        model : str
            Model identifier (e.g., "S7-1500", "ControlLogix 1756").
        description : str
            Any additional free-text description of the asset.

        Returns
        -------
        ClassificationResult
        """
        lookup = " ".join(
            filter(None, [device_type, manufacturer, model, description])
        ).strip()

        if not lookup:
            if self._strict:
                raise ValueError(
                    "At least one of device_type, manufacturer, model, or "
                    "description must be non-empty."
                )
            return ClassificationResult(
                device_type_matched="Unknown",
                purdue_level=PurdueLevel.L1,
                iec62443_zone=IEC62443Zone.UNKNOWN,
                asset_category=AssetCategory.UNKNOWN,
                classification_path="unmatched",
                confidence=0.0,
                observations=["No asset information provided — manual classification required."],
            )

        for rule, compiled_patterns in self._compiled:
            if any(pat.search(lookup) for pat in compiled_patterns):
                return ClassificationResult(
                    device_type_matched=rule["label"],
                    purdue_level=rule["purdue_level"],
                    iec62443_zone=rule["zone"],
                    asset_category=rule["category"],
                    classification_path="deterministic",
                    confidence=1.0,
                    matched_rule=rule["key"],
                    observations=list(rule["observations"]),
                )

        # No rule fired
        return ClassificationResult(
            device_type_matched="Unknown",
            purdue_level=PurdueLevel.L1,
            iec62443_zone=IEC62443Zone.UNKNOWN,
            asset_category=AssetCategory.UNKNOWN,
            classification_path="unmatched",
            confidence=0.0,
            observations=[
                f"No deterministic rule matched '{lookup}'. "
                "Forward to RAG+LLM path or manual review."
            ],
        )

    def classify_batch(
        self, assets: list[dict]
    ) -> list[ClassificationResult]:
        """
        Classify a list of asset dicts.

        Each dict may contain keys: device_type, manufacturer, model,
        description. Missing keys default to empty string.

        Parameters
        ----------
        assets : list[dict]
            List of asset attribute dicts.

        Returns
        -------
        list[ClassificationResult]
        """
        return [
            self.classify(
                device_type=a.get("device_type", ""),
                manufacturer=a.get("manufacturer", ""),
                model=a.get("model", ""),
                description=a.get("description", ""),
            )
            for a in assets
        ]

    @property
    def rule_count(self) -> int:
        """Number of deterministic rules loaded."""
        return len(self._compiled)

    def rule_keys(self) -> list[str]:
        """Return all rule keys in match-priority order."""
        return [rule["key"] for rule, _ in self._compiled]
