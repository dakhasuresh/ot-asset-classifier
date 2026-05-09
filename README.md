# ot-asset-classifier

**Deterministic IEC 62443-aligned OT asset classification and risk scoring.**

Classifies industrial OT assets into Purdue Model levels, IEC 62443 security zones, and asset categories using a deterministic rules engine covering 35+ device types. Scores each asset using a T × V × I (Threat × Vulnerability × Impact) risk model with 14 threat-actor patterns.

Designed for air-gapped operational technology environments — **zero network calls, zero LLM dependency, zero external services.**

---

## Why this exists

Classifying OT assets against IEC 62443 is a manual, time-consuming process in most security programmes. Practitioners working across multi-site industrial environments need a consistent, auditable, and reproducible classification baseline before any LLM or AI-assisted analysis can be trusted.

This library provides that baseline. Every classification decision is deterministic, traceable to a named rule, and produces the same output on every run. It is designed to be the rules engine layer in a larger OT security assessment pipeline — the component that handles known devices instantly and consistently, freeing LLM or human review for genuinely ambiguous assets.

---

## Features

- **35+ OT device-type rules** covering field devices, PLCs, RTUs, DCS, SCADA, HMI, historians, OT networking, remote access, safety systems, and IT/OT boundary assets
- **IEC 62443 zone classification** — Safety, Critical OT, General OT, OT DMZ, IT/OT Boundary, Enterprise
- **Purdue Model mapping** — L0 through L4 with L3.5 DMZ
- **T × V × I risk scoring** — 0–125 scale with Critical / High / Medium / Low bands
- **14 threat-actor patterns** — nation-state APT, ransomware lateral movement, insider threat, supply chain, legacy protocol exploitation, vendor remote access abuse, and more
- **IEC 62443 control recommendations** — zone-specific, mapped to IEC 62443-3-2 and IEC 62443-3-3
- **Batch classification** — process full asset registers in one call
- **Fully typed** — dataclasses with `.to_dict()` for downstream pipeline integration
- **Strict mode** — raises `ValueError` on empty input for pipeline validation
- **43 tests, 100% passing**

---

## Installation

```bash
pip install ot-asset-classifier
```

Or from source:

```bash
git clone https://github.com/dakhasuresh/ot-asset-classifier.git
cd ot-asset-classifier
pip install -e .
```

**Requirements:** Python 3.9+. No external dependencies.

---

## Quick start

```python
from ot_classifier import OTAssetClassifier, OTRiskScorer

clf = OTAssetClassifier()
scorer = OTRiskScorer()

# Classify a single asset
result = clf.classify(
    device_type="PLC",
    manufacturer="Siemens",
    model="SIMATIC S7-1500",
)

print(result.purdue_level)       # PurdueLevel.L1
print(result.iec62443_zone)      # IEC62443Zone.CRITICAL_OT
print(result.asset_category)     # AssetCategory.CONTROL_SYSTEM
print(result.confidence)         # 1.0
print(result.matched_rule)       # 'PLC'

# Score the risk
risk = scorer.score(result)

print(risk.risk_score)           # 80
print(risk.risk_band)            # 'Critical'
print(risk.threat_score)         # 5
print(risk.applicable_threat_patterns)
# ['TP-01: Nation-State APT — Critical Infrastructure Targeting',
#  'TP-05: Unauthenticated Protocol Exploitation — Legacy OT', ...]

print(risk.recommended_controls)
# ['IEC 62443-3-2 §6.2: Assign SL target SL2 minimum; SL3 for critical assets.',
#  'IEC 62443-3-3 SR 1.1: Enforce account lockout and unique credentials per asset.', ...]
```

---

## Batch classification

```python
assets = [
    {"device_type": "SIS",          "manufacturer": "Triconex"},
    {"device_type": "PLC",          "manufacturer": "Rockwell",  "model": "ControlLogix"},
    {"device_type": "SCADA Server", "manufacturer": "AVEVA"},
    {"device_type": "Historian",    "manufacturer": "OSIsoft",   "model": "PI Server"},
    {"device_type": "Jump Server"},
    {"device_type": "Unknown Panel"},          # will return unmatched — forward to LLM path
]

results = clf.classify_batch(assets)
risks   = scorer.score_batch(results)

for asset, result, risk in zip(assets, results, risks):
    print(
        f"{result.device_type_matched:<40} "
        f"{result.purdue_level.value:<6} "
        f"{result.iec62443_zone.value:<20} "
        f"{risk.risk_score:>3} ({risk.risk_band})"
    )
```

Output:
```
Safety Instrumented System (SIS)         L1     Safety               100 (Critical)
Programmable Logic Controller (PLC)      L1     Critical OT           80 (Critical)
SCADA Server                             L2     Critical OT           60 (High)
Process Historian                        L3     General OT            45 (High)
OT Jump Server / Privileged Access Wks   L3.5   IT/OT Boundary        20 (Medium)
Unknown                                  L1     Unknown               12 (Low)
```

---

## Classification path

Each result carries a `classification_path` field:

| Path            | Meaning                                                   | Confidence |
|-----------------|-----------------------------------------------------------|------------|
| `deterministic` | A named rule fired — result is 100% reproducible          | 1.0        |
| `unmatched`     | No rule matched — forward to LLM/RAG path or manual review | 0.0       |

The unmatched path is intentional. This library handles what it knows with certainty. Unknown devices should be forwarded to a RAG+LLM path (grounded in IEC 62443 standard text) or flagged for manual classification. Mixing deterministic and probabilistic results in the same output without distinguishing them is how OT security assessments produce unreliable outputs.

---

## Risk model

The T × V × I model produces a score on a 0–125 scale:

| Dimension       | Basis                                                                 | Range |
|-----------------|-----------------------------------------------------------------------|-------|
| **Threat (T)**  | Zone exposure + applicable threat-actor patterns                      | 1–5   |
| **Vulnerability (V)** | Purdue level (L0/L1 assets are hardest to patch) + unmatched flag | 1–5   |
| **Impact (I)**  | Zone criticality (Safety = 5, Enterprise = 2)                        | 1–5   |

| Band     | Score range |
|----------|-------------|
| Critical | ≥ 75        |
| High     | ≥ 40        |
| Medium   | ≥ 15        |
| Low      | < 15        |

### The 14 threat-actor patterns

| ID    | Pattern                                              |
|-------|------------------------------------------------------|
| TP-01 | Nation-State APT — Critical Infrastructure Targeting |
| TP-02 | Ransomware — IT/OT Lateral Movement                  |
| TP-03 | Insider Threat — Privileged OT Access Abuse          |
| TP-04 | Supply Chain Compromise — Vendor Software/Firmware   |
| TP-05 | Unauthenticated Protocol Exploitation — Legacy OT    |
| TP-06 | Remote Access Abuse — Vendor/Third-Party Session     |
| TP-07 | Denial of Service — Process Control Network          |
| TP-08 | Safety System Bypass — Zone Boundary Violation       |
| TP-09 | USB / Removable Media Introduction                   |
| TP-10 | Historian / DMZ Compromise — Bidirectional Data Flow |
| TP-11 | Physical Access — Unsecured Field Device Tampering   |
| TP-12 | Credential Theft — OT Domain / Local Account         |
| TP-13 | Zero-Day Exploitation — SCADA / HMI Software         |
| TP-14 | Wireless Attack — Rogue AP / Protocol Intercept      |

---

## Extending the rules engine

Add a new rule to `_DEVICE_RULES` in `ot_classifier/classifier.py`:

```python
{
    "key": "MY_DEVICE",
    "label": "My Device Type",
    "patterns": [
        r"\bmy.device\b",
        r"vendor.*modelname",
    ],
    "purdue_level": PurdueLevel.L1,
    "zone": IEC62443Zone.CRITICAL_OT,
    "category": AssetCategory.CONTROL_SYSTEM,
    "observations": [
        "Note specific to this device type.",
    ],
},
```

Rules are evaluated in list order — first match wins. Place more specific rules before broader catch-alls.

---

## Running the tests

```bash
pip install pytest
pytest tests/ -v
```

43 tests, 0 failures.

---

## Integration with LLM/RAG pipelines

This library is designed as the deterministic layer in a hybrid classification pipeline:

```
Asset data → OTAssetClassifier
                 ├── deterministic (confidence 1.0) → use result directly
                 └── unmatched (confidence 0.0)     → RAG+LLM path
                                                          ↓
                                               Ground in IEC 62443 standard text
                                               Validate with Pydantic
                                               Flag if confidence < 0.65
```

The deterministic layer handles known device types instantly and reproducibly. The RAG+LLM layer handles ambiguous or novel devices with standard-grounded reasoning. Keeping these paths separate — and recording which path was taken — makes the overall pipeline auditable.

---

## Roadmap

- [ ] YAML/JSON rule configuration (external rule files without code changes)
- [ ] CSV asset register import
- [ ] Excel output with conditional formatting (gap analysis sheet)
- [ ] Additional device-type coverage: building management systems, EV charging infrastructure, water/wastewater telemetry
- [ ] IEC 62443-3-3 Security Level requirement mapping per asset

Contributions welcome — particularly additional device-type rules and threat patterns from practitioners working in specific industrial sectors.

---

## Author

**Suresh Dakha**  
Senior Solution Architect — Physical AI, Edge AI & OT Cybersecurity  
[linkedin.com/in/suresh-dakha](https://linkedin.com/in/suresh-dakha)

---

## Licence

MIT — see [LICENSE](LICENSE)
