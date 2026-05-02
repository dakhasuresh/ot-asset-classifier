"""
examples/classify_site_assets.py
=================================
Worked example: classify a list of OT assets and produce a risk-scored
gap analysis summary.

Run from the repository root:
    python examples/classify_site_assets.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ot_classifier import OTAssetClassifier, OTRiskScorer

# ---------------------------------------------------------------------------
# Sample asset list — representative of a typical manufacturing site OT estate
# ---------------------------------------------------------------------------

SAMPLE_ASSETS = [
    {"id": "A001", "device_type": "SIS",          "manufacturer": "Triconex",          "model": "Tricon CX"},
    {"id": "A002", "device_type": "PLC",           "manufacturer": "Siemens",           "model": "SIMATIC S7-1500"},
    {"id": "A003", "device_type": "PLC",           "manufacturer": "Rockwell",          "model": "ControlLogix 1756-L85E"},
    {"id": "A004", "device_type": "HMI",           "manufacturer": "Siemens",           "model": "SIMATIC TP1200 Comfort"},
    {"id": "A005", "device_type": "SCADA Server",  "manufacturer": "AVEVA",             "model": "Wonderware InTouch 2020"},
    {"id": "A006", "device_type": "Historian",     "manufacturer": "OSIsoft",           "model": "PI Server 2018"},
    {"id": "A007", "device_type": "OPC-UA Server", "manufacturer": "Kepware",           "model": "KEPServerEX 6.x"},
    {"id": "A008", "device_type": "Managed Switch","manufacturer": "Hirschmann",        "model": "RSPE35 Industrial Switch"},
    {"id": "A009", "device_type": "Data Diode",    "manufacturer": "Waterfall Security","model": "Unidirectional Gateway"},
    {"id": "A010", "device_type": "Jump Server",   "manufacturer": "Dell",              "model": "PowerEdge R650"},
    {"id": "A011", "device_type": "RTU",           "manufacturer": "Emerson",           "model": "ROC809"},
    {"id": "A012", "device_type": "Protection Relay", "manufacturer": "Schweitzer",     "model": "SEL-311C"},
    {"id": "A013", "device_type": "Pressure Transmitter", "manufacturer": "Endress+Hauser", "model": "Cerabar PMC51"},
    {"id": "A014", "device_type": "OT IDS",        "manufacturer": "Claroty",           "model": "Continuous Threat Detection"},
    {"id": "A015", "device_type": "Unknown Panel", "manufacturer": "Local Build",       "model": "Custom SCADA panel"},
]


def main():
    clf = OTAssetClassifier()
    scorer = OTRiskScorer()

    print(f"\n{'=' * 90}")
    print(" OT ASSET CLASSIFICATION & RISK SCORING — EXAMPLE OUTPUT")
    print(f"{'=' * 90}")
    print(f" Assets: {len(SAMPLE_ASSETS)}  |  Rules engine: {clf.rule_count} device-type rules  |  Threat patterns: 14")
    print(f"{'=' * 90}\n")

    header = (
        f"{'ID':<6} {'Device Type Matched':<38} {'Purdue':<8} "
        f"{'Zone':<20} {'T':>2} {'V':>2} {'I':>2} {'Score':>5} {'Band':<10} {'Path':<14}"
    )
    print(header)
    print("-" * 115)

    band_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for asset in SAMPLE_ASSETS:
        asset_id = asset.pop("id")
        result = clf.classify(**asset)
        risk = scorer.score(result)
        band_counts[risk.risk_band] += 1

        flag = " ◄ UNMATCHED" if result.classification_path == "unmatched" else ""
        print(
            f"{asset_id:<6} {result.device_type_matched[:37]:<38} "
            f"{result.purdue_level.value:<8} {result.iec62443_zone.value:<20} "
            f"{risk.threat_score:>2} {risk.vulnerability_score:>2} {risk.impact_score:>2} "
            f"{risk.risk_score:>5} {risk.risk_band:<10} {result.classification_path:<14}{flag}"
        )

    print(f"\n{'=' * 90}")
    print(" RISK SUMMARY")
    print(f"{'=' * 90}")
    for band, count in band_counts.items():
        bar = "█" * count
        print(f"  {band:<10} {count:>3}  {bar}")

    print(f"\n{'=' * 90}")
    print(" SAMPLE DETAIL — Asset A001 (SIS / Triconex)")
    print(f"{'=' * 90}")

    sis_result = clf.classify(device_type="SIS", manufacturer="Triconex", model="Tricon CX")
    sis_risk = scorer.score(sis_result)

    print(f"\n  Classification")
    print(f"    Device type matched : {sis_result.device_type_matched}")
    print(f"    Purdue level        : {sis_result.purdue_level.value}")
    print(f"    IEC 62443 zone      : {sis_result.iec62443_zone.value}")
    print(f"    Asset category      : {sis_result.asset_category.value}")
    print(f"    Confidence          : {sis_result.confidence}")
    print(f"    Matched rule        : {sis_result.matched_rule}")

    print(f"\n  Risk Score  T={sis_risk.threat_score} × V={sis_risk.vulnerability_score} × I={sis_risk.impact_score} = {sis_risk.risk_score} ({sis_risk.risk_band})")

    print(f"\n  Applicable Threat Patterns ({len(sis_risk.applicable_threat_patterns)})")
    for tp in sis_risk.applicable_threat_patterns:
        print(f"    • {tp}")

    print(f"\n  Recommended Controls")
    for ctrl in sis_risk.recommended_controls:
        print(f"    • {ctrl}")

    print(f"\n  Observations")
    for obs in sis_result.observations:
        print(f"    • {obs}")

    print()


if __name__ == "__main__":
    main()
