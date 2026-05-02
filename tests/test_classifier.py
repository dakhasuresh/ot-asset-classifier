"""
Tests for ot-asset-classifier.

Run with: pytest tests/ -v
"""

import pytest
from ot_classifier import (
    AssetCategory,
    IEC62443Zone,
    OTAssetClassifier,
    OTRiskScorer,
    PurdueLevel,
)


# ---------------------------------------------------------------------------
# Classifier tests
# ---------------------------------------------------------------------------

class TestOTAssetClassifier:

    def setup_method(self):
        self.clf = OTAssetClassifier()

    # ── Safety systems ──────────────────────────────────────────────────────

    def test_sis_by_keyword(self):
        r = self.clf.classify(device_type="SIS", manufacturer="Triconex")
        assert r.purdue_level == PurdueLevel.L1
        assert r.iec62443_zone == IEC62443Zone.SAFETY
        assert r.asset_category == AssetCategory.SAFETY_SYSTEM
        assert r.confidence == 1.0
        assert r.classification_path == "deterministic"
        assert r.matched_rule == "SIS"

    def test_sis_by_manufacturer(self):
        r = self.clf.classify(device_type="Controller", manufacturer="HIMA")
        assert r.iec62443_zone == IEC62443Zone.SAFETY

    def test_esd_matched(self):
        r = self.clf.classify(description="Emergency Shutdown System ESD")
        assert r.iec62443_zone == IEC62443Zone.SAFETY

    def test_fire_gas_system(self):
        r = self.clf.classify(device_type="Fire and Gas System")
        assert r.asset_category == AssetCategory.SAFETY_SYSTEM
        assert r.iec62443_zone == IEC62443Zone.SAFETY

    # ── PLCs ────────────────────────────────────────────────────────────────

    def test_plc_siemens(self):
        r = self.clf.classify(
            device_type="PLC", manufacturer="Siemens", model="SIMATIC S7-1500"
        )
        assert r.purdue_level == PurdueLevel.L1
        assert r.iec62443_zone == IEC62443Zone.CRITICAL_OT
        assert r.asset_category == AssetCategory.CONTROL_SYSTEM
        assert r.matched_rule == "PLC"

    def test_plc_rockwell(self):
        r = self.clf.classify(
            manufacturer="Rockwell Automation", model="ControlLogix 1756-L85E"
        )
        assert r.purdue_level == PurdueLevel.L1
        assert r.matched_rule == "PLC"

    def test_plc_modicon(self):
        r = self.clf.classify(manufacturer="Schneider Electric", model="Modicon M340")
        assert r.matched_rule == "PLC"

    # ── RTU ─────────────────────────────────────────────────────────────────

    def test_rtu(self):
        r = self.clf.classify(device_type="RTU", manufacturer="Emerson")
        assert r.purdue_level == PurdueLevel.L1
        assert r.matched_rule == "RTU"
        assert "Modbus" in r.observations[0]

    # ── HMI / SCADA ─────────────────────────────────────────────────────────

    def test_hmi(self):
        r = self.clf.classify(device_type="HMI", model="Simatic HMI TP1200")
        assert r.purdue_level == PurdueLevel.L2
        assert r.iec62443_zone == IEC62443Zone.CRITICAL_OT
        assert r.asset_category == AssetCategory.SUPERVISORY

    def test_scada_server(self):
        r = self.clf.classify(
            device_type="SCADA Server", manufacturer="AVEVA", model="Wonderware"
        )
        assert r.purdue_level == PurdueLevel.L2
        assert r.matched_rule == "SCADA_SERVER"

    def test_ignition_scada(self):
        r = self.clf.classify(model="Ignition Server 8.1")
        assert r.matched_rule == "SCADA_SERVER"

    # ── Historian ────────────────────────────────────────────────────────────

    def test_pi_historian(self):
        r = self.clf.classify(
            device_type="Historian", manufacturer="OSIsoft", model="PI Server"
        )
        assert r.purdue_level == PurdueLevel.L3
        assert r.iec62443_zone == IEC62443Zone.GENERAL_OT
        assert r.matched_rule == "HISTORIAN"

    def test_aspentech_historian(self):
        r = self.clf.classify(manufacturer="AspenTech", model="IP21")
        assert r.matched_rule == "HISTORIAN"

    # ── Networking ──────────────────────────────────────────────────────────

    def test_industrial_switch(self):
        r = self.clf.classify(
            device_type="Managed Switch", manufacturer="Hirschmann"
        )
        assert r.asset_category == AssetCategory.NETWORKING
        assert r.iec62443_zone == IEC62443Zone.CRITICAL_OT
        assert r.matched_rule == "OT_SWITCH"

    def test_stratix_switch(self):
        r = self.clf.classify(manufacturer="Rockwell", model="Stratix 5700")
        assert r.matched_rule == "OT_SWITCH"

    def test_ot_firewall(self):
        r = self.clf.classify(device_type="Industrial Firewall", manufacturer="Tofino")
        assert r.iec62443_zone == IEC62443Zone.OT_DMZ
        assert r.purdue_level == PurdueLevel.L35

    def test_data_diode(self):
        r = self.clf.classify(device_type="Data Diode", manufacturer="Waterfall Security")
        assert r.matched_rule == "DATA_DIODE"
        assert r.iec62443_zone == IEC62443Zone.OT_DMZ

    def test_opc_ua_server(self):
        r = self.clf.classify(device_type="OPC-UA Server", manufacturer="Kepware")
        assert r.matched_rule == "OPC_SERVER"
        assert any("OPC-UA" in obs for obs in r.observations)

    # ── Remote access ────────────────────────────────────────────────────────

    def test_jump_server(self):
        r = self.clf.classify(device_type="Jump Server")
        assert r.iec62443_zone == IEC62443Zone.IT_OT_BOUNDARY
        assert r.purdue_level == PurdueLevel.L35
        assert r.asset_category == AssetCategory.REMOTE_ACCESS

    def test_vendor_remote(self):
        r = self.clf.classify(device_type="Vendor Remote Access", model="ewon Flexy 205")
        assert r.matched_rule == "VENDOR_REMOTE"

    # ── OT security ──────────────────────────────────────────────────────────

    def test_ot_ids_claroty(self):
        r = self.clf.classify(manufacturer="Claroty", device_type="OT IDS")
        assert r.asset_category == AssetCategory.SECURITY
        assert r.matched_rule == "OT_IDS"

    def test_ot_ids_nozomi(self):
        r = self.clf.classify(manufacturer="Nozomi Networks")
        assert r.matched_rule == "OT_IDS"

    # ── Field devices ────────────────────────────────────────────────────────

    def test_sensor(self):
        r = self.clf.classify(device_type="Pressure Transmitter", model="PT-101")
        assert r.purdue_level == PurdueLevel.L0
        assert r.asset_category == AssetCategory.FIELD_DEVICE

    def test_drive(self):
        r = self.clf.classify(manufacturer="ABB", model="ACS880 Drive")
        assert r.matched_rule == "DRIVE"

    def test_ied(self):
        r = self.clf.classify(
            device_type="Protection Relay", manufacturer="Schweitzer Engineering"
        )
        assert r.matched_rule == "IED"
        assert r.purdue_level == PurdueLevel.L1

    def test_fieldbus(self):
        r = self.clf.classify(device_type="PROFIBUS Device")
        assert r.matched_rule == "FIELDBUS_DEVICE"
        assert r.purdue_level == PurdueLevel.L0

    # ── Unmatched ────────────────────────────────────────────────────────────

    def test_unmatched_returns_unknown_zone(self):
        r = self.clf.classify(device_type="XYZ-9000 Quantum Fluxometer")
        assert r.classification_path == "unmatched"
        assert r.confidence == 0.0
        assert r.iec62443_zone == IEC62443Zone.UNKNOWN

    def test_empty_input_returns_unknown(self):
        r = self.clf.classify()
        assert r.classification_path == "unmatched"
        assert r.confidence == 0.0

    def test_strict_mode_raises_on_empty(self):
        clf = OTAssetClassifier(strict=True)
        with pytest.raises(ValueError):
            clf.classify()

    # ── Batch ────────────────────────────────────────────────────────────────

    def test_batch_classify(self):
        assets = [
            {"device_type": "PLC", "manufacturer": "Siemens"},
            {"device_type": "HMI", "manufacturer": "Rockwell"},
            {"device_type": "Unknown Device"},
        ]
        results = self.clf.classify_batch(assets)
        assert len(results) == 3
        assert results[0].matched_rule == "PLC"
        assert results[1].matched_rule == "HMI"
        assert results[2].classification_path == "unmatched"

    def test_rule_count(self):
        assert self.clf.rule_count >= 35

    def test_to_dict(self):
        r = self.clf.classify(device_type="PLC", manufacturer="Siemens")
        d = r.to_dict()
        assert "purdue_level" in d
        assert "iec62443_zone" in d
        assert d["confidence"] == 1.0


# ---------------------------------------------------------------------------
# Risk scorer tests
# ---------------------------------------------------------------------------

class TestOTRiskScorer:

    def setup_method(self):
        self.clf = OTAssetClassifier()
        self.scorer = OTRiskScorer()

    def test_sis_is_critical_risk(self):
        r = self.clf.classify(device_type="SIS", manufacturer="Triconex")
        risk = self.scorer.score(r)
        assert risk.risk_band == "Critical"
        assert risk.risk_score >= 75

    def test_safety_zone_has_high_impact(self):
        r = self.clf.classify(device_type="SIS")
        risk = self.scorer.score(r)
        assert risk.impact_score == 5

    def test_it_boundary_has_high_threat(self):
        r = self.clf.classify(device_type="Jump Server")
        risk = self.scorer.score(r)
        assert risk.threat_score >= 3

    def test_unmatched_gets_higher_vulnerability(self):
        matched = self.clf.classify(device_type="HMI")
        unmatched = self.clf.classify(device_type="Unknown Widget")
        risk_matched = self.scorer.score(matched)
        risk_unmatched = self.scorer.score(unmatched)
        assert risk_unmatched.vulnerability_score >= risk_matched.vulnerability_score

    def test_scores_bounded(self):
        for device in [
            {"device_type": "SIS", "manufacturer": "HIMA"},
            {"device_type": "PLC", "manufacturer": "Siemens"},
            {"device_type": "Jump Server"},
            {"device_type": "Unknown XYZ"},
        ]:
            r = self.clf.classify(**device)
            risk = self.scorer.score(r)
            assert 1 <= risk.threat_score <= 5
            assert 1 <= risk.vulnerability_score <= 5
            assert 1 <= risk.impact_score <= 5
            assert 0 <= risk.risk_score <= 125

    def test_applicable_threat_patterns_not_empty_for_known_assets(self):
        r = self.clf.classify(device_type="SIS")
        risk = self.scorer.score(r)
        assert len(risk.applicable_threat_patterns) > 0

    def test_controls_provided(self):
        r = self.clf.classify(device_type="PLC", manufacturer="Rockwell")
        risk = self.scorer.score(r)
        assert len(risk.recommended_controls) > 0

    def test_risk_rationale_contains_zone(self):
        r = self.clf.classify(device_type="PLC")
        risk = self.scorer.score(r)
        assert "Critical OT" in risk.risk_rationale

    def test_to_dict(self):
        r = self.clf.classify(device_type="PLC")
        risk = self.scorer.score(r)
        d = risk.to_dict()
        assert "risk_score" in d
        assert "risk_band" in d
        assert "applicable_threat_patterns" in d

    def test_batch_score(self):
        assets = [
            {"device_type": "SIS"},
            {"device_type": "PLC"},
            {"device_type": "HMI"},
        ]
        results = self.clf.classify_batch(assets)
        risks = self.scorer.score_batch(results)
        assert len(risks) == 3
        # SIS should be highest risk
        assert risks[0].risk_score >= risks[1].risk_score

    def test_risk_bands_ordering(self):
        sis = self.clf.classify(device_type="SIS")
        printer = self.clf.classify(device_type="Printer")
        risk_sis = self.scorer.score(sis)
        risk_printer = self.scorer.score(printer)
        assert risk_sis.risk_score > risk_printer.risk_score
