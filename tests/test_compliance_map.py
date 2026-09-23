"""Mapping-integrity and coverage-math tests for compliance_map."""

import pytest

from database.db_manager import PISF_CONTROLS
from modules.compliance_map import CONTROL_FRAMEWORK_MAP, FRAMEWORKS, framework_coverage


def test_map_covers_all_28_pisf_controls():
    control_ids = {c[0] for c in PISF_CONTROLS}
    assert len(PISF_CONTROLS) == 28
    assert set(CONTROL_FRAMEWORK_MAP) == control_ids
    for cid, mapping in CONTROL_FRAMEWORK_MAP.items():
        assert set(mapping) == set(FRAMEWORKS), f"{cid} missing a framework"
        assert all(mapping[fw] for fw in FRAMEWORKS)


def test_framework_coverage_math_on_seed_data(tmp_db):
    """Seed statuses: 20 Compliant / 8 Non-Compliant / 0 Under Attack."""
    cov = framework_coverage(tmp_db, "nist_csf_2_0")
    assert cov["total_mapped"] == 28
    assert cov["compliant"] == 20
    assert cov["coverage_pct"] == pytest.approx(71.4, abs=0.05)
    assert cov["by_status"]["Compliant"] == 20
    assert cov["by_status"]["Non-Compliant"] == 8
    assert sum(cov["by_status"].values()) == 28
    for key in ("iso_27001_2022", "pci_dss_4", "peca_2016"):
        c2 = framework_coverage(tmp_db, key)
        assert (c2["total_mapped"], c2["compliant"], c2["coverage_pct"]) == (
            28, 20, cov["coverage_pct"],
        )


def test_coverage_reflects_live_status_changes(tmp_db):
    tmp_db.update_control_status("PISF-01.1", "Under Attack", "test evidence")
    cov = framework_coverage(tmp_db, "iso_27001_2022")
    assert cov["compliant"] == 19
    assert cov["by_status"]["Under Attack"] == 1
    assert cov["coverage_pct"] == pytest.approx(100.0 * 19 / 28, abs=0.05)


def test_unknown_framework_raises_value_error(tmp_db):
    with pytest.raises(ValueError):
        framework_coverage(tmp_db, "soc2")
