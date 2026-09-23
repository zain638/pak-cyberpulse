"""Registry + annotation tests for modules/mitre_map.py."""

from modules.attack_patterns import PATTERN_BY_ID
from modules.mitre_map import TECHNIQUES, annotate_alert, get_mapping, technique_coverage

BASE = "https://attack.mitre.org/techniques/"


def test_all_19_pattern_ids_are_mapped():
    assert len(TECHNIQUES) == 19
    assert set(TECHNIQUES) == set(PATTERN_BY_ID)


def test_every_mapping_url_is_a_real_attack_url():
    for pid, m in TECHNIQUES.items():
        assert m["url"].startswith(BASE), f"{pid} has a bad URL"
        assert m["technique_id"] and m["technique"] and m["tactics"]


def test_get_mapping_spot_checks():
    assert get_mapping("SQLI")["technique_id"] == "T1190"
    assert get_mapping("BRUTEFORCE")["technique_id"] == "T1110.001"
    assert get_mapping("nope") is None


def test_annotate_alert_adds_four_mitre_keys_and_preserves_original():
    alert = {"pattern_id": "BRUTEFORCE", "src_ip": "203.0.113.9"}
    annotated = annotate_alert(alert)
    for key in ("mitre_technique_id", "mitre_technique", "mitre_tactics", "mitre_url"):
        assert key in annotated, f"missing {key}"
    assert annotated["mitre_technique_id"] == "T1110.001"
    assert annotated["mitre_url"].startswith(BASE)
    assert annotated["src_ip"] == "203.0.113.9"
    # The caller's dict must not be mutated in place.
    assert not any(k.startswith("mitre_") for k in alert)


def test_annotate_alert_unknown_id_leaves_alert_unchanged():
    alert = {"pattern_id": "NOPE", "src_ip": "203.0.113.9"}
    result = annotate_alert(alert)
    assert result is alert
    assert not any(k.startswith("mitre_") for k in result)


def test_technique_coverage_consistency():
    cov = technique_coverage()
    assert cov["mapped_patterns"] == 19
    assert cov["total_patterns"] == 19
    assert cov["distinct_techniques"] >= 10
    assert "Credential Access" in cov["tactics_covered"]
