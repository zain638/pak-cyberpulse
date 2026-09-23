"""Real-behavior tests for modules/threat_intel.py TIStore on a tmp DB."""

from modules.threat_intel import FEED_DEFS, IOC_TYPES, TIStore


def test_seed_feeds_inserts_61_iocs_and_is_idempotent(seeded_ti):
    assert seeded_ti.count_iocs() == 61
    assert {f["feed_name"] for f in seeded_ti.list_feeds()} == {
        d["feed_name"] for d in FEED_DEFS
    }
    reseeded = seeded_ti.seed_feeds()
    assert sum(reseeded.values()) == 0, "reseed must add nothing"
    assert seeded_ti.count_iocs() == 61


def test_ioc_types_are_all_valid(seeded_ti):
    for row in seeded_ti.list_iocs(limit=500):
        assert row["ioc_type"] in IOC_TYPES
        assert row["ioc"] and row["feed_name"]


def test_enrich_hit_returns_matches_with_confidence_and_first_seen(seeded_ti):
    ioc = seeded_ti.list_iocs(limit=1)[0]
    result = seeded_ti.enrich(ioc["ioc"])
    assert result["matches"], "known IOC must enrich to at least one match"
    match = result["matches"][0]
    assert match["ioc"] == ioc["ioc"]
    assert 55 <= match["confidence"] <= 98
    assert match["first_seen"] and match["feed_name"]


def test_enrich_miss_returns_empty_matches(seeded_ti):
    result = seeded_ti.enrich("999.0.0.1")
    assert result["matches"] == []
    assert "stale_feeds" in result


def test_enrich_domain_lookup_is_case_insensitive(seeded_ti):
    domains = [r for r in seeded_ti.list_iocs(limit=200) if r["ioc_type"] == "domain"]
    assert domains, "seed must include domain IOCs"
    result = seeded_ti.enrich(domains[0]["ioc"].upper())
    assert result["matches"], "domain lookup must be case-insensitive"


def test_refresh_feed_mutates_last_updated_and_clears_staleness(seeded_ti):
    names = [f["feed_name"] for f in seeded_ti.list_feeds()]
    before = {n: seeded_ti.db._rows(
        "SELECT last_updated FROM ti_feeds WHERE feed_name = ?", (n,))[0]["last_updated"]
        for n in names}
    for name in names:
        res = seeded_ti.refresh_feed(name)
        assert res["feed_name"] == name
        assert 1 <= len(res["rotated_iocs"]) <= 3
        assert not seeded_ti.feed_is_stale(name), f"{name} must be fresh after refresh"
    assert seeded_ti.list_stale_feeds() == []
    after = {n: seeded_ti.db._rows(
        "SELECT last_updated FROM ti_feeds WHERE feed_name = ?", (n,))[0]["last_updated"]
        for n in names}
    assert all(after[n] >= before[n] for n in names)


def test_refresh_unknown_feed_raises_value_error(seeded_ti):
    try:
        seeded_ti.refresh_feed("no-such-feed")
    except ValueError:
        return
    raise AssertionError("refresh_feed must raise ValueError on unknown feed")
