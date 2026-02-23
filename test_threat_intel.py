"""Tests for BlackRoad Threat Intel."""
import os
import pytest
from threat_intel import ThreatIntelDB, Indicator, IndicatorType, Severity, ThreatActor


@pytest.fixture
def db(tmp_path):
    return ThreatIntelDB(db_path=str(tmp_path / "test.db"))


def test_add_indicator_ip(db):
    ind = db.add_indicator("ip", "1.2.3.4", confidence=90, severity="high", source="test")
    assert ind.type == IndicatorType.IP
    assert ind.value == "1.2.3.4"
    assert ind.confidence == 90
    assert ind.severity == Severity.HIGH
    assert ind.active is True


def test_add_indicator_domain(db):
    ind = db.add_indicator("domain", "EVIL.COM", source="test")
    assert ind.value == "evil.com"  # normalized


def test_add_indicator_cve(db):
    ind = db.add_indicator("cve", "cve-2021-44228", source="nvd")
    assert ind.value == "CVE-2021-44228"  # uppercased


def test_lookup_by_value(db):
    db.add_indicator("ip", "10.0.0.1", source="test")
    found = db.lookup("10.0.0.1")
    assert found is not None
    assert found.value == "10.0.0.1"


def test_lookup_missing(db):
    assert db.lookup("not-in-db") is None


def test_check_ip(db):
    db.add_indicator("ip", "5.5.5.5", severity="critical", source="test")
    found = db.check_ip("5.5.5.5")
    assert found is not None
    assert found.severity == Severity.CRITICAL


def test_check_ip_invalid(db):
    with pytest.raises(ValueError, match="Invalid IP"):
        db.check_ip("not-an-ip")


def test_check_domain(db):
    db.add_indicator("domain", "phish.io", severity="high", source="test")
    found = db.check_domain("PHISH.IO")
    assert found is not None


def test_check_domain_not_found(db):
    assert db.check_domain("clean.example.com") is None


def test_bulk_import(db):
    data = [
        {"type": "ip", "value": "1.1.1.1", "severity": "low", "source": "bulk"},
        {"type": "domain", "value": "example.com", "severity": "medium", "source": "bulk"},
        {"type": "invalid-type", "value": "bad"},  # should be skipped
    ]
    count = db.bulk_import(data)
    assert count == 2


def test_get_active_by_severity(db):
    db.add_indicator("ip", "2.2.2.2", severity="info", source="test")
    db.add_indicator("ip", "3.3.3.3", severity="high", source="test")
    db.add_indicator("ip", "4.4.4.4", severity="critical", source="test")
    active = db.get_active("high")
    values = [i.value for i in active]
    assert "3.3.3.3" in values
    assert "4.4.4.4" in values
    assert "2.2.2.2" not in values


def test_get_active_invalid_severity(db):
    with pytest.raises(ValueError):
        db.get_active("nonexistent")


def test_deactivate(db):
    ind = db.add_indicator("ip", "6.6.6.6", source="test")
    ok = db.deactivate(ind.id)
    assert ok
    found = db.lookup("6.6.6.6")
    assert found.active is False


def test_update_existing(db):
    db.add_indicator("ip", "7.7.7.7", confidence=50, severity="low", source="test")
    updated = db.add_indicator("ip", "7.7.7.7", confidence=99, severity="critical", source="updated")
    assert updated.confidence == 99
    assert updated.severity == Severity.CRITICAL


def test_export_stix_json(db):
    import json
    db.add_indicator("ip", "8.8.8.8", severity="high", source="test")
    stix = db.export_stix_json()
    bundle = json.loads(stix)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 1
    assert bundle["objects"][0]["type"] == "indicator"


def test_export_stix_empty(db):
    import json
    stix = db.export_stix_json([])
    bundle = json.loads(stix)
    assert bundle["objects"] == []


def test_correlate(db):
    db.add_indicator("ip", "9.9.9.1", source="same-feed", tags=["c2"], severity="high")
    db.add_indicator("ip", "9.9.9.2", source="same-feed", tags=["c2"], severity="high")
    ind3 = db.add_indicator("ip", "9.9.9.3", source="different-feed", severity="low")
    ind1 = db.lookup("9.9.9.1")
    results = db.correlate(ind1.id)
    related_values = [r["indicator"]["value"] for r in results]
    assert "9.9.9.2" in related_values  # same source
    # ind3 not from same source or tag, should not appear


def test_correlate_nonexistent(db):
    results = db.correlate("nonexistent-id")
    assert results == []


def test_add_threat_actor(db):
    actor = db.add_threat_actor(
        name="APT-01",
        aliases=["Shadow"],
        motivation="espionage",
        ttps=["T1566"],
    )
    assert actor.name == "APT-01"
    assert "Shadow" in actor.aliases


def test_list_actors_empty(db):
    actors = db.list_actors()
    assert isinstance(actors, list)
    assert len(actors) == 0


def test_list_actors(db):
    db.add_threat_actor("APT-A", motivation="financial")
    db.add_threat_actor("APT-B", motivation="espionage")
    actors = db.list_actors()
    assert len(actors) == 2


def test_stats(db):
    db.add_indicator("ip", "10.0.0.5", severity="high", source="test")
    db.add_indicator("domain", "evil.org", severity="critical", source="test")
    s = db.stats()
    assert s["total_indicators"] == 2
    assert s["active_indicators"] == 2
    assert "ip" in s["by_type"]


def test_search(db):
    db.add_indicator("ip", "11.11.11.11", source="abuse-ch", tags=["botnet"])
    results = db.search("abuse-ch")
    assert len(results) >= 1
    assert results[0].source == "abuse-ch"


def test_invalid_indicator_type(db):
    with pytest.raises(ValueError, match="Unknown indicator type"):
        db.add_indicator("invalid-type", "value")


def test_invalid_confidence(db):
    with pytest.raises(ValueError, match="confidence"):
        db.add_indicator("ip", "1.2.3.4", confidence=150)


def test_to_dict(db):
    ind = db.add_indicator("ip", "1.2.3.4", source="test")
    d = ind.to_dict()
    assert d["type"] == "ip"
    assert d["severity"] == ind.severity.value
    assert isinstance(d["tags"], list)
