"""Tests for blackroad-threat-intel."""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from src.threat_intel import (
    ThreatIntelDB, ThreatIndicator, ThreatEvent,
    detect_ioc_type, _gen_id, MITRE_TECHNIQUES,
)


@pytest.fixture
def db(tmp_path):
    return ThreatIntelDB(str(tmp_path / "test_ti.db"))


class TestDetectIocType:
    def test_ipv4(self):
        assert detect_ioc_type("192.168.1.1") == "IP"

    def test_domain(self):
        assert detect_ioc_type("evil.example.com") == "DOMAIN"

    def test_md5(self):
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "HASH_MD5"

    def test_sha256(self):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_ioc_type(sha) == "HASH_SHA256"

    def test_url(self):
        assert detect_ioc_type("https://evil.example.com/payload") == "URL"

    def test_email(self):
        assert detect_ioc_type("attacker@evil.com") == "EMAIL"

    def test_cve(self):
        assert detect_ioc_type("CVE-2024-12345") == "CVE"


class TestThreatIntelDB:
    def test_add_lookup(self, db):
        ioc = ThreatIndicator(
            id=_gen_id("192.168.1.1"),
            type="IP", value="192.168.1.1",
            severity="HIGH", confidence=80,
            source="test",
        )
        db.add_indicator(ioc)
        result = db.lookup("192.168.1.1")
        assert result is not None
        assert result.value == "192.168.1.1"

    def test_search_by_type(self, db):
        ioc = ThreatIndicator(
            id=_gen_id("evil.com"),
            type="DOMAIN", value="evil.com",
            severity="MEDIUM", confidence=60,
            source="test",
        )
        db.add_indicator(ioc)
        results = db.search(ioc_type="DOMAIN")
        assert any(r.value == "evil.com" for r in results)

    def test_search_by_severity(self, db):
        ioc = ThreatIndicator(
            id=_gen_id("critical.com"),
            type="DOMAIN", value="critical.com",
            severity="CRITICAL", confidence=95,
            source="test",
        )
        db.add_indicator(ioc)
        results = db.search(severity="CRITICAL")
        assert any(r.value == "critical.com" for r in results)

    def test_lookup_missing_returns_none(self, db):
        assert db.lookup("10.0.0.1") is None

    def test_add_event(self, db):
        event = ThreatEvent(
            id="ev001", event_type="ALERT", severity="HIGH",
            source_ip="10.0.0.1", description="Brute force attempt",
        )
        db.add_event(event)
        events = db.get_events()
        assert len(events) >= 1

    def test_stats(self, db):
        s = db.stats()
        assert "active_iocs" in s
        assert "total_events" in s


class TestMitreTechniques:
    def test_t1078_exists(self):
        assert "T1078" in MITRE_TECHNIQUES

    def test_all_techniques_have_description(self):
        for tid, desc in MITRE_TECHNIQUES.items():
            assert tid.startswith("T")
            assert len(desc) > 10