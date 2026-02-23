"""
BlackRoad Threat Intelligence - IOC aggregation and threat actor tracking.
SQLite FTS5 backend, STIX 2.1 export, correlation engine.
"""

import json
import sqlite3
import hashlib
import ipaddress
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from enum import Enum


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    CVE = "cve"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Indicator:
    id: str
    type: IndicatorType
    value: str
    confidence: int          # 0-100
    severity: Severity
    source: str
    tags: list
    first_seen: str
    last_seen: str
    active: bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class ThreatActor:
    id: str
    name: str
    aliases: list
    motivation: str
    ttps: list                       # MITRE ATT&CK technique IDs
    associated_indicators: list      # Indicator IDs

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    tags TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE VIRTUAL TABLE IF NOT EXISTS indicators_fts USING fts5(
    id UNINDEXED,
    value,
    source,
    tags,
    content='indicators',
    content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS indicators_ai AFTER INSERT ON indicators BEGIN
    INSERT INTO indicators_fts(rowid, id, value, source, tags)
    VALUES (new.rowid, new.id, new.value, new.source, new.tags);
END;

CREATE TRIGGER IF NOT EXISTS indicators_ad AFTER DELETE ON indicators BEGIN
    INSERT INTO indicators_fts(indicators_fts, rowid, id, value, source, tags)
    VALUES ('delete', old.rowid, old.id, old.value, old.source, old.tags);
END;

CREATE TRIGGER IF NOT EXISTS indicators_au AFTER UPDATE ON indicators BEGIN
    INSERT INTO indicators_fts(indicators_fts, rowid, id, value, source, tags)
    VALUES ('delete', old.rowid, old.id, old.value, old.source, old.tags);
    INSERT INTO indicators_fts(rowid, id, value, source, tags)
    VALUES (new.rowid, new.id, new.value, new.source, new.tags);
END;

CREATE TABLE IF NOT EXISTS threat_actors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    aliases TEXT NOT NULL,
    motivation TEXT NOT NULL,
    ttps TEXT NOT NULL,
    associated_indicators TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS correlations (
    indicator_id TEXT NOT NULL,
    related_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (indicator_id, related_id)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_indicator(row: tuple) -> Indicator:
    (id_, type_, value, confidence, severity, source, tags_json,
     first_seen, last_seen, active) = row
    return Indicator(
        id=id_,
        type=IndicatorType(type_),
        value=value,
        confidence=confidence,
        severity=Severity(severity),
        source=source,
        tags=json.loads(tags_json),
        first_seen=first_seen,
        last_seen=last_seen,
        active=bool(active),
    )


def _row_to_actor(row: tuple) -> ThreatActor:
    id_, name, aliases_j, motivation, ttps_j, assoc_j = row
    return ThreatActor(
        id=id_,
        name=name,
        aliases=json.loads(aliases_j),
        motivation=motivation,
        ttps=json.loads(ttps_j),
        associated_indicators=json.loads(assoc_j),
    )


# ---------------------------------------------------------------------------
# ThreatIntelDB
# ---------------------------------------------------------------------------

class ThreatIntelDB:
    """Core threat intelligence database."""

    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self._init_db()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    # Indicators CRUD
    # ------------------------------------------------------------------

    def add_indicator(
        self,
        type: str,
        value: str,
        confidence: int = 70,
        severity: str = "medium",
        source: str = "manual",
        tags: Optional[list] = None,
    ) -> Indicator:
        """Add or update an IOC indicator."""
        if not (0 <= confidence <= 100):
            raise ValueError("confidence must be 0-100")
        try:
            ind_type = IndicatorType(type.lower())
        except ValueError:
            raise ValueError(f"Unknown indicator type: {type}")
        try:
            ind_severity = Severity(severity.lower())
        except ValueError:
            raise ValueError(f"Unknown severity: {severity}")

        tags = tags or []
        normalized = self._normalize_value(ind_type, value)
        ioc_id = hashlib.sha256(f"{ind_type.value}:{normalized}".encode()).hexdigest()[:16]
        now = _now()

        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM indicators WHERE id=?", (ioc_id,)
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE indicators SET confidence=?, severity=?, source=?,
                       tags=?, last_seen=?, active=1 WHERE id=?""",
                    (confidence, ind_severity.value, source,
                     json.dumps(tags), now, ioc_id),
                )
            else:
                conn.execute(
                    """INSERT INTO indicators
                       (id, type, value, confidence, severity, source, tags, first_seen, last_seen, active)
                       VALUES (?,?,?,?,?,?,?,?,?,1)""",
                    (ioc_id, ind_type.value, normalized, confidence,
                     ind_severity.value, source, json.dumps(tags), now, now),
                )
        return self.lookup(normalized)

    def lookup(self, value: str) -> Optional[Indicator]:
        """Find indicator by exact value (full-text search fallback)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM indicators WHERE value=?", (value,)
            ).fetchone()
            if row:
                return _row_to_indicator(row)
            # FTS fallback — quote the value to handle special chars
            fts_query = f'"{value}"'
            try:
                rows = conn.execute(
                    """SELECT i.* FROM indicators i
                       JOIN indicators_fts f ON i.rowid = f.rowid
                       WHERE indicators_fts MATCH ? LIMIT 1""",
                    (fts_query,),
                ).fetchall()
                if rows:
                    return _row_to_indicator(rows[0])
            except Exception:
                pass
        return None

    def bulk_import(self, data: list) -> int:
        """Import list of indicator dicts. Returns count imported."""
        count = 0
        for item in data:
            try:
                self.add_indicator(
                    type=item.get("type", "ip"),
                    value=item["value"],
                    confidence=item.get("confidence", 70),
                    severity=item.get("severity", "medium"),
                    source=item.get("source", "bulk"),
                    tags=item.get("tags", []),
                )
                count += 1
            except (KeyError, ValueError):
                continue
        return count

    def check_ip(self, ip: str) -> Optional[Indicator]:
        """Check if an IP address is in the threat database."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")
        return self.lookup(ip)

    def check_domain(self, domain: str) -> Optional[Indicator]:
        """Check if a domain is in the threat database."""
        domain = domain.lower().strip().rstrip(".")
        return self.lookup(domain)

    def get_active(self, severity_min: str = "low") -> list:
        """Get all active indicators at or above the given severity."""
        try:
            min_rank = SEVERITY_RANK[Severity(severity_min.lower())]
        except (KeyError, ValueError):
            raise ValueError(f"Unknown severity: {severity_min}")

        sevs = [s.value for s, r in SEVERITY_RANK.items() if r >= min_rank]
        placeholders = ",".join("?" * len(sevs))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM indicators WHERE active=1 AND severity IN ({placeholders})",
                sevs,
            ).fetchall()
        return [_row_to_indicator(r) for r in rows]

    def deactivate(self, indicator_id: str) -> bool:
        """Mark indicator as inactive."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE indicators SET active=0 WHERE id=?", (indicator_id,)
            )
        return cur.rowcount > 0

    def search(self, query: str) -> list:
        """Full-text search across indicators. Supports FTS5 syntax."""
        # Quote the query to handle special chars (hyphens, dots, etc.)
        fts_query = f'"{query}"'
        with self._connect() as conn:
            try:
                rows = conn.execute(
                    """SELECT i.* FROM indicators i
                       JOIN indicators_fts f ON i.rowid = f.rowid
                       WHERE indicators_fts MATCH ?""",
                    (fts_query,),
                ).fetchall()
            except Exception:
                # Fall back to LIKE search
                rows = conn.execute(
                    "SELECT * FROM indicators WHERE value LIKE ? OR source LIKE ? OR tags LIKE ?",
                    (f"%{query}%", f"%{query}%", f"%{query}%"),
                ).fetchall()
        return [_row_to_indicator(r) for r in rows]

    def stats(self) -> dict:
        """Return summary statistics."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            active = conn.execute("SELECT COUNT(*) FROM indicators WHERE active=1").fetchone()[0]
            by_type = conn.execute(
                "SELECT type, COUNT(*) FROM indicators GROUP BY type"
            ).fetchall()
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) FROM indicators GROUP BY severity"
            ).fetchall()
            actors = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
        return {
            "total_indicators": total,
            "active_indicators": active,
            "threat_actors": actors,
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
        }

    # ------------------------------------------------------------------
    # Threat Actors
    # ------------------------------------------------------------------

    def add_threat_actor(
        self,
        name: str,
        aliases: list = None,
        motivation: str = "unknown",
        ttps: list = None,
        associated_indicators: list = None,
    ) -> ThreatActor:
        """Register a threat actor."""
        actor = ThreatActor(
            id=str(uuid.uuid4()),
            name=name,
            aliases=aliases or [],
            motivation=motivation,
            ttps=ttps or [],
            associated_indicators=associated_indicators or [],
        )
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO threat_actors
                   (id, name, aliases, motivation, ttps, associated_indicators)
                   VALUES (?,?,?,?,?,?)""",
                (actor.id, actor.name, json.dumps(actor.aliases),
                 actor.motivation, json.dumps(actor.ttps),
                 json.dumps(actor.associated_indicators)),
            )
        return actor

    def get_actor(self, actor_id: str) -> Optional[ThreatActor]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM threat_actors WHERE id=?", (actor_id,)
            ).fetchone()
        return _row_to_actor(row) if row else None

    def list_actors(self) -> list:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM threat_actors").fetchall()
        return [_row_to_actor(r) for r in rows]

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def correlate(self, indicator_id: str) -> list:
        """Find indicators correlated with the given one."""
        with self._connect() as conn:
            target = conn.execute(
                "SELECT * FROM indicators WHERE id=?", (indicator_id,)
            ).fetchone()
            if not target:
                return []
            target_ind = _row_to_indicator(target)

            # Same source
            rows = conn.execute(
                "SELECT * FROM indicators WHERE source=? AND id!=?",
                (target_ind.source, indicator_id),
            ).fetchall()
            related: dict[str, dict] = {}
            for r in rows:
                ind = _row_to_indicator(r)
                related[ind.id] = {"indicator": ind, "reason": "same_source"}

            # Shared tags
            for tag in target_ind.tags:
                tag_rows = conn.execute(
                    "SELECT * FROM indicators WHERE tags LIKE ? AND id!=?",
                    (f'%"{tag}"%', indicator_id),
                ).fetchall()
                for r in tag_rows:
                    ind = _row_to_indicator(r)
                    if ind.id not in related:
                        related[ind.id] = {"indicator": ind, "reason": f"shared_tag:{tag}"}

            # Save correlations
            now = _now()
            for rel_id, info in related.items():
                conn.execute(
                    """INSERT OR REPLACE INTO correlations
                       (indicator_id, related_id, reason, created_at)
                       VALUES (?,?,?,?)""",
                    (indicator_id, rel_id, info["reason"], now),
                )

        return [{"indicator": v["indicator"].to_dict(), "reason": v["reason"]}
                for v in related.values()]

    def get_stored_correlations(self, indicator_id: str) -> list:
        """Return previously computed correlations from the DB."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT c.related_id, c.reason, i.*
                   FROM correlations c
                   JOIN indicators i ON i.id = c.related_id
                   WHERE c.indicator_id=?""",
                (indicator_id,),
            ).fetchall()
        results = []
        for row in rows:
            rel_id, reason = row[0], row[1]
            ind = _row_to_indicator(row[2:])
            results.append({"indicator": ind.to_dict(), "reason": reason})
        return results

    # ------------------------------------------------------------------
    # STIX 2.1 Export
    # ------------------------------------------------------------------

    def export_stix_json(self, indicators: list = None) -> str:
        """Export indicators as a STIX 2.1 bundle JSON string."""
        if indicators is None:
            indicators = self.get_active("info")

        stix_objects = []
        for ind in indicators:
            if isinstance(ind, dict):
                ind_type = ind.get("type")
                value = ind.get("value")
                severity = ind.get("severity", "unknown")
                first_seen = ind.get("first_seen")
                last_seen = ind.get("last_seen")
            else:
                ind_type = ind.type.value
                value = ind.value
                severity = ind.severity.value
                first_seen = ind.first_seen
                last_seen = ind.last_seen

            pattern = self._build_stix_pattern(ind_type, value)
            if pattern is None:
                continue

            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": first_seen,
                "modified": last_seen,
                "name": f"{ind_type}:{value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": first_seen,
                "labels": [severity],
            })

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects,
        }
        return json.dumps(bundle, indent=2)

    def _build_stix_pattern(self, ind_type: str, value: str) -> Optional[str]:
        mapping = {
            "ip": f"[ipv4-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "email": f"[email-addr:value = '{value}']",
            "hash": f"[file:hashes.MD5 = '{value}']",
            "cve": f"[vulnerability:name = '{value}']",
        }
        return mapping.get(ind_type)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _normalize_value(self, type: IndicatorType, value: str) -> str:
        if type == IndicatorType.DOMAIN:
            return value.lower().strip().rstrip(".")
        if type == IndicatorType.EMAIL:
            return value.lower().strip()
        if type == IndicatorType.URL:
            return value.strip()
        if type == IndicatorType.CVE:
            return value.upper().strip()
        return value.strip()


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _print_indicator(ind: Indicator):
    sev_colors = {
        "info": "\033[94m", "low": "\033[92m", "medium": "\033[93m",
        "high": "\033[91m", "critical": "\033[95m",
    }
    reset = "\033[0m"
    color = sev_colors.get(ind.severity.value, "")
    status = "ACTIVE" if ind.active else "inactive"
    print(f"  [{color}{ind.severity.value.upper()}{reset}] {ind.type.value}:{ind.value}")
    print(f"    ID: {ind.id}  Source: {ind.source}  Confidence: {ind.confidence}%")
    print(f"    Status: {status}  Tags: {', '.join(ind.tags) or 'none'}")
    print(f"    First: {ind.first_seen}  Last: {ind.last_seen}")


def _print_actor(actor: ThreatActor):
    print(f"  Actor: {actor.name} (ID: {actor.id})")
    print(f"    Aliases: {', '.join(actor.aliases) or 'none'}")
    print(f"    Motivation: {actor.motivation}")
    print(f"    TTPs: {', '.join(actor.ttps) or 'none'}")
    print(f"    Indicators: {len(actor.associated_indicators)}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    import sys
    db = ThreatIntelDB()
    args = sys.argv[1:]

    if not args:
        print("BlackRoad Threat Intel")
        print("Usage: python threat_intel.py <command> [args]")
        print()
        print("Commands:")
        print("  add <type> <value> [confidence] [severity] [source]")
        print("  lookup <value>")
        print("  check-ip <ip>")
        print("  check-domain <domain>")
        print("  active [severity_min]")
        print("  export-stix [outfile]")
        print("  correlate <indicator_id>")
        print("  search <query>")
        print("  stats")
        print("  add-actor <name> <motivation>")
        print("  actors")
        print("  demo   - load demo IOC data")
        return

    cmd = args[0]

    if cmd == "add":
        if len(args) < 3:
            print("Usage: add <type> <value> [confidence] [severity] [source]")
            return
        ind = db.add_indicator(
            type=args[1],
            value=args[2],
            confidence=int(args[3]) if len(args) > 3 else 70,
            severity=args[4] if len(args) > 4 else "medium",
            source=args[5] if len(args) > 5 else "manual",
        )
        print(f"✓ Indicator added/updated:")
        _print_indicator(ind)

    elif cmd == "lookup":
        if len(args) < 2:
            print("Usage: lookup <value>")
            return
        ind = db.lookup(args[1])
        if ind:
            print("✓ Found:")
            _print_indicator(ind)
        else:
            print("✗ Not found in threat intel database")

    elif cmd == "check-ip":
        if len(args) < 2:
            print("Usage: check-ip <ip>")
            return
        ind = db.check_ip(args[1])
        if ind:
            print(f"⚠ THREAT DETECTED for {args[1]}:")
            _print_indicator(ind)
        else:
            print(f"✓ {args[1]} not found in threat database")

    elif cmd == "check-domain":
        if len(args) < 2:
            print("Usage: check-domain <domain>")
            return
        ind = db.check_domain(args[1])
        if ind:
            print(f"⚠ THREAT DETECTED for {args[1]}:")
            _print_indicator(ind)
        else:
            print(f"✓ {args[1]} not found in threat database")

    elif cmd == "active":
        severity_min = args[1] if len(args) > 1 else "low"
        indicators = db.get_active(severity_min)
        print(f"Active indicators (>= {severity_min}): {len(indicators)}")
        for ind in indicators:
            _print_indicator(ind)

    elif cmd == "export-stix":
        stix_json = db.export_stix_json()
        if len(args) > 1:
            with open(args[1], "w") as f:
                f.write(stix_json)
            print(f"✓ STIX bundle exported to {args[1]}")
        else:
            print(stix_json)

    elif cmd == "correlate":
        if len(args) < 2:
            print("Usage: correlate <indicator_id>")
            return
        results = db.correlate(args[1])
        print(f"Correlations for {args[1]}: {len(results)}")
        for r in results:
            ind = r["indicator"]
            print(f"  [{r['reason']}] {ind['type']}:{ind['value']} ({ind['severity']})")

    elif cmd == "search":
        if len(args) < 2:
            print("Usage: search <query>")
            return
        results = db.search(args[1])
        print(f"Search results for '{args[1]}': {len(results)}")
        for ind in results:
            _print_indicator(ind)

    elif cmd == "stats":
        s = db.stats()
        print("Threat Intel Stats:")
        print(f"  Total indicators: {s['total_indicators']}")
        print(f"  Active: {s['active_indicators']}")
        print(f"  Threat actors: {s['threat_actors']}")
        print(f"  By type: {s['by_type']}")
        print(f"  By severity: {s['by_severity']}")

    elif cmd == "add-actor":
        if len(args) < 3:
            print("Usage: add-actor <name> <motivation>")
            return
        actor = db.add_threat_actor(name=args[1], motivation=args[2])
        print(f"✓ Threat actor added:")
        _print_actor(actor)

    elif cmd == "actors":
        actors = db.list_actors()
        print(f"Threat actors: {len(actors)}")
        for a in actors:
            _print_actor(a)

    elif cmd == "demo":
        demo_data = [
            {"type": "ip", "value": "185.220.101.45", "confidence": 95,
             "severity": "critical", "source": "abuse.ch", "tags": ["tor", "exit-node"]},
            {"type": "ip", "value": "45.142.212.100", "confidence": 85,
             "severity": "high", "source": "feodo", "tags": ["botnet", "c2"]},
            {"type": "domain", "value": "malware-c2.evil.com", "confidence": 90,
             "severity": "critical", "source": "urlhaus", "tags": ["c2", "malware"]},
            {"type": "domain", "value": "phishing-site.xyz", "confidence": 80,
             "severity": "high", "source": "openphish", "tags": ["phishing"]},
            {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "confidence": 99,
             "severity": "critical", "source": "virustotal", "tags": ["ransomware", "ryuk"]},
            {"type": "url", "value": "http://evil.com/payload.exe", "confidence": 88,
             "severity": "high", "source": "urlhaus", "tags": ["malware-download"]},
            {"type": "email", "value": "phisher@spoofed.com", "confidence": 75,
             "severity": "medium", "source": "spamhaus", "tags": ["phishing"]},
            {"type": "cve", "value": "CVE-2021-44228", "confidence": 100,
             "severity": "critical", "source": "nvd", "tags": ["log4shell", "rce"]},
            {"type": "ip", "value": "10.0.0.1", "confidence": 40,
             "severity": "low", "source": "internal", "tags": ["suspicious"]},
            {"type": "domain", "value": "suspicious-domain.ru", "confidence": 65,
             "severity": "medium", "source": "openphish", "tags": ["phishing", "c2"]},
        ]
        count = db.bulk_import(demo_data)
        print(f"✓ Demo: loaded {count} indicators")
        db.add_threat_actor(
            name="APT-BR-01",
            aliases=["ShadowGhost", "DarkNet-01"],
            motivation="espionage",
            ttps=["T1566", "T1059", "T1071"],
            associated_indicators=[],
        )
        db.add_threat_actor(
            name="FIN-99",
            aliases=["MoneyBadger"],
            motivation="financial",
            ttps=["T1486", "T1078"],
            associated_indicators=[],
        )
        print("✓ Demo: loaded 2 threat actors")
        s = db.stats()
        print(f"✓ Database now has {s['total_indicators']} indicators, {s['threat_actors']} actors")

    else:
        print(f"Unknown command: {cmd}")
        print("Run with no arguments for help")


if __name__ == "__main__":
    main()
