"""
BlackRoad Threat Intelligence – IoC tracking and threat correlation engine.
SQLite persistence, IP/domain/hash IOC management, MITRE ATT&CK mapping.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sqlite3
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class ThreatIndicator:
    """Indicator of Compromise (IoC)."""
    id: str
    type: str           # IP | DOMAIN | HASH_MD5 | HASH_SHA256 | URL | EMAIL | CVE
    value: str
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: int     # 0-100
    source: str
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expiry: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)  # e.g. ["T1078", "T1110"]
    active: bool = True

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ThreatActor:
    name: str
    aliases: List[str] = field(default_factory=list)
    motivation: str = ""          # financial | espionage | hacktivism | destruction
    origin: str = ""
    techniques: List[str] = field(default_factory=list)
    description: str = ""
    iocs: List[str] = field(default_factory=list)  # indicator IDs


@dataclass
class ThreatEvent:
    id: str
    event_type: str   # ALERT | DETECTION | INCIDENT
    severity: str
    source_ip: str = ""
    dest_ip: str = ""
    indicator_id: Optional[str] = None
    description: str = ""
    mitre_technique: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved: bool = False


# ─────────────────────────────────────────────
# MITRE ATT&CK quick reference
# ─────────────────────────────────────────────

MITRE_TECHNIQUES: Dict[str, str] = {
    "T1078": "Valid Accounts – Using legitimate credentials for access.",
    "T1110": "Brute Force – Attempting to gain access by guessing credentials.",
    "T1133": "External Remote Services – Exploiting VPN/RDP.",
    "T1190": "Exploit Public-Facing Application – Web app exploitation.",
    "T1059": "Command and Scripting Interpreter – Shell command execution.",
    "T1053": "Scheduled Task/Job – Persistence via cron/scheduled tasks.",
    "T1548": "Abuse Elevation Control Mechanism – Privilege escalation.",
    "T1071": "Application Layer Protocol – C2 over HTTP/DNS.",
    "T1027": "Obfuscated Files or Information – Malware obfuscation.",
    "T1566": "Phishing – Spear-phishing for initial access.",
    "T1486": "Data Encrypted for Impact – Ransomware.",
    "T1041": "Exfiltration Over C2 Channel – Data exfiltration.",
    "T1082": "System Information Discovery – Reconaissance.",
    "T1083": "File and Directory Discovery – Listing files.",
    "T1087": "Account Discovery – Enumerating accounts.",
}


# ─────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────

_HASH_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_HASH_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def detect_ioc_type(value: str) -> str:
    """Auto-detect IOC type from value."""
    try:
        ipaddress.ip_address(value)
        return "IP"
    except ValueError:
        pass
    if _HASH_MD5_RE.match(value):
        return "HASH_MD5"
    if _HASH_SHA256_RE.match(value):
        return "HASH_SHA256"
    if value.startswith(("http://", "https://")):
        return "URL"
    if "@" in value and "." in value:
        return "EMAIL"
    if _CVE_RE.match(value):
        return "CVE"
    if _DOMAIN_RE.match(value):
        return "DOMAIN"
    return "UNKNOWN"


def _gen_id(value: str) -> str:
    return "TI-" + hashlib.sha256(value.encode()).hexdigest()[:12]


# ─────────────────────────────────────────────
# SQLite persistence
# ─────────────────────────────────────────────

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    id                TEXT PRIMARY KEY,
    type              TEXT NOT NULL,
    value             TEXT NOT NULL,
    severity          TEXT NOT NULL,
    confidence        INTEGER DEFAULT 50,
    source            TEXT DEFAULT '',
    tags              TEXT DEFAULT '[]',
    description       TEXT DEFAULT '',
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    expiry            TEXT DEFAULT NULL,
    mitre_techniques  TEXT DEFAULT '[]',
    active            INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS threat_actors (
    name        TEXT PRIMARY KEY,
    aliases     TEXT DEFAULT '[]',
    motivation  TEXT DEFAULT '',
    origin      TEXT DEFAULT '',
    techniques  TEXT DEFAULT '[]',
    description TEXT DEFAULT '',
    iocs        TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS threat_events (
    id              TEXT PRIMARY KEY,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    source_ip       TEXT DEFAULT '',
    dest_ip         TEXT DEFAULT '',
    indicator_id    TEXT DEFAULT NULL,
    description     TEXT DEFAULT '',
    mitre_technique TEXT DEFAULT '',
    timestamp       TEXT NOT NULL,
    resolved        INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ioc_value ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON indicators(type);
CREATE INDEX IF NOT EXISTS idx_events_ts ON threat_events(timestamp);
"""


class ThreatIntelDB:
    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        with self._conn() as conn:
            conn.executescript(DB_SCHEMA)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def add_indicator(self, ioc: ThreatIndicator) -> bool:
        with self._conn() as conn:
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO indicators "
                    "(id,type,value,severity,confidence,source,tags,description,"
                    " first_seen,last_seen,expiry,mitre_techniques,active) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ioc.id, ioc.type, ioc.value, ioc.severity, ioc.confidence,
                     ioc.source, json.dumps(ioc.tags), ioc.description,
                     ioc.first_seen, ioc.last_seen, ioc.expiry,
                     json.dumps(ioc.mitre_techniques), int(ioc.active)),
                )
                return True
            except Exception:
                return False

    def lookup(self, value: str) -> Optional[ThreatIndicator]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM indicators WHERE value=?", (value,)).fetchone()
            if not row:
                return None
            return self._row_to_ioc(row)

    def search(self, query: str = "", ioc_type: Optional[str] = None,
               severity: Optional[str] = None, limit: int = 50) -> List[ThreatIndicator]:
        with self._conn() as conn:
            sql = "SELECT * FROM indicators WHERE active=1"
            params: List[Any] = []
            if query:
                sql += " AND (value LIKE ? OR description LIKE ?)"
                params += [f"%{query}%", f"%{query}%"]
            if ioc_type:
                sql += " AND type=?"
                params.append(ioc_type)
            if severity:
                sql += " AND severity=?"
                params.append(severity)
            sql += " ORDER BY last_seen DESC LIMIT ?"
            params.append(limit)
            return [self._row_to_ioc(r) for r in conn.execute(sql, params).fetchall()]

    def _row_to_ioc(self, row: sqlite3.Row) -> ThreatIndicator:
        return ThreatIndicator(
            id=row["id"], type=row["type"], value=row["value"],
            severity=row["severity"], confidence=row["confidence"],
            source=row["source"],
            tags=json.loads(row["tags"] or "[]"),
            description=row["description"],
            first_seen=row["first_seen"], last_seen=row["last_seen"],
            expiry=row["expiry"],
            mitre_techniques=json.loads(row["mitre_techniques"] or "[]"),
            active=bool(row["active"]),
        )

    def add_event(self, event: ThreatEvent) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO threat_events "
                "(id,event_type,severity,source_ip,dest_ip,indicator_id,"
                " description,mitre_technique,timestamp,resolved) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (event.id, event.event_type, event.severity,
                 event.source_ip, event.dest_ip, event.indicator_id,
                 event.description, event.mitre_technique,
                 event.timestamp, int(event.resolved)),
            )

    def get_events(self, limit: int = 50, resolved: Optional[bool] = None) -> List[Dict]:
        with self._conn() as conn:
            sql = "SELECT * FROM threat_events"
            params: List[Any] = []
            if resolved is not None:
                sql += " WHERE resolved=?"
                params.append(int(resolved))
            sql += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def stats(self) -> Dict[str, Any]:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM indicators WHERE active=1").fetchone()[0]
            by_sev = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as c FROM indicators GROUP BY severity"
            ).fetchall():
                by_sev[row["severity"]] = row["c"]
            events = conn.execute("SELECT COUNT(*) FROM threat_events").fetchone()[0]
            open_events = conn.execute(
                "SELECT COUNT(*) FROM threat_events WHERE resolved=0"
            ).fetchone()[0]
        return {
            "active_iocs": total,
            "by_severity": by_sev,
            "total_events": events,
            "open_events": open_events,
        }


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="BlackRoad Threat Intelligence")
    p.add_argument("--db", default="threat_intel.db")
    sub = p.add_subparsers(dest="cmd")

    add = sub.add_parser("add", help="Add IOC")
    add.add_argument("value")
    add.add_argument("--type", default=None, dest="ioc_type")
    add.add_argument("--severity", default="MEDIUM",
                     choices=["CRITICAL","HIGH","MEDIUM","LOW","INFO"])
    add.add_argument("--confidence", type=int, default=50)
    add.add_argument("--source", default="manual")
    add.add_argument("--tags", default="")
    add.add_argument("--description", default="")
    add.add_argument("--mitre", default="", help="Comma-separated MITRE technique IDs")

    lk = sub.add_parser("lookup", help="Lookup an IOC")
    lk.add_argument("value")

    sr = sub.add_parser("search", help="Search IOCs")
    sr.add_argument("query", nargs="?", default="")
    sr.add_argument("--type", default=None, dest="ioc_type")
    sr.add_argument("--severity", default=None)
    sr.add_argument("--limit", type=int, default=20)

    sub.add_parser("stats", help="Show statistics")

    ev = sub.add_parser("events", help="Show threat events")
    ev.add_argument("--limit", type=int, default=20)
    ev.add_argument("--open", action="store_true")

    mt = sub.add_parser("mitre", help="Show MITRE ATT&CK techniques")
    mt.add_argument("technique", nargs="?", default=None)

    args = p.parse_args(argv)
    db = ThreatIntelDB(args.db)

    if args.cmd == "add":
        ioc_type = args.ioc_type or detect_ioc_type(args.value)
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]
        mitre = [m.strip() for m in args.mitre.split(",") if m.strip()]
        ioc = ThreatIndicator(
            id=_gen_id(args.value),
            type=ioc_type, value=args.value,
            severity=args.severity, confidence=args.confidence,
            source=args.source, tags=tags,
            description=args.description,
            mitre_techniques=mitre,
        )
        db.add_indicator(ioc)
        print(f"✅ Added {ioc_type} IOC: {args.value} [{args.severity}]")

    elif args.cmd == "lookup":
        ioc = db.lookup(args.value)
        if ioc:
            print(json.dumps(ioc.to_dict(), indent=2))
        else:
            print(f"No match for: {args.value}")
            return 1

    elif args.cmd == "search":
        results = db.search(args.query, args.ioc_type, args.severity, args.limit)
        print(f"{'TYPE':<12} {'SEVERITY':<10} {'CONFIDENCE':>10}  VALUE")
        print("-" * 70)
        for ioc in results:
            print(f"{ioc.type:<12} {ioc.severity:<10} {ioc.confidence:>10}%  {ioc.value}")

    elif args.cmd == "stats":
        s = db.stats()
        print(json.dumps(s, indent=2))

    elif args.cmd == "events":
        events = db.get_events(args.limit, resolved=False if args.open else None)
        for e in events:
            status = "OPEN" if not e["resolved"] else "RESOLVED"
            print(f"  [{e['severity']:<8}] [{status}] {e['event_type']} | "
                  f"{e['timestamp'][:19]} | {e['description'][:60]}")

    elif args.cmd == "mitre":
        if args.technique:
            desc = MITRE_TECHNIQUES.get(args.technique, "Unknown technique")
            print(f"{args.technique}: {desc}")
        else:
            for tid, desc in sorted(MITRE_TECHNIQUES.items()):
                print(f"  {tid}: {desc}")
    else:
        p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
