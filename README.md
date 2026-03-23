# blackroad-threat-intel

> BlackRoad Security - Threat Intelligence

Part of the [BlackRoad OS](https://blackroad.io) ecosystem — [BlackRoad-Security](https://github.com/BlackRoad-Security)

---

# blackroad-threat-intel

> Threat intelligence aggregation and IOC tracking — BlackRoad Security

[![CI](https://github.com/BlackRoad-Security/blackroad-threat-intel/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackRoad-Security/blackroad-threat-intel/actions/workflows/ci.yml)

Aggregate, enrich, and correlate **Indicators of Compromise (IOCs)** across threat feeds. Track threat actors, export STIX 2.1 bundles, and run FTS5-powered lookups.

## Features

- 🔍 **IOC Types**: IP, Domain, Hash, URL, Email, CVE
- 🎯 **Confidence + Severity**: 0–100 confidence score, info/low/medium/high/critical severity
- 👤 **Threat Actors**: Track APT groups, aliases, TTPs (MITRE ATT&CK), motivation
- ⚡ **FTS5 Search**: Full-text search across all indicator fields
- 🔗 **Correlation Engine**: Find related IOCs by source, tags, and patterns
- 📦 **STIX 2.1 Export**: Export as standards-compliant STIX 2.1 bundle JSON
- 📥 **Bulk Import**: Import from lists or threat feed JSON
- 💾 **SQLite**: Self-contained, zero-config persistence

## Quick Start

```bash
# Load demo threat data
python threat_intel.py demo

# Check an IP address
python threat_intel.py check-ip 185.220.101.45

# Check a domain
python threat_intel.py check-domain malware-c2.evil.com

# Add a custom indicator
python threat_intel.py add ip 10.0.0.1 85 high internal-soc

# Search indicators
python threat_intel.py search "botnet"

# Get all active high+ indicators
python threat_intel.py active high

# Export as STIX 2.1
python threat_intel.py export-stix threat_bundle.json

# Correlate an indicator
python threat_intel.py correlate <indicator_id>

# View stats
python threat_intel.py stats
```

## API

```python
from threat_intel import ThreatIntelDB

db = ThreatIntelDB("my_intel.db")

# Add IOC
ind = db.add_indicator("ip", "185.220.101.45", confidence=95,
                        severity="critical", source="abuse.ch",
                        tags=["tor", "exit-node"])

# Lookup
found = db.check_ip("185.220.101.45")

# Bulk import from feed
count = db.bulk_import([
    {"type": "domain", "value": "evil.com", "confidence": 90,
     "severity": "high", "source": "urlhaus", "tags": ["malware"]}
])

# Get active critical indicators
active = db.get_active("critical")

# Correlate
related = db.correlate(ind.id)

# Export STIX 2.1
stix_json = db.export_stix_json()

# Track threat actor
actor = db.add_threat_actor("APT-01", aliases=["Shadow"],
                             motivation="espionage",
                             ttps=["T1566", "T1059"])
```

## Indicator Types

| Type | Example | Notes |
|------|---------|-------|
| `ip` | `185.220.101.45` | Normalized, validated |
| `domain` | `evil.com` | Lowercased, dot-stripped |
| `hash` | `d41d8cd98f...` | MD5/SHA1/SHA256 |
| `url` | `http://evil.com/payload` | As-is |
| `email` | `phish@bad.com` | Lowercased |
| `cve` | `CVE-2021-44228` | Uppercased |

## Running Tests

```bash
pip install pytest
pytest test_threat_intel.py -v
```
