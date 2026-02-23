# blackroad-threat-intel

Threat Intelligence management platform with IoC tracking, MITRE ATT&CK mapping, and threat correlation.

## Features

- 🎯 **IoC Management** – IP, domain, hash (MD5/SHA256), URL, email, CVE indicators
- 🔍 **Auto-Detection** – Automatically detect IoC type from value format
- 🗺️ **MITRE ATT&CK** – Map indicators to ATT&CK technique IDs (T1078, T1110, etc.)
- 📊 **Shannon Entropy** – Future integration with secret scanner
- 🔔 **Threat Events** – Track detection alerts and incidents
- 💾 **SQLite** – Persistent indicator database with full-text search

## Supported IoC Types

| Type | Example | Detection |
|------|---------|-----------|
| IP | 192.168.1.1 | IPv4/IPv6 parsing |
| Domain | evil.example.com | DNS regex |
| HASH_MD5 | d41d8cd98f00b204... | 32 hex chars |
| HASH_SHA256 | e3b0c44298fc1c14... | 64 hex chars |
| URL | https://phish.com | URL prefix |
| CVE | CVE-2024-1234 | CVE regex |
| EMAIL | attacker@evil.com | @ + domain |

## Usage

```bash
# Add an IoC
python src/threat_intel.py add "192.168.1.100" --severity HIGH --source "honeypot" --mitre "T1110"

# Auto-detect type
python src/threat_intel.py add "AKIAIOSFODNN7EXAMPLE" --source "scanner"

# Lookup IoC
python src/threat_intel.py lookup "192.168.1.100"

# Search IoCs
python src/threat_intel.py search --severity CRITICAL --limit 10

# MITRE techniques
python src/threat_intel.py mitre T1078
python src/threat_intel.py mitre  # list all

# Statistics
python src/threat_intel.py stats
```

## Tests

```bash
pytest tests/ -v --cov=src
```

## License

Proprietary – BlackRoad OS, Inc. All rights reserved.