# KUMARAN v2.0 — Smart Network Security Scanner

KUMARAN is a fast multi-threaded CLI network scanner built in Python.
It scans open ports, detects services, and calculates risk levels.

**Developer:** Ninshad  
**Language:** Python 3.8+  
**Style:** Kali Linux CLI tool

---

## Installation

```bash
# Clone or copy all files into one folder, then:
chmod +x kumaran.py
pip3 install --break-system-packages -r requirements.txt   # (no deps needed — stdlib only)
```

---

## Usage

```
python3 kumaran.py <target> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | IP or hostname | required |
| `-p`, `--ports` | Port range or list | `1-1024` |
| `-t`, `--threads` | Thread count | `150` |
| `--timeout` | Socket timeout (seconds) | `1.0` |
| `-o`, `--output` | Output filename (no extension) | none |
| `-f`, `--format` | `txt` / `json` / `xml` | `txt` |
| `-v`, `--verbose` | Live output during scan | off |
| `--no-banner` | Suppress ASCII banner | off |
| `--no-color` | Disable ANSI colors | off |

---

## Examples

```bash
# Basic scan — ports 1-1024
python3 kumaran.py scanme.nmap.org

# Specific ports
python3 kumaran.py 192.168.1.1 -p 22,80,443,3306

# Full port scan, 200 threads, verbose
python3 kumaran.py 10.0.0.1 -p 1-65535 -t 200 -v

# Save JSON report
python3 kumaran.py 10.0.0.1 -p 1-1024 -o report -f json

# Save XML, no color (for piping)
python3 kumaran.py target.com -p 1-1024 --no-color -o scan -f xml

# Mixed port specification
python3 kumaran.py 192.168.1.100 -p 22,80,443,8000-8090,3306
```

---

## File Structure

```
kumaran/
├── kumaran.py   ← main entry point
├── scanner.py   ← threaded port scanner + banner grabbing
├── risk.py      ← risk scoring engine (CVE-category aware)
├── output.py    ← TXT / JSON / XML report writer
└── README.md
```

---

## Risk Levels

| Level | Score Weight | Examples |
|-------|-------------|----------|
| HIGH | +3 | Telnet, SMB, Redis, MongoDB, Docker API, RDP |
| MEDIUM | +2 | SSH, HTTP, MySQL, DNS, SMTP |
| LOW | +1 | HTTPS, IMAPS, NTP |
| INFO | +0 | Unknown/unrecognized service |

**Overall Risk:**
- `CRITICAL` ≥ 7 points
- `HIGH` ≥ 5
- `MEDIUM` ≥ 3
- `LOW` > 0
- `SAFE` = 0

---

## Legal

This tool is for **authorized penetration testing and security auditing only**.  
Scanning systems you do not own or have explicit permission to test is illegal.

