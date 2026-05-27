# 🔍 Log Anomaly Analyzer

> A Python security tool that reads access and transactional logs, detects suspicious behaviour using MITRE ATT&CK-mapped rules, and generates a polished HTML report, built for Blue Team portfolios and production SOC environments.

---

## The Problem It Solves

Most organizations generate thousands of log lines per day across web servers, APIs, and transactional systems. Without automated analysis, threats like brute-force attacks, data exfiltration, and injection probes go unnoticed until it's too late.

This tool brings structured threat detection to raw log files with no SIEM required.

---

## Features

| Capability | Details |
|---|---|
| **Multi-format parsing** | CSV, JSON, Apache/Nginx combined log (`.log`, `.txt`) |
| **8 detection rules** | Brute force, credential stuffing, off-hours access, admin abuse, data exfiltration, SQLi, path traversal, suspicious user-agents |
| **MITRE ATT&CK mapping** | Every alert tagged with tactic and technique ID |
| **Severity classification** | CRITICAL / HIGH / MEDIUM / LOW with risk score |
| **HTML report** | Dark editorial UI with evidence tables and remediation guidance |
| **IOC enrichment** | Optional VirusTotal API v3 integration for IP reputation lookup |
| **CLI interface** | Simple flags, coloured terminal output |
| **27 unit tests** | Pytest suite covering all detectors and the parser |

---

## Security Framework Alignment

This project was built against real-world security standards:

- **MITRE ATT&CK** — Every detection rule maps to a technique (T1110, T1078, T1041, T1190, T1083, T1595, T1110.004, T1078.002)
- **OWASP Top 10** — Injection (A03), Security Misconfiguration (A05), Vulnerable Components (A06)
- **ISO 27001** — Annex A.12.4 (Logging and Monitoring), A.16.1 (Incident Management)

---

## Project Structure

```
log-analyzer/
├── log_analyzer/
│   ├── __init__.py       # Public API
│   ├── models.py         # LogEntry, Alert, AnalysisReport dataclasses
│   ├── parser.py         # Multi-format log parser
│   ├── detectors.py      # 8 MITRE ATT&CK-mapped detection rules
│   ├── enrichment.py     # VirusTotal IOC enrichment (optional)
│   └── report.py         # HTML report generator
├── tests/
│   └── test_detectors.py # 27 unit tests (pytest)
├── sample_logs/
│   └── access_sample.csv # Sample log with realistic attack patterns
├── output/               # Generated reports land here
├── main.py               # CLI entrypoint
└── requirements.txt
```

---

## Quickstart

### 1. Clone and install

```bash
git clone https://github.com/hobbit/log-analyzer.git
cd log-analyzer
pip install -r requirements.txt
```

### 2. Run against the sample log

```bash
python main.py --log sample_logs/access_sample.csv
```

Open `output/report_<timestamp>.html` in your browser.

### 3. Run against your own log

```bash
# CSV log (columns: timestamp, ip_address, user, action, status_code, endpoint, user_agent, bytes_sent)
python main.py --log /path/to/access.csv --output output/my_report.html

# Apache / Nginx combined log format
python main.py --log /var/log/nginx/access.log

# JSON log (array of objects with the same fields)
python main.py --log transactions.json
```

### 4. Enable VirusTotal enrichment

```bash
export VT_API_KEY="your_api_key_here"
python main.py --log sample_logs/access_sample.csv --vt
```

> Free VirusTotal accounts allow 4 requests/minute. The tool respects this rate limit automatically.

---

## Detection Rules

| Rule ID | Title | MITRE ID | Severity |
|---|---|---|---|
| `BF-001` | Brute Force Login Attack | T1110 | HIGH / CRITICAL |
| `CS-001` | Credential Stuffing / Password Spray | T1110.004 | HIGH |
| `OHA-001` | Admin Access Outside Business Hours | T1078.002 | HIGH |
| `OHU-001` | Off-Hours System Access | T1078 | LOW–MEDIUM |
| `EX-001` | Large Data Transfer to External IP | T1041 | CRITICAL |
| `INJ-001` | SQL Injection / Injection Probe | T1190 | HIGH |
| `PT-001` | Path Traversal Attempt | T1083 | HIGH |
| `UA-001` | Suspicious Scanner User-Agent | T1595 | MEDIUM |

### How thresholds are configured

Open `log_analyzer/detectors.py` and edit the constants at the top of the file:

```python
BRUTE_FORCE_THRESHOLD       = 5   # failed logins from same IP in BRUTE_WINDOW
BRUTE_FORCE_WINDOW_SECONDS  = 60
LARGE_BYTES_MB              = 10  # threshold for data exfiltration alert
BUSINESS_HOURS_START        = 7   # 07:00
BUSINESS_HOURS_END          = 20  # 20:00
```

---

## Log Format Reference

### CSV (recommended)

```csv
timestamp,ip_address,user,action,status_code,endpoint,user_agent,bytes_sent
2024-01-15 09:00:00,192.168.1.10,jsilva,LOGIN,200,/auth/login,Mozilla/5.0,1024
2024-01-15 02:14:05,185.220.101.42,admin,LOGIN,401,/auth/login,python-requests/2.28.0,512
```

Column names are flexible — the parser also understands `ip`, `username`, `method`, `status`, `path`, `url`, `useragent`, `bytes`, `size`.

### JSON

```json
[
  {
    "timestamp": "2024-01-15 09:00:00",
    "ip_address": "192.168.1.10",
    "user": "jsilva",
    "action": "GET",
    "status_code": 200,
    "endpoint": "/dashboard",
    "user_agent": "Mozilla/5.0",
    "bytes_sent": 4096
  }
]
```

### Apache / Nginx combined log

```
192.168.1.1 - frank [10/Jan/2024:13:55:36 -0300] "GET /dashboard HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```

---

## Running Tests

```bash
python -m pytest tests/ -v
# 27 passed in 0.07s
```

With coverage:

```bash
python -m pytest tests/ --cov=log_analyzer --cov-report=term-missing
```

---

## Extending the Tool

Adding a new detection rule takes 3 steps:

1. **Write the function** in `log_analyzer/detectors.py`:

```python
def detect_my_rule(entries: list[LogEntry]) -> list[Alert]:
    suspicious = [e for e in entries if ...]  # your logic here
    if not suspicious:
        return []
    return [Alert(
        rule_id="XX-001",
        title="My Custom Rule",
        description="...",
        severity=Severity.HIGH,
        mitre_tactic="...",
        mitre_id="T????",
        evidence=suspicious,
        recommendation="...",
    )]
```

2. **Register it** by adding it to `ALL_DETECTORS` at the bottom of `detectors.py`.

3. **Write tests** in `tests/test_detectors.py`.

---

## Roadmap

- [ ] JSON Lines (`.jsonl` / NDJSON) support
- [ ] Syslog / RFC 5424 parser
- [ ] Timeline visualisation in the HTML report
- [ ] Configurable rules via YAML file (no code changes needed)
- [ ] Slack / webhook alerting integration
- [ ] Docker image for CI/CD pipelines

---

## Author

**Daniel Cavalcante** — Automation & Financial Processes Analyst transitioning into Information Security.

- Focus areas: Blue Team · SOC · IAM · Threat Intelligence
- LinkedIn: [linkedin.com/in/hobbit](https://linkedin.com/in/hobbit)

---

## License

MIT — free to use, modify, and distribute.
