"""
detectors.py — Anomaly detection rules mapped to MITRE ATT&CK.

Each detector is a function that receives the full list of LogEntry objects
and returns a list of Alert objects (empty if nothing found).

Rules implemented:
  - BruteForce          → T1110   (Brute Force)
  - CredentialStuffing  → T1110.004
  - OffHoursAccess      → T1078   (Valid Accounts – Unusual Time)
  - LargeDataTransfer   → T1030 / T1041 (Exfiltration)
  - SQLInjectionProbe   → T1190   (Exploit Public-Facing Application)
  - SuspiciousUserAgent → T1203 / T1059
  - PathTraversal       → T1083   (File and Directory Discovery)
  - AdminAccessOffHours → T1078.002
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network

from .models import Alert, LogEntry, Severity


# ── Configurable thresholds ──────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD        = 5     # failed logins from same IP in BRUTE_WINDOW
BRUTE_FORCE_WINDOW_SECONDS   = 60
SPRAY_THRESHOLD              = 5     # different usernames from same IP
LARGE_BYTES_MB               = 10    # bytes_sent > this triggers data-exfil check
BUSINESS_HOURS_START         = 7     # 07:00
BUSINESS_HOURS_END           = 20    # 20:00

# Private / RFC-1918 ranges – accesses from outside these are "external"
_INTERNAL_RANGES = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
]

# Patterns that hint at injection / traversal attacks
_SQLI_PATTERNS = re.compile(
    r"('|%27|--|%2D%2D|/\*|\*/|xp_|union\s+select|select\s+.*from|"
    r"or\s+'?\d+'?\s*=\s*'?\d+'?|drop\s+table|insert\s+into|"
    r"sleep\s*\(|waitfor\s+delay|benchmark\s*\()",
    re.IGNORECASE,
)
_TRAVERSAL_PATTERNS = re.compile(
    r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e",
    re.IGNORECASE,
)

# User agents associated with automated scanners / exploit frameworks
_BAD_AGENTS = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|"
    r"hydra|medusa|burpsuite|nuclei|acunetix|nessus|openvas|"
    r"python-requests|go-http-client",
    re.IGNORECASE,
)

# Admin-like endpoints
_ADMIN_ENDPOINTS = re.compile(
    r"/admin|/superuser|/root|/manage|/console|/control",
    re.IGNORECASE,
)


def _is_internal(ip: str) -> bool:
    try:
        addr = ip_address(ip)
        return any(addr in net for net in _INTERNAL_RANGES)
    except ValueError:
        return False


def _is_off_hours(ts: datetime) -> bool:
    return not (BUSINESS_HOURS_START <= ts.hour < BUSINESS_HOURS_END)


# ── Individual detectors ─────────────────────────────────────────────────────

def detect_brute_force(entries: list[LogEntry]) -> list[Alert]:
    """
    T1110 — Brute Force
    Multiple failed logins from the same IP within a short time window.
    """
    alerts: list[Alert] = []
    failed_by_ip: dict[str, list[LogEntry]] = defaultdict(list)

    for e in entries:
        if e.action == "LOGIN" and e.status_code in (401, 403):
            failed_by_ip[e.ip_address].append(e)

    for ip, events in failed_by_ip.items():
        # Sliding-window check
        events.sort(key=lambda x: x.timestamp)
        for i, start_event in enumerate(events):
            window = [
                ev for ev in events[i:]
                if (ev.timestamp - start_event.timestamp).total_seconds()
                <= BRUTE_FORCE_WINDOW_SECONDS
            ]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                # Was the attack ultimately successful?
                window_end = window[-1].timestamp + timedelta(seconds=300)
                success_after = [
                    e for e in entries
                    if e.ip_address == ip
                    and e.action == "LOGIN"
                    and e.status_code == 200
                    and start_event.timestamp <= e.timestamp <= window_end
                ]
                severity = Severity.CRITICAL if success_after else Severity.HIGH
                desc = (
                    f"{len(window)} failed login attempts from {ip} in "
                    f"{BRUTE_FORCE_WINDOW_SECONDS}s targeting user "
                    f"'{window[0].user}'."
                )
                if success_after:
                    desc += f" ⚠️ Followed by SUCCESSFUL login at {success_after[0].timestamp}."

                alerts.append(Alert(
                    rule_id="BF-001",
                    title="Brute Force Login Attack",
                    description=desc,
                    severity=severity,
                    mitre_tactic="Credential Access",
                    mitre_id="T1110",
                    evidence=window + success_after,
                    recommendation=(
                        "Block IP immediately. Enable account lockout policy (≥5 failures). "
                        "Implement CAPTCHA and MFA. Review if account was compromised."
                    ),
                ))
                break  # one alert per IP

    return alerts


def detect_credential_stuffing(entries: list[LogEntry]) -> list[Alert]:
    """
    T1110.004 — Credential Stuffing
    One IP trying many different usernames (password-spray pattern).
    """
    alerts: list[Alert] = []
    attempts_by_ip: dict[str, list[LogEntry]] = defaultdict(list)

    for e in entries:
        if e.action == "LOGIN" and e.status_code in (401, 403):
            attempts_by_ip[e.ip_address].append(e)

    for ip, events in attempts_by_ip.items():
        unique_users = {e.user for e in events}
        if len(unique_users) >= SPRAY_THRESHOLD:
            alerts.append(Alert(
                rule_id="CS-001",
                title="Credential Stuffing / Password Spray",
                description=(
                    f"IP {ip} attempted login against {len(unique_users)} different accounts "
                    f"({len(events)} total attempts). Usernames: {', '.join(sorted(unique_users)[:10])}."
                ),
                severity=Severity.HIGH,
                mitre_tactic="Credential Access",
                mitre_id="T1110.004",
                evidence=events,
                recommendation=(
                    "Block source IP. Enable rate-limiting per IP (not per account). "
                    "Alert affected users to reset passwords. "
                    "Cross-reference IP against threat-intel feeds."
                ),
            ))

    return alerts


def detect_off_hours_admin(entries: list[LogEntry]) -> list[Alert]:
    """
    T1078.002 — Valid Accounts: Domain Accounts used outside business hours.
    Focus on admin endpoint access.
    """
    alerts: list[Alert] = []
    suspicious: list[LogEntry] = []

    for e in entries:
        if (
            _is_off_hours(e.timestamp)
            and _ADMIN_ENDPOINTS.search(e.endpoint)
            and e.status_code < 400
        ):
            suspicious.append(e)

    if suspicious:
        users = {e.user for e in suspicious}
        ips   = {e.ip_address for e in suspicious}
        alerts.append(Alert(
            rule_id="OHA-001",
            title="Admin Access Outside Business Hours",
            description=(
                f"{len(suspicious)} admin endpoint accesses detected outside business hours "
                f"(before {BUSINESS_HOURS_START:02d}:00 or after {BUSINESS_HOURS_END:02d}:00). "
                f"Users: {', '.join(users)}. IPs: {', '.join(ips)}."
            ),
            severity=Severity.HIGH,
            mitre_tactic="Privilege Escalation / Persistence",
            mitre_id="T1078.002",
            evidence=suspicious,
            recommendation=(
                "Verify activity with the account owner immediately. "
                "Enforce time-based access controls for admin roles. "
                "Review PAM / privileged access management policies."
            ),
        ))

    return alerts


def detect_off_hours_access(entries: list[LogEntry]) -> list[Alert]:
    """
    T1078 — Valid Accounts used at unusual hours (non-admin).
    """
    alerts: list[Alert] = []
    by_user: dict[str, list[LogEntry]] = defaultdict(list)

    for e in entries:
        if (
            _is_off_hours(e.timestamp)
            and e.action in ("LOGIN", "GET", "POST", "PUT", "DELETE")
            and e.status_code < 400
            and not _ADMIN_ENDPOINTS.search(e.endpoint)
        ):
            by_user[e.user].append(e)

    for user, events in by_user.items():
        if user in ("backup_svc", "system", "svc"):  # known service accounts
            severity = Severity.LOW
        else:
            severity = Severity.MEDIUM

        alerts.append(Alert(
            rule_id="OHU-001",
            title=f"Off-Hours System Access — {user}",
            description=(
                f"User '{user}' accessed the system at unusual hours: "
                f"{', '.join(str(e.timestamp) for e in events[:3])}{'...' if len(events) > 3 else ''}."
            ),
            severity=severity,
            mitre_tactic="Initial Access / Defense Evasion",
            mitre_id="T1078",
            evidence=events,
            recommendation=(
                "Confirm with user if activity was intentional. "
                "Implement behavioural baseline alerts (UEBA). "
                "Consider requiring MFA re-authentication outside normal hours."
            ),
        ))

    return alerts


def detect_large_data_transfer(entries: list[LogEntry]) -> list[Alert]:
    """
    T1041 — Exfiltration Over C2 Channel / T1030 — Data Transfer Size Limits.
    Large responses to external IPs.
    """
    alerts: list[Alert] = []
    threshold_bytes = LARGE_BYTES_MB * 1024 * 1024

    suspicious = [
        e for e in entries
        if e.bytes_sent >= threshold_bytes and not _is_internal(e.ip_address)
    ]

    if suspicious:
        total_mb = sum(e.bytes_sent for e in suspicious) / (1024 * 1024)
        alerts.append(Alert(
            rule_id="EX-001",
            title="Potential Data Exfiltration — Large Transfer to External IP",
            description=(
                f"{len(suspicious)} large responses sent to external IPs. "
                f"Total data volume: {total_mb:.1f} MB. "
                f"Endpoints: {', '.join({e.endpoint for e in suspicious})}."
            ),
            severity=Severity.CRITICAL,
            mitre_tactic="Exfiltration",
            mitre_id="T1041",
            evidence=suspicious,
            recommendation=(
                "Immediately audit what data was served. "
                "Check DLP controls and endpoint egress policies. "
                "Review user/service account permissions for the involved endpoints. "
                "Cross-check with backup or ETL schedules before escalating."
            ),
        ))

    return alerts


def detect_sql_injection(entries: list[LogEntry]) -> list[Alert]:
    """
    T1190 — Exploit Public-Facing Application (SQLi / injection probes).
    """
    alerts: list[Alert] = []
    suspicious = [
        e for e in entries
        if _SQLI_PATTERNS.search(e.endpoint)
    ]

    if suspicious:
        ips = {e.ip_address for e in suspicious}
        alerts.append(Alert(
            rule_id="INJ-001",
            title="SQL Injection / Injection Probe Detected",
            description=(
                f"{len(suspicious)} requests with SQL injection patterns detected "
                f"from {len(ips)} IP(s): {', '.join(ips)}. "
                f"Sample endpoint: {suspicious[0].endpoint[:120]}."
            ),
            severity=Severity.HIGH,
            mitre_tactic="Initial Access",
            mitre_id="T1190",
            evidence=suspicious,
            recommendation=(
                "Block offending IPs at WAF / firewall level. "
                "Review application code for parameterised query usage. "
                "Enable WAF rules for OWASP Top 10 (A03:2021 – Injection). "
                "Audit database logs for any successful injection queries."
            ),
        ))

    return alerts


def detect_path_traversal(entries: list[LogEntry]) -> list[Alert]:
    """
    T1083 — File and Directory Discovery via path traversal probes.
    """
    suspicious = [
        e for e in entries
        if _TRAVERSAL_PATTERNS.search(e.endpoint)
    ]
    if not suspicious:
        return []

    return [Alert(
        rule_id="PT-001",
        title="Path Traversal Attempt",
        description=(
            f"{len(suspicious)} path traversal pattern(s) detected. "
            f"IPs: {', '.join({e.ip_address for e in suspicious})}. "
            f"Sample: {suspicious[0].endpoint[:120]}."
        ),
        severity=Severity.HIGH,
        mitre_tactic="Discovery",
        mitre_id="T1083",
        evidence=suspicious,
        recommendation=(
            "Sanitise all file path inputs server-side. "
            "Block IPs at WAF. "
            "Confirm no sensitive files were served (check response codes and sizes). "
            "Review chroot / sandbox configurations."
        ),
    )]


def detect_suspicious_user_agent(entries: list[LogEntry]) -> list[Alert]:
    """
    Heuristic — requests from known scanner / exploit-framework user agents.
    """
    suspicious = [
        e for e in entries
        if _BAD_AGENTS.search(e.user_agent)
    ]
    if not suspicious:
        return []

    tools = set()
    for e in suspicious:
        m = _BAD_AGENTS.search(e.user_agent)
        if m:
            tools.add(m.group().lower())

    return [Alert(
        rule_id="UA-001",
        title="Suspicious / Automated Scanner User-Agent",
        description=(
            f"{len(suspicious)} requests from known scanning tools: {', '.join(tools)}. "
            f"IPs: {', '.join({e.ip_address for e in suspicious})}."
        ),
        severity=Severity.MEDIUM,
        mitre_tactic="Reconnaissance",
        mitre_id="T1595",
        evidence=suspicious,
        recommendation=(
            "Block IPs proactively. Add scanner UA strings to WAF blocklist. "
            "Review endpoints targeted for exposure risk. "
            "Check if any requests returned 200 responses."
        ),
    )]


# ── Detector registry ────────────────────────────────────────────────────────

ALL_DETECTORS = [
    detect_brute_force,
    detect_credential_stuffing,
    detect_off_hours_admin,
    detect_off_hours_access,
    detect_large_data_transfer,
    detect_sql_injection,
    detect_path_traversal,
    detect_suspicious_user_agent,
]


def run_all_detectors(entries: list[LogEntry]) -> list[Alert]:
    """Run every registered detector and return the merged alert list."""
    all_alerts: list[Alert] = []
    for detector in ALL_DETECTORS:
        try:
            results = detector(entries)
            all_alerts.extend(results)
        except Exception as exc:
            print(f"  [WARN] Detector {detector.__name__} raised: {exc}")
    return all_alerts
