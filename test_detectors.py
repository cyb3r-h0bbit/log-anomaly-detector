"""
tests/test_detectors.py — Unit tests for detection rules.

Run with:  python -m pytest tests/ -v
"""
import csv
import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from log_analyzer.detectors import (
    detect_brute_force,
    detect_credential_stuffing,
    detect_large_data_transfer,
    detect_off_hours_admin,
    detect_path_traversal,
    detect_sql_injection,
    detect_suspicious_user_agent,
    run_all_detectors,
)
from log_analyzer.models import LogEntry, Severity
from log_analyzer.parser import parse_log_file


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_entry(
    ts: str = "2024-01-15 14:00:00",
    ip: str = "192.168.1.1",
    user: str = "jsilva",
    action: str = "GET",
    status: int = 200,
    endpoint: str = "/dashboard",
    ua: str = "Mozilla/5.0",
    bytes_sent: int = 1024,
) -> LogEntry:
    return LogEntry(
        timestamp=datetime.strptime(ts, "%Y-%m-%d %H:%M:%S"),
        ip_address=ip,
        user=user,
        action=action,
        status_code=status,
        endpoint=endpoint,
        user_agent=ua,
        bytes_sent=bytes_sent,
    )


def _failed_logins(ip: str, user: str, n: int, base_ts: str) -> list[LogEntry]:
    """Generate n failed login entries 2 seconds apart."""
    base = datetime.strptime(base_ts, "%Y-%m-%d %H:%M:%S")
    from datetime import timedelta
    entries = []
    for i in range(n):
        e = _make_entry(
            ts=(base + timedelta(seconds=i * 2)).strftime("%Y-%m-%d %H:%M:%S"),
            ip=ip,
            user=user,
            action="LOGIN",
            status=401,
            endpoint="/auth/login",
        )
        entries.append(e)
    return entries


# ── Parser tests ─────────────────────────────────────────────────────────────

class TestParser:
    def test_parse_csv(self, tmp_path):
        f = tmp_path / "test.csv"
        f.write_text(
            "timestamp,ip_address,user,action,status_code,endpoint,user_agent,bytes_sent\n"
            "2024-01-15 09:00:00,10.0.0.1,alice,GET,200,/home,Mozilla/5.0,512\n"
            "2024-01-15 09:05:00,10.0.0.2,bob,LOGIN,401,/auth/login,curl/7.0,256\n"
        )
        entries = parse_log_file(f)
        assert len(entries) == 2
        assert entries[0].user == "alice"
        assert entries[1].status_code == 401

    def test_parse_json(self, tmp_path):
        f = tmp_path / "test.json"
        data = [
            {"timestamp": "2024-01-15 10:00:00", "ip_address": "1.2.3.4",
             "user": "carol", "action": "GET", "status_code": 200,
             "endpoint": "/api", "user_agent": "Mozilla", "bytes_sent": 1024}
        ]
        f.write_text(json.dumps(data))
        entries = parse_log_file(f)
        assert len(entries) == 1
        assert entries[0].user == "carol"

    def test_sorted_by_timestamp(self, tmp_path):
        f = tmp_path / "test.csv"
        f.write_text(
            "timestamp,ip_address,user,action,status_code,endpoint,user_agent,bytes_sent\n"
            "2024-01-15 12:00:00,10.0.0.1,z,GET,200,/,ua,100\n"
            "2024-01-15 08:00:00,10.0.0.1,a,GET,200,/,ua,100\n"
        )
        entries = parse_log_file(f)
        assert entries[0].user == "a"
        assert entries[1].user == "z"

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_log_file("/nonexistent/path/file.csv")


# ── Detector tests ────────────────────────────────────────────────────────────

class TestBruteForce:
    def test_detects_brute_force(self):
        entries = _failed_logins("5.5.5.5", "admin", 6, "2024-01-15 03:00:00")
        alerts = detect_brute_force(entries)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "BF-001"
        assert alerts[0].severity in (Severity.HIGH, Severity.CRITICAL)

    def test_no_alert_below_threshold(self):
        entries = _failed_logins("5.5.5.5", "admin", 4, "2024-01-15 03:00:00")
        alerts = detect_brute_force(entries)
        assert len(alerts) == 0

    def test_critical_when_successful_after(self):
        from datetime import timedelta
        failed = _failed_logins("9.9.9.9", "admin", 6, "2024-01-15 02:00:00")
        success = _make_entry(
            ts="2024-01-15 02:00:30",
            ip="9.9.9.9", user="admin", action="LOGIN", status=200,
        )
        alerts = detect_brute_force(failed + [success])
        assert any(a.severity == Severity.CRITICAL for a in alerts)

    def test_different_ips_no_alert(self):
        entries = [
            _make_entry(ip=f"10.0.0.{i}", action="LOGIN", status=401)
            for i in range(10)
        ]
        alerts = detect_brute_force(entries)
        assert len(alerts) == 0


class TestCredentialStuffing:
    def test_detects_spray(self):
        entries = [
            _make_entry(ip="7.7.7.7", user=f"user{i:03d}", action="LOGIN", status=401)
            for i in range(8)
        ]
        alerts = detect_credential_stuffing(entries)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "CS-001"

    def test_no_alert_single_user(self):
        entries = _failed_logins("7.7.7.7", "admin", 10, "2024-01-15 12:00:00")
        alerts = detect_credential_stuffing(entries)
        assert len(alerts) == 0


class TestOffHoursAdmin:
    def test_detects_off_hours_admin(self):
        e = _make_entry(ts="2024-01-15 03:00:00", endpoint="/admin/users", status=200)
        alerts = detect_off_hours_admin([e])
        assert len(alerts) == 1
        assert alerts[0].rule_id == "OHA-001"

    def test_no_alert_during_business_hours(self):
        e = _make_entry(ts="2024-01-15 10:00:00", endpoint="/admin/users", status=200)
        alerts = detect_off_hours_admin([e])
        assert len(alerts) == 0

    def test_no_alert_failed_admin_access(self):
        e = _make_entry(ts="2024-01-15 03:00:00", endpoint="/admin/users", status=403)
        alerts = detect_off_hours_admin([e])
        assert len(alerts) == 0


class TestLargeDataTransfer:
    def test_detects_large_external_transfer(self):
        e = _make_entry(ip="8.8.8.8", bytes_sent=50 * 1024 * 1024)  # 50 MB
        alerts = detect_large_data_transfer([e])
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.CRITICAL

    def test_no_alert_internal_large_transfer(self):
        e = _make_entry(ip="192.168.1.50", bytes_sent=50 * 1024 * 1024)
        alerts = detect_large_data_transfer([e])
        assert len(alerts) == 0

    def test_no_alert_small_external_transfer(self):
        e = _make_entry(ip="8.8.8.8", bytes_sent=1024)
        alerts = detect_large_data_transfer([e])
        assert len(alerts) == 0


class TestSQLInjection:
    def test_detects_sqli(self):
        e = _make_entry(endpoint="/api/users?id=1' OR '1'='1")
        alerts = detect_sql_injection([e])
        assert len(alerts) == 1
        assert alerts[0].rule_id == "INJ-001"

    def test_detects_drop_table(self):
        e = _make_entry(endpoint="/api/q?sort=name;DROP TABLE users")
        alerts = detect_sql_injection([e])
        assert len(alerts) == 1

    def test_clean_request_no_alert(self):
        e = _make_entry(endpoint="/api/users?id=42&sort=name")
        alerts = detect_sql_injection([e])
        assert len(alerts) == 0


class TestPathTraversal:
    def test_detects_traversal(self):
        e = _make_entry(endpoint="/admin/../../../etc/passwd")
        alerts = detect_path_traversal([e])
        assert len(alerts) == 1
        assert alerts[0].rule_id == "PT-001"

    def test_detects_encoded_traversal(self):
        e = _make_entry(endpoint="/files/%2e%2e%2f%2e%2e%2fetc/shadow")
        alerts = detect_path_traversal([e])
        assert len(alerts) == 1

    def test_clean_path_no_alert(self):
        e = _make_entry(endpoint="/files/report_2024.pdf")
        alerts = detect_path_traversal([e])
        assert len(alerts) == 0


class TestSuspiciousUserAgent:
    def test_detects_sqlmap(self):
        e = _make_entry(ua="sqlmap/1.7#stable (https://sqlmap.org)")
        alerts = detect_suspicious_user_agent([e])
        assert len(alerts) == 1
        assert alerts[0].rule_id == "UA-001"

    def test_detects_nikto(self):
        e = _make_entry(ua="Nikto/2.1.5 (Evasion: None)")
        alerts = detect_suspicious_user_agent([e])
        assert len(alerts) == 1

    def test_clean_ua_no_alert(self):
        e = _make_entry(ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
        alerts = detect_suspicious_user_agent([e])
        assert len(alerts) == 0


class TestRunAllDetectors:
    def test_run_all_returns_list(self):
        entries = [_make_entry()]
        alerts = run_all_detectors(entries)
        assert isinstance(alerts, list)

    def test_empty_entries(self):
        alerts = run_all_detectors([])
        assert alerts == []
