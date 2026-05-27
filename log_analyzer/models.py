"""
models.py — Core data structures for the Log Analyzer.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class LogEntry:
    """Normalized representation of a single log line."""
    timestamp:   datetime
    ip_address:  str
    user:        str
    action:      str
    status_code: int
    endpoint:    str
    user_agent:  str
    bytes_sent:  int
    raw:         str = ""


@dataclass
class Alert:
    """A security alert raised by a detector."""
    rule_id:      str
    title:        str
    description:  str
    severity:     Severity
    mitre_tactic: str
    mitre_id:     str
    evidence:     list[LogEntry]
    recommendation: str
    timestamp:    datetime = field(default_factory=datetime.now)
    ioc_matches:  list[str] = field(default_factory=list)

    @property
    def event_count(self) -> int:
        return len(self.evidence)

    @property
    def affected_ips(self) -> list[str]:
        return list({e.ip_address for e in self.evidence})

    @property
    def affected_users(self) -> list[str]:
        return list({e.user for e in self.evidence})


@dataclass
class AnalysisReport:
    """Final output aggregating all alerts and statistics."""
    generated_at:  datetime
    log_file:      str
    total_entries: int
    alerts:        list[Alert]
    analysis_window: tuple[datetime, datetime]

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == Severity.LOW)

    @property
    def alerts_by_severity(self) -> list[Alert]:
        return sorted(self.alerts, key=lambda a: SEVERITY_ORDER[a.severity], reverse=True)
