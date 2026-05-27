"""
parser.py — Multi-format log parser (CSV, JSON, Apache/Nginx combined log).

Normalizes all formats into a list of LogEntry objects so the detectors
never need to know about the original format.
"""
import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .models import LogEntry


# ── Apache / Nginx Combined Log Format ──────────────────────────────────────
# 192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
_APACHE_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<bytes>\S+)'
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)
_APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

# Suspicious user-agent fragments (lowercase)
_SUSPICIOUS_UA = {
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "python-requests", "go-http-client", "curl", "wget",
    "dirbuster", "gobuster", "hydra", "medusa", "burpsuite",
}


def _clean_bytes(val: str) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def _parse_csv(path: Path) -> Iterator[LogEntry]:
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        # Normalise column names: lowercase + strip spaces
        reader.fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]
        for row in reader:
            try:
                # Support common timestamp column names
                ts_raw = (
                    row.get("timestamp")
                    or row.get("time")
                    or row.get("date")
                    or ""
                ).strip()
                ts = _parse_timestamp(ts_raw)

                yield LogEntry(
                    timestamp=ts,
                    ip_address=row.get("ip_address", row.get("ip", "")).strip(),
                    user=row.get("user", row.get("username", "")).strip(),
                    action=row.get("action", row.get("method", "")).strip().upper(),
                    status_code=int(row.get("status_code", row.get("status", 0)) or 0),
                    endpoint=row.get("endpoint", row.get("path", row.get("url", ""))).strip(),
                    user_agent=row.get("user_agent", row.get("useragent", "")).strip(),
                    bytes_sent=_clean_bytes(
                        row.get("bytes_sent", row.get("bytes", row.get("size", 0)))
                    ),
                    raw=str(row),
                )
            except Exception:
                continue  # skip malformed rows silently


def _parse_json(path: Path) -> Iterator[LogEntry]:
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)

    if isinstance(data, dict):
        data = [data]

    for entry in data:
        try:
            ts_raw = (
                entry.get("timestamp")
                or entry.get("time")
                or entry.get("@timestamp", "")
            )
            yield LogEntry(
                timestamp=_parse_timestamp(str(ts_raw)),
                ip_address=entry.get("ip_address", entry.get("ip", "")),
                user=entry.get("user", entry.get("username", "")),
                action=str(entry.get("action", entry.get("method", ""))).upper(),
                status_code=int(entry.get("status_code", entry.get("status", 0)) or 0),
                endpoint=entry.get("endpoint", entry.get("path", entry.get("url", ""))),
                user_agent=entry.get("user_agent", entry.get("useragent", "")),
                bytes_sent=_clean_bytes(entry.get("bytes_sent", entry.get("bytes", 0))),
                raw=json.dumps(entry),
            )
        except Exception:
            continue


def _parse_txt(path: Path) -> Iterator[LogEntry]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _APACHE_RE.match(line)
            if m:
                try:
                    yield LogEntry(
                        timestamp=datetime.strptime(m.group("ts"), _APACHE_TS_FMT).replace(tzinfo=None),
                        ip_address=m.group("ip"),
                        user=m.group("user").replace("-", "anonymous"),
                        action=m.group("method"),
                        status_code=int(m.group("status")),
                        endpoint=m.group("endpoint"),
                        user_agent=m.group("ua") or "",
                        bytes_sent=_clean_bytes(m.group("bytes")),
                        raw=line,
                    )
                except Exception:
                    continue


def _parse_timestamp(ts: str) -> datetime:
    """Try multiple timestamp formats."""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%d/%b/%Y:%H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timestamp: {ts!r}")


def parse_log_file(path: str | Path) -> list[LogEntry]:
    """
    Parse a log file in CSV, JSON, or Apache/Nginx text format.
    Returns a list of normalised LogEntry objects, sorted by timestamp.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".csv":
        entries = list(_parse_csv(path))
    elif suffix == ".json":
        entries = list(_parse_json(path))
    else:  # .log, .txt, or anything else → try Apache/combined format
        entries = list(_parse_txt(path))

    entries.sort(key=lambda e: e.timestamp)
    return entries
