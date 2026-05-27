"""
enrichment.py — Optional IOC enrichment via VirusTotal API v3.

Set the environment variable VT_API_KEY to enable.
Falls back gracefully if the key is absent or the API is unreachable.
"""
import os
import time
from functools import lru_cache
from typing import Optional

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

from .models import Alert

_VT_BASE  = "https://www.virustotal.com/api/v3"
_VT_KEY   = os.environ.get("VT_API_KEY", "")
_HEADERS  = {"x-apikey": _VT_KEY, "Accept": "application/json"}
_RATE_S   = 15  # free tier: 4 req/min → 1 per 15s


@lru_cache(maxsize=256)
def _check_ip(ip: str) -> Optional[dict]:
    """Query VirusTotal for an IP reputation. Returns None on failure."""
    if not _REQUESTS_AVAILABLE or not _VT_KEY:
        return None
    try:
        resp = _requests.get(
            f"{_VT_BASE}/ip_addresses/{ip}",
            headers=_HEADERS,
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 401:
            print("  [VT] Invalid API key — enrichment disabled.")
        return None
    except Exception:
        return None


def _is_malicious(vt_data: dict) -> bool:
    """Return True if VirusTotal considers the IP malicious."""
    try:
        stats = (
            vt_data["data"]["attributes"]
            ["last_analysis_stats"]
        )
        return (stats.get("malicious", 0) + stats.get("suspicious", 0)) > 0
    except (KeyError, TypeError):
        return False


def _vt_summary(vt_data: dict) -> str:
    try:
        stats  = vt_data["data"]["attributes"]["last_analysis_stats"]
        mal    = stats.get("malicious", 0)
        sus    = stats.get("suspicious", 0)
        total  = sum(stats.values())
        vendor = vt_data["data"]["attributes"].get("as_owner", "unknown ASN")
        return f"VT: {mal} malicious, {sus} suspicious / {total} engines. ASN: {vendor}"
    except (KeyError, TypeError):
        return "VT: no summary available"


def enrich_alerts_with_vt(alerts: list[Alert]) -> list[Alert]:
    """
    For each alert, check unique IPs against VirusTotal.
    Appends IOC match strings to alert.ioc_matches in-place.
    Returns the same list (mutated).
    """
    if not _VT_KEY:
        print("  [VT] VT_API_KEY not set — skipping IOC enrichment.")
        return alerts

    print("  [VT] Enriching alerts via VirusTotal…")
    checked: set[str] = set()

    for alert in alerts:
        for ip in alert.affected_ips:
            if ip in checked:
                continue
            checked.add(ip)

            vt_data = _check_ip(ip)
            if vt_data and _is_malicious(vt_data):
                summary = _vt_summary(vt_data)
                alert.ioc_matches.append(f"{ip} — {summary}")
                print(f"    [VT] ⚠ MATCH: {ip} ({summary})")
            
            time.sleep(_RATE_S)  # respect free-tier rate limit

    return alerts
