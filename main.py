#!/usr/bin/env python3
"""
main.py — CLI entrypoint for the Log Analyzer.

Usage:
    python main.py --log sample_logs/access_sample.csv
    python main.py --log sample_logs/access_sample.csv --output output/report.html --vt
    python main.py --log /var/log/nginx/access.log --format txt
"""
import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

from log_analyzer.detectors import run_all_detectors
from log_analyzer.enrichment import enrich_alerts_with_vt
from log_analyzer.models import AnalysisReport
from log_analyzer.parser import parse_log_file
from log_analyzer.report import generate_html_report

# ── ANSI colours for terminal output ────────────────────────────────────────
_R  = "\033[91m"
_O  = "\033[93m"
_Y  = "\033[33m"
_G  = "\033[92m"
_B  = "\033[94m"
_DIM = "\033[2m"
_RST = "\033[0m"
_BOLD = "\033[1m"

_SEV_COLOR = {
    "CRITICAL": _R,
    "HIGH":     _O,
    "MEDIUM":   _Y,
    "LOW":      _G,
    "INFO":     _DIM,
}


def _banner() -> None:
    print(f"""
{_B}{_BOLD}┌─────────────────────────────────────────────┐
│          LOG ANOMALY ANALYZER v1.0          │
│   MITRE ATT&CK · OWASP · ISO 27001 aligned │
└─────────────────────────────────────────────┘{_RST}
""")


def _print_summary(report: AnalysisReport) -> None:
    print(f"\n{_BOLD}{'─'*50}{_RST}")
    print(f"{_BOLD}  ANALYSIS COMPLETE{_RST}")
    print(f"{'─'*50}")
    print(f"  Log file    : {report.log_file}")
    print(f"  Entries     : {report.total_entries:,}")
    print(f"  Alerts      : {len(report.alerts)}")
    print()

    if not report.alerts:
        print(f"  {_G}✓  No anomalies detected.{_RST}\n")
        return

    for alert in report.alerts_by_severity:
        col = _SEV_COLOR.get(alert.severity.value, "")
        print(
            f"  {col}[{alert.severity.value:<8}]{_RST} "
            f"{_BOLD}{alert.title}{_RST}\n"
            f"           {_DIM}{alert.rule_id} · {alert.mitre_id} · "
            f"{alert.event_count} events · IPs: {', '.join(alert.affected_ips[:3])}{_RST}"
        )
        if alert.ioc_matches:
            for ioc in alert.ioc_matches:
                print(f"           {_R}⚠ IOC: {ioc}{_RST}")
        print()

    risk = report.critical_count * 40 + report.high_count * 20 + report.medium_count * 8 + report.low_count * 2
    risk_label = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 40 else "MEDIUM" if risk >= 15 else "LOW"
    col = _SEV_COLOR.get(risk_label, "")
    print(f"  {_BOLD}Overall Risk Score: {col}{risk} ({risk_label}){_RST}\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyse access/transaction logs for security anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --log sample_logs/access_sample.csv
  python main.py --log /var/log/nginx/access.log --output output/report.html
  python main.py --log logs/transactions.json --vt
        """,
    )
    parser.add_argument(
        "--log", "-l",
        required=True,
        help="Path to log file (CSV, JSON, or Apache/Nginx txt).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output HTML report path (default: output/report_<timestamp>.html).",
    )
    parser.add_argument(
        "--vt",
        action="store_true",
        help="Enrich alerts with VirusTotal IOC lookup (requires VT_API_KEY env var).",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip HTML report generation; print summary only.",
    )
    args = parser.parse_args()

    _banner()

    # ── 1. Parse ─────────────────────────────────────────────────────────────
    log_path = Path(args.log)
    print(f"  {_B}[1/4]{_RST} Parsing log file: {log_path.name} …", end=" ", flush=True)
    t0 = time.perf_counter()
    try:
        entries = parse_log_file(log_path)
    except FileNotFoundError as exc:
        print(f"\n  {_R}ERROR: {exc}{_RST}")
        return 1
    except Exception as exc:
        print(f"\n  {_R}ERROR parsing log: {exc}{_RST}")
        return 1

    elapsed = time.perf_counter() - t0
    print(f"{_G}done{_RST} ({len(entries):,} entries, {elapsed:.2f}s)")

    if not entries:
        print(f"  {_Y}WARNING: No parseable entries found in the file.{_RST}")
        return 1

    # ── 2. Detect ─────────────────────────────────────────────────────────────
    print(f"  {_B}[2/4]{_RST} Running anomaly detectors …", end=" ", flush=True)
    t0 = time.perf_counter()
    alerts = run_all_detectors(entries)
    elapsed = time.perf_counter() - t0
    print(f"{_G}done{_RST} ({len(alerts)} alert(s), {elapsed:.2f}s)")

    # ── 3. Enrich ─────────────────────────────────────────────────────────────
    print(f"  {_B}[3/4]{_RST} IOC enrichment …", end=" ", flush=True)
    if args.vt:
        print()
        enrich_alerts_with_vt(alerts)
    else:
        print(f"{_DIM}skipped (use --vt to enable){_RST}")

    # ── 4. Report ─────────────────────────────────────────────────────────────
    ts_range = (entries[0].timestamp, entries[-1].timestamp)
    report = AnalysisReport(
        generated_at=datetime.now(),
        log_file=str(log_path),
        total_entries=len(entries),
        alerts=alerts,
        analysis_window=ts_range,
    )

    if not args.no_report:
        output_path = Path(args.output) if args.output else (
            Path("output") / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        print(f"  {_B}[4/4]{_RST} Generating HTML report …", end=" ", flush=True)
        t0 = time.perf_counter()
        generate_html_report(report, output_path)
        elapsed = time.perf_counter() - t0
        print(f"{_G}done{_RST} ({elapsed:.2f}s)")
        print(f"\n  {_BOLD}Report saved:{_RST} {output_path.resolve()}\n")
    else:
        print(f"  {_B}[4/4]{_RST} Report generation {_DIM}skipped (--no-report){_RST}")

    _print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
