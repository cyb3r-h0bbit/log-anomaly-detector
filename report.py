"""
report.py — Generates a polished HTML security report from an AnalysisReport.
"""
from datetime import datetime
from pathlib import Path

from .models import Alert, AnalysisReport, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#ff3b30",
    Severity.HIGH:     "#ff9500",
    Severity.MEDIUM:   "#ffd60a",
    Severity.LOW:      "#30d158",
    Severity.INFO:     "#636366",
}

_SEVERITY_BG = {
    Severity.CRITICAL: "rgba(255,59,48,0.12)",
    Severity.HIGH:     "rgba(255,149,0,0.12)",
    Severity.MEDIUM:   "rgba(255,214,10,0.10)",
    Severity.LOW:      "rgba(48,209,88,0.10)",
    Severity.INFO:     "rgba(99,99,102,0.10)",
}

_CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,600;0,700;1,400&display=swap');

:root {
  --bg:          #0a0a0f;
  --surface:     #111118;
  --surface2:    #18181f;
  --border:      #2a2a35;
  --text:        #e8e8ed;
  --text-muted:  #8e8e9a;
  --accent:      #5e7eff;
  --critical:    #ff3b30;
  --high:        #ff9500;
  --medium:      #ffd60a;
  --low:         #30d158;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'IBM Plex Sans', sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
  line-height: 1.6;
}

/* ── NOISE TEXTURE ── */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
  pointer-events: none;
  z-index: 0;
}

.container { max-width: 1100px; margin: 0 auto; padding: 0 32px; position: relative; z-index: 1; }

/* ── HEADER ── */
.header {
  border-bottom: 1px solid var(--border);
  padding: 48px 0 32px;
  margin-bottom: 40px;
}

.header-eyebrow {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 12px;
}

.header h1 {
  font-size: 32px;
  font-weight: 700;
  letter-spacing: -0.02em;
  line-height: 1.2;
  margin-bottom: 16px;
}

.header-meta {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  color: var(--text-muted);
  display: flex;
  gap: 32px;
  flex-wrap: wrap;
}

.header-meta span { display: flex; align-items: center; gap: 6px; }

/* ── SCORE CARDS ── */
.scorecard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 16px;
  margin-bottom: 40px;
}

.scorecard {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  position: relative;
  overflow: hidden;
}

.scorecard::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
}

.scorecard.critical::before { background: var(--critical); }
.scorecard.high::before     { background: var(--high); }
.scorecard.medium::before   { background: var(--medium); }
.scorecard.low::before      { background: var(--low); }
.scorecard.total::before    { background: var(--accent); }

.scorecard-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 8px;
}

.scorecard-value {
  font-size: 36px;
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1;
}

.scorecard.critical .scorecard-value { color: var(--critical); }
.scorecard.high     .scorecard-value { color: var(--high); }
.scorecard.medium   .scorecard-value { color: var(--medium); }
.scorecard.low      .scorecard-value { color: var(--low); }
.scorecard.total    .scorecard-value { color: var(--accent); }

/* ── SECTION TITLE ── */
.section-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 20px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
}

.section-title::before {
  content: '';
  display: inline-block;
  width: 4px;
  height: 14px;
  background: var(--accent);
  border-radius: 2px;
}

/* ── ALERT CARDS ── */
.alerts-section { margin-bottom: 48px; }

.alert-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 16px;
  overflow: hidden;
  transition: border-color 0.2s;
}

.alert-card:hover { border-color: var(--accent); }

.alert-header {
  padding: 16px 20px;
  display: flex;
  align-items: flex-start;
  gap: 16px;
  cursor: pointer;
  user-select: none;
}

.alert-header::-webkit-details-marker { display: none; }

.severity-badge {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.08em;
  padding: 3px 8px;
  border-radius: 4px;
  text-transform: uppercase;
  flex-shrink: 0;
  margin-top: 2px;
}

.alert-title-block { flex: 1; }

.alert-title {
  font-size: 15px;
  font-weight: 600;
  margin-bottom: 4px;
}

.alert-subtitle {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  color: var(--text-muted);
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.alert-body {
  padding: 0 20px 20px;
  border-top: 1px solid var(--border);
}

.alert-desc {
  padding: 14px 0 12px;
  color: var(--text);
  font-size: 13px;
  line-height: 1.7;
}

.alert-field {
  margin-bottom: 12px;
}

.field-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 6px;
}

.field-value {
  font-size: 13px;
  color: var(--text);
}

.mitre-tag {
  display: inline-block;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  background: rgba(94,126,255,0.12);
  border: 1px solid rgba(94,126,255,0.3);
  color: var(--accent);
  padding: 3px 10px;
  border-radius: 4px;
  margin-right: 8px;
}

.recommendation-box {
  background: var(--surface2);
  border-left: 3px solid var(--accent);
  padding: 12px 14px;
  border-radius: 0 4px 4px 0;
  font-size: 13px;
  line-height: 1.65;
}

.ioc-box {
  background: rgba(255,59,48,0.06);
  border: 1px solid rgba(255,59,48,0.2);
  border-radius: 6px;
  padding: 10px 14px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  color: var(--critical);
}

/* Evidence table */
.evidence-toggle {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  color: var(--accent);
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  text-decoration: underline;
  text-underline-offset: 3px;
  margin-bottom: 8px;
}

.evidence-table {
  width: 100%;
  border-collapse: collapse;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  margin-top: 8px;
}

.evidence-table th {
  text-align: left;
  padding: 6px 10px;
  background: var(--surface2);
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  letter-spacing: 0.05em;
  font-weight: 600;
}

.evidence-table td {
  padding: 5px 10px;
  border-bottom: 1px solid rgba(42,42,53,0.5);
  color: var(--text);
  vertical-align: top;
  word-break: break-all;
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.status-ok   { color: var(--low); }
.status-warn { color: var(--medium); }
.status-bad  { color: var(--critical); }

/* ── FOOTER ── */
.footer {
  border-top: 1px solid var(--border);
  padding: 24px 0 40px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  color: var(--text-muted);
}
"""


def _severity_badge(sev: Severity) -> str:
    color = _SEVERITY_COLOR[sev]
    bg    = _SEVERITY_BG[sev]
    return (
        f'<span class="severity-badge" '
        f'style="color:{color};background:{bg};border:1px solid {color}33">'
        f'{sev.value}</span>'
    )


def _status_class(code: int) -> str:
    if code < 300:    return "status-ok"
    if code < 400:    return "status-warn"
    return "status-bad"


def _render_alert(alert: Alert, idx: int) -> str:
    badge   = _severity_badge(alert.severity)
    color   = _SEVERITY_COLOR[alert.severity]
    ioc_html = ""
    if alert.ioc_matches:
        ioc_lines = "".join(f"<div>⚠ {m}</div>" for m in alert.ioc_matches)
        ioc_html = f'<div class="alert-field"><div class="field-label">IOC Matches (VirusTotal)</div><div class="ioc-box">{ioc_lines}</div></div>'

    evidence_rows = "".join(
        f'<tr>'
        f'<td>{e.timestamp.strftime("%H:%M:%S")}</td>'
        f'<td>{e.ip_address}</td>'
        f'<td>{e.user}</td>'
        f'<td>{e.action}</td>'
        f'<td class="{_status_class(e.status_code)}">{e.status_code}</td>'
        f'<td title="{e.endpoint}">{e.endpoint[:60]}{"…" if len(e.endpoint) > 60 else ""}</td>'
        f'<td>{e.bytes_sent:,}</td>'
        f'</tr>'
        for e in alert.evidence[:20]
    )
    extra = f"<tr><td colspan='7' style='color:var(--text-muted);padding:6px 10px'>…and {len(alert.evidence)-20} more events</td></tr>" if len(alert.evidence) > 20 else ""

    return f"""
<details class="alert-card" {'open' if alert.severity in (Severity.CRITICAL, Severity.HIGH) else ''}>
  <summary class="alert-header" style="list-style:none">
    {badge}
    <div class="alert-title-block">
      <div class="alert-title">{alert.title}</div>
      <div class="alert-subtitle">
        <span>Rule: {alert.rule_id}</span>
        <span>Events: {alert.event_count}</span>
        <span>IPs: {', '.join(alert.affected_ips[:3])}{'…' if len(alert.affected_ips) > 3 else ''}</span>
        <span>{alert.timestamp.strftime('%H:%M:%S')}</span>
      </div>
    </div>
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;color:var(--text-muted)"><path d="m6 9 6 6 6-6"/></svg>
  </summary>
  <div class="alert-body">
    <div class="alert-desc">{alert.description}</div>
    <div class="alert-field">
      <div class="field-label">MITRE ATT&amp;CK</div>
      <div>
        <span class="mitre-tag">{alert.mitre_id}</span>
        <span style="font-size:13px;color:var(--text-muted)">{alert.mitre_tactic}</span>
      </div>
    </div>
    {ioc_html}
    <div class="alert-field">
      <div class="field-label">Recommended Action</div>
      <div class="recommendation-box">{alert.recommendation}</div>
    </div>
    <div class="alert-field">
      <div class="field-label">Evidence ({min(len(alert.evidence),20)} of {len(alert.evidence)} events)</div>
      <div style="overflow-x:auto">
        <table class="evidence-table">
          <thead><tr>
            <th>Time</th><th>IP</th><th>User</th><th>Action</th><th>Status</th><th>Endpoint</th><th>Bytes</th>
          </tr></thead>
          <tbody>{evidence_rows}{extra}</tbody>
        </table>
      </div>
    </div>
  </div>
</details>
"""


def generate_html_report(report: AnalysisReport, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    window_start, window_end = report.analysis_window
    risk_score = (
        report.critical_count * 40
        + report.high_count    * 20
        + report.medium_count  * 8
        + report.low_count     * 2
    )
    risk_label = (
        "CRITICAL" if risk_score >= 80 else
        "HIGH"     if risk_score >= 40 else
        "MEDIUM"   if risk_score >= 15 else
        "LOW"
    )
    risk_color = {
        "CRITICAL": "#ff3b30",
        "HIGH":     "#ff9500",
        "MEDIUM":   "#ffd60a",
        "LOW":      "#30d158",
    }[risk_label]

    alerts_html = "\n".join(
        _render_alert(a, i) for i, a in enumerate(report.alerts_by_severity)
    )

    if not report.alerts:
        alerts_html = '<div style="text-align:center;padding:40px;color:var(--text-muted)">✓ No anomalies detected in this log file.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Log Analysis Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">

  <!-- HEADER -->
  <header class="header">
    <div class="header-eyebrow">Security Operations · Log Analysis Report</div>
    <h1>Anomaly Detection<br>Analysis Report</h1>
    <div class="header-meta">
      <span>📁 {report.log_file}</span>
      <span>🕐 Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</span>
      <span>📊 {report.total_entries:,} entries analysed</span>
      <span>🗓 Window: {window_start.strftime('%Y-%m-%d %H:%M')} → {window_end.strftime('%Y-%m-%d %H:%M')}</span>
      <span style="color:{risk_color};font-weight:600">⚡ Overall Risk: {risk_label}</span>
    </div>
  </header>

  <!-- SCORECARDS -->
  <div class="scorecard-grid">
    <div class="scorecard total">
      <div class="scorecard-label">Total Alerts</div>
      <div class="scorecard-value">{len(report.alerts)}</div>
    </div>
    <div class="scorecard critical">
      <div class="scorecard-label">Critical</div>
      <div class="scorecard-value">{report.critical_count}</div>
    </div>
    <div class="scorecard high">
      <div class="scorecard-label">High</div>
      <div class="scorecard-value">{report.high_count}</div>
    </div>
    <div class="scorecard medium">
      <div class="scorecard-label">Medium</div>
      <div class="scorecard-value">{report.medium_count}</div>
    </div>
    <div class="scorecard low">
      <div class="scorecard-label">Low</div>
      <div class="scorecard-value">{report.low_count}</div>
    </div>
    <div class="scorecard total" style="--accent:#30d158">
      <div class="scorecard-label">Risk Score</div>
      <div class="scorecard-value" style="font-size:28px;color:{risk_color}">{risk_score}</div>
    </div>
  </div>

  <!-- ALERTS -->
  <section class="alerts-section">
    <div class="section-title">Detected Anomalies — sorted by severity</div>
    {alerts_html}
  </section>

  <!-- FOOTER -->
  <footer class="footer">
    <span>log-analyzer · github.com/hobbit</span>
    <span>MITRE ATT&amp;CK® · OWASP Top 10 · ISO 27001</span>
    <span>Generated {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}</span>
  </footer>

</div>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    return output_path
