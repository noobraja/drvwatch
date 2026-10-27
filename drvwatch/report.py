"""Console, JSON and HTML rendering."""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any

COLORS = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;34m",
    "info": "\033[2;37m",
    "none": "\033[2;37m",
}
RESET = "\033[0m"


def _paint(text: str, severity: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLORS.get(severity, '')}{text}{RESET}"


def _short(value: Any, width: int) -> str:
    text = "-" if value in (None, "") else str(value)
    return text if len(text) <= width else text[: width - 1] + "\u2026"


def render_console(report: dict[str, Any], color: bool = True) -> str:
    summary = report["summary"]
    lines = []
    lines.append(f"drvwatch \u2014 {summary['drivers']} kernel drivers, "
                 f"{summary['drivers_at_risk']} at risk")
    counts = summary["findings_by_severity"]
    breakdown = "  ".join(
        f"{severity}={counts[severity]}"
        for severity in ("critical", "high", "medium", "low", "info")
    )
    lines.append(f"findings: {breakdown}")
    lines.append("")

    header = f"{'SEVERITY':<9} {'DRIVER':<24} {'STATE':<9} {'START':<7} {'SIGNATURE':<14} FINDING"
    lines.append(header)
    lines.append("-" * 100)

    for driver in report["drivers"]:
        worst = driver["worst"]
        if worst == "none":
            continue
        primary = driver["findings"][0]
        severity_cell = _paint(f"{worst:<9}", worst, color)
        name = _short(driver.get("name"), 24)
        state = _short(driver.get("state"), 9)
        start = _short(driver.get("start_mode"), 7)
        signature = _short(driver.get("signature_status"), 14)
        lines.append(
            f"{severity_cell} {name:<24} {state:<9} {start:<7} "
            f"{signature:<14} {primary['rule']}"
        )

    clean = sum(1 for d in report["drivers"] if d["worst"] == "none")
    lines.append("-" * 100)
    lines.append(f"{clean} drivers clean")
    return "\n".join(lines)


def render_json(report: dict[str, Any]) -> str:
    payload = {
        "tool": "drvwatch",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "report": report,
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def render_html(report: dict[str, Any]) -> str:
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    summary = report["summary"]
    counts = summary["findings_by_severity"]

    badge_colors = {
        "critical": "#b3261e",
        "high": "#c2410c",
        "medium": "#a16207",
        "low": "#1d4ed8",
        "info": "#52525b",
        "none": "#3f6212",
    }

    rows = []
    for driver in report["drivers"]:
        color = badge_colors.get(driver["worst"], "#52525b")
        findings = driver["findings"]
        if findings:
            detail = "<br>".join(
                f"<code>{html.escape(f['rule'])}</code> "
                f"<span class='tech'>{html.escape(f['technique'])}</span> "
                f"{html.escape(f['detail'])}"
                for f in findings
            )
        else:
            detail = "<span class='muted'>no findings</span>"

        rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{color}'>{html.escape(driver['worst'])}</span></td>"
            f"<td><strong>{html.escape(str(driver.get('name') or '-'))}</strong></td>"
            f"<td>{html.escape(str(driver.get('state') or '-'))}</td>"
            f"<td>{html.escape(str(driver.get('start_mode') or '-'))}</td>"
            f"<td>{html.escape(str(driver.get('signature_status') or 'not checked'))}</td>"
            f"<td class='detail'>{detail}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>drvwatch report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
         margin: 2rem; max-width: 1200px; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 .25rem; }}
  .muted {{ color: #71717a; }}
  .stats {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 1rem 0 1.5rem; }}
  .stat {{ background: #f4f4f5; border-radius: 8px; padding: .6rem .9rem; }}
  .stat b {{ display: block; font-size: 1.3rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #e4e4e7;
            vertical-align: top; }}
  th {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: #71717a; }}
  .badge {{ display: inline-block; padding: .1rem .45rem; border-radius: 999px;
            color: #fff; font-size: .7rem; font-weight: 600; text-transform: uppercase; }}
  .detail {{ font-size: .85rem; }}
  code {{ background: #f4f4f5; padding: .05rem .3rem; border-radius: 4px; font-size: .8rem; }}
  .tech {{ color: #7c3aed; font-size: .75rem; font-weight: 600; }}
  @media (prefers-color-scheme: dark) {{
    .stat, code {{ background: #27272a; }}
    td, th {{ border-color: #3f3f46; }}
  }}
</style>
</head>
<body>
<h1>drvwatch \u2014 kernel driver findings</h1>
<p class="muted">Generated {html.escape(generated)}</p>
<div class="stats">
  <div class="stat"><b>{summary['drivers']}</b>drivers</div>
  <div class="stat"><b>{summary['drivers_at_risk']}</b>at risk</div>
  <div class="stat"><b>{counts['critical']}</b>critical findings</div>
  <div class="stat"><b>{counts['high']}</b>high findings</div>
  <div class="stat"><b>{counts['medium']}</b>medium findings</div>
</div>
<table>
<thead><tr><th>Severity</th><th>Driver</th><th>State</th><th>Start</th><th>Signature</th><th>Findings</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>
"""
