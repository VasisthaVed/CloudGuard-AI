"""
html_report.py -- Generates a self-contained HTML security report.

Usage:
    from html_report import generate_html_report
    generate_html_report(findings, risk_score, risk_level, filename="report.html")

CLI flag: python main.py --html
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

VERSION = "2.0.0"
TEMPLATE_PATH = Path(__file__).parent / "report_template.html"


def _severity_class(sev: str) -> str:
    return {
        "Critical": "sev-critical",
        "High":     "sev-high",
        "Medium":   "sev-medium",
        "Low":      "sev-low",
    }.get(sev, "sev-low")


def _build_findings_rows(findings: list[dict]) -> str:
    rows = []
    for i, f in enumerate(findings):
        service  = f.get("service", "—")
        resource = f.get("resource_name", "—")
        issue    = f.get("issue", "—")
        severity = f.get("severity", "Low")
        region   = f.get("region", "global")
        details  = f.get("details", "")
        sev_cls  = _severity_class(severity)
        sev_lower = severity.lower()

        # Compliance tags
        compliance = f.get("compliance", [])
        tags_html = "".join(f'<span class="tag">{t}</span>' for t in compliance)
        tags_block = f'<div class="compliance-tags">{tags_html}</div>' if tags_html else "—"

        # AI advice
        raw_advice = f.get("ai_advice", "No AI advice available.")
        if isinstance(raw_advice, list):
            raw_advice = "\n".join(raw_advice)
        # Escape < > for HTML safety
        safe_advice = raw_advice.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # Judge info
        judge      = f.get("judge_info", {})
        winner     = judge.get("winning_model", "—")
        confidence = judge.get("confidence_score", "—")
        reasoning  = judge.get("reasoning", "—")
        safe_reason = reasoning.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # Main finding row
        rows.append(f"""
          <tr class="finding-row" id="row-{i}" data-sev="{severity}" onclick="toggleAdvice({i})">
            <td><span class="badge-service">{service}</span></td>
            <td>
              <span class="resource-name">{resource}</span><br/>
              <span style="font-size:0.7rem;color:var(--text-muted)">{region}</span>
            </td>
            <td class="issue-text">{issue}</td>
            <td><span class="sev {sev_cls}"><span class="sev-dot" style="background:currentColor"></span>{severity}</span></td>
            <td>{tags_block}</td>
            <td><span class="chevron" id="chev-{i}">&#9660;</span></td>
          </tr>
          <tr class="advice-row" data-sev="{severity}">
            <td colspan="6">
              <div class="advice-panel" id="advice-{i}">
                <h4>AI Remediation Advice</h4>
                <pre>{safe_advice}</pre>
                <div class="advice-details">
                  <div class="advice-meta-item">
                    <label>Details</label>
                    <span>{details}</span>
                  </div>
                  <div class="advice-meta-item">
                    <label>Region</label>
                    <span>{region}</span>
                  </div>
                  <div class="advice-meta-item">
                    <label>Winning Model</label>
                    <span>{winner}</span>
                  </div>
                  <div class="advice-meta-item">
                    <label>Confidence</label>
                    <span>{confidence}</span>
                  </div>
                </div>
              </div>
            </td>
          </tr>
        """)
    return "\n".join(rows)


def generate_html_report(
    findings: list[dict],
    risk_score: int = 0,
    risk_level: str = "LOW",
    filename: str = None,
) -> str:
    """
    Generates a standalone HTML report from findings.
    Returns the filename.
    """
    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cloudguard_report_{ts}.html"

    # Load template
    if not TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Template not found at: {TEMPLATE_PATH}")

    template = TEMPLATE_PATH.read_text(encoding="utf-8")

    # Severity counts
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    regions = set()
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
        r = f.get("region")
        if r:
            regions.add(r)

    # Risk percentage for the bar (cap at 100)
    risk_pct = min(int(risk_score / 1.0), 100)

    # Build findings rows
    findings_rows = _build_findings_rows(findings)

    # Timestamp
    ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Replace all template placeholders
    replacements = {
        "{{VERSION}}":       VERSION,
        "{{TIMESTAMP}}":     ts_str,
        "{{RISK_SCORE}}":    str(risk_score),
        "{{RISK_LEVEL}}":    risk_level,
        "{{RISK_PCT}}":      str(risk_pct),
        "{{TOTAL_FINDINGS}}": str(len(findings)),
        "{{REGION_COUNT}}":  str(max(len(regions), 1)),
        "{{COUNT_CRITICAL}}": str(counts["Critical"]),
        "{{COUNT_HIGH}}":    str(counts["High"]),
        "{{COUNT_MEDIUM}}":  str(counts["Medium"]),
        "{{COUNT_LOW}}":     str(counts["Low"]),
        "{{FINDINGS_ROWS}}": findings_rows,
    }

    html = template
    for placeholder, value in replacements.items():
        html = html.replace(placeholder, value)

    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(html)

    return filename


if __name__ == "__main__":
    # Quick local test with mock data
    mock = [
        {
            "service": "S3", "resource_name": "s3-bucket-customer-data",
            "region": "us-east-1", "issue": "Public Read Access Enabled",
            "severity": "Critical", "details": "Bucket policy allows public GetObject.",
            "compliance": ["CIS AWS 2.1.1", "SOC 2 CC6.1"],
            "ai_advice": "1. Go to S3 Console\n2. Select bucket\n3. Enable Block All Public Access",
        },
        {
            "service": "IAM", "resource_name": "User: dev-intern",
            "region": "global", "issue": "MFA Not Enabled",
            "severity": "High", "details": "No MFA device configured.",
            "compliance": ["CIS AWS 1.2"],
            "ai_advice": "Enable MFA via IAM console -> Users -> Security Credentials",
        },
        {
            "service": "EC2/VPC", "resource_name": "sg-web-server",
            "region": "us-east-1", "issue": "SSH open to 0.0.0.0/0",
            "severity": "Critical", "details": "Port 22 exposed to the internet.",
            "compliance": ["CIS AWS 4.1", "PCI-DSS 1.2.1"],
            "ai_advice": "Restrict inbound rule to your specific IP address.",
        },
    ]

    out = generate_html_report(mock, risk_score=35, risk_level="ELEVATED")
    print(f"Report saved: {out}")
    print(f"Open in browser: file:///{os.path.abspath(out)}")
