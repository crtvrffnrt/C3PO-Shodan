#!/usr/bin/env python3
import argparse
import base64
import json
import os
import sys
from datetime import datetime
from html import escape
from typing import Optional


def risk_badge(level: str) -> str:
    return {
        "critical": "badge-critical",
        "high": "badge-high",
        "medium": "badge-medium",
        "low": "badge-low",
    }.get(level, "badge-low")


def human_date(iso_value: str) -> str:
    if not iso_value:
        return "unknown"
    try:
        dt = datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y %H:%M UTC")
    except Exception:
        return iso_value


def inline_image(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "rb") as handle:
            encoded = base64.b64encode(handle.read()).decode("utf-8")
        ext = os.path.splitext(path)[1].lower().strip(".")
        return f"data:image/{ext};base64,{encoded}"
    except Exception:
        return ""


def screenshot_map(manifest: dict) -> dict:
    mapping = {}
    for entry in manifest.get("entries") or []:
        host = entry.get("hostname")
        if host:
            mapping[host] = entry
    return mapping


def join_list(items: list, empty: str = "none") -> str:
    valid = [str(i) for i in items if i]
    return ", ".join(valid) if valid else empty


def render_host_card(host: dict, screenshot_entry: Optional[dict]) -> str:
    screenshot_html = ""
    if screenshot_entry and screenshot_entry.get("status") == "captured":
        image = inline_image(screenshot_entry.get("path", ""))
        if image:
            screenshot_html = (
                '<div class="shot-wrap">'
                f'<img class="shot" src="{image}" alt="Screenshot of {escape(host.get("hostname", ""))}">'
                "</div>"
            )
    
    services = "".join(
        f'<span class="pill port">{escape(str(port))}</span>'
        for port in host.get("ports", [])[:8]
    )
    
    vulns = "".join(
        f'<span class="pill vuln">{escape(str(v))}</span>'
        for v in host.get("vulns", [])[:8]
    )

    factors = "".join(f"<li>{escape(factor)}</li>" for factor in host.get("risk_factors", [])[:5])
    
    ips = host.get("current_ips", [])
    primary_ip = ips[0] if ips else "n/a"

    return f"""
      <article class="host-card">
        <div class="host-head">
          <div class="host-title-group">
            <span class="eyebrow" style="margin-bottom:4px;">Target Asset</span>
            <h3>{escape(host.get("hostname", ""))}</h3>
            <span class="muted mono" style="font-size:10px;">Sources: {escape(", ".join(host.get("sources", [])))}</span>
          </div>
          <div class="risk-badge badge-{host.get('risk_level', 'low')}">
            {escape(host.get('risk_level', '').upper())} {host.get('risk_score', 0)}
          </div>
        </div>
        
        <div class="kv-grid">
          <div class="kv"><span class="meta-label">Primary IP</span><strong class="mono">{escape(primary_ip)}</strong></div>
          <div class="kv"><span class="meta-label">HTTP URL</span><strong class="mono">{escape(host.get("http", {}).get("url", "n/a"))}</strong></div>
        </div>

        <div class="pill-group">{services}{vulns}</div>

        <div class="risk-factors">
          <span class="meta-label">Risk Profile</span>
          <ul>{factors or '<li>Baseline risk detected.</li>'}</ul>
        </div>

        {screenshot_html}
      </article>
    """


def html_report(payload: dict, manifest: dict, nuclei_results: list[dict]) -> str:
    target = payload.get("target", {})
    summary = payload.get("summary", {})
    hosts = payload.get("hosts", [])
    ip_assets = payload.get("ips", [])
    discoveries = payload.get("discoveries", {})
    screenshots = screenshot_map(manifest)

    # Nuclei Summary Metrics
    nuclei_critical = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "critical")
    nuclei_high = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "high")
    nuclei_med = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "medium")
    nuclei_total = len(nuclei_results)

    summary_cards = [
        ("Surface Score", str(summary.get("original_total_hosts", 0))),
        ("Target Focus", str(len(hosts))),
        ("Web Entrypoints", str(summary.get("web_host_count", 0))),
        ("Risk (C/H/M)", f"{summary.get('critical_count', 0)} / {summary.get('high_count', 0)} / {summary.get('medium_count', 0)}"),
        ("Nuclei Hits", str(nuclei_total)),
        ("Nuclei (C/H)", f"{nuclei_critical} / {nuclei_high}"),
    ]
    summary_card_html = "".join(
        f'<section class="summary-card"><span class="meta-label">{escape(label)}</span><strong>{escape(value)}</strong></section>'
        for label, value in summary_cards
    )

    # Nuclei Findings Table
    nuclei_rows = "".join(
        f"""
        <tr>
          <td><span class="badge badge-{r.get('info', {}).get('severity', 'low')}">{escape(r.get('info', {}).get('severity', '').upper())}</span></td>
          <td class="mono small">{escape(r.get('template-id', ''))}</td>
          <td class="small">{escape(r.get('info', {}).get('name', ''))}</td>
          <td class="mono small">{escape(r.get('matched-at', ''))}</td>
        </tr>
        """
        for r in nuclei_results[:50]
    ) or '<tr><td colspan="4" class="muted">No nuclei findings recorded for this session.</td></tr>'

    takeover_html = "".join(
        f"""
        <article class="callout">
          <div class="pill-group"><span class="badge">Takeover Target</span></div>
          <h3>{escape(item.get('hostname', ''))}</h3>
          <p class="small">{escape(join_list(item.get('reasons', []), empty='No reason recorded'))}</p>
        </article>
        """
        for item in discoveries.get("takeover_candidates", [])[:12]
    ) or '<article class="callout"><h3>No Takeover Signals</h3><p class="small">Current heuristics indicate stable infrastructure.</p></article>'

    txt_html = "".join(
        f"""
        <article class="callout">
          <div class="pill-group"><span class="badge">DNS Intelligence</span></div>
          <h3>{escape(item.get('hostname', ''))}</h3>
          <p class="meta-label" style="margin-top:8px;">{escape(item.get('label', ''))}</p>
          <code class="mono" style="display:block; margin-top:8px; font-size:11px; word-break:break-all; background:#f7f8fa; padding:8px; border-radius:8px; border:1px solid var(--line);">{escape(item.get('value', ''))}</code>
        </article>
        """
        for item in discoveries.get("interesting_txt", [])[:12]
    ) or '<article class="callout"><h3>No TXT Signals</h3><p class="small">No interesting DNS evidence collected.</p></article>'

    ip_rows = "".join(
        f"""
        <tr>
          <td class="mono small">{escape(item.get('ip', ''))}</td>
          <td class="mono small">{escape(item.get('network_hint', ''))}</td>
          <td class="small">{escape(join_list(item.get('hostnames', [])))}</td>
          <td class="mono small">{escape(join_list([str(port) for port in item.get('ports', [])]))}</td>
          <td class="small">{escape(join_list(item.get('products', [])))}</td>
          <td class="muted small">{escape(item.get('org', '') or 'n/a')}</td>
        </tr>
        """
        for item in ip_assets[:80]
    )

    host_cards = "".join(render_host_card(host, screenshots.get(host.get("hostname", ""))) for host in hosts)
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EASM | {escape(target.get('core_domain', ''))}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Manrope:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --viewer-bg: #eef1f4;
      --viewer-bg-soft: #f6f7f9;
      --paper: #ffffff;
      --paper-strong: #fbfbfc;
      --text: #111111;
      --text-soft: #2a2a2a;
      --text-muted: #666666;
      --line: #d7dbe0;
      --line-strong: #c4c9cf;
      --shadow: 0 24px 60px rgba(0, 0, 0, 0.08);
      --radius-lg: 28px;
      --radius-md: 18px;
      --radius-sm: 12px;
      --danger: #d93025;
      --warn: #f29900;
      --ok: #1e8e3e;
      --accent: #1a73e8;
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: linear-gradient(180deg, #f7f8fa 0%, #eef1f4 100%);
      color: var(--text);
      font: 400 14px/1.68 "Manrope", sans-serif;
    }}
    a {{ color: inherit; }}
    .viewer-shell {{
      width: min(1460px, calc(100% - 28px));
      margin: 0 auto;
      padding: 28px 0 52px;
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      gap: 28px;
    }}
    .sidebar {{
      position: sticky;
      top: 20px;
      align-self: start;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }}
    .panel {{
      background: rgba(255, 255, 255, 0.92);
      border: 1px solid rgba(0, 0, 0, 0.08);
      border-radius: var(--radius-lg);
      box-shadow: 0 18px 36px rgba(0, 0, 0, 0.05);
      padding: 22px 22px 20px;
    }}
    .eyebrow, .meta-label, .terminal-title, .badge, .pill, .toc a, .footer-meta {{
      font-family: "IBM Plex Mono", monospace;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }}
    .eyebrow {{ margin: 0 0 12px; font-size: 0.7rem; color: var(--text-muted); }}
    .sidebar h1, .paper h1, .paper h2, .paper h3 {{
      font-family: "Space Grotesk", sans-serif;
      line-height: 1.08;
      letter-spacing: -0.03em;
      color: #060606;
    }}
    .sidebar h1 {{ margin: 0 0 14px; font-size: 1.5rem; }}
    .sidebar p {{ margin: 0; color: var(--text-soft); font-size: 0.9rem; }}
    .sidebar .muted {{ color: var(--text-muted); }}
    .quick-facts {{ margin-top: 16px; display: grid; gap: 12px; }}
    .fact {{
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      padding: 12px 13px;
      background: linear-gradient(180deg, #ffffff 0%, #fafbfc 100%);
    }}
    .meta-label {{ display: block; font-size: 0.65rem; color: var(--text-muted); margin-bottom: 4px; }}
    .meta-value {{ font-size: 0.9rem; font-weight: 700; color: var(--text); }}
    .toc h2, .info-card h2, .researcher-card h2 {{ margin: 0 0 14px; font-size: 0.9rem; }}
    .toc nav {{ display: grid; gap: 8px; }}
    .toc a {{
      display: block;
      font-size: 0.72rem;
      text-decoration: none;
      color: var(--text-soft);
      padding: 8px 10px;
      border-radius: 10px;
      border: 1px solid transparent;
      transition: all 140ms ease;
    }}
    .toc a:hover {{ background: #fafbfc; border-color: var(--line); transform: translateX(2px); }}
    .paper-wrap {{ min-width: 0; }}
    .paper {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 34px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }}
    .paper-inner {{ padding: 44px 52px 54px; }}
    .cover {{ padding-bottom: 26px; border-bottom: 1px solid var(--line); }}
    .cover-kicker {{ margin: 0 0 14px; font: 600 0.72rem/1 "IBM Plex Mono", monospace; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); }}
    .paper h1 {{ margin: 0 0 16px; font-size: clamp(1.8rem, 4vw, 2.8rem); }}
    .lede {{ margin: 0; max-width: 860px; font-size: 1.05rem; color: var(--text-soft); }}
    .cover-grid {{ margin-top: 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
    .summary-card {{
      padding: 16px 16px 15px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(180deg, #ffffff 0%, #fafbfc 100%);
    }}
    .summary-card .meta-label {{ margin-bottom: 8px; }}
    .summary-card strong {{ display: block; font-size: 1rem; line-height: 1.35; font-family: "IBM Plex Mono", monospace; }}
    .paper-section {{ padding-top: 30px; border-top: 1px solid var(--line); margin-top: 30px; }}
    .paper-section:first-of-type {{ border-top: 0; margin-top: 0; padding-top: 0; }}
    .paper h2 {{ margin: 0 0 16px; font-size: 1.4rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .paper h3 {{ margin: 24px 0 12px; font-size: 1.05rem; }}
    .paper p, .paper li {{ color: var(--text-soft); }}
    .paper p {{ margin: 0 0 14px; }}
    .grid-two {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    .grid-three {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    .callout {{
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(180deg, #ffffff 0%, #fafbfc 100%);
      padding: 18px 18px 16px;
    }}
    .callout h3 {{ margin-top: 0; font-size: 1rem; color: var(--text); }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 0.65rem;
      line-height: 1;
      background: #f7f7f7;
      color: var(--text-muted);
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.65rem;
      font-family: "IBM Plex Mono", monospace;
      border: 1px solid var(--line);
      background: #fff;
    }}
    .pill.port {{ color: var(--ok); border-color: #ceead6; background: #e6f4ea; }}
    .pill.vuln {{ color: var(--danger); border-color: #fad2cf; background: #fce8e6; }}
    .pill-group {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }}
    
    .evidence-table {{ width: 100%; border-collapse: collapse; border: 1px solid var(--line); border-radius: 12px; overflow: hidden; font-size: 0.85rem; }}
    .evidence-table th, .evidence-table td {{ text-align: left; vertical-align: middle; padding: 10px 14px; border-bottom: 1px solid var(--line); }}
    .evidence-table th {{ background: #f7f8fa; color: var(--text-muted); font-size: 0.65rem; text-transform: uppercase; font-family: "IBM Plex Mono", monospace; }}
    .evidence-table tr:last-child td {{ border-bottom: 0; }}

    .badge-critical {{ background: #fce8e6 !important; color: #d93025 !important; border-color: #fad2cf !important; }}
    .badge-high {{ background: #fff4e5 !important; color: #f29900 !important; border-color: #ffe1bb !important; }}
    .badge-medium {{ background: #e8f0fe !important; color: #1a73e8 !important; border-color: #d2e3fc !important; }}
    .badge-low {{ background: #e6f4ea !important; color: #1e8e3e !important; border-color: #ceead6 !important; }}

    .host-card {{
      background: #ffffff;
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      padding: 24px;
      transition: all 0.2s ease;
      position: relative;
    }}
    .host-card:hover {{ border-color: var(--line-strong); box-shadow: 0 12px 24px rgba(0,0,0,0.04); }}
    .host-head {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }}
    .host-title-group h3 {{ margin: 0; font-size: 1.15rem; letter-spacing: -0.01em; }}
    .risk-badge {{
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.7rem;
      font-weight: 700;
      font-family: "IBM Plex Mono", monospace;
      border: 1px solid var(--line);
    }}
    .kv-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }}
    .kv strong {{ font-size: 0.85rem; word-break: break-all; color: var(--text-soft); }}
    .risk-factors ul {{ margin: 0; padding-left: 18px; font-size: 0.85rem; color: var(--text-muted); }}
    .risk-factors li + li {{ margin-top: 4px; }}
    .shot-wrap {{ margin-top: 16px; border-radius: 8px; overflow: hidden; border: 1px solid var(--line); }}
    .shot {{ width: 100%; display: block; }}
    .mono {{ font-family: "IBM Plex Mono", monospace; }}
    .small {{ font-size: 0.8rem; }}
    .muted {{ color: var(--text-muted); }}
    
    @media (max-width: 1180px) {{
      .viewer-shell {{ grid-template-columns: 1fr; }}
      .sidebar {{ position: static; }}
    }}
  </style>
</head>
<body>
  <div class="viewer-shell">
    <aside class="sidebar">
      <section class="panel toc">
        <h2>Contents</h2>
        <nav>
          <a href="#summary">1. Executive Summary</a>
          <a href="#nuclei">2. Nuclei Scan Findings</a>
          <a href="#targets">3. Exposure Targets</a>
          <a href="#intelligence">4. DNS Intelligence</a>
          <a href="#inventory">5. Infrastructure Inventory</a>
        </nav>
      </section>

      <section class="panel info-card">
        <p class="eyebrow">EASM Session</p>
        <h1>{escape(target.get('core_domain', ''))}</h1>
        <p>Attack surface analysis report for the specified domain and its sub-infrastructure.</p>
        <div class="quick-facts">
          <div class="fact">
            <span class="meta-label">Total Assets</span>
            <div class="meta-value">{escape(str(summary.get("original_total_hosts", 0)))}</div>
          </div>
          <div class="fact">
            <span class="meta-label">Web Targets</span>
            <div class="meta-value">{escape(str(summary.get("web_host_count", 0)))}</div>
          </div>
          <div class="fact">
            <span class="meta-label">Generated At</span>
            <div class="meta-value">{escape(target.get('generated_at', ''))}</div>
          </div>
        </div>
      </section>

      <section class="panel researcher-card">
        <h2>Researcher</h2>
        <p><strong>Patrick Binder</strong></p>
        <p class="small muted">Offensive Cybersecurity Expert specializing in Microsoft Cloud pentesting and adversarial research.</p>
        <div style="margin-top: 12px;">
          <a href="https://patrickbrand34846.z6.web.core.windows.net/" class="badge" style="text-decoration: none;">[ Portfolio ]</a>
        </div>
      </section>
    </aside>

    <main class="paper-wrap">
      <article class="paper">
        <div class="paper-inner">
          <header class="cover">
            <p class="cover-kicker">External Attack Surface Management Report</p>
            <h1>{escape(target.get('core_domain', ''))}</h1>
            <p class="lede">Comprehensive analysis of the external attack surface, identifying high-risk exposure points, service vulnerabilities, and infrastructure metadata.</p>

            <div class="cover-grid">
              {summary_card_html}
            </div>
          </header>

          <section id="summary" class="paper-section">
            <h2>1. Executive Summary</h2>
            <p>The reconnaissance phase for <strong>{escape(target.get('core_domain', ''))}</strong> has concluded. The analysis identified {len(hosts)} primary high-interest targets from a total discovery pool of {summary.get("original_total_hosts", 0)} assets.</p>
            <p>Risk scoring indicates a {summary.get('critical_count', 0) > 0 and 'CRITICAL' or summary.get('high_count', 0) > 0 and 'HIGH' or 'BASELINE'} risk profile based on observed vulnerabilities and exposed management interfaces.</p>
          </section>

          <section id="nuclei" class="paper-section">
            <h2>2. Nuclei Vulnerability Scan</h2>
            <p>Automated vulnerability templates were matched against discovered web entrypoints. The following findings were recorded:</p>
            <table class="evidence-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Template</th>
                  <th>Finding Name</th>
                  <th>Matched Target</th>
                </tr>
              </thead>
              <tbody>
                {nuclei_rows}
              </tbody>
            </table>
          </section>

          <section id="targets" class="paper-section">
            <h2>3. Top Exposure Targets</h2>
            <p>Detailed analysis of high-priority assets based on service composition, known vulnerabilities, and risk scoring.</p>
            <div class="grid-two">
              {host_cards}
            </div>
          </section>

          <section id="intelligence" class="paper-section">
            <h2>4. Takeover & DNS Intelligence</h2>
            <div class="grid-two">
              {takeover_html}
              {txt_html}
            </div>
          </section>

          <section id="inventory" class="paper-section">
            <h2>5. Infrastructure Inventory</h2>
            <p>Condensed view of discovered IP infrastructure and network groupings.</p>
            <div style="overflow-x: auto;">
              <table class="evidence-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Network</th>
                    <th>Hostnames</th>
                    <th>Ports</th>
                    <th>Products</th>
                    <th>Organization</th>
                  </tr>
                </thead>
                <tbody>
                  {ip_rows}
                </tbody>
              </table>
            </div>
          </section>

          <footer style="margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--line); display: flex; justify-content: space-between;">
            <div class="footer-meta">C3PO-SHODAN // EASM ENGINE</div>
            <div class="footer-meta">CONFIDENTIAL RECONNAISSANCE DATA</div>
          </footer>
        </div>
      </article>
    </main>
  </div>
</body>
</html>
"""


def markdown_report(payload: dict, manifest: dict, nuclei_results: list[dict]) -> str:
    target = payload.get("target", {})
    summary = payload.get("summary", {})
    hosts = payload.get("hosts", [])

    lines = [
        f"# EASM Report: {target.get('core_domain', 'unknown')}",
        "",
        f"- Generated: {target.get('generated_at', '')}",
        f"- Target Focus: {len(hosts)} top targets analyzed.",
        f"- Nuclei Hits: {len(nuclei_results)} total vulnerabilities.",
        "",
        "## Top Vulnerability Targets",
        "",
    ]

    for host in hosts:
        lines.append(f"### {host.get('hostname', 'unknown')} (Risk: {host.get('risk_score', 0)})")
        lines.append(f"- IPs: {', '.join(host.get('current_ips', []))}")
        lines.append(f"- HTTP: {host.get('http', {}).get('url', 'n/a')}")
        lines.append(f"- Ports: {', '.join([str(p) for p in host.get('ports', [])])}")
        if host.get("risk_factors"):
            lines.append("- Risk Factors:")
            for f in host["risk_factors"][:5]:
                lines.append(f"  - {f}")
        lines.append("")

    if nuclei_results:
        lines.append("## Nuclei Scan Findings")
        lines.append("")
        lines.append("| Severity | Template | Name | Target |")
        lines.append("|----------|----------|------|--------|")
        for r in nuclei_results[:20]:
            sev = r.get("info", {}).get("severity", "").upper()
            tid = r.get("template-id", "")
            name = r.get("info", {}).get("name", "")
            target_url = r.get("matched-at", "")
            lines.append(f"| {sev} | {tid} | {name} | {target_url} |")
        lines.append("")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render markdown and HTML reports from raw attack-surface JSON.")
    parser.add_argument("--input", required=True, help="Raw attack-surface JSON file")
    parser.add_argument("--screenshots", required=True, help="Screenshot manifest JSON path")
    parser.add_argument("--nuclei", help="Nuclei JSONL output path")
    parser.add_argument("--markdown-output", required=True, help="Markdown report path")
    parser.add_argument("--html-output", required=True, help="HTML output path")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    with open(args.screenshots, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    nuclei_results = []
    if args.nuclei and os.path.isfile(args.nuclei):
        with open(args.nuclei, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    try:
                        nuclei_results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    markdown = markdown_report(payload, screenshot_map(manifest), nuclei_results)
    html = html_report(payload, manifest, nuclei_results)

    os.makedirs(os.path.dirname(args.markdown_output), exist_ok=True)
    os.makedirs(os.path.dirname(args.html_output), exist_ok=True)

    with open(args.markdown_output, "w", encoding="utf-8") as handle:
        handle.write(markdown)
    with open(args.html_output, "w", encoding="utf-8") as handle:
        handle.write(html)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
