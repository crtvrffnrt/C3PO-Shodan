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
          <div>
            <h3>{escape(host.get("hostname", ""))}</h3>
            <span class="muted mono" style="font-size:10px;">{escape(", ".join(host.get("sources", [])))}</span>
          </div>
          <div class="risk-pill badge-{host.get('risk_level', 'low')}">
            {escape(host.get('risk_level', '').upper())} {host.get('risk_score', 0)}
          </div>
        </div>
        
        <div class="kv-stack">
          <div class="kv"><span>Primary IP</span><strong>{escape(primary_ip)}</strong></div>
          <div class="kv"><span>HTTP URL</span><strong>{escape(host.get("http", {}).get("url", "n/a"))}</strong></div>
        </div>

        <div class="pill-row">{services}</div>
        <div class="pill-row">{vulns}</div>

        <div style="margin-top:16px;">
          <span style="font-size:10px; text-transform:uppercase; color:var(--text-muted); display:block; margin-bottom:8px;">Risk Profile</span>
          <ul style="margin:0; padding-left:18px; font-size:12px; color:var(--text-secondary);">{factors or '<li>Baseline risk detected.</li>'}</ul>
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
        f'<article class="summary-card"><span>{escape(label)}</span><strong>{escape(value)}</strong></article>'
        for label, value in summary_cards
    )

    # Nuclei Findings Table
    nuclei_rows = "".join(
        f"""
        <tr>
          <td><span class="badge-{r.get('info', {}).get('severity', 'low')}">{escape(r.get('info', {}).get('severity', '').upper())}</span></td>
          <td class="mono">{escape(r.get('template-id', ''))}</td>
          <td>{escape(r.get('info', {}).get('name', ''))}</td>
          <td class="mono">{escape(r.get('matched-at', ''))}</td>
        </tr>
        """
        for r in nuclei_results[:50]
    ) or '<tr><td colspan="4" class="muted">No nuclei findings recorded for this session.</td></tr>'

    takeover_html = "".join(
        f"""
        <article class="finding-card">
          <h4>{escape(item.get('hostname', ''))}</h4>
          <p>{escape(join_list(item.get('reasons', []), empty='No reason recorded'))}</p>
        </article>
        """
        for item in discoveries.get("takeover_candidates", [])[:12]
    ) or '<article class="finding-card"><h4>No Takeover Signals</h4><p>Current heuristics indicate stable infrastructure.</p></article>'

    txt_html = "".join(
        f"""
        <article class="finding-card">
          <h4>{escape(item.get('hostname', ''))}</h4>
          <p class="label">{escape(item.get('label', ''))}</p>
          <code>{escape(item.get('value', ''))}</code>
        </article>
        """
        for item in discoveries.get("interesting_txt", [])[:12]
    ) or '<article class="finding-card"><h4>No TXT Signals</h4><p>No interesting DNS evidence collected.</p></article>'

    ip_rows = "".join(
        f"""
        <tr>
          <td class="mono">{escape(item.get('ip', ''))}</td>
          <td class="mono">{escape(item.get('network_hint', ''))}</td>
          <td>{escape(join_list(item.get('hostnames', [])))}</td>
          <td class="mono">{escape(join_list([str(port) for port in item.get('ports', [])]))}</td>
          <td>{escape(join_list(item.get('products', [])))}</td>
          <td class="muted">{escape(item.get('org', '') or 'n/a')}</td>
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
  <style>
    :root {{
      --font-ui: "Space Grotesk", system-ui, -apple-system, sans-serif;
      --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, monospace;
      --bg-main: #03030a;
      --bg-secondary: #050111;
      --bloom-magenta: rgba(255, 79, 248, 0.18);
      --bloom-cyan: rgba(76, 246, 255, 0.18);
      --panel-bg: rgba(3, 5, 12, 0.92);
      --panel-border: 1px solid rgba(255, 255, 255, 0.22);
      --panel-shadow: 0 45px 110px rgba(0, 0, 0, 0.7), inset 0 1px 0 rgba(255, 255, 255, 0.06);
      --text-main: #f4f7ff;
      --text-muted: #7f8cad;
      --accent: #4cf6ff;
      --accent-magenta: #ff4ff8;
      --ok: #5cff8d;
      --warn: #e8d66c;
      --danger: #ff4c68;
      --radius: 14px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: linear-gradient(var(--bg-main), var(--bg-secondary));
      color: var(--text-main);
      font-family: var(--font-ui);
      line-height: 1.6;
      font-size: 14px;
      overflow-x: hidden;
      min-height: 100vh;
      position: relative;
    }}
    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      background:
        radial-gradient(ellipse at 20% 20%, var(--bloom-magenta), transparent 45%),
        radial-gradient(ellipse at 80% 40%, var(--bloom-cyan), transparent 45%),
        repeating-linear-gradient(
          to bottom,
          rgba(255, 255, 255, 0.02) 0,
          rgba(255, 255, 255, 0.02) 2px,
          transparent 4px,
          transparent 8px
        );
      pointer-events: none;
      z-index: 0;
    }}
    .dust-film {{
      position: fixed;
      inset: 0;
      pointer-events: none;
      z-index: 0;
      background-image:
        radial-gradient(rgba(255, 255, 255, 0.055) 0.55px, transparent 1.2px),
        radial-gradient(rgba(255, 255, 255, 0.035) 0.6px, transparent 1.3px),
        linear-gradient(transparent 65%, rgba(255, 255, 255, 0.04));
      background-size: 240px 240px, 320px 320px, 100% 100%;
      background-position: 30px 40px, 140px 120px, 0 0;
      opacity: 0.6;
      mix-blend-mode: screen;
    }}
    .mono {{ font-family: var(--font-mono); }}
    .shell {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 40px 20px;
      position: relative;
      z-index: 1;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      margin-bottom: 40px;
      padding-bottom: 20px;
      border-bottom: var(--panel-border);
    }}
    .header-left .eyebrow {{
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 0.3em;
      font-size: 10px;
      margin-bottom: 8px;
      display: block;
    }}
    h1 {{
      margin: 0;
      font-size: 32px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }}
    .header-right {{ text-align: right; }}
    .header-right span {{ display: block; color: var(--text-muted); font-size: 11px; text-transform: uppercase; }}
    .header-right strong {{ color: var(--accent-magenta); font-size: 13px; font-family: var(--font-mono); }}

    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 40px;
    }}
    .summary-card {{
      background: var(--panel-bg);
      border: var(--panel-border);
      border-radius: var(--radius);
      box-shadow: var(--panel-shadow);
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 4px;
      backdrop-filter: blur(14px);
    }}
    .summary-card span {{ color: var(--text-muted); text-transform: uppercase; font-size: 10px; letter-spacing: 0.1em; font-weight: 600; }}
    .summary-card strong {{ font-size: 24px; color: var(--accent); font-family: var(--font-mono); }}

    section {{ margin-bottom: 60px; }}
    section h2 {{
      font-size: 18px;
      text-transform: uppercase;
      letter-spacing: 0.15em;
      margin-bottom: 24px;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    section h2::after {{
      content: "";
      height: 1px;
      flex: 1;
      background: linear-gradient(90deg, rgba(255,255,255,0.1), transparent);
    }}

    .card {{
      background: var(--panel-bg);
      border: var(--panel-border);
      border-radius: var(--radius);
      box-shadow: var(--panel-shadow);
      padding: 24px;
      margin-bottom: 20px;
      position: relative;
      backdrop-filter: blur(14px);
    }}
    
    table {{ width: 100%; border-collapse: collapse; text-align: left; }}
    th {{
      padding: 12px 16px;
      color: var(--text-muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      border-bottom: var(--panel-border);
    }}
    td {{ padding: 14px 16px; border-bottom: 1px solid rgba(255,255,255,0.03); }}
    
    .badge-critical {{ color: var(--danger); font-weight: bold; }}
    .badge-high {{ color: var(--warn); font-weight: bold; }}
    .badge-medium {{ color: var(--accent); font-weight: bold; }}
    .badge-low {{ color: var(--ok); font-weight: bold; }}

    .finding-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 20px;
    }}
    .finding-card {{
      background: var(--panel-bg);
      border: var(--panel-border);
      border-radius: var(--radius);
      box-shadow: var(--panel-shadow);
      padding: 20px;
      backdrop-filter: blur(14px);
    }}
    .finding-card h4 {{ margin: 0 0 10px; color: var(--accent); }}
    .finding-card p {{ margin: 0; color: var(--text-muted); font-size: 13px; }}
    .finding-card code {{ display: block; margin-top: 12px; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 4px; font-size: 12px; color: var(--accent-magenta); word-break: break-all; border: 1px dashed rgba(255,255,255,0.1); }}

    .hosts-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
      gap: 24px;
    }}
    .host-card {{
      background: var(--panel-bg);
      border: var(--panel-border);
      border-radius: var(--radius);
      box-shadow: var(--panel-shadow);
      padding: 28px;
      transition: transform 0.2s ease, box-shadow 0.2s ease;
      backdrop-filter: blur(14px);
    }}
    .host-card:hover {{ transform: translateY(-2px); box-shadow: 0 30px 80px rgba(0,0,0,0.8); border-color: var(--accent); }}
    .host-head {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }}
    .host-head h3 {{ margin: 0; font-size: 20px; letter-spacing: -0.01em; }}
    .risk-pill {{
      padding: 4px 12px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      background: rgba(255,255,255,0.05);
      font-family: var(--font-mono);
    }}

    .kv-stack {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }}
    .kv span {{ display: block; color: var(--text-muted); font-size: 10px; text-transform: uppercase; margin-bottom: 4px; }}
    .kv strong {{ display: block; font-size: 13px; word-break: break-all; font-family: var(--font-mono); }}

    .pill-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }}
    .pill {{ padding: 3px 10px; border-radius: 4px; font-size: 11px; border: 1px solid rgba(255,255,255,0.1); font-family: var(--font-mono); }}
    .pill.port {{ color: var(--ok); border-color: rgba(92, 255, 141, 0.3); }}
    .pill.vuln {{ color: var(--danger); border-color: rgba(255, 76, 104, 0.3); }}

    .shot-wrap {{ margin-top: 16px; border-radius: 8px; overflow: hidden; border: var(--panel-border); }}
    .shot {{ width: 100%; display: block; filter: brightness(0.8) contrast(1.1); }}

    .muted {{ color: var(--text-muted); }}
  </style>
</head>
<body>
  <div class="dust-film" aria-hidden="true"></div>
  <div class="shell">
    <header>
      <div class="header-left">
        <span class="eyebrow">External Attack Surface Management</span>
        <h1>{escape(target.get('core_domain', ''))}</h1>
      </div>
      <div class="header-right">
        <span>System Status</span>
        <strong>OPERATIONAL // {escape(target.get('generated_at', ''))}</strong>
      </div>
    </header>


    <div class="summary-grid">
      {summary_card_html}
    </div>

    <section>
      <h2>Nuclei Vulnerability Scan</h2>
      <div class="card" style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Template</th>
              <th>Name</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {nuclei_rows}
          </tbody>
        </table>
      </div>
    </section>

    <section>
      <h2>Top 10 Exposure Targets</h2>
      <div class="hosts-grid">
        {host_cards}
      </div>
    </section>

    <section>
      <h2>Takeover & DNS Intelligence</h2>
      <div class="finding-grid">
        {takeover_html}
        {txt_html}
      </div>
    </section>

    <section>
      <h2>Infrastructure Inventory</h2>
      <div class="card" style="overflow-x: auto;">
        <table>
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

    <footer style="margin-top: 100px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 11px; display: flex; justify-content: space-between;">
      <div>C3PO-SHODAN // EASM ENGINE</div>
      <div>CLASSIFIED OPERATOR ACCESS ONLY</div>
    </footer>
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
