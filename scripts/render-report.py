#!/usr/bin/env python3
import argparse
import base64
import json
import os
import sys
from datetime import datetime
from html import escape
from typing import Optional

RISKY_PORTS = {
    21: "FTP: Cleartext authentication and data transfer. High risk of credential sniffing and unauthorized file access.",
    22: "SSH: Secure Shell. Public exposure invites brute-force attacks and makes a management path externally reachable.",
    23: "Telnet: Cleartext protocol. Extremely vulnerable to sniffing and should never be public-facing.",
    25: "SMTP: Mail transfer. Can expose mail infrastructure and relay abuse opportunities.",
    53: "DNS: Potential for amplification, recursion abuse, or zone disclosure if misconfigured.",
    80: "HTTP: Unencrypted web traffic. Susceptible to interception and session abuse.",
    110: "POP3: Cleartext mail retrieval. Credentials and content may be intercepted.",
    111: "RPCBind: Often used for port mapping in older Unix services. High risk of information disclosure.",
    135: "RPC: Windows RPC. Frequently targeted for remote code execution and service discovery.",
    137: "NetBIOS: Windows naming service. Discloses internal network information and hostnames.",
    139: "NetBIOS: Windows file sharing. High risk of unauthorized data access.",
    143: "IMAP: Cleartext mail access. Sensitive communications and credentials at risk.",
    161: "SNMP: Network management. Weak community strings can expose deep infrastructure data.",
    389: "LDAP: Directory access. May disclose sensitive organizational metadata.",
    445: "SMB: Windows file sharing. Commonly targeted and rarely appropriate on the public internet.",
    548: "AFP: Apple Filing Protocol. Potential for unauthorized file access.",
    1433: "MSSQL: Database access. High impact if exposed with weak authentication.",
    1521: "Oracle: Database access. Similar exposure concerns to MSSQL.",
    2049: "NFS: Network File System. Risk of unauthorized filesystem mounting.",
    3306: "MySQL: Database access. High risk of credential theft and data exposure.",
    3389: "RDP: Remote Desktop. Critical entry point and brute-force target.",
    5432: "PostgreSQL: Database access. Similar exposure concerns to MySQL and MSSQL.",
    5900: "VNC: Remote desktop. Often weakly protected when exposed externally.",
    6379: "Redis: In-memory store. Frequently left without strong authentication.",
    8080: "HTTP-Alt: Often used for management interfaces and application consoles.",
    9200: "Elasticsearch: High risk of data exposure if unauthenticated.",
    27017: "MongoDB: Historically targeted due to missing default authentication.",
}


def inline_image(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "rb") as handle:
            encoded = base64.b64encode(handle.read()).decode("utf-8")
        ext = os.path.splitext(path)[1].lower().strip(".") or "png"
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


def human_date(iso_value: str) -> str:
    if not iso_value:
        return "unknown"
    try:
        dt = datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y %H:%M UTC")
    except Exception:
        return iso_value


def severity_rank(level: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get((level or "").lower(), 0)


def severity_class(level: str) -> str:
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }.get((level or "").lower(), "low")


def risk_label(score: int, level: str) -> str:
    level_text = (level or "low").upper()
    return f"{level_text} {score}"


def risk_tone(level: str) -> str:
    normalized = (level or "").lower()
    if normalized in {"critical", "high"}:
        return "risk"
    if normalized == "medium":
        return "medium"
    return "neutral"


def summary_tone(critical: int = 0, high: int = 0, medium: int = 0) -> str:
    if critical or high:
        return "risk"
    if medium:
        return "medium"
    return "neutral"


def split_metric_html(items: list[tuple[str, str, str]]) -> str:
    return "".join(
        f'<span class="metric-chip chip-{escape(tone)}"><span>{escape(label)}</span><strong>{escape(value)}</strong></span>'
        for label, value, tone in items
    )


def render_metric_card(label: str, value: str, tone: str = "neutral", detail_html: str = "") -> str:
    detail_block = f'<div class="metric-detail">{detail_html}</div>' if detail_html else ""
    return (
        f'<section class="metric-card metric-{escape(tone)}">'
        f'<span class="meta-label">{escape(label)}</span>'
        f'<div class="metric-main"><strong>{escape(value)}</strong></div>'
        f"{detail_block}"
        "</section>"
    )


def vulnerability_summary_rows(hosts: list[dict]) -> str:
    all_vulns = []
    for host in hosts:
        details = host.get("vuln_details", {})
        for cve_id, info in details.items():
            all_vulns.append({
                "cve": cve_id,
                "cvss": float(info.get("cvss", 0.0) or 0.0),
                "summary": info.get("summary", "No details available."),
                "host": host.get("hostname", "n/a"),
                "severity": host.get("risk_level", "low"),
            })

    all_vulns.sort(key=lambda x: x["cvss"], reverse=True)

    rows = ""
    for v in all_vulns[:20]:
        badge_class = severity_class(
            "critical" if v["cvss"] >= 9.0 else "high" if v["cvss"] >= 7.0 else "medium" if v["cvss"] >= 4.0 else "low"
        )
        rows += f"""
        <tr>
          <td class="mono small"><strong>{escape(v['cve'])}</strong></td>
          <td><span class="badge badge-{badge_class}">{escape(f"{v['cvss']:.1f}")}</span></td>
          <td class="mono small">{escape(v['host'])}</td>
          <td class="small">{escape(v['summary'])}</td>
          <td><span class="badge badge-neutral">{escape(v['severity'].upper())}</span></td>
        </tr>
        """
    return rows or '<tr><td colspan="5" class="muted">No infrastructure vulnerabilities identified.</td></tr>'


def render_host_card(host: dict, screenshot_entry: Optional[dict]) -> str:
    screenshot_html = ""
    cf_intel_html = ""

    if screenshot_entry and screenshot_entry.get("status") == "captured":
        image = inline_image(screenshot_entry.get("path", ""))
        if image:
            screenshot_html = (
                '<figure class="shot-frame">'
                f'<img class="shot" src="{image}" alt="Screenshot of {escape(host.get("hostname", ""))}">'
                f'<figcaption class="shot-caption mono">Screenshot evidence | {escape(host.get("hostname", ""))}</figcaption>'
                "</figure>"
            )

        cf_info = screenshot_entry.get("cloudflare_info", {})
        if cf_info:
            tech_stack = ", ".join(cf_info.get("tech_stack", [])) or "n/a"
            cf_intel_html = f"""
            <div class="evidence-strip">
              <div class="kv"><span class="meta-label">Cloudflare Server</span><strong class="mono small">{escape(cf_info.get("server", "n/a"))}</strong></div>
              <div class="kv"><span class="meta-label">TLS / Security</span><strong class="mono small">{escape(cf_info.get("tls_protocol", "n/a"))} / {escape(cf_info.get("security_state", "n/a"))}</strong></div>
              <div class="kv full"><span class="meta-label">Tech Stack</span><strong class="small">{escape(tech_stack)}</strong></div>
            </div>
            """

    services_list = []
    for port in host.get("ports", []):
        try:
            port_int = int(port)
        except Exception:
            continue
        if port_int in RISKY_PORTS:
            risk_text = RISKY_PORTS[port_int]
            color_class = "danger" if port_int in (21, 23, 135, 139, 445, 3389, 6379, 9200) else "warn"
            services_list.append(f'<span class="pill port {color_class}" title="{escape(risk_text)}">{escape(str(port))}</span>')
        else:
            services_list.append(f'<span class="pill port">{escape(str(port))}</span>')
    services = "".join(services_list[:12])

    vulns = "".join(
        f'<span class="pill vuln" title="{escape(host.get("vuln_details", {}).get(v, {}).get("summary", "No details available."))}\nCVSS: {host.get("vuln_details", {}).get(v, {}).get("cvss", "n/a")}">{escape(str(v))}</span>'
        for v in host.get("vulns", [])[:12]
    )

    factors = "".join(f"<li>{escape(factor)}</li>" for factor in host.get("risk_factors", [])[:5])
    ips = host.get("current_ips", [])
    primary_ip = ips[0] if ips else "n/a"
    sh_hostnames = ", ".join(host.get("shodan_hostnames", [])) or "n/a"
    sh_domains = ", ".join(host.get("shodan_domains", [])) or "n/a"
    url = host.get("http", {}).get("url", "n/a")
    source_list = join_list(host.get("sources", []), empty="unspecified")
    risk_class = severity_class(host.get("risk_level", "low"))

    return f"""
      <article class="host-card">
        <div class="host-head">
          <div class="host-title-group">
            <span class="eyebrow">Top Exposure Target</span>
            <h3>{escape(host.get("hostname", ""))}</h3>
            <div class="host-subline mono">{escape(source_list)}</div>
          </div>
          <div class="risk-badge badge-{risk_class}">
            {escape(risk_label(host.get('risk_score', 0), host.get('risk_level', 'low')))}
          </div>
        </div>

        <div class="host-metrics">
          <div class="kv"><span class="meta-label">Primary IP</span><strong class="mono">{escape(primary_ip)}</strong></div>
          <div class="kv"><span class="meta-label">City</span><strong>{escape(host.get("city", "n/a"))}</strong></div>
          <div class="kv"><span class="meta-label">HTTP URL</span><strong class="mono truncate" title="{escape(url)}">{escape(url)}</strong></div>
          <div class="kv"><span class="meta-label">Shodan Hostnames</span><strong class="mono truncate" title="{escape(sh_hostnames)}">{escape(sh_hostnames)}</strong></div>
          <div class="kv full"><span class="meta-label">Associated Domains</span><strong class="mono truncate" title="{escape(sh_domains)}">{escape(sh_domains)}</strong></div>
        </div>

        <div class="section-label">Open Ports</div>
        <div class="pill-group">{services or '<span class="muted small">No port data recorded.</span>'}</div>

        <div class="section-label">Known Vulnerabilities</div>
        <div class="vuln-grid">{vulns or '<span class="muted small">No CVEs recorded for this host.</span>'}</div>

        <div class="risk-factors">
          <span class="section-label">Risk Factors</span>
          <ul>{factors or '<li>Baseline exposure observed.</li>'}</ul>
        </div>

        {cf_intel_html}
        {screenshot_html}

        <div class="asset-footer mono">
          <span>Sources: {escape(source_list)}</span>
          <span>Recorded IPs: {escape(join_list(ips))}</span>
        </div>
      </article>
    """


def html_report(payload: dict, manifest: dict, nuclei_results: list[dict]) -> str:
    target = payload.get("target", {})
    summary = payload.get("summary", {})
    hosts = payload.get("hosts", [])
    ip_assets = payload.get("ips", [])
    discoveries = payload.get("discoveries", {})
    screenshots = screenshot_map(manifest)

    cf_entries = [e for e in manifest.get("entries", []) if e.get("cloudflare_info")]
    if cf_entries:
        cf_intel_rows = ""
        for e in cf_entries:
            info = e["cloudflare_info"]
            techs = ", ".join(info.get("tech_stack", [])) or "n/a"
            cf_intel_rows += f"""
            <tr>
              <td class="mono small">{escape(e.get('hostname', ''))}</td>
              <td class="small">{escape(info.get('server', 'n/a'))}</td>
              <td class="mono small">{escape(info.get('tls_protocol', 'n/a'))}</td>
              <td><span class="badge badge-neutral">{escape(info.get('security_state', 'n/a'))}</span></td>
              <td class="small">{escape(techs)}</td>
              <td class="mono small">{escape(info.get('ip', 'n/a'))} ({escape(info.get('country', 'n/a'))})</td>
            </tr>
            """
    else:
        cf_intel_rows = """
        <tr>
          <td colspan="6" class="muted">
            <strong>No Cloudflare intelligence available.</strong><br>
            Cloudflare API credentials were not provided during this session. Refer to the collection documentation to enable enriched edge metadata.
          </td>
        </tr>
        """

    nuclei_critical = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "critical")
    nuclei_high = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "high")
    nuclei_med = sum(1 for r in nuclei_results if r.get("info", {}).get("severity") == "medium")
    nuclei_total = len(nuclei_results)

    critical_count = int(summary.get("critical_count", 0) or 0)
    high_count = int(summary.get("high_count", 0) or 0)
    medium_count = int(summary.get("medium_count", 0) or 0)
    web_count = int(summary.get("web_host_count", 0) or 0)
    asset_total = int(summary.get("original_total_hosts", 0) or 0)

    priority_hosts = sorted(hosts, key=lambda h: (severity_rank(h.get("risk_level")), h.get("risk_score", 0)), reverse=True)
    top_hosts = priority_hosts[:6]
    supporting_hosts = priority_hosts[6:12]

    summary_card_html = "".join(
        [
            render_metric_card("Discovered Assets", str(asset_total)),
            render_metric_card("Priority Targets", str(len(hosts))),
            render_metric_card("Web Exposures", str(web_count)),
            render_metric_card(
                "Critical / High / Medium",
                str(critical_count + high_count + medium_count),
                summary_tone(critical_count, high_count, medium_count),
                split_metric_html(
                    [
                        ("Critical", str(critical_count), "risk" if critical_count else "neutral"),
                        ("High", str(high_count), "risk" if high_count else "neutral"),
                        ("Medium", str(medium_count), "medium" if medium_count else "neutral"),
                    ]
                ),
            ),
            render_metric_card(
                "Nuclei Findings",
                str(nuclei_total),
                summary_tone(nuclei_critical, nuclei_high, nuclei_med),
                split_metric_html(
                    [
                        ("Critical", str(nuclei_critical), "risk" if nuclei_critical else "neutral"),
                        ("High", str(nuclei_high), "risk" if nuclei_high else "neutral"),
                        ("Medium", str(nuclei_med), "medium" if nuclei_med else "neutral"),
                    ]
                ) if nuclei_total else "",
            ),
            render_metric_card(
                "Critical / High Nuclei",
                str(nuclei_critical + nuclei_high),
                summary_tone(nuclei_critical, nuclei_high, 0),
                split_metric_html(
                    [
                        ("Critical", str(nuclei_critical), "risk" if nuclei_critical else "neutral"),
                        ("High", str(nuclei_high), "risk" if nuclei_high else "neutral"),
                    ]
                ),
            ),
        ]
    )

    nuclei_breakdown_html = (
        '<div class="metric-grid">'
        + "".join(
            [
                render_metric_card("Critical", str(nuclei_critical), "risk" if nuclei_critical else "neutral"),
                render_metric_card("High", str(nuclei_high), "risk" if nuclei_high else "neutral"),
                render_metric_card("Medium", str(nuclei_med), "medium" if nuclei_med else "neutral"),
                render_metric_card("Total", str(nuclei_total), summary_tone(nuclei_critical, nuclei_high, nuclei_med)),
            ]
        )
        + "</div>"
    ) if nuclei_total else '<div class="callout compact-callout"><h3>No Nuclei Detections</h3><p class="small">No templates matched during this session, so the finding breakdown stays neutral.</p></div>'

    nuclei_rows = "".join(
        f"""
        <tr>
          <td><span class="badge badge-{severity_class(r.get('info', {}).get('severity', 'low'))}">{escape(r.get('info', {}).get('severity', '').upper())}</span></td>
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
          <div class="pill-group"><span class="badge badge-neutral">Takeover Target</span></div>
          <h3>{escape(item.get('hostname', ''))}</h3>
          <p class="small">{escape(join_list(item.get('reasons', []), empty='No reason recorded'))}</p>
        </article>
        """
        for item in discoveries.get("takeover_candidates", [])[:12]
    ) or '<article class="callout"><h3>No Takeover Signals</h3><p class="small">Current heuristics indicate stable infrastructure.</p></article>'

    txt_html = "".join(
        f"""
        <article class="callout">
          <div class="pill-group"><span class="badge badge-neutral">DNS Intelligence</span></div>
          <h3>{escape(item.get('hostname', ''))}</h3>
          <p class="meta-label" style="margin-top:8px;">{escape(item.get('label', ''))}</p>
          <code class="mono dns-value">{escape(item.get('value', ''))}</code>
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

    host_cards = "".join(render_host_card(host, screenshots.get(host.get("hostname", ""))) for host in top_hosts)
    supporting_cards = "".join(render_host_card(host, screenshots.get(host.get("hostname", ""))) for host in supporting_hosts)

    overall_state = "CRITICAL" if critical_count else "HIGH" if high_count else "MEDIUM" if medium_count else "BASELINE"
    overall_badge_class = "critical" if critical_count else "high" if high_count else "medium" if medium_count else "low"

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
      color-scheme: light;
      --bg: #f3f5f7;
      --paper: #ffffff;
      --paper-alt: #fafbfc;
      --text: #101214;
      --text-soft: #2a2f35;
      --text-muted: #66707a;
      --line: #dbe1e7;
      --line-strong: #c9d1d9;
      --shadow: 0 18px 50px rgba(16, 18, 20, 0.08);
      --radius-lg: 26px;
      --radius-md: 18px;
      --radius-sm: 12px;
      --risk-red-text: #b42318;
      --risk-red-line: #f0c6c2;
      --risk-red-bg: #fdf1f0;
      --risk-orange-text: #9a6700;
      --risk-orange-line: #f0ddb2;
      --risk-orange-bg: #fff7eb;
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: linear-gradient(180deg, #f8fafc 0%, #eef2f6 100%);
      color: var(--text);
      font: 400 15px/1.65 "Manrope", sans-serif;
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
      border: 1px solid rgba(16, 18, 20, 0.08);
      border-radius: var(--radius-lg);
      box-shadow: 0 14px 28px rgba(16, 18, 20, 0.05);
      padding: 22px 22px 20px;
    }}
    .eyebrow, .meta-label, .terminal-title, .badge, .pill, .toc a, .footer-meta, .section-label, .host-subline {{
      font-family: "IBM Plex Mono", monospace;
      letter-spacing: 0.03em;
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
    .quick-facts {{ margin-top: 16px; display: grid; gap: 8px; }}
    .fact-row {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 0;
      border-bottom: 1px solid var(--line);
    }}
    .fact-row:last-child {{ border-bottom: 0; padding-bottom: 0; }}
    .fact-row .meta-label {{ margin-bottom: 0; }}
    .fact-row .meta-value {{
      font-size: 0.88rem;
      font-weight: 700;
      color: var(--text);
      text-align: right;
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
    .metric-grid {{ margin-top: 24px; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }}
    .metric-card {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: #fcfdfe;
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .metric-main {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
    }}
    .metric-main strong {{
      display: block;
      font-size: 1rem;
      line-height: 1.2;
      font-family: "IBM Plex Mono", monospace;
      color: var(--text);
    }}
    .metric-detail {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .metric-chip {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: #fff;
      color: var(--text-muted);
      font-size: 0.62rem;
      line-height: 1;
      font-family: "IBM Plex Mono", monospace;
      text-transform: uppercase;
    }}
    .metric-chip strong {{ font-size: 0.72rem; color: inherit; }}
    .metric-risk {{ border-color: var(--risk-red-line); background: var(--risk-red-bg); }}
    .metric-medium {{ border-color: var(--risk-orange-line); background: var(--risk-orange-bg); }}
    .chip-risk {{ border-color: var(--risk-red-line); background: var(--risk-red-bg); color: var(--risk-red-text); }}
    .chip-medium {{ border-color: var(--risk-orange-line); background: var(--risk-orange-bg); color: var(--risk-orange-text); }}
    .compact-callout {{ margin-top: 16px; }}
    .paper-section {{ padding-top: 30px; border-top: 1px solid var(--line); margin-top: 30px; }}
    .paper-section:first-of-type {{ border-top: 0; margin-top: 0; padding-top: 0; }}
    .paper h2 {{ margin: 0 0 16px; font-size: 1.4rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .paper h3 {{ margin: 24px 0 12px; font-size: 1.05rem; }}
    .paper p, .paper li {{ color: var(--text-soft); }}
    .paper p {{ margin: 0 0 14px; }}
    .grid-two {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }}
    .callout {{
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(180deg, #ffffff 0%, var(--paper-alt) 100%);
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
      font-size: 0.68rem;
      font-family: "IBM Plex Mono", monospace;
      border: 1px solid var(--line);
      background: #fff;
    }}
    .pill.port {{ color: var(--text-soft); border-color: var(--line); background: #fff; }}
    .pill.port.danger {{ color: var(--risk-red-text); border-color: var(--risk-red-line); background: var(--risk-red-bg); }}
    .pill.port.warn {{ color: var(--risk-orange-text); border-color: var(--risk-orange-line); background: var(--risk-orange-bg); }}
    .pill.vuln {{ color: var(--risk-red-text); border-color: var(--risk-red-line); background: var(--risk-red-bg); }}
    .pill-group {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }}
    .badge-neutral {{ background: #eef2f6 !important; color: var(--text-soft) !important; border-color: var(--line) !important; }}
    .evidence-table {{ width: 100%; border-collapse: separate; border-spacing: 0; border: 1px solid var(--line); border-radius: 16px; overflow: hidden; font-size: 0.86rem; background: #fff; }}
    .evidence-table th, .evidence-table td {{ text-align: left; vertical-align: top; padding: 11px 14px; border-bottom: 1px solid var(--line); }}
    .evidence-table th {{ background: #f7f9fb; color: var(--text-muted); font-size: 0.65rem; text-transform: uppercase; font-family: "IBM Plex Mono", monospace; }}
    .evidence-table tr:last-child td {{ border-bottom: 0; }}
    .badge-critical {{ background: var(--risk-red-bg) !important; color: var(--risk-red-text) !important; border-color: var(--risk-red-line) !important; }}
    .badge-high {{ background: var(--risk-red-bg) !important; color: var(--risk-red-text) !important; border-color: var(--risk-red-line) !important; }}
    .badge-medium {{ background: var(--risk-orange-bg) !important; color: var(--risk-orange-text) !important; border-color: var(--risk-orange-line) !important; }}
    .badge-low {{ background: #f7f9fb !important; color: var(--text-soft) !important; border-color: var(--line) !important; }}
    .host-card {{
      background: #ffffff;
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      padding: 22px;
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }}
    .host-card:hover {{ border-color: var(--line-strong); box-shadow: 0 12px 24px rgba(16,18,20,0.04); }}
    .host-head {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }}
    .host-title-group h3 {{ margin: 0; font-size: 1.15rem; letter-spacing: -0.01em; }}
    .host-subline {{ margin-top: 6px; color: var(--text-muted); font-size: 0.68rem; word-break: break-all; }}
    .risk-badge {{
      padding: 6px 10px;
      border-radius: 8px;
      font-size: 0.68rem;
      font-weight: 700;
      font-family: "IBM Plex Mono", monospace;
      border: 1px solid var(--line);
      white-space: nowrap;
    }}
    .host-metrics {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 14px; }}
    .host-metrics .full {{ grid-column: 1 / -1; }}
    .kv strong {{ font-size: 0.84rem; word-break: break-word; color: var(--text-soft); }}
    .truncate {{ display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .section-label {{ margin-top: 2px; font: 600 0.68rem/1 "IBM Plex Mono", monospace; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; }}
    .risk-factors ul {{ margin: 0; padding-left: 18px; font-size: 0.85rem; color: var(--text-muted); }}
    .risk-factors li + li {{ margin-top: 4px; }}
    .shot-frame {{ margin: 0; border: 1px solid var(--line); border-radius: 14px; overflow: hidden; background: #fff; }}
    .shot {{ width: 100%; display: block; }}
    .shot-caption {{ padding: 10px 12px; border-top: 1px solid var(--line); background: #f8fafc; font-size: 0.62rem; color: var(--text-muted); }}
    .evidence-strip {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 14px; padding: 14px; border: 1px solid var(--line); border-radius: 14px; background: #fbfcfd; }}
    .evidence-strip .full {{ grid-column: 1 / -1; }}
    .dns-value {{
      display: block;
      margin-top: 8px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #f8fafc;
      font-size: 0.76rem;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .asset-footer {{ display: flex; flex-wrap: wrap; justify-content: space-between; gap: 10px; padding-top: 6px; border-top: 1px solid var(--line); color: var(--text-muted); font-size: 0.62rem; }}
    .mono {{ font-family: "IBM Plex Mono", monospace; }}
    .small {{ font-size: 0.8rem; }}
    .muted {{ color: var(--text-muted); }}
    @media (max-width: 1180px) {{
      .viewer-shell {{ grid-template-columns: 1fr; }}
      .sidebar {{ position: static; }}
    }}
    @media (max-width: 760px) {{
      .paper-inner {{ padding: 28px 18px 34px; }}
      .viewer-shell {{ width: min(100% - 16px, 1460px); padding-top: 16px; }}
      .grid-two, .metric-grid, .host-metrics, .evidence-strip {{ grid-template-columns: 1fr; }}
      .host-head, .asset-footer {{ flex-direction: column; }}
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
          <a href="#metrics">2. Key Metrics</a>
          <a href="#priority">3. Priority Findings</a>
          <a href="#targets">4. Top Exposed Assets</a>
          <a href="#supporting">5. Supporting Intelligence</a>
          <a href="#inventory">6. Infrastructure Inventory</a>
        </nav>
      </section>

      <section class="panel info-card">
        <p class="eyebrow">EASM Session</p>
        <h1>{escape(target.get('core_domain', ''))}</h1>
        <p>Attack surface analysis report for the specified domain and its sub-infrastructure.</p>
        <div class="quick-facts">
          <div class="fact-row">
            <span class="meta-label">Total Assets</span>
            <div class="meta-value mono">{escape(str(asset_total))}</div>
          </div>
          <div class="fact-row">
            <span class="meta-label">Web Targets</span>
            <div class="meta-value mono">{escape(str(web_count))}</div>
          </div>
          <div class="fact-row">
            <span class="meta-label">Exposure State</span>
            <div class="meta-value"><span class="badge badge-{overall_badge_class}">{escape(overall_state)}</span></div>
          </div>
          <div class="fact-row">
            <span class="meta-label">Generated At</span>
            <div class="meta-value">{escape(human_date(target.get('generated_at', '')))}</div>
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
            <p class="lede">Comprehensive analysis of the external attack surface, structured to highlight priority exposure, supporting evidence, and the assets that merit the earliest analyst review.</p>
            <div class="metric-grid">
              {summary_card_html}
            </div>
          </header>

          <section id="summary" class="paper-section">
            <h2>1. Executive Summary</h2>
            <p>The external reconnaissance scope for <strong>{escape(target.get('core_domain', ''))}</strong> identified {asset_total} discovered assets, of which {len(hosts)} were prioritized for deeper analysis based on exposure, service composition, and observed risk indicators.</p>
            <p>Overall exposure is assessed as <strong>{overall_state}</strong>. The most relevant findings are concentrated in exposed web services, vulnerable internet-facing hosts, and a small set of infrastructure entries requiring analyst review first.</p>
            <div class="callout" style="margin-top: 20px;">
              <h3>Observed Infrastructure Vulnerabilities</h3>
              <p class="small muted">Key vulnerabilities identified via host intelligence across the discovered infrastructure.</p>
              <table class="evidence-table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>Score</th>
                    <th>Affected Host</th>
                    <th>Vulnerability Summary</th>
                    <th>Host Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerability_summary_rows(hosts)}
                </tbody>
              </table>
            </div>
          </section>

          <section id="metrics" class="paper-section">
            <h2>2. Key Metrics</h2>
            <p>High-level summary for quick triage and prioritization.</p>
            <div class="metric-grid">
              {summary_card_html}
            </div>
          </section>

          <section id="priority" class="paper-section">
            <h2>3. Priority Findings</h2>
            <p>Automated templates matched against discovered web entrypoints. Findings are ordered by severity to highlight items that deserve immediate validation.</p>
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
            <h3 style="margin-top: 24px;">Nuclei Severity Breakdown</h3>
            {nuclei_breakdown_html}
          </section>

          <section id="targets" class="paper-section">
            <h2>4. Top Exposed Assets</h2>
            <p>The most relevant hosts are presented first based on risk score, severity, and exposure characteristics.</p>
            <div class="grid-two">
              {host_cards}
            </div>
            {f'<h3 style="margin-top:24px;">Additional Priority Assets</h3><div class="grid-two">{supporting_cards}</div>' if supporting_cards else ''}
          </section>

          <section id="supporting" class="paper-section">
            <h2>5. Supporting Intelligence</h2>
            <p>Edge metadata, takeover candidates, and DNS observations used to support triage and deeper validation.</p>
            <h3>Cloudflare Intelligence</h3>
            <div style="overflow-x: auto;">
              <table class="evidence-table">
                <thead>
                  <tr>
                    <th>Target Host</th>
                    <th>Server</th>
                    <th>TLS</th>
                    <th>Security</th>
                    <th>Tech Stack</th>
                    <th>Edge IP</th>
                  </tr>
                </thead>
                <tbody>
                  {cf_intel_rows}
                </tbody>
              </table>
            </div>
            <h3 style="margin-top: 24px;">DNS / Takeover Intelligence</h3>
            <div class="grid-two">
              {takeover_html}
              {txt_html}
            </div>
          </section>

          <section id="inventory" class="paper-section">
            <h2>6. Infrastructure Inventory</h2>
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

          <footer style="margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--line); display: flex; justify-content: space-between; gap: 12px;">
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

    markdown = markdown_report(payload, manifest, nuclei_results)
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
