from __future__ import annotations

import base64
import json
import os
from html import escape


def inline_image(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    with open(path, "rb") as handle:
        return "data:image/png;base64," + base64.b64encode(handle.read()).decode("ascii")


def render_html(payload: dict, reference_doc: str = "") -> str:
    domains = payload.get("domains", [])
    summary = payload.get("summary", {})
    domain_sections = []
    for domain in domains:
        section = [
            f'<section class="domain-card" id="{escape(domain.get("root_domain", ""))}">',
            f'<h2>{escape(domain.get("root_domain", ""))}</h2>',
            f'<p class="muted">Connected domains: {escape(", ".join(domain.get("connected_domains", [])))}</p>',
            f'<p class="muted">Found: {domain.get("discovered_count", 0)} | Considered: {domain.get("considered_count", 0)} | Deep checks: {domain.get("deep_checked_count", 0)}</p>',
        ]
        if domain.get("selection_limited"):
            section.append('<div class="badge badge-high">Selection limited to 20 targets</div>')
        if domain.get("errors"):
            section.append('<div class="badge badge-critical">Errors present</div>')
            for error in domain.get("errors", []):
                section.append(f'<p class="muted">{escape(error)}</p>')
        for asset in domain.get("selected_assets", [])[:20]:
            section.append(
                f'<article class="asset"><h3>{escape(asset.get("hostname", ""))}</h3>'
                f'<p>Score: {asset.get("score", 0)} | {escape(asset.get("severity", ""))}</p>'
                f'<p class="mono">{escape(", ".join(asset.get("ips", [])))}</p>'
                f'<p>{escape("; ".join(asset.get("evidence", [])))}</p></article>'
            )
        section.append("</section>")
        domain_sections.append("\n".join(section))
    return f"""<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>C3PO-shodan Report</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #050505;
      --panel: rgba(255,255,255,.04);
      --line: rgba(255,255,255,.12);
      --text: #ffffff;
      --muted: rgba(255,255,255,.72);
      --high: #ffb86b;
      --crit: #ff6b6b;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; background: var(--bg); color: var(--text); font: 400 15px/1.6 Manrope, Arial, sans-serif; overflow-y: auto; }}
    .shell {{ max-width: 1440px; margin: 0 auto; padding: 24px; }}
    .hero, .domain-card, .summary {{ background: var(--panel); border: 1px solid var(--line); border-radius: 20px; padding: 20px; margin-bottom: 18px; }}
    h1,h2,h3 {{ margin: 0 0 12px; font-family: "Space Grotesk", sans-serif; }}
    .muted {{ color: var(--muted); }}
    .mono {{ font-family: "IBM Plex Mono", monospace; }}
    .badge {{ display:inline-block; padding: 4px 10px; border-radius: 999px; margin: 4px 8px 0 0; }}
    .badge-high {{ background: rgba(255,184,107,.16); color: var(--high); }}
    .badge-critical {{ background: rgba(255,107,107,.16); color: var(--crit); }}
    .asset {{ padding: 14px; border-top: 1px solid var(--line); }}
    .asset:first-of-type {{ border-top: 0; }}
  </style>
</head>
<body>
  <div class="shell">
    <div class="hero">
      <h1>C3PO-shodan</h1>
      <p class="muted">One-page scrollable report. Reference layout informed by docs/index-ref.html.</p>
    </div>
    <div class="summary">
      <h2>Übersicht</h2>
      <p>Root Domains: {escape(", ".join(payload.get("root_domains", [])))}</p>
      <p>Domains insgesamt: {summary.get("domain_count", 0)} | Assets: {summary.get("asset_count", 0)} | Deep Checks: {summary.get("deep_check_count", 0)}</p>
    </div>
    {''.join(domain_sections)}
  </div>
</body>
</html>"""

def render_json(payload: dict) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)
