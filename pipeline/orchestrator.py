from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from .discovery import discover_scope, load_discovery_config
from .gemini_client import render_json_prompt, run_gemini
from .models import Asset, DomainResult, Finding, ReportPayload, to_builtin
from .reporting import render_html, render_json
from .shodan_adapter import discover_shodan_assets


def _run_batch(title: str, payload: dict, instruction: str, model: str = "") -> str:
    prompt = render_json_prompt(title, payload, instruction)
    res = run_gemini(prompt, model=model)
    return res.text if res.ok else f"Error: {res.raw}"


def run_pipeline(domains: list[str], output_dir: str, model: str = "") -> dict:
    config = load_discovery_config()
    provider_fragments_path = Path(__file__).resolve().parent.parent / "config" / "provider-fragments.txt"
    with open(provider_fragments_path, "r", encoding="utf-8") as f:
        provider_fragments = f.read()

    results = []
    for domain in domains:
        print(f"[*] Processing {domain}...")
        data = discover_shodan_assets(domain, provider_fragments, config)
        results.append(data)

    # Simplified aggregation for the prompt to save tokens
    batch4_input = {
        "targets": domains,
        "summary_stats": [r.get("summary") for r in results],
        "top_risks": []
    }
    for r in results:
        for h in r.get("hosts", [])[:3]:
            batch4_input["top_risks"].append({
                "host": h.get("hostname"),
                "level": h.get("risk_level"),
                "factors": h.get("risk_factors"),
                "vulns": h.get("vulns")
            })

    # CISO-optimized prompt
    ciso_instruction = (
        "Act as a Senior EASM Specialist. Generate a concise CISO Executive Report (2-3 min read).\n"
        "1. HEADLINE: Business Impact (High-level statement on operational/reputational risk).\n"
        "2. TOP 5 RISKS: Prioritized by criticality. Include specific findings like '~all' SPF softfail (flag as 'Risky SPF Softfail').\n"
        "3. RECOMMENDATIONS: Actionable steps. For CVEs, recommend a Pentest to validate business impact.\n"
        "4. Criticality: Define company-perspective criticality for each major risk.\n"
        "Keep it professional, eindringlich (clear/urgent), and in German. Avoid fluff."
    )

    try:
        management_summary = _run_batch(
            "CISO-Executive-Summary",
            batch4_input,
            ciso_instruction,
            model=model,
        )
    except Exception as exc:
        management_summary = f"Gemini summary failed: {exc}"

    # Merge results
    merged_data = results[0] if results else {}
    if len(results) > 1:
        # Basic merge logic
        for r in results[1:]:
            merged_data["hosts"].extend(r.get("hosts", []))
            merged_data["ips"].extend(r.get("ips", []))
            # ... more merge logic if needed

    payload = ReportPayload(
        target=merged_data.get("target", {}),
        summary=merged_data.get("summary", {}),
        discoveries=merged_data.get("discoveries", {}),
        hosts=merged_data.get("hosts", []),
        ips=merged_data.get("ips", []),
        management_summary=management_summary,
    )
    
    payload_dict = to_builtin(payload)
    docs_index_ref = Path(__file__).resolve().parent.parent / "docs" / "index-ref.html"
    payload_dict["html"] = render_html(payload_dict, docs_index_ref)
    payload_dict["json"] = render_json(payload_dict)
    
    return payload_dict
