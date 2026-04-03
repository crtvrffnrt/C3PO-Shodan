from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .models import DomainResult, ReportPayload, to_builtin
from .reporting import render_html, render_json
from .shodan_adapter import discover_shodan_assets


def _normalize_related_domains(primary_domain: str, related_domains: list[str] | None) -> list[str]:
    values = []
    seen = set()
    for item in [primary_domain, *(related_domains or [])]:
        value = str(item).strip().lower().rstrip(".")
        if value and value not in seen:
            seen.add(value)
            values.append(value)
    return values


def run_pipeline(
    domains: list[str],
    related_domains: list[str] | None,
    config: dict,
    provider_fragments_path: str | Path,
    docs_index_ref: str | Path,
    output_dir: str,
    debug: bool = False,
) -> dict:
    primary_domain = str(domains[0]).strip().lower()
    connected_domains = _normalize_related_domains(primary_domain, related_domains)

    print(f"[*] Processing {primary_domain}...")
    collected = discover_shodan_assets(primary_domain, str(provider_fragments_path), config, debug=debug)

    domain_result = DomainResult(
        root_domain=primary_domain,
        connected_domains=connected_domains,
        discovered_count=int(collected.get("summary", {}).get("host_count", 0) or 0),
        considered_count=int(collected.get("summary", {}).get("host_count", 0) or 0),
        deep_checked_count=0,
        errors=[],
        selection_limited=False,
        selected_assets=collected.get("hosts", []),
    )

    summary = dict(collected.get("summary", {}))
    summary.setdefault("domain_count", len(connected_domains))
    summary.setdefault("asset_count", int(summary.get("host_count", 0) or 0))
    summary.setdefault("deep_check_count", 0)

    payload = ReportPayload(
        generated_at=collected.get("target", {}).get("generated_at")
        or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        root_domains=[primary_domain],
        domains=[domain_result],
        summary=summary,
        artifacts={},
    )

    payload_dict = to_builtin(payload)
    payload_dict["target"] = collected.get("target", {})
    payload_dict["discoveries"] = collected.get("discoveries", {})
    payload_dict["hosts"] = collected.get("hosts", [])
    payload_dict["ips"] = collected.get("ips", [])
    payload_dict["html"] = render_html(payload_dict, str(docs_index_ref or Path()))
    payload_dict["json"] = render_json(payload_dict)
    return payload_dict
