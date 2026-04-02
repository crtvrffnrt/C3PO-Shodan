from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_subtaker_module():
    path = Path(__file__).resolve().parent.parent / "subtaker.py"
    spec = importlib.util.spec_from_file_location("subtaker", path)
    if not spec or not spec.loader:
        raise RuntimeError("Unable to load subtaker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def discover_shodan_assets(domain: str, provider_fragments: str, config: dict, debug: bool = False) -> dict:
    subtaker = _load_subtaker_module()
    return subtaker.run_domain_shodan_checks(
        domain=domain,
        provider_fragments=provider_fragments,
        dns_page_limit=int(config.get("shodan_dns_page_limit", 4) or 4),
        host_enrichment_limit=int(config.get("shodan_host_enrichment_limit", 20) or 20),
        debug=debug,
    )

