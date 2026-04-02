from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.request import urlopen

from .models import DomainResult


@dataclass
class DiscoveryConfig:
    endpoint: str = ""
    timeout: int = 15
    source_name: str = "placeholder"


def load_discovery_config(config: dict) -> DiscoveryConfig:
    return DiscoveryConfig(
        endpoint=str(config.get("domain_discovery_endpoint", "") or ""),
        timeout=int(config.get("domain_discovery_timeout_seconds", 15) or 15),
        source_name=str(config.get("domain_discovery_source", "placeholder") or "placeholder"),
    )


def discover_connected_domains(root_domain: str, cfg: DiscoveryConfig, debug: bool = False) -> list[str]:
    if not cfg.endpoint:
        return [root_domain]
    url = cfg.endpoint.replace("{domain}", root_domain)
    with urlopen(url, timeout=cfg.timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    domains = payload.get("connected_domains") or payload.get("domains") or []
    normalized = []
    seen = set()
    for item in [root_domain, *domains]:
        value = str(item).strip().lower().rstrip(".")
        if value and value not in seen:
            seen.add(value)
            normalized.append(value)
    return normalized


def discover_scope(root_domain: str, cfg: DiscoveryConfig, debug: bool = False) -> DomainResult:
    domains = discover_connected_domains(root_domain, cfg, debug=debug)
    return DomainResult(root_domain=root_domain, connected_domains=domains)

