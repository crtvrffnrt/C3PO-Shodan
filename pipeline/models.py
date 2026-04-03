from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    title: str
    severity: str
    evidence: list[str] = field(default_factory=list)
    recommended_action: str = ""
    source: str = ""


@dataclass
class Asset:
    hostname: str
    ips: list[str] = field(default_factory=list)
    current_ips: list[str] = field(default_factory=list)
    cname_targets: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    score: int = 0
    severity: str = "low"
    selected_for_deep_check: bool = False
    findings: list[Finding] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class DomainResult:
    root_domain: str
    connected_domains: list[str] = field(default_factory=list)
    discovered_assets: list[Asset] = field(default_factory=list)
    selected_assets: list[Asset] = field(default_factory=list)
    deep_checked_assets: list[Asset] = field(default_factory=list)
    discovered_count: int = 0
    considered_count: int = 0
    deep_checked_count: int = 0
    errors: list[str] = field(default_factory=list)
    selection_limited: bool = False
    batch_summaries: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportPayload:
    generated_at: str
    root_domains: list[str]
    domains: list[DomainResult]
    summary: dict[str, Any]
    errors: list[str] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)


def to_builtin(value: Any) -> Any:
    if isinstance(value, list):
        return [to_builtin(item) for item in value]
    if isinstance(value, dict):
        return {key: to_builtin(val) for key, val in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    return value
