# Collection Workflow

Purpose: collect DNS, Shodan, and HTTP evidence into a coherent host inventory.

Rules:
- Avoid duplicate testing that does not produce new signal.
- Normalize domains once and keep core-domain selection consistent across shell and Python code.
- Respect config-driven limits for DNS pages, host enrichment, web probes, and CT lookups.
- Use safe retry behavior for rate limits and transient API failures.
- Preserve evidence fields separately from derived scoring fields.
- Keep IPv4 and IPv6 network hints canonical instead of hand-building fragile CIDR strings.
- Treat provider-linked takeover signals as heuristics, not hard proof.
- Pair this file with [`SKILL.md`](/root/dev/c3po-shodan/docs/workflows/collection/SKILL.md) for implementation-focused checks.

Acceptance checks:

- DNS, Shodan host enrichment, and web probing produce deterministic JSON fields.
- Config knobs actually control collection limits.
- IPv6 network grouping remains valid for compressed addresses.
