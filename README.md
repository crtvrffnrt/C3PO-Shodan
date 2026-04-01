# C3PO-shodan

C3PO-shodan is a Bash-orchestrated Shodan attack-surface workflow that mirrors the execution style of `C3PO-Osinter`, but targets domain-centric infrastructure discovery instead of trading intelligence.

## Execution

Run it exactly from the project root:

```bash
./run.sh example.com
```

If no domain is provided, the workflow prompts for one interactively.

## What It Does

- Collects domain and subdomain intelligence from Shodan DNS data.
- Optionally enriches the surface with certificate transparency hostnames.
- Resolves current IPs and preserves historical DNS/IP evidence.
- Pulls Shodan host data for discovered IPs to map exposed ports, products, orgs, and vuln hints.
- Highlights takeover-oriented CNAME/provider patterns inspired by the `BountyHelperScripts` helpers.
- Attempts screenshots for live HTTP/S hosts when a headless browser tool is present.
- Renders a markdown report and a self-contained HTML dashboard.

## Structure

- `run.sh`: Root entrypoint.
- `bin/run.sh`: Main orchestration flow.
- `scripts/`: Shared shell helpers plus Python collection/rendering modules.
- `config/`: Workflow configuration and provider fragment lists.
- `docs/`: Architecture, flow, style guide, and HTML reference.
- `output/`: Generated JSON and HTML outputs.
- `runtime/`: Generated markdown, screenshots, and cache artifacts.
- `GEMINI.md`: Project context for future AI-assisted extensions.

## Required Inputs

- `SHODANAPI` in the environment or `~/.shodan/api_key`

## Notes

- The workflow is intentionally local-first and deterministic. No Gemini execution is required for report generation.
- Screenshots are best effort. If Chromium, Chrome, Edge, or `wkhtmltoimage` is not available, the report still renders and notes the skipped captures.
