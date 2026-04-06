<div align="center">
  <img src="logo.jpg" alt="C3PO-shodan logo" width="360">

  <h1>C3PO-shodan</h1>

  <p><strong>A Shodan-driven EASM pipeline for mapping exposed infrastructure, enriching risky web targets, and rendering operator-friendly reports.</strong></p>

  <p>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"></a>
    <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/shell-bash-121011?style=flat-square&logo=gnu-bash&logoColor=white" alt="Bash"></a>
    <a href="https://www.shodan.io/"><img src="https://img.shields.io/badge/data-Shodan-EA4335?style=flat-square" alt="Shodan"></a>
    <a href="https://github.com/projectdiscovery/nuclei"><img src="https://img.shields.io/badge/scanner-Nuclei-0F766E?style=flat-square" alt="Nuclei"></a>
    <a href="https://github.com/projectdiscovery/httpx"><img src="https://img.shields.io/badge/enrichment-httpx-2563EB?style=flat-square" alt="httpx"></a>
    <a href="https://github.com/google-gemini/gemini-cli"><img src="https://img.shields.io/badge/workflow-Gemini_CLI-5B5BD6?style=flat-square" alt="Gemini CLI"></a>
  </p>

  <p>
    <a href="#quick-start"><strong>Quick Start</strong></a> •
    <a href="#pipeline"><strong>Pipeline</strong></a> •
    <a href="#configuration"><strong>Configuration</strong></a> •
    <a href="#outputs"><strong>Outputs</strong></a>
  </p>
</div>

---

## Report Preview

The HTML report is designed as a high-contrast attack-surface console with infrastructure summaries, risk scoring, screenshots, and findings in one place.

<div align="center">
  <img src="example.png" alt="Example report view" width="1000">
</div>

## Overview

`C3PO-shodan` takes a root domain, discovers exposed infrastructure with Shodan and DNS data, enriches high-value web targets, runs focused Nuclei scans, and produces local Markdown + HTML artifacts for review.

The pipeline is deterministic. Gemini is used for repo workflow and operator assistance around the run, not for generating a separate executive-summary artifact.

## What It Does

| Capability | Details |
| --- | --- |
| Discovery | Collects Shodan DNS records, hostname/IP enrichment, DNS resolution, and optional `crt.sh` expansion. |
| Risk Signal Collection | Extracts TXT verification signals, provider-linked CNAME patterns, and takeover-oriented indicators. |
| Web Enrichment | Probes reachable HTTP/S targets and adds tech-stack enrichment with `httpx` when available. |
| Vulnerability Triage | Runs Nuclei against the top 25 risky reachable web targets. |
| Visual Evidence | Captures screenshots for up to 16 reachable targets, preferring Cloudflare URL Scanner and falling back to local tooling. |
| Reporting | Renders a versioned Markdown report, self-contained HTML dashboard, and supporting JSON artifacts. |

## Quick Start

### 1. Install dependencies

Required:

- `python3` 3.10+
- `bash`
- `curl`
- `nuclei`
- `httpx`
- `gemini` CLI

Optional but useful:

- One local screenshot tool: `chromium`, `google-chrome`, `microsoft-edge`, or `wkhtmltoimage`
- Cloudflare API credentials for better screenshots and URL intelligence

Recommended installs:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
npm install -g @google/gemini-cli
nuclei -update-templates
```

### 2. Configure credentials

Copy the example env file and add your keys:

```bash
cp .env.example .env
```

Minimum required:

```bash
SHODANAPI=your_shodan_api_key
```

Optional Cloudflare token flow:

```bash
CF_ACCOUNT_ID=your_account_id
CF_API_TOKEN=your_api_token
```

Alternative Shodan key file:

```bash
mkdir -p ~/.shodan
printf '%s\n' "your_shodan_api_key" > ~/.shodan/api_key
chmod 600 ~/.shodan/api_key
```

### 3. Run the pipeline

```bash
chmod +x run.sh bin/run.sh scripts/*.sh install.sh
./install.sh
./run.sh example.com
```

Gemini-assisted prompt from the repo root:

```text
Run ./run.sh against example.com, then help me inspect the HTML report and the Nuclei findings.
```

## Pipeline

| Phase | Action |
| --- | --- |
| 1. Validation | Checks config, required files, Python, keys, and optional screenshot tooling. |
| 2. Discovery | Builds the domain inventory from Shodan DNS, current resolution, and optional CT hostnames. |
| 3. TXT / takeover enrichment | Adds TXT verification signals and provider-linked CNAME analysis. |
| 4. Nuclei scan | Scans the top reachable risky web targets with focused tags and severities. |
| 5. Screenshot capture | Uses Cloudflare URL Scanner first when configured, otherwise local browsers/tools. |
| 6. Rendering | Produces Markdown and HTML reports plus JSON support artifacts. |

## Configuration

### Common runtime knobs

Defaults come from [`config/config.yaml`](config/config.yaml).

| Key | Default | Purpose |
| --- | --- | --- |
| `domain_ct_enabled` | `true` | Enable `crt.sh` hostname expansion. |
| `shodan_dns_page_limit` | `4` | Limit Shodan DNS paging. |
| `shodan_host_enrichment_limit` | `20` | Cap Shodan host detail enrichment. |
| `max_hosts_for_http_probe` | `40` | Limit HTTP probing volume. |
| `max_screenshots` | `16` | Limit screenshot captures. |
| `screenshot_timeout_seconds` | `35` | Local screenshot timeout. |

### Detailed setup

<details>
<summary><strong>Cloudflare URL Scanner setup</strong></summary>

For better screenshots and URL intelligence, create an API token at `https://dash.cloudflare.com/profile/api-tokens` with:

- `Account -> Cloudflare Radar:Read`
- `Account -> URL Scanner:Read`
- `Account -> URL Scanner:Edit`

Then add:

```bash
CF_ACCOUNT_ID=your_account_id
CF_API_TOKEN=your_api_token
```

Legacy global-key auth is also supported:

```bash
CF_ACCOUNT_ID=your_account_id
CF_EMAIL=your_cloudflare_email
CF_API_KEY=your_global_api_key
```

</details>

<details>
<summary><strong>Gemini CLI authentication</strong></summary>

Authenticate once before using Gemini-driven repo workflow:

```bash
gemini login
```

The report pipeline remains deterministic; Gemini is not used to fabricate a separate executive summary.

</details>

<details>
<summary><strong>Python requirements</strong></summary>

The Python code uses the standard library. A minimal [`requirements.txt`](requirements.txt) is included for automation compatibility:

```bash
python3 -m pip install -r requirements.txt
```

</details>

## Outputs

After a run, expect these primary artifacts:

| Path | Description |
| --- | --- |
| `output/attack_surface_<target>_<date>.json` | Raw collected attack-surface payload. |
| `output/attack_surface_<target>_<date>.html` | Self-contained HTML dashboard. |
| `runtime/reports/attack_surface_<target>_<date>.md` | Markdown report. |
| `output/nuclei_<target>_<date>.jsonl` | Nuclei findings for scanned web targets. |
| `output/attack_surface_<target>_<date>_screenshots.json` | Screenshot manifest. |
| `attack_surface_latest.html` | Convenience copy of the latest HTML report. |

## Project Layout

| Path | Role |
| --- | --- |
| [`bin/run.sh`](bin/run.sh) | Main entrypoint and phase orchestration. |
| [`install.sh`](install.sh) | Preflight checks for tools and credentials. |
| [`scripts/collect-attack-surface.py`](scripts/collect-attack-surface.py) | Shodan/DNS collection and enrichment. |
| [`scripts/capture-screenshots.py`](scripts/capture-screenshots.py) | Screenshot capture with local tooling. |
| [`scripts/render-report.py`](scripts/render-report.py) | Markdown and HTML report rendering. |
| [`docs/architecture.md`](docs/architecture.md) | High-level architecture notes. |
| [`docs/flow.md`](docs/flow.md) | End-to-end execution flow. |

## Notes

- Screenshot capture is best-effort and is skipped automatically when tooling is unavailable.
- If Cloudflare rate-limits or credentials are missing, the pipeline falls back to local screenshot capture.
- If `nuclei` is unavailable or no reachable web targets exist, the rest of the collection and reporting pipeline can still complete.
- Output is generated locally for inspection; the repo does not create a separate CISO-summary text artifact.
