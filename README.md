<div align="center">

# C3PO-shodan EASM Agent
---
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Bash](https://img.shields.io/badge/shell-bash-orange.svg)](https://www.gnu.org/software/bash/)
[![Shodan](https://img.shields.io/badge/API-Shodan-red.svg)](https://www.shodan.io/)
[![Nuclei](https://img.shields.io/badge/Scanner-Nuclei-teal.svg)](https://github.com/projectdiscovery/nuclei)
[![Gemini CLI](https://img.shields.io/badge/CLI-Gemini-5b5bd6.svg)](https://github.com/google-gemini/gemini-cli)
# 
**A local Shodan and Nuclei attack-surface workflow intended to be driven from Gemini CLI.**
</div>

<div align="center">
  <img src="logo.jpg" alt="C3PO-shodan Logo" width="400">
</div>
## Overview

`C3PO-shodan` maps a domain's exposed infrastructure with Shodan DNS and host telemetry, enriches the most relevant web targets with Nuclei, and renders the result into Markdown and HTML artifacts for operator review.

The pipeline is deterministic. Gemini is for operator workflow and orchestration around the repo, not for generating a separate executive-summary artifact.

## Workflow

- Shodan DNS discovery and host enrichment
- TXT and takeover-oriented DNS signal collection
- Nuclei execution against the top reachable web targets
- Optional screenshot capture for reachable HTTP/S targets
- Markdown and HTML report generation

## Prepare

### 1. System dependencies

Install these first:

- `python3` 3.10 or newer
- `bash`
- `curl`
- `nuclei`
- `gemini` CLI
- One screenshot tool if you want captures: `chromium`, `google-chrome`, `microsoft-edge`, or `wkhtmltoimage`

Recommended Nuclei install:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Recommended Gemini CLI install:

```bash
npm install -g @google/gemini-cli
```

### 2. Python requirements

The Python code uses only the standard library. A minimal `requirements.txt` is included for automation compatibility.

If your environment expects the step anyway:

```bash
python3 -m pip install -r requirements.txt
```

### 3. Configure Shodan

Set your API key with either an environment variable or a local file.

Environment variable:

```bash
export SHODANAPI="your_shodan_api_key"
```

Or local key file:

```bash
mkdir -p ~/.shodan
printf '%s\n' "your_shodan_api_key" > ~/.shodan/api_key
chmod 600 ~/.shodan/api_key
```

You can also keep the key in a local `.env` file because `scripts/common.sh` loads it automatically:

```bash
printf 'SHODANAPI=%s\n' "your_shodan_api_key" > .env
```

### 4. Authenticate Gemini CLI

Authenticate once before using the repo through Gemini:

```bash
gemini
```

Complete the browser login flow, then return to the terminal.

### 5. Refresh Nuclei templates

```bash
nuclei -update-templates
```

### 6. Clone and preflight

```bash
git clone <your-repo-url>
cd c3po-shodan
chmod +x run.sh bin/run.sh scripts/*.sh install.sh
./install.sh
```

`install.sh` performs preflight checks for Python, Shodan, Nuclei, and Gemini.

## Run

Direct shell usage:

```bash
./run.sh example.com
```

Recommended Gemini-driven workflow from the repository root:

```text
Run ./run.sh against example.com, then help me inspect the HTML report and the Nuclei findings.
```

Primary outputs:

- `output/attack_surface_<target>_<date>.json`
- `output/attack_surface_<target>_<date>.html`
- `runtime/reports/attack_surface_<target>_<date>.md`
- `output/nuclei_<target>_<date>.jsonl`

## Notes

- Screenshot capture is optional and skipped automatically if no supported browser/image tool is installed.
- The pipeline no longer creates a separate CISO summary text artifact.
- If `nuclei` is missing, the rest of the Shodan collection and report pipeline can still complete, but vulnerability enrichment will be absent.

## Example Report

The generated reports provide a comprehensive, interactive view of the discovered attack surface. 

<div align="center">
  <div style="border: 1px solid #d1d5da; border-radius: 8px; overflow: hidden; max-width: 800px; box-shadow: 0 10px 30px rgba(0,0,0,0.1);">
    <div style="background-color: #f6f8fa; border-bottom: 1px solid #d1d5da; padding: 12px; display: flex; align-items: center;">
      <div style="display: flex; gap: 8px; margin-right: 16px;">
        <span style="width: 12px; height: 12px; border-radius: 50%; background-color: #ff5f56; display: inline-block;"></span>
        <span style="width: 12px; height: 12px; border-radius: 50%; background-color: #ffbd2e; display: inline-block;"></span>
        <span style="width: 12px; height: 12px; border-radius: 50%; background-color: #27c93f; display: inline-block;"></span>
      </div>
      <div style="background-color: white; border: 1px solid #e1e4e8; border-radius: 4px; padding: 4px 12px; font-family: 'IBM Plex Mono', monospace; font-size: 12px; flex-grow: 1; text-align: left; color: #586069; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        attack_surface_latest.html
      </div>
    </div>
    <div style="padding: 60px 20px; background-color: white; text-align: center;">
      <a href="attack_surface_latest.html">
        <img src="logo.jpg" alt="Click to view Report" width="120" style="margin-bottom: 20px; opacity: 0.8;"><br>
        <h3 style="margin: 0; color: #0366d6;">View Interactive Attack Surface Report</h3>
        <p style="color: #586069; margin-top: 8px;">Click to open the latest generated EASM dashboard</p>
      </a>
    </div>
  </div>
</div>

## Sample Report

You can view a sample of the generated output here: [attack_surface_latest.html](attack_surface_latest.html)

