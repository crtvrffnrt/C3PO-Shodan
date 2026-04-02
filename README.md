<div align="center">

  # C3PO-shodan

  [![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
  [![Bash](https://img.shields.io/badge/shell-bash-orange.svg)](https://www.gnu.org/software/bash/)
  [![Shodan](https://img.shields.io/badge/API-Shodan-red.svg)](https://www.shodan.io/)
  [![Gemini CLI](https://img.shields.io/badge/CLI-Gemini-purple.svg)](https://github.com/google/gemini-cli)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

  **A Bash-orchestrated Shodan attack-surface workflow for deterministic infrastructure discovery.**
</div>
---
  <img src="logo.jpg" alt="C3PO-shodan Logo" width="400">

---

## 🤖 Overview

**C3PO-shodan** is a powerful, deterministic pipeline designed to map a domain's external attack surface using Shodan DNS data and host telemetry. It mirrors the execution style of `C3PO-Osinter` but focuses strictly on infrastructure discovery, IP resolution, and risk scoring.

The tool generates both a versioned **Markdown report** and a self-contained **HTML operator dashboard**, providing actionable insights into exposed ports, vulnerable products, and potential subdomain takeover opportunities.

---

## ✨ Features

- 🔍 **DNS Intelligence**: Collects subdomains and DNS records directly from Shodan.
- 🌐 **Host Enrichment**: Pulls Shodan host data for discovered IPs (ports, products, vulnerabilities).
- 🛡️ **Risk Scoring**: Automatically scores hosts based on exposure and historical risk.
- 🚀 **Takeover Detection**: Highlights CNAME/provider patterns (inspired by `BountyHelperScripts`).
- 📸 **Visual Recon**: Best-effort screenshots of live HTTP/S targets.
- 📊 **Dual Reporting**: Generates clean Markdown for documentation and interactive HTML for analysis.
- 🤖 **Gemini Integrated**: Built-in context (`GEMINI.md`) for AI-assisted workflow extensions.

---

## 🛠️ Installation & Setup

### 1. Prerequisites
Ensure you have the following installed:
- **Python 3.10+**
- **Node.js 20+** (for Gemini CLI)
- **Bash** (Linux/macOS)

### 2. Shodan API Configuration
You need a Shodan API key. You can provide it in two ways:

#### Option A: Environment Variable (Recommended)
Add this to your `~/.bashrc` or `~/.zshrc`:
```bash
export SHODANAPI="your_shodan_api_key_here"
```

#### Option B: .env File
Copy the example and edit it:
```bash
cp .env.example .env
# Add SHODANAPI=your_key to .env
```

### 3. Gemini CLI Installation & Auth
The Gemini CLI is used for AI-assisted analysis and workflow extensions.

#### Install:
```bash
npm install -g @google/gemini-cli
```

#### Authenticate:
1. Run the CLI:
   ```bash
   gemini
   ```
2. Select **"Sign in with Google"** when prompted.
3. Complete the OAuth flow in your browser.
4. Once authorized, return to the terminal.

### 4. Project Setup
```bash
git clone https://github.com/your-org/c3po-shodan.git
cd c3po-shodan
chmod +x run.sh bin/run.sh scripts/*.sh
./install.sh # If applicable, to setup python dependencies
```

---

## 🚀 Execution

Run the workflow from the project root:

```bash
./run.sh example.com
```

If no domain is provided, the script will prompt you interactively.

---

## 📁 Project Structure

- `run.sh`: Root entrypoint and wrapper.
- `bin/run.sh`: Main orchestration logic.
- `scripts/`: Collection and rendering modules (Python/Shell).
- `config/`: YAML configurations and provider fragments.
- `output/`: Final JSON artifacts and HTML dashboards.
- `runtime/`: Temp reports, logs, and screenshots.
- `docs/`: Technical documentation and style guides.

---

## 📝 Notes

- **Screenshots**: Requires a headless browser (Chromium/Chrome/Edge) or `wkhtmltoimage`. If missing, the pipeline gracefully skips captures.
- **Local-First**: Report generation is entirely deterministic and does not require active Gemini execution.
- **Privacy**: No data is sent to external services other than the Shodan API.

---

<div align="center">
  <sub>Built with ❤️ by the C3PO-shodan Team</sub>
</div>
