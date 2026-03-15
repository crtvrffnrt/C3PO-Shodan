# C3PO-shodan Architecture

## Overview

C3PO-shodan follows the same root-centric orchestration model as `C3PO-Osinter`, but swaps prompt-driven intelligence stages for a deterministic Shodan collection and rendering pipeline.

## Layers

1. `run.sh` and `bin/run.sh`
   Coordinate validation, collection, screenshots, rendering, and Azure upload.

2. `scripts/common.sh`
   Centralizes path resolution, dotenv loading, config parsing, and helper functions.

3. `scripts/collect-attack-surface.py`
   Performs Shodan DNS collection, hostname/IP enrichment, TXT/provider analysis, and host risk scoring.

4. `scripts/capture-screenshots.py`
   Attempts visual capture of reachable web hosts using whatever headless browser tooling is available locally.

5. `scripts/render-report.py`
   Builds both markdown and a self-contained HTML dashboard from the collected JSON plus screenshot artifacts.

6. `scripts/deploy-report.sh`
   Uploads the named HTML artifact into the existing Azure static website container without replacing `index.html`.

## Runtime Outputs

- `runtime/output/*.json`: Raw collection and screenshot manifests
- `runtime/reports/*.md`: Markdown attack-surface reports
- `runtime/output/*.html`: Self-contained HTML dashboards
- `runtime/screenshots/*.png`: Optional host screenshots

## Design Principles

- Deterministic and inspectable
- Single-command execution
- No hard dependency on Gemini
- Best-effort screenshots
- Same Azure auth model, different blob names
