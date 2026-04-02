# C3PO-shodan Flow

1. Operator runs `./run.sh <domain>` from the project root.
2. `scripts/fetch-context.sh` optionally refreshes `GEMINI.md` and keeps the operator context file current.
3. `scripts/validate.sh` checks config, required files, Python, and Shodan key presence.
4. `scripts/collect-attack-surface.py` gathers:
   - Shodan DNS records and subdomains
   - optional certificate-transparency subdomains
   - current DNS resolution
   - Shodan host telemetry for discovered IPs
   - takeover-oriented provider matches
   - TXT verification signals
5. `scripts/capture-screenshots.py` captures live HTTP/S targets where tooling exists.
6. `scripts/render-report.py` creates:
   - versioned markdown report
   - versioned HTML dashboard
7. The rendered HTML dashboard is written locally to `output/`.

Each phase should be read alongside the matching `GEMINI.md` and `SKILL.md` guidance files under `docs/workflows/`.
