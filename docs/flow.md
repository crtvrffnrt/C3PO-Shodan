# C3PO-shodan Flow

1. Operator runs `./run.sh <domain>` from the project root.
2. `scripts/fetch-context.sh` optionally refreshes `GEMINI.md`.
3. `scripts/validate.sh` checks config, required files, Python, Shodan key presence, and Azure readiness.
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
7. `scripts/deploy-report.sh` uploads the HTML dashboard to Azure static-web storage under a distinct blob name.
