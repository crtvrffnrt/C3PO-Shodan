#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_PATH/.." && pwd)"
cd "$PROJECT_ROOT"

source "$PROJECT_ROOT/scripts/common.sh"

usage() {
  cat <<EOF
Usage: $0 [options] [domain]

Orchestrate Shodan attack-surface discovery and EASM reporting.

Options:
  -d, --domain   Target root domain
  --debug, -Debug Enable shell tracing
  -h, --help     Show this help
EOF
}

DEBUG_MODE=false
TARGET_DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)
            TARGET_DOMAIN="${2:-}"
            shift 2
            ;;
        --debug|-Debug)
            DEBUG_MODE=true
            set -x
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [ -z "$TARGET_DOMAIN" ]; then
                TARGET_DOMAIN="$1"
                shift
            else
                echo "[!] Unknown argument: $1" >&2
                usage
                exit 1
            fi
            ;;
    esac
done

if [ -z "$TARGET_DOMAIN" ]; then
    echo "[!] No target domain specified." >&2
    usage
    exit 1
fi

TARGET_DOMAIN="$(printf %s "$TARGET_DOMAIN" | tr '[:upper:]' '[:lower:]')"

if [ -z "${SHODANAPI:-}" ]; then
    # Try to load from shodan cli config if env is missing
    SHODANAPI="$(resolve_shodan_key || echo "")"
    if [ -z "$SHODANAPI" ]; then
        echo "[!] SHODANAPI environment variable not set and no Shodan config found." >&2
        exit 1
    fi
    export SHODANAPI
fi

# 0. Preflight
./scripts/fetch-context.sh
./scripts/validate.sh "$TARGET_DOMAIN"

REPORT_DATE="$(date +%Y-%m-%d)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TARGET_SLUG="$(slugify "$TARGET_DOMAIN")"

RAW_JSON="$OUTPUT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}.json"
SCREENSHOT_MANIFEST="$OUTPUT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}_screenshots.json"
MARKDOWN_REPORT="$REPORT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}.md"
HTML_REPORT="$OUTPUT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}.html"
LATEST_HTML="$PROJECT_ROOT/attack_surface_latest.html"

# Load config values
SHODAN_DNS_PAGE_LIMIT="$(parse_yaml shodan_dns_page_limit)"
SHODAN_HOST_ENRICHMENT_LIMIT="$(parse_yaml shodan_host_enrichment_limit)"
DOMAIN_CT_ENABLED="$(parse_yaml domain_ct_enabled)"
DOMAIN_CT_TIMEOUT_SECONDS="$(parse_yaml domain_ct_timeout_seconds)"
WEB_PROBE_TIMEOUT_SECONDS="$(parse_yaml web_probe_timeout_seconds)"
MAX_HOSTS_FOR_HTTP_PROBE="$(parse_yaml max_hosts_for_http_probe)"
SCREENSHOT_ENABLED="$(parse_yaml screenshot_enabled)"
MAX_SCREENSHOTS="$(parse_yaml max_screenshots)"
SCREENSHOT_TIMEOUT_SECONDS="$(parse_yaml screenshot_timeout_seconds)"
SCREENSHOT_WIDTH="$(parse_yaml screenshot_window_width)"
SCREENSHOT_HEIGHT="$(parse_yaml screenshot_window_height)"
echo "[*] Phase 1: Collecting Shodan attack-surface intelligence for $TARGET_DOMAIN ..."
collector_cmd=(
    python3 "$SCRIPTS_DIR/collect-attack-surface.py"
    --domain "$TARGET_DOMAIN"
    --output "$RAW_JSON"
    --provider-fragments "$CONFIG_DIR/provider-fragments.txt"
    --dns-page-limit "${SHODAN_DNS_PAGE_LIMIT:-4}"
    --host-enrichment-limit "${SHODAN_HOST_ENRICHMENT_LIMIT:-30}"
    --web-timeout "${WEB_PROBE_TIMEOUT_SECONDS:-10}"
    --max-web-probes "${MAX_HOSTS_FOR_HTTP_PROBE:-40}"
    --ct-timeout "${DOMAIN_CT_TIMEOUT_SECONDS:-20}"
)
if config_is_true "${DOMAIN_CT_ENABLED:-true}"; then
    collector_cmd+=(--include-crtsh)
fi
if [ "$DEBUG_MODE" = true ]; then
    collector_cmd+=(--debug)
fi
"${collector_cmd[@]}"

if [ ! -s "$RAW_JSON" ]; then
    echo "[!] Raw JSON output was not created." >&2
    exit 1
fi

echo "[*] Phase 2: Capturing screenshots where possible ..."
if config_is_true "${SCREENSHOT_ENABLED:-true}"; then
    screenshot_cmd=(
        python3 "$SCRIPTS_DIR/capture-screenshots.py"
        --input "$RAW_JSON"
        --output "$SCREENSHOT_MANIFEST"
        --screenshot-dir "$SCREENSHOT_DIR"
        --max-screenshots "${MAX_SCREENSHOTS:-16}"
        --timeout "${SCREENSHOT_TIMEOUT_SECONDS:-35}"
        --width "${SCREENSHOT_WIDTH:-1440}"
        --height "${SCREENSHOT_HEIGHT:-1024}"
    )
    if [ "$DEBUG_MODE" = true ]; then
        screenshot_cmd+=(--debug)
    fi
    "${screenshot_cmd[@]}"
else
    printf '{\n  "generated_at": "%s",\n  "entries": []\n}\n' "$TIMESTAMP" > "$SCREENSHOT_MANIFEST"
fi

NUCLEI_OUTPUT="$OUTPUT_DIR/nuclei_${TARGET_SLUG}_${REPORT_DATE}.jsonl"
echo "[*] Phase 3: Running basic Nuclei scan on discovered web hosts ..."
# Extract URLs from RAW_JSON using jq
mapfile -t URLS < <(jq -r '.hosts[] | select(.http.reachable == true) | .http.url' "$RAW_JSON" 2>/dev/null || true)

if [ ${#URLS[@]} -gt 0 ]; then
    printf "%s\n" "${URLS[@]}" > "$OUTPUT_DIR/targets_${TARGET_SLUG}.txt"
    nuclei -l "$OUTPUT_DIR/targets_${TARGET_SLUG}.txt" \
           -tags generic,tech,cve \
           -severity critical,high,medium,low \
           -jsonl \
           -o "$NUCLEI_OUTPUT" \
           -silent || true
else
    echo "[*] No reachable web hosts found for Nuclei scan."
    echo "" > "$NUCLEI_OUTPUT"
fi

echo "[*] Phase 4: Rendering markdown and HTML attack-surface reports ..."
render_cmd=(
    python3 "$SCRIPTS_DIR/render-report.py"
    --input "$RAW_JSON"
    --screenshots "$SCREENSHOT_MANIFEST"
    --markdown-output "$MARKDOWN_REPORT"
    --html-output "$HTML_REPORT"
)

if [ -f "$NUCLEI_OUTPUT" ] && [ -s "$NUCLEI_OUTPUT" ]; then
    render_cmd+=(--nuclei "$NUCLEI_OUTPUT")
fi

"${render_cmd[@]}"

if [ ! -s "$HTML_REPORT" ]; then
    echo "[!] HTML report was not created." >&2
    exit 1
fi

cp "$HTML_REPORT" "$LATEST_HTML"

echo "[*] Report JSON: $RAW_JSON"
echo "[*] Report Markdown: $MARKDOWN_REPORT"
echo "[*] Report HTML: $HTML_REPORT"
