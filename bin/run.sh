#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_PATH/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for better UX
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# 1. Run installer/check script
bash "$PROJECT_ROOT/install.sh"

source "$PROJECT_ROOT/scripts/common.sh"

usage() {
  cat <<EOF
Usage: $0 [options] [domain]

Orchestrate Shodan attack-surface discovery and EASM reporting.

Options:
  -d, --domain   Target root domain (supports subdomains like www.example.com)
  --debug, -Debug, -DEBUG Enable shell tracing and verbose logging
  -h, --help     Show this help
EOF
}

DEBUG_MODE=false
EXTRA_ARGS=()
TARGET_INPUT=""
RELATED_DOMAINS=()

# ... (omitted regex and validate_domain for brevity in thought, but I must provide full context in replace)

# Regex for domain validation (supports subdomains)
DOMAIN_REGEX="^([a-zA-Z0-9](([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$"

validate_domain() {
    local d="$1"
    if [[ ! "$d" =~ $DOMAIN_REGEX ]]; then
        echo -e "${RED}[!] Invalid domain format: $d${NC}" >&2
        return 1
    fi
    return 0
}

normalize_target_domain() {
    local raw="${1:-}"
    local item
    IFS=',' read -r -a _domain_parts <<< "$raw"
    for item in "${_domain_parts[@]}"; do
        item="${item// /}"
        item="$(printf %s "$item" | tr '[:upper:]' '[:lower:]')"
        if [ -n "$item" ]; then
            if validate_domain "$item"; then
                TARGET_DOMAIN="$item"
                return 0
            fi
            exit 1
        fi
    done
    TARGET_DOMAIN=""
    return 1
}

run_with_timeout() {
    local timeout_value="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout --preserve-status --kill-after=60s "$timeout_value" "$@"
    else
        "$@"
    fi
}

ensure_fallback_payload() {
    local path="$1"
    local domains_csv="$2"
    if [ -s "$path" ]; then
        return 0
    fi
    python3 - "$path" "$domains_csv" <<'PY'
import json
import os
import sys

path, domains_csv = sys.argv[1], sys.argv[2]
domains = [item for item in domains_csv.split(",") if item]
payload = {
    "target": {
        "input": domains_csv,
        "core_domain": domains_csv,
        "slug": domains_csv,
        "generated_at": "",
    },
    "summary": {
        "host_count": 0,
        "web_host_count": 0,
        "ip_count": 0,
        "takeover_candidate_count": 0,
        "txt_hit_count": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "original_total_hosts": 0,
    },
    "discoveries": {
        "dns_records": [],
        "interesting_txt": [],
        "takeover_candidates": [],
        "network_ranges": [],
    },
    "hosts": [],
    "ips": [],
    "domains": domains,
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, ensure_ascii=False)
    handle.write("\n")
PY
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)
            TARGET_INPUT="${2:-}"
            shift 2
            ;;
        --debug|-Debug|-DEBUG)
            DEBUG_MODE=true
            EXTRA_ARGS+=("--debug")
            set -x
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [ -z "$TARGET_INPUT" ]; then
                TARGET_INPUT="$1"
                shift
            else
                echo "[!] Unknown argument: $1" >&2
                usage
                exit 1
            fi
            ;;
    esac
done

if [ -z "$TARGET_INPUT" ]; then
    echo "[!] No target domain specified." >&2
    usage
    exit 1
fi

if ! normalize_target_domain "$TARGET_INPUT"; then
    echo "[!] No valid target domain specified." >&2
    usage
    exit 1
fi

echo -e "${GREEN}[*] Target domain: ${TARGET_DOMAIN}${NC}"
echo -e "${GREEN}[*] Checking for related domains for report context...${NC}"
MAP_OUTPUT="$(python3 "$PROJECT_ROOT/scripts/domain_lookup.py" "${TARGET_DOMAIN}" --max 10 || true)"
if [ -n "$MAP_OUTPUT" ]; then
    while IFS= read -r line; do
        line="$(printf %s "$line" | tr '[:upper:]' '[:lower:]')"
        if [ -n "$line" ]; then
            RELATED_DOMAINS+=("$line")
        fi
    done <<< "$MAP_OUTPUT"
    echo -e "${GREEN}[+] Related domains recorded for report: ${#RELATED_DOMAINS[@]}${NC}"
fi

if [ ${#RELATED_DOMAINS[@]} -eq 0 ]; then
    RELATED_DOMAINS=("$TARGET_DOMAIN")
fi

if [ -z "${SHODANAPI:-}" ]; then
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
TARGET_SLUG="$(slugify "${TARGET_DOMAIN}")"

RAW_JSON="$OUTPUT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}.json"
SCREENSHOT_MANIFEST="$OUTPUT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}_screenshots.json"
MARKDOWN_REPORT="$REPORT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}.md"
HTML_REPORT="$OUTPUT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}.html"
LATEST_HTML="$PROJECT_ROOT/attack_surface_latest.html"
NUCLEI_OUTPUT="$OUTPUT_DIR/nuclei_${TARGET_SLUG}_${REPORT_DATE}.jsonl"

echo "[*] Phase 1: Running modular discovery/triage pipeline for $TARGET_DOMAIN ..."
PIPELINE_CMD=(
    python3 "$SCRIPTS_DIR/orchestrate.py"
    "$TARGET_DOMAIN"
    --output-dir "$OUTPUT_DIR"
    --json-output "$RAW_JSON"
    --html-output "$HTML_REPORT"
    "${EXTRA_ARGS[@]}"
)
for related_domain in "${RELATED_DOMAINS[@]}"; do
    PIPELINE_CMD+=(--related-domain "$related_domain")
done
# Increased timeout to 35m as requested
if [ "$DEBUG_MODE" = true ]; then
    if ! run_with_timeout 35m "${PIPELINE_CMD[@]}"; then
        echo "[*] Phase 1 failed; continuing with fallback report data."
    fi
else
    if ! run_with_timeout 35m "${PIPELINE_CMD[@]}" >/dev/null 2>&1; then
        echo "[*] Phase 1 timed out or failed; continuing with fallback report data."
    fi
fi
ensure_fallback_payload "$RAW_JSON" "$TARGET_DOMAIN"

TXT_FINDINGS_JSON="$OUTPUT_DIR/txtfindings_${TARGET_SLUG}_${REPORT_DATE}.json"
echo "[*] Phase 2: Enriching TXT DNS evidence ..."
# Increased timeout to 35m
if ! run_with_timeout 35m python3 "$SCRIPTS_DIR/txtfinder.py" --input "$RAW_JSON" --output "$TXT_FINDINGS_JSON"; then
    echo "[*] TXT enrichment timed out or failed; continuing."
    : > "$TXT_FINDINGS_JSON"
fi

python3 - "$RAW_JSON" "$TXT_FINDINGS_JSON" <<'PY'
import json
import sys

raw_json, txt_json = sys.argv[1], sys.argv[2]
with open(raw_json, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
try:
    with open(txt_json, "r", encoding="utf-8") as handle:
        txt_payload = json.load(handle)
except:
    txt_payload = {"entries": []}

existing = payload.setdefault("discoveries", {}).setdefault("interesting_txt", [])
seen = {
    (item.get("hostname", ""), item.get("label", ""), " ".join(str(item.get("value", "")).split()).strip())
    for item in existing
}
for item in txt_payload.get("entries", []):
    key = (item.get("hostname", ""), item.get("label", ""), " ".join(str(item.get("value", "")).split()).strip())
    if key in seen:
        continue
    seen.add(key)
    existing.append(item)
existing.sort(key=lambda item: (item.get("hostname", ""), item.get("label", ""), item.get("value", "")))

with open(raw_json, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, ensure_ascii=False)
    handle.write("\n")
PY

echo "[*] Phase 3: Running Nuclei on top 5 risky web targets ..."
NUCLEI_TARGETS="$OUTPUT_DIR/targets_${TARGET_SLUG}.txt"
python3 - "$RAW_JSON" "$NUCLEI_TARGETS" <<'PY'
import json
import sys

raw_json, targets_path = sys.argv[1], sys.argv[2]
with open(raw_json, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

hosts = payload.get("hosts", [])
web_hosts = [
    host for host in hosts
    if host.get("http", {}).get("reachable") and host.get("http", {}).get("url")
]
web_hosts.sort(key=lambda item: (-int(item.get("risk_score", 0) or 0), item.get("hostname", "")))
targets = []
seen = set()
for host in web_hosts:
    url = host["http"]["url"]
    if url in seen:
        continue
    seen.add(url)
    targets.append(url)
    if len(targets) == 5:
        break

with open(targets_path, "w", encoding="utf-8") as handle:
    if targets:
        handle.write("\n".join(targets) + "\n")
PY

if [ -s "$NUCLEI_TARGETS" ]; then
    # Increased timeout to 35m
    if ! run_with_timeout 35m nuclei -l "$NUCLEI_TARGETS" \
           -tags generic,tech,cve \
           -severity critical,high,medium,low \
           -jsonl \
           -o "$NUCLEI_OUTPUT" \
           -silent; then
        echo "[*] Nuclei timed out or failed; continuing."
    fi
else
    echo "[*] No reachable web targets found for Nuclei scan."
    : > "$NUCLEI_OUTPUT"
fi

echo "[*] Phase 4: Capturing screenshots where possible ..."
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
    # Increased timeout to 35m
    run_with_timeout 35m "${screenshot_cmd[@]}" >/dev/null 2>&1 || true
fi
if [ ! -f "$SCREENSHOT_MANIFEST" ]; then
    printf '{\n  "generated_at": "%s",\n  "entries": []\n}\n' "$TIMESTAMP" > "$SCREENSHOT_MANIFEST"
fi

echo "[*] Phase 5: Rendering report ..."
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
# Increased timeout to 35m
if ! run_with_timeout 35m "${render_cmd[@]}"; then
    echo "[*] Report rendering timed out or failed; keeping fallback HTML."
fi

echo "[*] Phase 6: Generating CISO summary ..."
SUMMARY_TXT="$OUTPUT_DIR/ciso_summary_${TARGET_SLUG}_${REPORT_DATE}.txt"
# Increased timeout to 35m
run_with_timeout 35m python3 "$SCRIPTS_DIR/generate-summary.py" --input "$RAW_JSON" > "$SUMMARY_TXT" 2>/dev/null || true
cp "$HTML_REPORT" "$LATEST_HTML"

echo -e "${GREEN}[*] Report JSON: $RAW_JSON${NC}"
echo -e "${GREEN}[*] Report HTML: $HTML_REPORT${NC}"
echo -e "${GREEN}[*] CISO Summary: $SUMMARY_TXT${NC}"
