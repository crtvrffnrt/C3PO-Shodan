#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_PATH/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for better UX
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
PHASE_RESULTS=()
PHASE_INTERRUPT_REQUESTED=0

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

info() {
    echo -e "${GREEN}[*] $*${NC}"
}

warn() {
    echo -e "${YELLOW}[!] $*${NC}" >&2
}

error() {
    echo -e "${RED}[!] $*${NC}" >&2
}

fatal() {
    error "$*"
    exit 1
}

record_phase_result() {
    local phase_key="$1"
    local outcome="$2"
    local detail="$3"
    PHASE_RESULTS+=("${phase_key}|${outcome}|${detail}")
}

print_phase_summary() {
    local entry phase_key outcome detail
    echo
    info "Phase summary:"
    for entry in "${PHASE_RESULTS[@]:-}"; do
        IFS='|' read -r phase_key outcome detail <<< "$entry"
        case "$outcome" in
            ok) info "${phase_key}: completed (${detail})" ;;
            skipped) warn "${phase_key}: skipped (${detail})" ;;
            timeout) warn "${phase_key}: timed out (${detail})" ;;
            failed) warn "${phase_key}: failed (${detail})" ;;
            *) warn "${phase_key}: ${outcome} (${detail})" ;;
        esac
    done
}

run_with_timeout() {
    local timeout_value="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout --kill-after=60s "$timeout_value" "$@"
    else
        "$@"
    fi
}

timeout_to_seconds() {
    local raw="${1:-0}"
    if [[ "$raw" =~ ^([0-9]+)h$ ]]; then
        echo $(( BASH_REMATCH[1] * 3600 ))
    elif [[ "$raw" =~ ^([0-9]+)m$ ]]; then
        echo $(( BASH_REMATCH[1] * 60 ))
    elif [[ "$raw" =~ ^([0-9]+)s$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$raw" =~ ^[0-9]+$ ]]; then
        echo "$raw"
    else
        echo 0
    fi
}

format_duration() {
    local total_seconds="${1:-0}"
    local hours=$(( total_seconds / 3600 ))
    local minutes=$(( (total_seconds % 3600) / 60 ))
    local seconds=$(( total_seconds % 60 ))
    if [ "$hours" -gt 0 ]; then
        printf '%02d:%02d:%02d' "$hours" "$minutes" "$seconds"
    else
        printf '%02d:%02d' "$minutes" "$seconds"
    fi
}

render_progress_bar() {
    local elapsed_seconds="$1"
    local total_seconds="$2"
    local width=24
    local filled=0
    local empty=0
    local bar=""
    local spinner='|/-\'
    local spinner_index=$(( elapsed_seconds % 4 ))
    local spinner_char="${spinner:spinner_index:1}"

    if [ "$total_seconds" -gt 0 ]; then
        filled=$(( elapsed_seconds * width / total_seconds ))
        if [ "$filled" -gt "$width" ]; then
            filled="$width"
        fi
    fi
    empty=$(( width - filled ))

    if [ "$filled" -gt 0 ]; then
        printf -v bar '%*s' "$filled" ''
        bar="${bar// /=}"
    fi
    if [ "$empty" -gt 0 ]; then
        printf -v padding '%*s' "$empty" ''
        bar+="${padding// /.}"
    fi
    if [ "$filled" -lt "$width" ]; then
        local marker_pos="$filled"
        if [ "$marker_pos" -lt 0 ]; then
            marker_pos=0
        fi
        bar="${bar:0:marker_pos}${spinner_char}${bar:marker_pos+1}"
    fi
    printf '%s' "$bar"
}

show_phase_progress() {
    local phase_key="$1"
    local timeout_value="$2"
    local target_pid="$3"
    local started_at
    local now
    local elapsed
    local timeout_seconds
    local bar

    timeout_seconds="$(timeout_to_seconds "$timeout_value")"
    started_at="$(date +%s)"

    while kill -0 "$target_pid" >/dev/null 2>&1; do
        now="$(date +%s)"
        elapsed=$(( now - started_at ))
        bar="$(render_progress_bar "$elapsed" "$timeout_seconds")"
        printf '\r[*] %s [%s] %s / %s' \
            "$phase_key" \
            "$bar" \
            "$(format_duration "$elapsed")" \
            "$(format_duration "$timeout_seconds")"
        sleep 1
    done
    printf '\r%120s\r' ''
}

run_phase_command() {
    local phase_key="$1"
    local phase_title="$2"
    local timeout_value="$3"
    local quiet_mode="$4"
    shift 4

    local log_file="$LOG_DIR/${phase_key}_${TARGET_SLUG}_${REPORT_DATE}.log"
    local status=0
    local phase_pid=""

    info "$phase_title"
    info "Press Ctrl+C to skip this phase. Log: $log_file"
    : > "$log_file"

    PHASE_INTERRUPT_REQUESTED=0
    trap 'PHASE_INTERRUPT_REQUESTED=1; if [ -n "${phase_pid:-}" ]; then kill -INT "${phase_pid}" >/dev/null 2>&1 || true; fi' INT

    set +e
    if [ "$DEBUG_MODE" = true ]; then
        run_with_timeout "$timeout_value" "$@" 2>&1 | tee "$log_file"
        status=${PIPESTATUS[0]}
    else
        run_with_timeout "$timeout_value" "$@" >"$log_file" 2>&1 &
        phase_pid=$!
        show_phase_progress "$phase_key" "$timeout_value" "$phase_pid"
        wait "$phase_pid"
        status=$?
    fi
    set -e

    trap - INT

    if [ "$PHASE_INTERRUPT_REQUESTED" -eq 1 ] || [ "$status" -eq 130 ]; then
        warn "${phase_key} interrupted by user. Continuing to the next phase."
        record_phase_result "$phase_key" "skipped" "user interrupt; log: $log_file"
        PHASE_INTERRUPT_REQUESTED=0
        return 130
    fi

    case "$status" in
        0)
            record_phase_result "$phase_key" "ok" "log: $log_file"
            return 0
            ;;
        124)
            warn "${phase_key} timed out after ${timeout_value}. Continuing."
            record_phase_result "$phase_key" "timeout" "after ${timeout_value}; log: $log_file"
            return 124
            ;;
        137|143)
            warn "${phase_key} exceeded the timeout and was terminated. Continuing."
            record_phase_result "$phase_key" "timeout" "terminated after timeout; log: $log_file"
            return "$status"
            ;;
        *)
            warn "${phase_key} failed with exit code ${status}. Continuing."
            record_phase_result "$phase_key" "failed" "exit ${status}; log: $log_file"
            return "$status"
            ;;
    esac
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
        fatal "SHODANAPI environment variable not set and no Shodan config found."
    fi
    export SHODANAPI
fi

# 0. Preflight
if ! ./scripts/fetch-context.sh; then
    warn "Context refresh failed. Continuing with the local context file."
fi
if ! ./scripts/validate.sh "$TARGET_DOMAIN"; then
    fatal "Validation failed. Fix the reported problem and rerun."
fi

REPORT_DATE="$(date +%Y-%m-%d)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TARGET_SLUG="$(slugify "${TARGET_DOMAIN}")"

RAW_JSON="$OUTPUT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}.json"
SCREENSHOT_MANIFEST="$OUTPUT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}_screenshots.json"
MARKDOWN_REPORT="$REPORT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}.md"
HTML_REPORT="$OUTPUT_DIR/attack_surface_${TARGET_SLUG}_${REPORT_DATE}.html"
LATEST_HTML="$PROJECT_ROOT/attack_surface_latest.html"
NUCLEI_OUTPUT="$OUTPUT_DIR/nuclei_${TARGET_SLUG}_${REPORT_DATE}.jsonl"

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
PHASE1_QUIET=true
if [ "$DEBUG_MODE" = true ]; then
    PHASE1_QUIET=false
fi
if ! run_phase_command "phase1" "Phase 1: Running modular discovery/triage pipeline for $TARGET_DOMAIN ..." 35m "$PHASE1_QUIET" "${PIPELINE_CMD[@]}"; then
    warn "Phase 1 did not complete cleanly; fallback report data will be used where needed."
fi
ensure_fallback_payload "$RAW_JSON" "$TARGET_DOMAIN"

TXT_FINDINGS_JSON="$OUTPUT_DIR/txtfindings_${TARGET_SLUG}_${REPORT_DATE}.json"
if ! run_phase_command "phase2" "Phase 2: Enriching TXT DNS evidence ..." 35m false \
    python3 "$SCRIPTS_DIR/txtfinder.py" --input "$RAW_JSON" --output "$TXT_FINDINGS_JSON"; then
    warn "TXT enrichment did not complete cleanly; continuing with an empty TXT findings file."
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
    if len(targets) == 25:
        break

with open(targets_path, "w", encoding="utf-8") as handle:
    if targets:
        handle.write("\n".join(targets) + "\n")
PY

if [ -s "$NUCLEI_TARGETS" ]; then
    if ! run_phase_command "phase3" "Phase 3: Running Nuclei on top 25 risky web targets ..." 35m false \
        nuclei -l "$NUCLEI_TARGETS" \
            -tags misconfig,exposure,takeover,cve,tech,default-login \
            -severity critical,high,medium \
            -c 150 -bs 25 -rl 300 -timeout 5 \
            -jsonl \
            -o "$NUCLEI_OUTPUT" \
            -silent; then
        warn "Nuclei scan did not complete cleanly; continuing without additional findings."
    fi
else
    info "Phase 3: No reachable web targets found for Nuclei scan."
    : > "$NUCLEI_OUTPUT"
    record_phase_result "phase3" "skipped" "no reachable web targets"
fi

if config_is_true "${SCREENSHOT_ENABLED:-true}"; then
    info "Phase 4: Capturing screenshots and URL intelligence..."
    
    # Check for Cloudflare credentials
    CF_SCANNER_ENABLED=false
    if [ -n "${CF_ACCOUNT_ID:-}" ] && [ -n "${CF_API_TOKEN:-}" ]; then
        CF_SCANNER_ENABLED=true
        info "[+] Cloudflare credentials detected. Using Cloudflare URL Scanner as primary source."
    fi

    if [ "$CF_SCANNER_ENABLED" = true ]; then
        # Primary Cloudflare Scan Path with local fallback logic
        python3 - "$RAW_JSON" "$SCREENSHOT_MANIFEST" "$SCREENSHOT_DIR" "${MAX_SCREENSHOTS:-16}" "$CF_ACCOUNT_ID" "$CF_API_TOKEN" <<'PY'
import json
import os
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

raw_json, manifest_path, screenshot_dir, max_screenshots, account_id, api_token = sys.argv[1:]
max_screenshots = int(max_screenshots)

with open(raw_json, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

hosts = payload.get("hosts", [])
reachable = [
    h for h in hosts 
    if h.get("http", {}).get("reachable") and h.get("http", {}).get("url")
]
reachable.sort(key=lambda x: (-int(x.get("risk_score", 0)), x.get("hostname", "")))

targets = reachable[:max_screenshots]
entries = []

os.makedirs(screenshot_dir, exist_ok=True)

# Shared state for rate limiting and delay
state = {
    "rate_limited": False,
    "last_scan_time": 0.0,
    "lock": threading.Lock()
}

def scan_target(target):
    hostname = target.get("hostname")
    url = target.get("http", {}).get("url")
    clean_host = "".join(c if c.isalnum() else "_" for c in hostname)
    png_path = os.path.join(screenshot_dir, f"{clean_host}.png")
    json_path = os.path.join(screenshot_dir, f"cloudflare_{clean_host}.json")
    
    with state["lock"]:
        if state["rate_limited"]:
            print(f" [!] Rate limit hit previously. Skipping Cloudflare for {hostname}...")
            return None

        # Ensure at least 11 seconds between scan submissions
        now = time.time()
        elapsed = now - state["last_scan_time"]
        if elapsed < 11.0:
            sleep_time = 11.0 - elapsed
            time.sleep(sleep_time)
        
        state["last_scan_time"] = time.time()

    print(f"[*] Scanning {hostname} via Cloudflare...")
    
    cmd = [
        "bash", os.path.join(os.getcwd(), "scripts/cloudflare-scanner.sh"),
        "-d", url,
        "-o", screenshot_dir,
        "-q"
    ]
    
    env = os.environ.copy()
    env["CF_ACCOUNT_ID"] = account_id
    env["CF_API_TOKEN"] = api_token
    
    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
        
        if result.returncode == 42:
            print(f" [!] Cloudflare rate limit detected for {hostname}. Switching to local tools for future targets.")
            with state["lock"]:
                state["rate_limited"] = True
            return None

        if result.returncode == 0 and os.path.exists(png_path):
            cf_data = {}
            if os.path.exists(json_path):
                with open(json_path, "r") as f:
                    cf_data = json.load(f)
            
            print(f" [+] Success: {hostname}")
            return {
                "hostname": hostname,
                "url": url,
                "status": "captured",
                "tool": "cloudflare",
                "path": png_path,
                "cloudflare_info": cf_data
            }
        else:
            print(f" [!] Cloudflare failed for {hostname}: {result.stderr}")
            return {
                "hostname": hostname,
                "url": url,
                "status": "failed",
                "tool": "cloudflare",
                "reason": result.stderr or "Unknown error"
            }
    except Exception as e:
        print(f" [!] Error scanning {hostname}: {str(e)}")
        return {
            "hostname": hostname,
            "url": url,
            "status": "failed",
            "tool": "cloudflare",
            "reason": str(e)
        }

# Use max_workers=2 but the Lock handles the 11s interval
with ThreadPoolExecutor(max_workers=2) as executor:
    results = list(executor.map(scan_target, targets))
    entries.extend([r for r in results if r is not None])

# Fallback for failed or missing targets
captured_hosts = {e["hostname"] for e in entries if e["status"] == "captured"}
remaining_targets = [t for t in targets if t["hostname"] not in captured_hosts]

if remaining_targets:
    print(f"[*] Fallback: Capturing {len(remaining_targets)} targets using local tools...")
    
    # Create a temporary filtered JSON for the local scanner
    filtered_payload = payload.copy()
    filtered_payload["hosts"] = [h for h in hosts if h["hostname"] in {t["hostname"] for t in remaining_targets}]
    
    tmp_json = os.path.join(screenshot_dir, "fallback_targets.json")
    tmp_manifest = os.path.join(screenshot_dir, "fallback_manifest.json")
    
    with open(tmp_json, "w") as f:
        json.dump(filtered_payload, f)
    
    try:
        # Call capture-screenshots.py
        fallback_cmd = [
            sys.executable,
            os.path.join(os.getcwd(), "scripts/capture-screenshots.py"),
            "--input", tmp_json,
            "--output", tmp_manifest,
            "--screenshot-dir", screenshot_dir,
            "--max-screenshots", str(len(remaining_targets))
        ]
        subprocess.run(fallback_cmd, check=False)
        
        if os.path.exists(tmp_manifest):
            with open(tmp_manifest, "r") as f:
                fallback_data = json.load(f)
                for entry in fallback_data.get("entries", []):
                    entry["tool"] = "local-fallback"
                    entries.append(entry)
    except Exception as e:
        print(f" [!] Local fallback failed: {str(e)}")
    finally:
        if os.path.exists(tmp_json): os.remove(tmp_json)
        if os.path.exists(tmp_manifest): os.remove(tmp_manifest)

manifest = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "tool": "cloudflare-with-local-fallback",
    "entries": entries
}

with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2)
PY
        record_phase_result "phase4" "ok" "Cloudflare parallel scanner completed"
    else:
        # Fallback to local capture
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
        if ! run_phase_command "phase4" "Phase 4: Capturing local screenshots ..." 35m true "${screenshot_cmd[@]}"; then
            warn "Local screenshot capture did not complete cleanly."
        fi
    fi
else
    info "Phase 4: Screenshot capture disabled by configuration."
    record_phase_result "phase4" "skipped" "disabled by configuration"
fi
if [ ! -f "$SCREENSHOT_MANIFEST" ]; then
    printf '{\n  "generated_at": "%s",\n  "entries": []\n}\n' "$TIMESTAMP" > "$SCREENSHOT_MANIFEST"
fi

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
if ! run_phase_command "phase5" "Phase 5: Rendering report ..." 35m false "${render_cmd[@]}"; then
    warn "Report rendering did not complete cleanly; keeping the fallback HTML output."
fi

if ! cp "$HTML_REPORT" "$LATEST_HTML"; then
    warn "Unable to update latest HTML shortcut at $LATEST_HTML."
fi

print_phase_summary

echo -e "${GREEN}[*] Report JSON: $RAW_JSON${NC}"
echo -e "${GREEN}[*] Report HTML: $HTML_REPORT${NC}"
