#!/usr/bin/env bash

# Cloudflare URL Scanner Integration for C3PO-shodan
# Primary source for high-fidelity screenshots and security intelligence.

set -euo pipefail

# Prioritize environment variables from the project environment
CF_ACCOUNT_ID="${CF_ACCOUNT_ID:-}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
DEBUG=false
DOMAIN=""
OUTPUT_DIR="."
QUIET=false

# Dependencies check
for cmd in curl jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[!] Error: $cmd is not installed." >&2
        exit 1
    fi
done

usage() {
    echo "Usage: $0 -d <domain/url> [-o <output_dir>] [-v] [-q]"
    echo "  -d: Domain or URL to scan"
    echo "  -o: Output directory for screenshots and JSON data"
    echo "  -v: Enable debug/verbose mode"
    echo "  -q: Quiet mode (only errors and final results)"
    exit 1
}

# Parse arguments
while getopts ":d:o:vq" opt; do
  case $opt in
    d) DOMAIN="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    v) DEBUG=true ;;
    q) QUIET=true ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
  esac
done

if [ -z "$DOMAIN" ]; then
    usage
fi

if [ -z "$CF_ACCOUNT_ID" ] || [ -z "$CF_API_TOKEN" ]; then
    echo "[!] Cloudflare API credentials (CF_ACCOUNT_ID, CF_API_TOKEN) are missing." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Ensure URL has protocol
if [[ ! "$DOMAIN" =~ ^https?:// ]]; then
    URL="https://$DOMAIN"
else
    URL="$DOMAIN"
fi

[ "$DEBUG" = true ] && echo "[DEBUG] Target URL: $URL"
[ "$DEBUG" = true ] && echo "[DEBUG] Using Account ID: $CF_ACCOUNT_ID"

if [ "$QUIET" = false ]; then
    echo "[*] Initiating scan for $URL..."
fi

# Submit scan
SCAN_RESPONSE=$(curl -sS -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/urlscanner/v2/scan" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "{\"url\":\"${URL}\",\"visibility\":\"unlisted\"}")

if [ "$DEBUG" = true ]; then
    echo "[DEBUG] Submit Response:"
    echo "$SCAN_RESPONSE" | jq .
fi

# Rate limit check
HTTP_STATUS=$(echo "${SCAN_RESPONSE}" | jq -r '.status // empty')
ERR_CODE=$(echo "${SCAN_RESPONSE}" | jq -r '.result.errors[0].code // empty')

if [ "$HTTP_STATUS" == "429" ] || [ "$ERR_CODE" == "1015" ]; then
    echo "[!] Cloudflare API Rate Limit Reached (429/1015)." >&2
    exit 42
fi

# Extract UUID
SCAN_ID=$(echo "${SCAN_RESPONSE}" | jq -r '.uuid // .result.tasks[0].uuid // empty')

if [ -z "$SCAN_ID" ] || [ "$SCAN_ID" == "null" ]; then
    echo "[!] Failed to initiate scan for $URL:" >&2
    echo "${SCAN_RESPONSE}" | jq . >&2
    exit 1
fi

if [ "$QUIET" = false ]; then
    echo "[+] Scan ID: ${SCAN_ID}"
    echo "[*] Waiting for results to be ready..."
fi

# Wait loop (Optimized polling)
MAX_RETRIES=60
RETRY_COUNT=0
STATUS="queued"
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    STATUS_RESPONSE=$(curl -sS "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/urlscanner/v2/result/${SCAN_ID}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}")
    
    # Extract status
    STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.task.status // .status // empty')
    
    if [ "$DEBUG" = true ]; then
        echo -e "\n[DEBUG] Status Check (Retry $RETRY_COUNT): $STATUS"
    fi

    if [ "$STATUS" == "finished" ]; then
        if [ "$QUIET" = false ]; then
            echo " [+] Scan finished!"
        fi
        FULL_RESULT="$STATUS_RESPONSE"
        break
    fi
    
    if [ "$QUIET" = false ]; then
        echo -n "."
    fi
    sleep 5
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "\n[!] Timeout waiting for scan to finish for $URL." >&2
    exit 1
fi

# --- Intelligence Extraction ---
# Extract hostname from URL for cleaner filenames
CLEAN_DOMAIN=$(echo "$DOMAIN" | awk -F/ '{print $NF}' | sed -E 's/[^a-zA-Z0-9]+/_/g')
INFO_FILE="$OUTPUT_DIR/cloudflare_${CLEAN_DOMAIN}.json"

if [ "$QUIET" = false ]; then
    echo "[*] Extracting Attack Surface Intelligence..."
fi

# JQ filter for relevant security items, with C3PO naming convention
echo "$FULL_RESULT" | jq -r '{
  "target": .page.url,
  "ip": .page.ip,
  "asn": .page.asnname,
  "country": .page.country,
  "server": (.page.server // "N/A"),
  "status_code": .page.status,
  "security_state": .stats.tlsStats[0].securityState,
  "tls_protocol": (.stats.tlsStats[0].protocols | keys | .[0] // "N/A"),
  "secure_percentage": .stats.securePercentage,
  "tech_stack": (.meta.processors.wappa.data // [] | map(.app) | unique),
  "scan_id": "'"${SCAN_ID}"'",
  "generated_at": (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
}' > "$INFO_FILE"

if [ "$QUIET" = false ]; then
    echo "[+] Security Intelligence saved to: $INFO_FILE"
fi

# --- Download Screenshot ---
OUTPUT_FILE="$OUTPUT_DIR/${CLEAN_DOMAIN}.png"
if [ "$QUIET" = false ]; then
    echo "[*] Downloading screenshot to $OUTPUT_FILE..."
fi

curl -sS "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/urlscanner/v2/screenshots/${SCAN_ID}.png" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  --output "${OUTPUT_FILE}"

# Reliability Check
if [ -s "${OUTPUT_FILE}" ]; then
    FIRST_BYTE=$(head -c 1 "${OUTPUT_FILE}")
    if [ "$FIRST_BYTE" == "{" ]; then
        echo "[!] Screenshot download failed for $URL (server error)." >&2
        rm -f "${OUTPUT_FILE}"
        exit 1
    else
        if [ "$QUIET" = false ]; then
            echo "[+] Screenshot saved successfully: ${OUTPUT_FILE}"
        fi
    fi
else
    echo "[!] Failed to download valid screenshot for $URL." >&2
    exit 1
fi

exit 0
