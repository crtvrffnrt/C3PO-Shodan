#!/usr/bin/env bash

# Cloudflare URL Scanner Integration for C3PO-shodan
# Primary source for high-fidelity screenshots and security intelligence.

set -euo pipefail

# Prioritize environment variables from the project environment
CF_ACCOUNT_ID="${CF_ACCOUNT_ID:-}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_API_KEY="${CF_API_KEY:-}"
CF_EMAIL="${CF_EMAIL:-}"
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

AUTH_MODE=""
if [ -n "$CF_ACCOUNT_ID" ] && [ -n "$CF_API_TOKEN" ]; then
    AUTH_MODE="bearer"
elif [ -n "$CF_ACCOUNT_ID" ] && [ -n "$CF_API_KEY" ] && [ -n "$CF_EMAIL" ]; then
    AUTH_MODE="legacy"
else
    echo "[!] Cloudflare API credentials are missing." >&2
    echo "[!] Set CF_ACCOUNT_ID plus CF_API_TOKEN, or CF_ACCOUNT_ID plus CF_API_KEY and CF_EMAIL." >&2
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
[ "$DEBUG" = true ] && echo "[DEBUG] Auth mode: $AUTH_MODE"

if [ "$QUIET" = false ]; then
    echo "[*] Initiating scan for $URL..."
fi

tmp_body="$(mktemp)"
tmp_meta="$(mktemp)"
trap 'rm -f "$tmp_body" "$tmp_meta"' EXIT

curl_args=(
  -sS -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/urlscanner/v2/scan"
  -H "Content-Type: application/json"
  --data "{\"url\":\"${URL}\",\"visibility\":\"unlisted\"}"
  -o "$tmp_body"
  -w "%{http_code}"
)
if [ "$AUTH_MODE" = "bearer" ]; then
    curl_args+=(-H "Authorization: Bearer ${CF_API_TOKEN}")
else
    curl_args+=(-H "X-Auth-Email: ${CF_EMAIL}" -H "X-Auth-Key: ${CF_API_KEY}")
fi

# Submit scan
HTTP_CODE=$(curl "${curl_args[@]}" || true)
SCAN_RESPONSE="$(cat "$tmp_body")"

if [ "$DEBUG" = true ]; then
    echo "[DEBUG] Submit Response:"
    echo "$SCAN_RESPONSE" | jq .
fi

HTTP_STATUS="$HTTP_CODE"
ERR_CODE=$(echo "${SCAN_RESPONSE}" | jq -r '.errors[0].code // .result.errors[0].code // empty' 2>/dev/null || true)
ERR_MESSAGE=$(echo "${SCAN_RESPONSE}" | jq -r '.errors[0].message // .result.errors[0].message // empty' 2>/dev/null || true)
ERR_HINT="${ERR_MESSAGE,,}"

if [[ "$HTTP_STATUS" =~ ^2 ]] && ! echo "$SCAN_RESPONSE" | jq -e '.success == true' >/dev/null 2>&1; then
    ERR_MESSAGE="${ERR_MESSAGE:-Cloudflare returned a non-success response}"
fi

if [ "$HTTP_STATUS" = "401" ] || [ "$HTTP_STATUS" = "403" ] || [[ "$ERR_HINT" == *"authentication"* ]] || [[ "$ERR_HINT" == *"unauthorized"* ]] || [[ "$ERR_HINT" == *"forbidden"* ]] || [[ "$ERR_HINT" == *"invalid api token"* ]]; then
    echo "[!] Cloudflare authentication failed for $URL (status=${HTTP_STATUS:-n/a}, code=${ERR_CODE:-n/a})." >&2
    echo "[!] Check CF_ACCOUNT_ID and either CF_API_TOKEN or CF_API_KEY/CF_EMAIL." >&2
    exit 43
fi

if [ "$HTTP_STATUS" == "429" ] || [ "$ERR_CODE" == "1015" ] || [[ "${ERR_MESSAGE,,}" == *"rate limit"* ]]; then
    echo "[!] Cloudflare API rate limit reached for $URL (status=${HTTP_STATUS:-n/a}, code=${ERR_CODE:-n/a})." >&2
    echo "[*] Falling back to local screenshot tooling for this target." >&2
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
    if [ "$AUTH_MODE" = "bearer" ]; then
        STATUS_RESPONSE=$(curl -sS "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/urlscanner/v2/result/${SCAN_ID}" \
          -H "Authorization: Bearer ${CF_API_TOKEN}")
    else
        STATUS_RESPONSE=$(curl -sS "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/urlscanner/v2/result/${SCAN_ID}" \
          -H "X-Auth-Email: ${CF_EMAIL}" -H "X-Auth-Key: ${CF_API_KEY}")
    fi
    
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

if [ "$AUTH_MODE" = "bearer" ]; then
    curl -sS "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/urlscanner/v2/screenshots/${SCAN_ID}.png" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      --output "${OUTPUT_FILE}"
else
    curl -sS "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/urlscanner/v2/screenshots/${SCAN_ID}.png" \
      -H "X-Auth-Email: ${CF_EMAIL}" -H "X-Auth-Key: ${CF_API_KEY}" \
      --output "${OUTPUT_FILE}"
fi

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
            echo "[+] Cloudflare screenshot captured for $URL"
        fi
    fi
else
    echo "[!] Failed to download valid screenshot for $URL." >&2
    exit 1
fi

exit 0
