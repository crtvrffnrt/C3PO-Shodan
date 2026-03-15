#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

HTML_FILE="${1:-}"
BLOB_NAME="${2:-}"

if [ -z "$HTML_FILE" ] || [ -z "$BLOB_NAME" ]; then
    echo "Usage: $0 <html-file> <blob-name>" >&2
    exit 1
fi

if [ ! -f "$HTML_FILE" ]; then
    echo "[!] HTML file not found: $HTML_FILE" >&2
    exit 1
fi

STORAGE_ACCOUNT_NAME="$(parse_yaml "storage_account_name")"
STORAGE_CONTAINER_NAME="$(parse_yaml "storage_container_name")"
STATIC_WEB_HOST="$(parse_yaml "static_web_host")"
AZURE_UPLOAD_ENABLED="$(parse_yaml "azure_upload_enabled")"

if ! config_is_true "$AZURE_UPLOAD_ENABLED"; then
    echo "[*] Azure upload disabled in config."
    exit 0
fi

DEPLOY_SUCCESS=false

if az storage blob upload \
    --account-name "$STORAGE_ACCOUNT_NAME" \
    --container-name "$STORAGE_CONTAINER_NAME" \
    --file "$HTML_FILE" \
    --name "$BLOB_NAME" \
    --overwrite \
    --content-type "text/html" \
    --auth-mode login >/dev/null 2>&1; then
    DEPLOY_SUCCESS=true
elif [ -n "${OPENCLAW_APP_ID:-}" ] && [ -n "${OPENCLAW_APP_SECRET:-}" ] && [ -n "${OPENCLAW_TENANT_ID:-}" ]; then
    echo "[*] Default Azure login failed. Retrying with service principal..."
    if az login --service-principal \
        --username "$OPENCLAW_APP_ID" \
        --password "$OPENCLAW_APP_SECRET" \
        --tenant "$OPENCLAW_TENANT_ID" >/dev/null 2>&1; then
        if az storage blob upload \
            --account-name "$STORAGE_ACCOUNT_NAME" \
            --container-name "$STORAGE_CONTAINER_NAME" \
            --file "$HTML_FILE" \
            --name "$BLOB_NAME" \
            --overwrite \
            --content-type "text/html" \
            --auth-mode login >/dev/null 2>&1; then
            DEPLOY_SUCCESS=true
        fi
    fi
fi

if [ "$DEPLOY_SUCCESS" = true ]; then
    echo "[*] Live report: https://$STATIC_WEB_HOST/$BLOB_NAME"
else
    echo "[!] Azure upload failed." >&2
    exit 1
fi
