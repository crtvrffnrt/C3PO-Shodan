#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TARGET_DOMAIN="${1:-}"

FILES_TO_CHECK=(
    "$CONFIG_DIR/config.yaml"
    "$CONFIG_DIR/provider-fragments.txt"
    "$DOCS_DIR/index-ref.html"
    "$DOCS_DIR/style.md"
    "$SCRIPTS_DIR/collect-attack-surface.py"
    "$SCRIPTS_DIR/capture-screenshots.py"
    "$SCRIPTS_DIR/render-report.py"
)

for file in "${FILES_TO_CHECK[@]}"; do
    if [ ! -f "$file" ]; then
        echo "[!] Missing required file: $file" >&2
        exit 1
    fi
done

require_command python3
require_command curl

if ! resolve_shodan_key >/dev/null 2>&1; then
    echo "[!] Missing Shodan API key. Set SHODANAPI or ~/.shodan/api_key." >&2
    exit 1
fi

SCREENSHOT_ENABLED="$(parse_yaml "screenshot_enabled")"
if config_is_true "$SCREENSHOT_ENABLED"; then
    if ! find_screenshot_binary >/dev/null 2>&1; then
        echo "[*] Screenshot capture tools not found. HTML generation will continue without screenshots." >&2
    fi
fi

if [ -n "$TARGET_DOMAIN" ] && [[ ! "$TARGET_DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "[!] Invalid target domain: $TARGET_DOMAIN" >&2
    exit 1
fi

echo "[*] Validation successful."
