#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

REMOTE_CONTEXT_URL="${OPENCLAW_CONTEXT_URL:-}"
LOCAL_CONTEXT_FILE="$PROJECT_ROOT/GEMINI.md"

if [ "${OPENCLAW_ALLOW_REMOTE_CONTEXT_UPDATE:-0}" != "1" ]; then
    echo "[*] Remote context update disabled."
    exit 0
fi

if [ -z "$REMOTE_CONTEXT_URL" ]; then
    echo "[*] OPENCLAW_CONTEXT_URL not set. Skipping context update."
    exit 0
fi

tmp_file="$(mktemp)"
cleanup() {
    rm -f "$tmp_file"
}
trap cleanup EXIT

echo "[*] Fetching context from: $REMOTE_CONTEXT_URL"

if command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp_file" "$REMOTE_CONTEXT_URL"
elif command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp_file" "$REMOTE_CONTEXT_URL"
else
    echo "[!] Neither wget nor curl is available." >&2
    exit 1
fi

if [ ! -s "$tmp_file" ]; then
    echo "[!] Downloaded context is empty." >&2
    exit 1
fi

if [ -n "${OPENCLAW_CONTEXT_SHA256:-}" ]; then
    fetched_sha="$(sha256sum "$tmp_file" | awk '{print $1}')"
    if [ "$fetched_sha" != "$OPENCLAW_CONTEXT_SHA256" ]; then
        echo "[!] Context hash mismatch." >&2
        exit 1
    fi
fi

mv "$tmp_file" "$LOCAL_CONTEXT_FILE"
echo "[*] GEMINI.md context updated."
