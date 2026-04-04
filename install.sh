#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for better UX
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[*] Starting C3PO-shodan environment check...${NC}"

resolve_httpx_binary() {
    local candidates=()
    if [ -n "${HTTPX_BIN:-}" ]; then
        candidates+=("$HTTPX_BIN")
    fi
    candidates+=(
        "$HOME/.pdtm/go/bin/httpx"
        "$HOME/go/bin/httpx"
    )
    if command -v httpx >/dev/null 2>&1; then
        candidates+=("$(command -v httpx)")
    fi
    candidates+=(
        "/usr/local/bin/httpx"
        "/usr/bin/httpx"
    )

    local candidate
    for candidate in "${candidates[@]}"; do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# 1. Check for Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[!] Python 3 is not installed. Please install it first.${NC}"
    exit 1
fi

# 2. Check for curl
if ! command -v curl >/dev/null 2>&1; then
    echo -e "${YELLOW}[*] Installing curl...${NC}"
    apt-get update -qq && apt-get install -y curl -qq
fi

# 3. Check for nuclei
if ! command -v nuclei >/dev/null 2>&1; then
    echo -e "${YELLOW}[*] nuclei not found. Attempting to install...${NC}"
    # Simple install for nuclei (binary)
    CURL_CMD="curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep 'browser_download_url' | grep 'linux_amd64' | cut -d '\"' -f 4 | wget -qi -"
    # This is a bit complex for a simple script, better to suggest installation or use a basic apt if available
    # For now, we assume it's installed as per previous environment check, but add a message
    echo -e "${RED}[!] nuclei is missing. Please install it: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'${NC}"
fi

# 4. Check for httpx
if ! HTTPX_PATH="$(resolve_httpx_binary)"; then
    echo -e "${YELLOW}[*] httpx not found. Attempting to install...${NC}"
    echo -e "${RED}[!] httpx is missing. Please install it: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'${NC}"
    echo -e "${YELLOW}[i] Website tech-stack enrichment will be skipped until httpx is available.${NC}"
else
    echo -e "${GREEN}[+] httpx found at ${HTTPX_PATH}${NC}"
fi

# 5. Check for Shodan API Key
SHODAN_KEY_FILE="$HOME/.shodan/api_key"
if [ -z "${SHODANAPI:-}" ] && [ ! -f "$SHODAN_KEY_FILE" ]; then
    echo -e "${YELLOW}[?] Shodan API key not found.${NC}"
    read -p "Please enter your Shodan API key: " USER_SHODAN_KEY
    if [ -n "$USER_SHODAN_KEY" ]; then
        mkdir -p "$(dirname "$SHODAN_KEY_FILE")"
        echo "$USER_SHODAN_KEY" > "$SHODAN_KEY_FILE"
        export SHODANAPI="$USER_SHODAN_KEY"
        echo -e "${GREEN}[+] Shodan API key saved to $SHODAN_KEY_FILE${NC}"
    else
        echo -e "${RED}[!] Shodan API key is required.${NC}"
        exit 1
    fi
fi

# 6. Check for Cloudflare API Credentials (Optional)
echo -e "${GREEN}[*] Checking for Cloudflare API credentials...${NC}"
CF_ENV_FILE="$PROJECT_ROOT/.env"
if [ -z "${CF_ACCOUNT_ID:-}" ] || [ -z "${CF_API_TOKEN:-}" ]; then
    if [ -f "$CF_ENV_FILE" ]; then
        source "$CF_ENV_FILE" || true
    fi
fi

if [ -z "${CF_ACCOUNT_ID:-}" ] || { [ -z "${CF_API_TOKEN:-}" ] && { [ -z "${CF_API_KEY:-}" ] || [ -z "${CF_EMAIL:-}" ]; }; }; then
    echo -e "${YELLOW}[!] Cloudflare credentials missing in environment and .env file.${NC}"
    echo -e "${YELLOW}[i] To enable high-fidelity screenshots and URL scanning, add the following to your .env file:${NC}"
    echo -e "    CF_ACCOUNT_ID=your_account_id"
    echo -e "    CF_API_TOKEN=your_api_token"
    echo -e "    or"
    echo -e "    CF_EMAIL=your_cloudflare_email"
    echo -e "    CF_API_KEY=your_global_api_key"
    echo -e "${YELLOW}[i] Refer to the documentation for instructions on obtaining these.${NC}"
    echo -e "${YELLOW}[i] Falling back to local screenshot tools (chromium/wkhtmltoimage).${NC}"
else
    echo -e "${GREEN}[+] Cloudflare credentials found. Cloudflare URL Scanner will be used as the primary screenshot source.${NC}"
fi

# 7. Check for Gemini CLI authentication
echo -e "${GREEN}[*] Checking Gemini CLI authentication...${NC}"
if ! gemini -p "ping" -o text >/dev/null 2>&1; then
    echo -e "${RED}[!] Gemini CLI is not authenticated or not installed correctly.${NC}"
    echo -e "${YELLOW}[i] Please run 'gemini login' manually if you haven't yet.${NC}"
    # We don't exit here because the user might have configured it differently, but we warn.
fi

echo -e "${GREEN}[+] Prerequisites check complete.${NC}"
exit 0
