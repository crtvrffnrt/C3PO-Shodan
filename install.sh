#!/usr/bin/env bash
set -euo pipefail

# Colors for better UX
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[*] Starting C3PO-shodan environment check...${NC}"

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

# 4. Check for Shodan API Key
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

# 5. Check for Gemini CLI authentication
echo -e "${GREEN}[*] Checking Gemini CLI authentication...${NC}"
if ! gemini -p "ping" -o text >/dev/null 2>&1; then
    echo -e "${RED}[!] Gemini CLI is not authenticated or not installed correctly.${NC}"
    echo -e "${YELLOW}[i] Please run 'gemini login' manually if you haven't yet.${NC}"
    # We don't exit here because the user might have configured it differently, but we warn.
fi

echo -e "${GREEN}[+] Prerequisites check complete.${NC}"
exit 0
