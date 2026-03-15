#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
export BIN_DIR="$PROJECT_ROOT/bin"
export CONFIG_DIR="$PROJECT_ROOT/config"
export DOCS_DIR="$PROJECT_ROOT/docs"
export SCRIPTS_DIR="$PROJECT_ROOT/scripts"
export RUNTIME_DIR="$PROJECT_ROOT/runtime"
export LOG_DIR="$RUNTIME_DIR/logs"
export REPORT_DIR="$RUNTIME_DIR/reports"
export OUTPUT_DIR="$RUNTIME_DIR/output"
export SCREENSHOT_DIR="$RUNTIME_DIR/screenshots"
export CACHE_DIR="$RUNTIME_DIR/cache"
export PROMPT_DIR="$PROJECT_ROOT/prompts"

trim_whitespace() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

load_env_file() {
    local env_file="$1"
    local line key value

    [ -f "$env_file" ] || return 0

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in
            ''|[[:space:]]*'#'*) continue ;;
        esac

        line="${line#export }"
        if [[ "$line" != *"="* ]]; then
            continue
        fi

        key="${line%%=*}"
        value="${line#*=}"
        key="$(trim_whitespace "$key")"
        value="$(trim_whitespace "$value")"

        if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            continue
        fi

        if [[ "$value" == \"*\" && "$value" == *\" ]]; then
            value="${value:1:${#value}-2}"
        elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
            value="${value:1:${#value}-2}"
        fi

        printf -v "$key" '%s' "$value"
        export "$key"
    done < "$env_file"
}

parse_yaml() {
    local key="$1"
    local yaml_file="${2:-$CONFIG_DIR/config.yaml}"
    [ -f "$yaml_file" ] || return 0

    awk -v wanted_key="$key" '
        BEGIN { FS=":" }
        $1 ~ "^[[:space:]]*" wanted_key "[[:space:]]*$" {
            value = substr($0, index($0, ":") + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            gsub(/^"/, "", value)
            gsub(/"$/, "", value)
            gsub(/^'\''/, "", value)
            gsub(/'\''$/, "", value)
            print value
            exit
        }
    ' "$yaml_file"
}

config_is_true() {
    local value="${1:-}"
    value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

slugify() {
    local value="${1:-}"
    value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    value="$(printf '%s' "$value" | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//; s/-{2,}/-/g')"
    printf '%s' "$value"
}

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[!] Missing required command: $cmd" >&2
        return 1
    fi
}

find_screenshot_binary() {
    local candidate
    for candidate in chromium chromium-browser google-chrome google-chrome-stable microsoft-edge wkhtmltoimage; do
        if command -v "$candidate" >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

resolve_shodan_key() {
    if [ -n "${SHODANAPI:-}" ]; then
        printf '%s' "$SHODANAPI"
        return 0
    fi

    if [ -f "$HOME/.shodan/api_key" ]; then
        tr -d '\r\n' < "$HOME/.shodan/api_key"
        return 0
    fi

    return 1
}

load_env_file "$PROJECT_ROOT/.env"
mkdir -p "$LOG_DIR" "$REPORT_DIR" "$OUTPUT_DIR" "$SCREENSHOT_DIR" "$CACHE_DIR"
