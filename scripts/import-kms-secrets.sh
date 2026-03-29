#!/usr/bin/env bash
# import-kms-secrets.sh — Import cloud API keys into Yashigani KMS after stack startup.
# Keys are prompted securely, written to a temp file (mode 0600), imported, then shredded.
# Usage: scripts/import-kms-secrets.sh [--backoffice-url URL]

set -euo pipefail

BACKOFFICE_URL="${BACKOFFICE_URL:-https://localhost:8443}"
TMPFILE=""
SESSION_TOKEN=""

cleanup() {
    if [ -n "$TMPFILE" ] && [ -f "$TMPFILE" ]; then
        if command -v shred >/dev/null 2>&1; then
            shred -u "$TMPFILE" 2>/dev/null || rm -f "$TMPFILE"
        else
            rm -f "$TMPFILE"
        fi
    fi
    unset ANTHROPIC_KEY AZURE_KEY GEMINI_KEY SESSION_TOKEN
    echo "Secrets cleared from memory and disk."
}
trap cleanup EXIT

echo "=== Cloud API Key Import ==="
echo "Keys will be stored in KMS and never written to .env"
echo "Press Enter to skip any key (configure later in Admin -> KMS)"
echo ""

prompt_secret() {
    local prompt="$1"
    local varname="$2"
    read -rsp "$prompt: " val
    echo ""
    eval "$varname=\"\$val\""
}

prompt_secret "Anthropic API key (claude-haiku-4-5)" ANTHROPIC_KEY
prompt_secret "Azure OpenAI key" AZURE_KEY
prompt_secret "Gemini API key" GEMINI_KEY

# Login to get session token
echo ""
echo "Authenticating with backoffice..."
read -rsp "Admin username: " ADMIN_USER; echo ""
read -rsp "Admin password: " ADMIN_PASS; echo ""

SESSION_TOKEN=$(curl -sf -k \
    -X POST "${BACKOFFICE_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    | jq -r '.session_token // empty')
unset ADMIN_USER ADMIN_PASS

if [ -z "$SESSION_TOKEN" ]; then
    echo "ERROR: Login failed. Check credentials."
    exit 1
fi

import_key() {
    local key_name="$1"
    local key_value="$2"
    if [ -z "$key_value" ]; then
        echo "  Skipping $key_name (not provided)"
        return
    fi
    local result
    result=$(curl -sf -k \
        -X POST "${BACKOFFICE_URL}/admin/kms/secrets" \
        -H "Authorization: Bearer $SESSION_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"key\":\"${key_name}\",\"value\":\"${key_value}\"}" \
        | jq -r '.status // "error"')
    echo "  $key_name: $result"
    unset key_value
}

echo ""
echo "Importing keys..."
import_key "anthropic_api_key" "$ANTHROPIC_KEY"
import_key "azure_openai_key" "$AZURE_KEY"
import_key "gemini_api_key" "$GEMINI_KEY"

echo ""
echo "Import complete. Run cleanup is automatic."
