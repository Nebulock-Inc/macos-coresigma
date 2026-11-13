#!/bin/bash
# Thoroughly wipe all macOS telemetry indices from Elasticsearch
# Usage: wipe_elasticsearch.sh [--yes]   (--yes skips the confirmation prompt)

set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
# Credentials (as scripts/setup_elasticsearch_templates.sh): $ES_API_KEY, else $ES_USER and $ES_PASSWORD, else the
# macOS Keychain entry scripts/setup_credentials.sh stores (service coreSigma-Elasticsearch).
KEYCHAIN_SERVICE="coreSigma-Elasticsearch"
basic_auth() { printf 'Authorization: Basic %s' "$(printf '%s:%s' "$1" "$2" | base64 | tr -d '\n')"; }
if [ -n "${ES_API_KEY:-}" ]; then
    AUTH_HEADER="Authorization: ApiKey $ES_API_KEY"
elif [ -n "${ES_USER:-}" ] && [ -n "${ES_PASSWORD:-}" ]; then
    AUTH_HEADER=$(basic_auth "$ES_USER" "$ES_PASSWORD")
elif KEYCHAIN_PASSWORD=$(security find-generic-password -s "$KEYCHAIN_SERVICE" -a "${ES_USER:-elastic}" -w 2>/dev/null); then
    AUTH_HEADER=$(basic_auth "${ES_USER:-elastic}" "$KEYCHAIN_PASSWORD")
else
    echo "❌ No Elasticsearch credentials: set ES_API_KEY, or ES_USER and ES_PASSWORD, or store them in the Keychain" \
         "with ./scripts/setup_credentials.sh" >&2
    exit 1
fi
# curl with the Authorization header on stdin (-H @-), as setup_credentials.sh does: on curl's command line, -u or -H
# would show the secret to other users in `ps`. (No call here sends a body on stdin.)
es_curl() { printf '%s\n' "$AUTH_HEADER" | curl -H @- "$@"; }

echo "========================================="
echo "Wiping Elasticsearch macOS Telemetry Indices"
echo "========================================="
echo ""

# Check if Elasticsearch is running
if ! es_curl -s "$ES_URL" > /dev/null 2>&1; then
    echo "❌ Error: Elasticsearch is not running at $ES_URL"
    exit 1
fi

echo "📋 Current indices:"
es_curl -s "$ES_URL/_cat/indices/macos-telemetry-*?v" || echo "  (none found)"
echo ""

if [ "${1:-}" != "--yes" ]; then
    read -r -p "Delete every macos-telemetry-* index on $ES_URL? Type yes to continue: " ANSWER || true
    if [ "$ANSWER" != "yes" ]; then
        echo "Aborted: nothing deleted"
        exit 1
    fi
fi

# Method 1: Delete by wildcard pattern
echo "🗑️  Deleting indices with wildcard pattern..."
RESPONSE=$(es_curl -s -w "\n%{http_code}" -X DELETE "$ES_URL/macos-telemetry-*" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
echo "  HTTP Status: $HTTP_CODE"

# Method 2: List and delete each index individually (more reliable)
echo ""
echo "🗑️  Deleting indices individually..."
INDICES=$(es_curl -s "$ES_URL/_cat/indices/macos-telemetry-*?h=index" 2>/dev/null || true)

if [ -z "$INDICES" ]; then
    echo "  ✓ No indices found"
else
    echo "$INDICES" | while read -r index; do
        if [ -n "$index" ]; then
            echo "  Deleting: $index"
            es_curl -s -X DELETE "$ES_URL/$index" > /dev/null 2>&1 || true
        fi
    done
fi

# Wait for deletion to complete
echo ""
echo "⏳ Waiting for deletion to complete..."
sleep 5

# Force refresh
es_curl -s -X POST "$ES_URL/_refresh" > /dev/null 2>&1 || true
sleep 2

# Verify indices are gone
echo ""
echo "🔍 Verifying deletion..."
# grep -c prints 0 and exits 1 when nothing is left: || true keeps that single 0
REMAINING=$(es_curl -s "$ES_URL/_cat/indices/macos-telemetry-*?h=index" 2>/dev/null | grep -c . || true)

if [ "$REMAINING" -eq 0 ]; then
    echo "✅ All indices successfully deleted!"
else
    echo "⚠️  $REMAINING indices still exist:"
    es_curl -s "$ES_URL/_cat/indices/macos-telemetry-*?v" || true
    echo ""
    echo "Attempting force deletion..."
    es_curl -s "$ES_URL/_cat/indices/macos-telemetry-*?h=index" | while read -r index; do
        if [ -n "$index" ]; then
            echo "  Force deleting: $index"
            es_curl -s -X DELETE "$ES_URL/$index?ignore_unavailable=true" > /dev/null 2>&1 || true
        fi
    done
    sleep 3
fi

echo ""
echo "✅ Index wipe complete"
echo ""

