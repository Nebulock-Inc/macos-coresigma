#!/bin/bash
# Thoroughly wipe all macOS telemetry indices from Elasticsearch

set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASSWORD="${ES_PASSWORD:-changeme}"
CURL_AUTH="-u $ES_USER:$ES_PASSWORD"

echo "========================================="
echo "Wiping Elasticsearch macOS Telemetry Indices"
echo "========================================="
echo ""

# Check if Elasticsearch is running
if ! curl -s $CURL_AUTH "$ES_URL" > /dev/null 2>&1; then
    echo "❌ Error: Elasticsearch is not running at $ES_URL"
    exit 1
fi

echo "📋 Current indices:"
curl -s $CURL_AUTH "$ES_URL/_cat/indices/macos-telemetry-*?v" || echo "  (none found)"
echo ""

# Method 1: Delete by wildcard pattern
echo "🗑️  Deleting indices with wildcard pattern..."
RESPONSE=$(curl -s $CURL_AUTH -w "\n%{http_code}" -X DELETE "$ES_URL/macos-telemetry-*" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
echo "  HTTP Status: $HTTP_CODE"

# Method 2: List and delete each index individually (more reliable)
echo ""
echo "🗑️  Deleting indices individually..."
INDICES=$(curl -s $CURL_AUTH "$ES_URL/_cat/indices/macos-telemetry-*?h=index" 2>/dev/null || true)

if [ -z "$INDICES" ]; then
    echo "  ✓ No indices found"
else
    echo "$INDICES" | while read -r index; do
        if [ -n "$index" ]; then
            echo "  Deleting: $index"
            curl -s $CURL_AUTH -X DELETE "$ES_URL/$index" > /dev/null 2>&1 || true
        fi
    done
fi

# Wait for deletion to complete
echo ""
echo "⏳ Waiting for deletion to complete..."
sleep 5

# Force refresh
curl -s $CURL_AUTH -X POST "$ES_URL/_refresh" > /dev/null 2>&1 || true
sleep 2

# Verify indices are gone
echo ""
echo "🔍 Verifying deletion..."
REMAINING=$(curl -s $CURL_AUTH "$ES_URL/_cat/indices/macos-telemetry-*?h=index" 2>/dev/null | grep -v "^$" | wc -l | tr -d ' ' || echo "0")

if [ "$REMAINING" -eq 0 ]; then
    echo "✅ All indices successfully deleted!"
else
    echo "⚠️  $REMAINING indices still exist:"
    curl -s $CURL_AUTH "$ES_URL/_cat/indices/macos-telemetry-*?v" || true
    echo ""
    echo "Attempting force deletion..."
    curl -s $CURL_AUTH "$ES_URL/_cat/indices/macos-telemetry-*?h=index" | while read -r index; do
        if [ -n "$index" ]; then
            echo "  Force deleting: $index"
            curl -s $CURL_AUTH -X DELETE "$ES_URL/$index?ignore_unavailable=true" > /dev/null 2>&1 || true
        fi
    done
    sleep 3
fi

echo ""
echo "✅ Index wipe complete"
echo ""

