#!/bin/bash
# Create Kibana Data View (Kibana 8.x uses Data Views, not Index Patterns)

set -euo pipefail

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
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
echo "Creating Kibana Data Views"
echo "========================================="
echo ""

# Function to create data view
create_data_view() {
    local title=$1
    local pattern=$2
    local time_field=$3
    
    echo "Creating data view: $title"
    
    # Check if already exists: GET /api/data_views lists them under "data_view"
    EXISTING=$(es_curl -s "$KIBANA_URL/api/data_views" \
        -H 'kbn-xsrf: true' 2>/dev/null | \
        python3 -c 'import json, sys
views = json.load(sys.stdin).get("data_view", [])
print("exists" if any(v.get("title") == sys.argv[1] for v in views) else "new")' "$pattern" 2>/dev/null || echo "new")
    
    if [ "$EXISTING" = "exists" ]; then
        echo "  ⚠️  Data view already exists"
        return 0
    fi
    
    # Create data view
    RESPONSE=$(es_curl -s -X POST "$KIBANA_URL/api/data_views/data_view" \
        -H 'kbn-xsrf: true' \
        -H 'Content-Type: application/json' \
        -d "{
            \"data_view\": {
                \"title\": \"$pattern\",
                \"name\": \"$title\",
                \"timeFieldName\": \"$time_field\"
            }
        }")
    
    if echo "$RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); exit(0 if data.get('data_view', {}).get('id') else 1)" 2>/dev/null; then
        DATA_VIEW_ID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['data_view']['id'])" 2>/dev/null)
        echo "  ✓ Created: $title (ID: $DATA_VIEW_ID)"
        
        # Set as default if first one
        es_curl -s -X POST "$KIBANA_URL/api/kibana/settings" \
            -H 'kbn-xsrf: true' \
            -H 'Content-Type: application/json' \
            -d "{\"changes\": {\"defaultIndex\": \"$DATA_VIEW_ID\"}}" > /dev/null 2>&1 || true
        
        return 0
    else
        echo "  ✗ Failed"
        echo "  Response: $RESPONSE" | head -3
        return 1
    fi
}

# Create UL data view (|| keeps set -e from ending the script before the ESF view and the summary)
UL_SUCCESS=0
create_data_view "macOS Unified Logging" "macos-telemetry-ul-*" "@timestamp" || UL_SUCCESS=1

# Create ESF data view
ESF_SUCCESS=0
create_data_view "macOS ESF Events" "macos-telemetry-esf-*" "@timestamp" || ESF_SUCCESS=1

echo ""
echo "========================================="
echo "Summary"
echo "========================================="

if [ $UL_SUCCESS -eq 0 ] && [ $ESF_SUCCESS -eq 0 ]; then
    echo "✓ Data views created successfully"
    echo ""
    echo "Next steps:"
    echo "  1. Open: http://localhost:5601/app/discover"
    echo "  2. Select data view: 'macOS Unified Logging'"
    echo "  3. Set time range: 'Last 7 days'"
    echo "  4. Click Refresh"
else
    echo "✗ Some data views failed to create"
    exit 1
fi

