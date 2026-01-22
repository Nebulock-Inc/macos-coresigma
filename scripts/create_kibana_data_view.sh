#!/bin/bash
# Create Kibana Data View (Kibana 8.x uses Data Views, not Index Patterns)

set -euo pipefail

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
ES_USER="${ES_USER:-elastic}"
ES_PASSWORD="${ES_PASSWORD:-changeme}"
AUTH_HEADER="Authorization: Basic $(echo -n ${ES_USER}:${ES_PASSWORD} | base64)"

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
    
    # Check if already exists
    EXISTING=$(curl -s -X GET "$KIBANA_URL/api/data_views/data_view" \
        -H "$AUTH_HEADER" \
        -H 'kbn-xsrf: true' \
        -H 'Content-Type: application/json' 2>/dev/null | \
        python3 -c "import sys, json; 
        data = json.load(sys.stdin) if sys.stdin.read() else {'dataViews': []};
        matches = [dv for dv in data.get('dataViews', []) if dv.get('title') == '$pattern'];
        print('exists' if matches else 'new')" 2>/dev/null || echo "new")
    
    if [ "$EXISTING" = "exists" ]; then
        echo "  ⚠️  Data view already exists"
        return 0
    fi
    
    # Create data view
    RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/data_views/data_view" \
        -H "$AUTH_HEADER" \
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
        curl -s -X POST "$KIBANA_URL/api/kibana/settings" \
            -H "$AUTH_HEADER" \
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

# Create UL data view
create_data_view "macOS Unified Logging" "macos-telemetry-ul-*" "@timestamp"
UL_SUCCESS=$?

# Create ESF data view
create_data_view "macOS ESF Events" "macos-telemetry-esf-*" "@timestamp"
ESF_SUCCESS=$?

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

