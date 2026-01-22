#!/bin/bash
# Configure Kibana Index Patterns for ESF and UL data

set -euo pipefail

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"

echo "========================================="
echo "Configuring Kibana Index Patterns"
echo "========================================="
echo ""

# Wait for Kibana to be ready
echo "Waiting for Kibana to be ready..."
MAX_ATTEMPTS=30
ATTEMPT=0
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    if curl -s -f "$KIBANA_URL/api/status" > /dev/null 2>&1; then
        echo "✓ Kibana is ready"
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    echo -n "."
    sleep 2
done
echo ""

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    echo "❌ Error: Kibana is not responding at $KIBANA_URL"
    echo "   Make sure Kibana is running: docker ps | grep kibana"
    exit 1
fi

# Function to create index pattern
create_index_pattern() {
    local pattern=$1
    local title=$2
    local time_field=$3
    
    echo "Creating index pattern: $pattern"
    
    # Check if pattern already exists
    EXISTING=$(curl -s -X GET "$KIBANA_URL/api/saved_objects/_find?type=index-pattern&search_fields=title&search=$pattern" \
        -H 'kbn-xsrf: true' \
        -H 'Content-Type: application/json' 2>/dev/null)
    
    if echo "$EXISTING" | grep -q "\"total\":1"; then
        echo "  ⚠️  Index pattern already exists"
        return 0
    fi
    
    # Create index pattern
    RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/index-pattern" \
        -H 'kbn-xsrf: true' \
        -H 'Content-Type: application/json' \
        -d "{
            \"attributes\": {
                \"title\": \"$pattern\",
                \"timeFieldName\": \"$time_field\"
            }
        }")
    
    if echo "$RESPONSE" | grep -q "\"id\""; then
        echo "  ✓ Created successfully"
        PATTERN_ID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
        if [ -n "$PATTERN_ID" ]; then
            echo "     Pattern ID: $PATTERN_ID"
        fi
        return 0
    else
        echo "  ✗ Failed to create"
        echo "     Response: $RESPONSE" | head -3
        return 1
    fi
}

# Create ESF index pattern
echo ""
echo "Setting up ESF index pattern..."
create_index_pattern "macos-telemetry-esf-*" "macOS ESF Events" "@timestamp"
ESF_SUCCESS=$?

# Create UL index pattern
echo ""
echo "Setting up UL index pattern..."
create_index_pattern "macos-telemetry-ul-*" "macOS Unified Logging" "@timestamp"
UL_SUCCESS=$?

# Summary
echo ""
echo "========================================="
echo "Configuration Summary"
echo "========================================="

if [ $ESF_SUCCESS -eq 0 ]; then
    echo "✓ ESF index pattern: macos-telemetry-esf-*"
else
    echo "✗ ESF index pattern: Failed"
fi

if [ $UL_SUCCESS -eq 0 ]; then
    echo "✓ UL index pattern: macos-telemetry-ul-*"
else
    echo "✗ UL index pattern: Failed"
fi

echo ""
echo "Access Kibana:"
echo "  1. Open: http://localhost:5601"
echo "  2. Go to: Discover (left sidebar)"
echo "  3. Select index pattern from dropdown:"
echo "     - macOS ESF Events"
echo "     - macOS Unified Logging"
echo "  4. Explore your data!"
echo ""

if [ $ESF_SUCCESS -eq 0 ] && [ $UL_SUCCESS -eq 0 ]; then
    echo "✓ Both index patterns configured successfully!"
    exit 0
else
    echo "⚠️  Some patterns failed to create. Check Kibana UI for manual setup."
    exit 1
fi

