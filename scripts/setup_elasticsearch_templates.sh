#!/bin/bash
# Setup Elasticsearch index templates for macOS telemetry
# This ensures @timestamp is always mapped as a date field

set -e

ES_URL="${ES_URL:-http://localhost:9200}"

echo "========================================="
echo "Setting up Elasticsearch Index Templates"
echo "========================================="
echo ""

# Check if Elasticsearch is running
if ! curl -s "$ES_URL" > /dev/null; then
    echo "❌ Elasticsearch is not running at $ES_URL"
    echo "   Start it with: docker-compose up -d"
    exit 1
fi

echo "✅ Elasticsearch is running"
echo ""

# Function to create/update template
create_template() {
    local template_name=$1
    local index_pattern=$2
    local template_body=$3
    
    echo "Creating/updating template: $template_name"
    
    # Check if template exists
    if curl -s "$ES_URL/_index_template/$template_name" | grep -q "\"$template_name\""; then
        echo "  ⚠️  Template exists, updating..."
    else
        echo "  Creating new template..."
    fi
    
    # Create/update template
    RESPONSE=$(curl -s -X PUT "$ES_URL/_index_template/$template_name" \
        -H 'Content-Type: application/json' \
        -d "$template_body")
    
    if echo "$RESPONSE" | grep -q "\"acknowledged\":true"; then
        echo "  ✅ Template created/updated successfully"
        return 0
    else
        echo "  ❌ Failed to create template"
        echo "     Response: $RESPONSE" | head -5
        return 1
    fi
}

# ESF Template
ESF_TEMPLATE='{
  "index_patterns": ["macos-telemetry-esf-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date",
          "format": "strict_date_optional_time||epoch_millis"
        },
        "sourcetype": {"type": "keyword"},
        "event_type": {"type": "integer"},
        "event_name": {"type": "keyword"},
        "Image": {"type": "keyword"},
        "CommandLine": {"type": "text"},
        "ProcessId": {"type": "long"},
        "ParentProcessId": {"type": "long"},
        "User": {"type": "keyword"},
        "UserId": {"type": "long"},
        "user.name": {"type": "keyword"},
        "user.id": {"type": "long"},
        "TargetFilename": {"type": "keyword"},
        "file.path": {"type": "keyword"}
      }
    },
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    }
  }
}'

# UL Template
UL_TEMPLATE='{
  "index_patterns": ["macos-telemetry-ul-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date",
          "format": "strict_date_optional_time||epoch_millis"
        },
        "sourcetype": {"type": "keyword"},
        "subsystem": {"type": "keyword"},
        "category": {"type": "keyword"},
        "message": {"type": "text"},
        "CommandLine": {"type": "text"},
        "ProcessName": {"type": "keyword"},
        "ProcessId": {"type": "long"},
        "process": {"type": "keyword"},
        "User": {"type": "keyword"},
        "UserId": {"type": "long"},
        "host.name": {"type": "keyword"}
      }
    },
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    }
  }
}'

# Create templates
create_template "macos-telemetry-esf-template" "macos-telemetry-esf-*" "$ESF_TEMPLATE"
ESF_SUCCESS=$?

echo ""

create_template "macos-telemetry-ul-template" "macos-telemetry-ul-*" "$UL_TEMPLATE"
UL_SUCCESS=$?

# Summary
echo ""
echo "========================================="
echo "Summary"
echo "========================================="

if [ $ESF_SUCCESS -eq 0 ]; then
    echo "✅ ESF template: macos-telemetry-esf-template"
else
    echo "❌ ESF template: Failed"
fi

if [ $UL_SUCCESS -eq 0 ]; then
    echo "✅ UL template: macos-telemetry-ul-template"
else
    echo "❌ UL template: Failed"
fi

echo ""
echo "✅ Index templates configured"
echo "   New indices will automatically have correct @timestamp mapping"
echo ""

