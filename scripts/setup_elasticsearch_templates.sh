#!/bin/bash
# Setup Elasticsearch/OpenSearch index templates for macOS telemetry.
# Field types match the collectors' ECS documents: path and command-line fields are
# `wildcard` (no 256-char .keyword limit), identifiers `keyword`, @timestamp a date.
# Every taxonomy field the collectors emit is mapped, even before a document has it: an EQL query
# (deploy_sigma_rules.py) on an unmapped field fails ("Unknown column") instead of matching nothing.
# Env: ES_URL, then ES_API_KEY or ES_USER+ES_PASSWORD (else macOS Keychain).

set -e

ES_URL="${ES_URL:-http://localhost:9200}"
KEYCHAIN_SERVICE="coreSigma-Elasticsearch"

# Get credentials (priority: env vars > keychain)
get_credentials() {
    # Check environment variables first
    if [ -n "$ES_API_KEY" ]; then
        echo "api_key"
        return
    fi
    
    if [ -n "$ES_USER" ] && [ -n "$ES_PASSWORD" ]; then
        echo "env"
        return
    fi
    
    # Try macOS Keychain
    if command -v security &> /dev/null; then
        if security find-generic-password -s "$KEYCHAIN_SERVICE" -a "elastic" -w &>/dev/null; then
            echo "keychain"
            return
        fi
    fi
    
    echo "none"
}

# Build curl auth options based on credential source (an array, so values are never word-split)
AUTH_SOURCE=$(get_credentials)
case "$AUTH_SOURCE" in
    api_key)
        CURL_AUTH=(-H "Authorization: ApiKey $ES_API_KEY")
        echo "Using API key authentication"
        ;;
    env)
        CURL_AUTH=(-u "$ES_USER:$ES_PASSWORD")
        echo "Using environment variable credentials"
        ;;
    keychain)
        KEYCHAIN_PASSWORD=$(security find-generic-password -s "$KEYCHAIN_SERVICE" -a "elastic" -w 2>/dev/null)
        CURL_AUTH=(-u "elastic:$KEYCHAIN_PASSWORD")
        echo "Using macOS Keychain credentials"
        ;;
    none)
        CURL_AUTH=()
        echo "⚠️  No credentials found - trying without authentication"
        echo "   Set up credentials with: ./scripts/setup_credentials.sh"
        ;;
esac

echo "========================================="
echo "Setting up Elasticsearch Index Templates"
echo "========================================="
echo ""

# Check if Elasticsearch is running
if ! ROOT_INFO=$(curl -sf "${CURL_AUTH[@]}" "$ES_URL"); then
    echo "❌ Elasticsearch is not running at $ES_URL or authentication failed"
    echo "   Start it with: docker-compose up -d"
    echo "   Or provide credentials: ES_USER=elastic ES_PASSWORD=<ELASTIC_PASSWORD from .env> $0"
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
    if curl -s "${CURL_AUTH[@]}" "$ES_URL/_index_template/$template_name" | grep -q "\"$template_name\""; then
        echo "  ⚠️  Template exists, updating..."
    else
        echo "  Creating new template..."
    fi
    
    # Create/update template
    RESPONSE=$(curl -s "${CURL_AUTH[@]}" -X PUT "$ES_URL/_index_template/$template_name" \
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
        "event.action": {"type": "keyword"},
        "event.category": {"type": "keyword"},
        "event.type": {"type": "keyword"},
        "host.name": {"type": "keyword"},
        "process.code_signature.signing_id": {"type": "keyword"},
        "process.code_signature.team_id": {"type": "keyword"},
        "file.Ext.extattr": {"type": "keyword"},
        "signal.number": {"type": "long"},
        "memory.protection": {"type": "long"},
        "xpc.service_name": {"type": "keyword"},
        "tcc.service": {"type": "keyword"},
        "tcc.identity": {"type": "keyword"},
        "tcc.right": {"type": "keyword"},
        "tcc.reason": {"type": "keyword"},
        "btm.item.url": {"type": "wildcard"},
        "btm.item.type": {"type": "long"},
        "kext.identifier": {"type": "keyword"},
        "process.command_line": {"type": "wildcard"},
        "process.executable": {"type": "wildcard"},
        "process.parent.executable": {"type": "wildcard"},
        "file.path": {"type": "wildcard"},
        "file.Ext.original.path": {"type": "wildcard"},
        "file.directory": {"type": "wildcard"},
        "Target.process.executable": {"type": "wildcard"},
        "btm.executable_path": {"type": "wildcard"},
        "process.pid": {"type": "keyword"},
        "process.parent.pid": {"type": "keyword"},
        "user.id": {"type": "keyword"},
        "user.target.id": {"type": "keyword"},
        "user.target.group.id": {"type": "keyword"},
        "user.name": {"type": "keyword"},
        "user.target.name": {"type": "keyword"},
        "user.target.group.name": {"type": "keyword"},
        "source.user.name": {"type": "keyword"},
        "source.address": {"type": "keyword"},
        "event.outcome": {"type": "keyword"},
        "event.reason": {"type": "wildcard"},
        "authentication.type": {"type": "long"},
        "screensharing.viewer_appleid": {"type": "keyword"},
        "screensharing.existing_session": {"type": "boolean"},
        "profile.identifier": {"type": "keyword"},
        "profile.display_name": {"type": "keyword"},
        "profile.install_source": {"type": "long"},
        "profile.scope": {"type": "keyword"},
        "od.attribute_name": {"type": "keyword"},
        "od.attribute_value": {"type": "wildcard"},
        "xprotect.malware_identifier": {"type": "keyword"},
        "xprotect.incident_identifier": {"type": "keyword"},
        "xprotect.action_type": {"type": "keyword"},
        "file.hash.sha256": {"type": "keyword"},
        "file.code_signature.signing_id": {"type": "keyword"},
        "file.code_signature.team_id": {"type": "keyword"}
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
        "message": {"type": "wildcard"},
        "process.executable": {"type": "wildcard"},
        "unified_log.subsystem": {"type": "keyword"},
        "unified_log.category": {"type": "keyword"},
        "unified_log.sender_image_path": {"type": "keyword"},
        "log.level": {"type": "keyword"},
        "process.pid": {"type": "keyword"},
        "user.id": {"type": "keyword"},
        "host.name": {"type": "keyword"}
      }
    },
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    }
  }
}'

# OpenSearch (2.19) finds nothing for a leading-wildcard query_string (*x, the Lucene backend's contains and
# endswith) on a `wildcard` field. There the same fields are `keyword` with a lowercase normalizer instead:
# matching is case-insensitive as in Sigma, also for |re (case-sensitive in Sigma), and values over 8191
# characters are stored but not indexed (Lucene's 32 KB term limit).
if echo "$ROOT_INFO" | grep -q '"distribution" *: *"opensearch"'; then
    echo "OpenSearch: wildcard fields become lowercase-normalized keyword"
    WILDCARD='{"type": "wildcard"}'
    KEYWORD='{"type": "keyword", "normalizer": "lowercase", "ignore_above": 8191}'
    SETTINGS='"settings": {'
    NORMALIZER='"settings": {"analysis": {"normalizer": {"lowercase": {"type": "custom", "filter": ["lowercase"]}}},'
    ESF_TEMPLATE=${ESF_TEMPLATE//"$WILDCARD"/$KEYWORD}
    ESF_TEMPLATE=${ESF_TEMPLATE/"$SETTINGS"/$NORMALIZER}
    UL_TEMPLATE=${UL_TEMPLATE//"$WILDCARD"/$KEYWORD}
    UL_TEMPLATE=${UL_TEMPLATE/"$SETTINGS"/$NORMALIZER}
fi

# Create templates; "|| ..." keeps set -e from aborting before the summary
ESF_SUCCESS=0
create_template "macos-telemetry-esf-template" "macos-telemetry-esf-*" "$ESF_TEMPLATE" || ESF_SUCCESS=1

echo ""

UL_SUCCESS=0
create_template "macos-telemetry-ul-template" "macos-telemetry-ul-*" "$UL_TEMPLATE" || UL_SUCCESS=1

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
if [ $ESF_SUCCESS -ne 0 ] || [ $UL_SUCCESS -ne 0 ]; then
    exit 1
fi
echo "✅ Index templates configured"
echo "   New indices will use these mappings"
echo ""

