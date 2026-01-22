#!/bin/bash
# Quick Elasticsearch Query Helper Script

ES_URL="${ES_URL:-http://localhost:9200}"

echo "Elasticsearch Query Helper"
echo "=========================="
echo ""

# Function to show help
show_help() {
    cat << EOF
Usage: $0 [command] [options]

Commands:
  status       - Show cluster status
  indices      - List all indices
  search       - Search events (requires query)
  test-event   - Find test event (ProcessId: 12345)
  recent       - Show recent events
  stats        - Show event statistics

Examples:
  $0 status
  $0 indices
  $0 search 'event_name:exec'
  $0 recent
  $0 stats

Environment:
  ES_URL - Elasticsearch URL (default: http://localhost:9200)
EOF
}

# Status check
if [ "$1" = "status" ] || [ "$1" = "" ]; then
    echo "Cluster Status:"
    curl -s "$ES_URL" | python3 -m json.tool 2>/dev/null | grep -E "(cluster_name|version)" | head -5
    echo ""
fi

# List indices
if [ "$1" = "indices" ] || [ "$1" = "" ]; then
    echo "Indices:"
    curl -s "$ES_URL/_cat/indices?v" | grep macos-telemetry
    echo ""
fi

# Search
if [ "$1" = "search" ]; then
    QUERY="${2:-match_all}"
    echo "Searching for: $QUERY"
    echo ""
    if [ "$QUERY" = "match_all" ]; then
        curl -s -X GET "$ES_URL/macos-telemetry-esf-*/_search?pretty" \
            -H 'Content-Type: application/json' \
            -d '{
              "size": 5,
              "query": {"match_all": {}},
              "sort": [{"@timestamp": {"order": "desc"}}]
            }'
    else
        curl -s -X GET "$ES_URL/macos-telemetry-esf-*/_search?pretty" \
            -H 'Content-Type: application/json' \
            -d "{
              \"size\": 10,
              \"query\": {
                \"query_string\": {
                  \"query\": \"$QUERY\"
                }
              },
              \"sort\": [{\"@timestamp\": {\"order\": \"desc\"}}]
            }"
    fi
    echo ""
fi

# Test event
if [ "$1" = "test-event" ]; then
    echo "Searching for test event (ProcessId: 12345)..."
    curl -s -X GET "$ES_URL/macos-telemetry-esf-*/_search?pretty" \
        -H 'Content-Type: application/json' \
        -d '{
          "query": {"term": {"ProcessId": 12345}},
          "size": 1
        }'
    echo ""
fi

# Recent events
if [ "$1" = "recent" ]; then
    echo "Recent events:"
    curl -s -X GET "$ES_URL/macos-telemetry-esf-*/_search?pretty" \
        -H 'Content-Type: application/json' \
        -d '{
          "size": 10,
          "query": {"match_all": {}},
          "sort": [{"@timestamp": {"order": "desc"}}],
          "_source": ["@timestamp", "event_name", "Image", "CommandLine", "ProcessId"]
        }' | grep -A 5 "_source"
    echo ""
fi

# Statistics
if [ "$1" = "stats" ]; then
    echo "Event Statistics:"
    curl -s -X GET "$ES_URL/macos-telemetry-esf-*/_search?pretty" \
        -H 'Content-Type: application/json' \
        -d '{
          "size": 0,
          "aggs": {
            "event_types": {
              "terms": {
                "field": "event_name.keyword",
                "size": 10
              }
            }
          }
        }' | grep -A 2 "key\|doc_count"
    echo ""
fi

# Help
if [ "$1" = "help" ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help
fi

