#!/bin/bash
# Start Kibana for Elasticsearch visualization

set -euo pipefail

echo "========================================="
echo "Starting Kibana for macOS Sigma Pipelines"
echo "========================================="
echo ""

# Check if Elasticsearch is running
if ! curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo "❌ Error: Elasticsearch is not running"
    echo "   Start it first with:"
    echo "   docker run -d -p 9200:9200 -e 'discovery.type=single-node' -e 'xpack.security.enabled=false' docker.elastic.co/elasticsearch/elasticsearch:8.11.0"
    exit 1
fi

echo "✓ Elasticsearch is running"
echo ""

# Check if Kibana is already running
if docker ps --format '{{.Names}}' | grep -q "^kibana$"; then
    echo "⚠️  Kibana is already running"
    echo "   Access it at: http://localhost:5601"
    exit 0
fi

# Get Elasticsearch container ID/name
ES_CONTAINER=$(docker ps --filter "ancestor=docker.elastic.co/elasticsearch/elasticsearch:8.11.0" --format "{{.Names}}" | head -1)

if [ -z "$ES_CONTAINER" ]; then
    echo "⚠️  Could not find Elasticsearch container name"
    echo "   Using host.docker.internal to connect"
    ES_HOST="http://host.docker.internal:9200"
else
    echo "✓ Found Elasticsearch container: $ES_CONTAINER"
    ES_HOST="http://$ES_CONTAINER:9200"
fi

echo ""
echo "Starting Kibana..."
echo "  Elasticsearch URL: $ES_HOST"
echo "  Kibana URL: http://localhost:5601"
echo ""

# Start Kibana
docker run -d \
  --name kibana \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=$ES_HOST" \
  -e "SERVER_NAME=kibana" \
  -e "SERVER_HOST=0.0.0.0" \
  docker.elastic.co/kibana/kibana:8.11.0

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Kibana is starting..."
    echo ""
    echo "Wait ~30-60 seconds for Kibana to fully start, then:"
    echo "  1. Open: http://localhost:5601"
    echo "  2. Go to: Stack Management → Index Patterns"
    echo "  3. Create pattern: macos-telemetry-esf-*"
    echo "  4. Time field: @timestamp"
    echo "  5. Explore data in Discover or create visualizations"
    echo ""
    echo "Check status: docker logs -f kibana"
    echo "Stop Kibana: docker stop kibana && docker rm kibana"
else
    echo "❌ Failed to start Kibana"
    exit 1
fi

