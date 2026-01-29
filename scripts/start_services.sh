#!/bin/bash
# Start Elasticsearch and Kibana services for testing

set -euo pipefail

echo "========================================="
echo "Starting Elasticsearch and Kibana"
echo "========================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running"
    echo ""
    echo "Please:"
    echo "  1. Start Docker Desktop"
    echo "  2. Wait for it to fully start"
    echo "  3. Run this script again"
    echo ""
    exit 1
fi

echo "✅ Docker is running"
echo ""

# Check if docker-compose is available
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo "❌ Error: docker-compose not found"
    echo "   Install it or use Docker Desktop which includes compose"
    exit 1
fi

echo "✅ Found: $COMPOSE_CMD"
echo ""

# Navigate to project root
cd "$(dirname "$0")/.."

# Start services
echo "Starting Elasticsearch and Kibana..."
echo ""

$COMPOSE_CMD up -d

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Services are starting..."
    echo ""
    echo "Wait ~30-60 seconds for services to be ready, then:"
    echo ""
    echo "  Elasticsearch: http://localhost:9200"
    echo "  Kibana: http://localhost:5601"
    echo ""
    echo "Check status:"
    echo "  $COMPOSE_CMD ps"
    echo ""
    echo "View logs:"
    echo "  $COMPOSE_CMD logs -f"
    echo ""
    echo "Stop services:"
    echo "  $COMPOSE_CMD down"
    echo ""
    
    # Wait a bit and check if services are up
    echo "Checking service status..."
    sleep 5
    
    if curl -s http://localhost:9200 > /dev/null 2>&1; then
        echo "✅ Elasticsearch is responding"
    else
        echo "⏳ Elasticsearch is still starting (this is normal, wait 30-60 seconds)"
    fi
else
    echo "❌ Failed to start services"
    exit 1
fi

