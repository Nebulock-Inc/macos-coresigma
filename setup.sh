#!/bin/bash
# Quick setup script for macOS Sigma Pipelines

set -euo pipefail

echo "========================================="
echo "macOS Sigma Pipelines Setup"
echo "========================================="
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✓ Found Python $PYTHON_VERSION"

# Check for virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Check for sigma CLI
if ! command -v sigma &> /dev/null; then
    echo "Installing sigmatools..."
    pip install sigmatools
fi

# Setup Elasticsearch templates (if Elasticsearch is running)
ES_URL="${ES_URL:-http://localhost:9200}"
ES_USER="${ES_USER:-}"
ES_PASSWORD="${ES_PASSWORD:-}"

if [ -n "$ES_USER" ] && [ -n "$ES_PASSWORD" ]; then
    CURL_AUTH="-u ${ES_USER}:${ES_PASSWORD}"
else
    CURL_AUTH=""
fi

if curl -s $CURL_AUTH "$ES_URL" > /dev/null 2>&1; then
    echo ""
    echo "Setting up Elasticsearch index templates..."
    ES_USER="$ES_USER" ES_PASSWORD="$ES_PASSWORD" bash scripts/setup_elasticsearch_templates.sh
else
    echo ""
    echo "⚠️  Elasticsearch not running or credentials incorrect - skipping template setup"
    echo "   Run 'ES_USER=elastic ES_PASSWORD=changeme bash scripts/setup_elasticsearch_templates.sh' after starting Elasticsearch"
fi

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Start Elasticsearch: docker-compose up -d (optional)"
echo "3. Setup templates: bash scripts/setup_elasticsearch_templates.sh (if using Elasticsearch)"
echo "4. Run tests: python3 tests/test_e2e.py"
echo "5. Read documentation: docs/INSTALLATION.md"
echo ""

