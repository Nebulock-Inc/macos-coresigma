#!/bin/bash
# Quick setup script for coreSigma

set -euo pipefail

echo "========================================="
echo "coreSigma Setup"
echo "========================================="
echo ""

# Find Python 3.10 to 3.14 (macOS's /usr/bin/python3 is 3.9; Homebrew's python3 may be 3.15, which
# has no PyYAML wheel, and PyYAML built without libyaml breaks pySigma 1.5.1's import)
PYTHON=""
for p in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do  # newest first: ClickHouse needs 3.13+
    if command -v "$p" &> /dev/null && "$p" -c 'import sys; sys.exit(not (3, 10) <= sys.version_info[:2] <= (3, 14))' 2> /dev/null; then
        PYTHON="$p"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo "Error: the rule tooling needs Python 3.10 to 3.14 (pySigma 1.5.1); found $(python3 --version 2>&1 || echo none)."
    echo "       Install one, e.g. brew install python@3.13. The collectors themselves run on the stock python3."
    exit 1
fi
PYTHON_VERSION=$("$PYTHON" --version | cut -d' ' -f2)
echo "✓ Found Python $PYTHON_VERSION ($PYTHON)"

# A venv from an older setup may be on a Python outside the range: rebuild it
if [ -d "venv" ] && ! venv/bin/python -c 'import sys; sys.exit(not (3, 10) <= sys.version_info[:2] <= (3, 14))' 2> /dev/null; then
    echo "Rebuilding venv: it was built with $(venv/bin/python --version 2>&1 || echo a missing Python), outside 3.10 to 3.14"
    rm -rf venv
fi
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    "$PYTHON" -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Check for sigma CLI (from sigma-cli package, NOT sigmatools)
if ! command -v sigma &> /dev/null; then
    echo "Installing sigma-cli..."
    pip install sigma-cli
fi

# Remove conflicting sigmatools if present
if pip show sigmatools &> /dev/null; then
    echo "Removing conflicting sigmatools package..."
    pip uninstall sigmatools -y
fi

# Elasticsearch index templates, if Elasticsearch answers at all (a 401 too): the templates script finds the
# credentials itself (ES_API_KEY, ES_USER/ES_PASSWORD or the Keychain), and its failure doesn't fail setup
ES_URL="${ES_URL:-http://localhost:9200}"
if curl -s -o /dev/null "$ES_URL"; then
    echo ""
    echo "Setting up Elasticsearch index templates..."
    if ! bash scripts/setup_elasticsearch_templates.sh; then
        echo "⚠️  Template setup failed (see above). Once credentials are set, run: bash scripts/setup_elasticsearch_templates.sh"
    fi
else
    echo ""
    echo "⚠️  Elasticsearch not running at $ES_URL - skipping template setup"
    echo "   Run 'ES_USER=elastic ES_PASSWORD=<ELASTIC_PASSWORD from .env> bash scripts/setup_elasticsearch_templates.sh' after starting Elasticsearch"
fi

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Run tests: pytest -q"
echo "3. Start Elasticsearch and Kibana in Docker, with the index templates: ./scripts/bench_up.sh elastic (optional)"
echo "4. Credentials for the scripts: export ES_USER=elastic ES_PASSWORD=<ELASTIC_PASSWORD from .env>"
echo "5. Read documentation: docs/INSTALLATION.md"
echo ""

