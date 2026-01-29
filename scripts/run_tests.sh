#!/bin/bash
# Run the coreSigma end-to-end test suite
#
# This script runs all tests for:
# 1. ESF Collector - Event normalization and field mapping
# 2. Sigma Pipeline - Field transformations from Sigma to ECS
# 3. End-to-End - Full flow from raw ESF to Elasticsearch queries

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Activate virtual environment
source venv/bin/activate

# Set PYTHONPATH
export PYTHONPATH="$PROJECT_DIR"

echo "=============================================="
echo "    coreSigma End-to-End Test Suite"
echo "=============================================="
echo ""

# Run all tests with verbose output
pytest tests/ -v --tb=short "$@"

echo ""
echo "=============================================="
echo "    All tests completed!"
echo "=============================================="
