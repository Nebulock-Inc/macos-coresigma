#!/bin/bash
# Restart collectors to fix issues

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "========================================="
echo "Restarting Collectors"
echo "========================================="
echo ""

# Stop existing collectors
echo "1. Stopping existing collectors..."
echo ""

if pgrep -f "esf_collector.py" > /dev/null; then
    echo "  Stopping ESF collector..."
    sudo pkill -f "esf_collector.py" || true
    sleep 2
fi

if pgrep -f "ul_collector.py" > /dev/null; then
    echo "  Stopping UL collector..."
    pkill -f "ul_collector.py" || true
    sleep 2
fi

echo "✅ Collectors stopped"
echo ""

# Check Elasticsearch
echo "2. Verifying Elasticsearch..."
echo ""

if curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo "✅ Elasticsearch is running"
else
    echo "❌ Elasticsearch is not running"
    echo "   Start it with: ./scripts/start_services.sh"
    exit 1
fi

echo ""

# Start collectors
echo "3. Starting collectors..."
echo ""

echo "⚠️  ESF Collector requires sudo and must be started manually in a terminal"
echo "   Run this command in a separate terminal:"
echo ""
echo "   cd $PROJECT_ROOT"
echo "   sudo python3 collectors/esf_collector.py --output elasticsearch --es-url http://localhost:9200"
echo ""

# Start UL collector
echo "Starting UL collector in background..."
cd "$PROJECT_ROOT"

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

nohup python3 collectors/ul_collector.py --output elasticsearch --es-url http://localhost:9200 > /tmp/ul_collector.log 2>&1 &
UL_PID=$!

echo "✅ UL collector started (PID: $UL_PID)"
echo "   Logs: tail -f /tmp/ul_collector.log"
echo ""

# Wait and verify
echo "4. Verifying collectors started..."
echo ""

sleep 3

if pgrep -f "ul_collector.py" > /dev/null; then
    echo "✅ UL Collector: Running"
else
    echo "❌ UL Collector: Failed to start"
    echo "   Check logs: cat /tmp/ul_collector.log"
fi

echo ""
echo "========================================="
echo "Next Steps:"
echo "========================================="
echo ""
echo "1. Start ESF collector in a separate terminal (see command above)"
echo "2. Monitor UL collector: tail -f /tmp/ul_collector.log"
echo "3. Generate test activity:"
echo "   • Run a command: ls -la"
echo "   • Open an app: open -a Photos"
echo "   • Check events: ./scripts/diagnose_collector_issues.sh"
echo ""

