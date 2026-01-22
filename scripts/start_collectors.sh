#!/bin/bash
# Start ESF and UL collectors for data collection

set -euo pipefail

echo "========================================="
echo "Starting macOS Data Collectors"
echo "========================================="
echo ""

# Check if Elasticsearch is running
if ! curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo "❌ Error: Elasticsearch is not running at http://localhost:9200"
    echo "   Start it with: bash scripts/start_services.sh"
    exit 1
fi

echo "✅ Elasticsearch is running"
echo ""

# Check if collectors are already running
if pgrep -f "esf_collector.py" > /dev/null; then
    echo "⚠️  ESF collector is already running"
else
    echo "Starting ESF collector..."
    echo "  ⚠️  NOTE: ESF collector requires sudo and must be started in a terminal"
    echo "  Run this command in a separate terminal:"
    echo ""
    echo "  sudo python3 $(pwd)/collectors/esf_collector.py --output elasticsearch --es-url http://localhost:9200"
    echo ""
fi

# Start UL collector in background
if pgrep -f "ul_collector.py" > /dev/null; then
    echo "⚠️  UL collector is already running"
else
    echo "Starting UL collector..."
    cd "$(dirname "$0")/.."
    source venv/bin/activate
    
    nohup python3 collectors/ul_collector.py --output elasticsearch --es-url http://localhost:9200 > /tmp/ul_collector.log 2>&1 &
    UL_PID=$!
    
    echo "  ✅ UL collector started (PID: $UL_PID)"
    echo "  Logs: tail -f /tmp/ul_collector.log"
fi

echo ""
echo "========================================="
echo "Collector Status"
echo "========================================="
echo ""

# Wait a moment for collectors to start
sleep 2

# Check running processes
if pgrep -f "esf_collector.py" > /dev/null; then
    echo "✅ ESF Collector: Running"
else
    echo "❌ ESF Collector: Not running (needs sudo in separate terminal)"
fi

if pgrep -f "ul_collector.py" > /dev/null; then
    echo "✅ UL Collector: Running"
else
    echo "❌ UL Collector: Not running"
fi

echo ""
echo "To monitor collection:"
echo "  • Check ESF events: curl -s http://localhost:9200/macos-telemetry-esf-*/_count"
echo "  • Check UL events: curl -s http://localhost:9200/macos-telemetry-ul-*/_count"
echo "  • View UL logs: tail -f /tmp/ul_collector.log"
echo "  • Stop UL collector: pkill -f ul_collector.py"
echo ""
echo "========================================="

