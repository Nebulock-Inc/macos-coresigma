#!/bin/bash
# Quick script to check data collection status

echo "========================================="
echo "Data Collection Status"
echo "========================================="
echo ""

# Check if collectors are running
if pgrep -f "esf_collector.py" > /dev/null; then
    echo "✅ ESF Collector: Running"
else
    echo "❌ ESF Collector: Not running"
fi

if pgrep -f "ul_collector.py" > /dev/null; then
    echo "✅ UL Collector: Running"
else
    echo "❌ UL Collector: Not running"
fi

echo ""

# Check event counts (properly quoted for zsh)
echo "Event Counts:"
ESF_COUNT=$(curl -s 'http://localhost:9200/macos-telemetry-esf-*/_count' 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('count', 0))" 2>/dev/null || echo "0")
UL_COUNT=$(curl -s 'http://localhost:9200/macos-telemetry-ul-*/_count' 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('count', 0))" 2>/dev/null || echo "0")

echo "  ESF Events: ${ESF_COUNT}"
echo "  UL Events: ${UL_COUNT}"
echo ""
echo "========================================="

