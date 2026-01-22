#!/bin/bash
# Reset Elasticsearch indices and generate test events

ES_URL="http://localhost:9200"
ES_USER="elastic"
ES_PASSWORD="changeme"

echo "=== Deleting existing telemetry indices ==="
curl -s -u $ES_USER:$ES_PASSWORD -X DELETE "$ES_URL/macos-telemetry-*"
echo ""

echo "=== Verifying deletion ==="
curl -s -u $ES_USER:$ES_PASSWORD "$ES_URL/_cat/indices/macos*?v" || echo "No macos indices found (expected)"
echo ""

echo "=== Indices cleaned. Ready to start collector. ==="
echo ""
echo "To start collector, run:"
echo "  sudo python3 collectors/esf_collector.py --output elasticsearch --es-url $ES_URL"
echo ""
echo "=== Generating test events to trigger Sigma rules ==="

# Wait a moment
sleep 2

# Process execution from temp (triggers process_execution_suspicious)
echo "1. Process from /tmp (triggers suspicious process execution)"
/usr/bin/touch /tmp/test_sigma_$$
/bin/bash -c 'echo test' 2>/dev/null

# File creation in persistence locations (triggers file_creation_persistence)
echo "2. File in LaunchAgents (triggers persistence detection)"
touch ~/Library/LaunchAgents/.test_sigma_$$ 2>/dev/null || echo "   (May need permissions)"
rm -f ~/Library/LaunchAgents/.test_sigma_$$ 2>/dev/null

# curl/wget with URLs (triggers suspicious_curl_download)
echo "3. curl with URL (triggers suspicious curl download)"
curl -s -o /dev/null "https://example.com" 2>/dev/null

# SSH connection (triggers ssh_connection_detection)
echo "4. SSH command (triggers SSH detection)"
ssh -V 2>/dev/null || true

# File operations in sensitive dirs
echo "5. File operations in /etc (triggers sensitive file access)"
cat /etc/hosts > /dev/null 2>&1

# Hidden file creation (triggers rename_to_hidden_dotfile)
echo "6. Create hidden file (triggers hidden file detection)"
touch /tmp/.hidden_test_$$ 2>/dev/null
rm -f /tmp/.hidden_test_$$ 2>/dev/null

# Cleanup
rm -f /tmp/test_sigma_$$

echo ""
echo "=== Test events generated ==="
echo "Check Kibana/Elasticsearch for new events"
echo ""
echo "Quick check for new events:"
sleep 3
curl -s -u $ES_USER:$ES_PASSWORD "$ES_URL/macos-telemetry-esf-*/_count" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Total events: {d.get(\"count\", 0)}')" 2>/dev/null || echo "No events yet (start collector first)"
