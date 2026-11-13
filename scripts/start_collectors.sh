#!/bin/bash
# Start ESF and UL collectors for data collection
# Elasticsearch: $ES_URL (default http://localhost:9200)

set -euo pipefail

cd "$(dirname "$0")/.."
ES_URL="${ES_URL:-http://localhost:9200}"
# Credentials (as scripts/setup_elasticsearch_templates.sh): $ES_API_KEY, else $ES_USER and $ES_PASSWORD, else the
# macOS Keychain entry scripts/setup_credentials.sh stores (service coreSigma-Elasticsearch).
KEYCHAIN_SERVICE="coreSigma-Elasticsearch"
basic_auth() { printf 'Authorization: Basic %s' "$(printf '%s:%s' "$1" "$2" | base64 | tr -d '\n')"; }
if [ -n "${ES_API_KEY:-}" ]; then
    AUTH_HEADER="Authorization: ApiKey $ES_API_KEY"
elif [ -n "${ES_USER:-}" ] && [ -n "${ES_PASSWORD:-}" ]; then
    AUTH_HEADER=$(basic_auth "$ES_USER" "$ES_PASSWORD")
elif KEYCHAIN_PASSWORD=$(security find-generic-password -s "$KEYCHAIN_SERVICE" -a "${ES_USER:-elastic}" -w 2>/dev/null); then
    AUTH_HEADER=$(basic_auth "${ES_USER:-elastic}" "$KEYCHAIN_PASSWORD")
else
    AUTH_HEADER=""  # the collectors look for their own (collectors/auth.py, config file included)
fi
# curl with the Authorization header on stdin (-H @-), as setup_credentials.sh does: on curl's command line, -u or -H
# would show the secret to other users in `ps`. (No call here sends a body on stdin.)
es_curl() { printf '%s\n' "$AUTH_HEADER" | curl -H @- "$@"; }

echo "========================================="
echo "Starting macOS Data Collectors"
echo "========================================="
echo ""

# Check that Elasticsearch answers; a 401/403 means it's up but these credentials aren't (the collectors use their own)
HTTP_CODE=$(es_curl -s -o /dev/null -w "%{http_code}" "$ES_URL" 2>/dev/null || true)
case "$HTTP_CODE" in
    2??) echo "✅ Elasticsearch is running" ;;
    401|403)
        echo "⚠️  Elasticsearch is running at $ES_URL but answered HTTP $HTTP_CODE: check the credentials"
        echo "   (./scripts/setup_credentials.sh --test)" ;;
    *)
        echo "❌ Error: Elasticsearch is not reachable at $ES_URL (HTTP ${HTTP_CODE:-000})"
        echo "   Start the bench with: ./scripts/bench_up.sh elastic"
        exit 1 ;;
esac
echo ""

# Check if collectors are already running
if pgrep -f "esf_collector.py" > /dev/null; then
    echo "⚠️  ESF collector is already running"
else
    echo "Starting ESF collector..."
    echo "  ⚠️  NOTE: ESF collector requires sudo and must be started in a terminal"
    echo "  Run this command in a separate terminal, with ES_USER/ES_PASSWORD or ES_API_KEY exported"
    echo "  (sudo drops environment variables unless told to keep them, and can't read your Keychain):"
    echo ""
    echo "  sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY /usr/bin/python3 $(pwd)/collectors/esf_collector.py --output elasticsearch --es-url $ES_URL"
    echo ""
fi

# Start UL collector in background
if pgrep -f "ul_collector.py" > /dev/null; then
    echo "⚠️  UL collector is already running"
else
    echo "Starting UL collector..."
    source venv/bin/activate

    nohup python3 collectors/ul_collector.py --output elasticsearch --es-url "$ES_URL" > /tmp/ul_collector.log 2>&1 &
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
echo "  • Event counts: ./scripts/check_collection_status.sh"
echo "  • View UL logs: tail -f /tmp/ul_collector.log"
echo "  • Stop UL collector: pkill -f ul_collector.py"
echo ""
echo "========================================="
