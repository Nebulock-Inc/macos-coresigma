#!/bin/bash
# Quick script to check data collection status
# Elasticsearch: $ES_URL (default http://localhost:9200)

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
    echo "❌ No Elasticsearch credentials: set ES_API_KEY, or ES_USER and ES_PASSWORD, or store them in the Keychain" \
         "with ./scripts/setup_credentials.sh" >&2
    exit 1
fi
# curl with the Authorization header on stdin (-H @-), as setup_credentials.sh does: on curl's command line, -u or -H
# would show the secret to other users in `ps`. (No call here sends a body on stdin.)
es_curl() { printf '%s\n' "$AUTH_HEADER" | curl -H @- "$@"; }

# The index pattern's document count, or the error Elasticsearch answered with (e.g. a 401)
count() {
    es_curl -s "$ES_URL/$1/_count" 2>/dev/null | python3 -c 'import json, sys
reply = json.load(sys.stdin)
print(reply["count"] if "count" in reply else "error: " + json.dumps(reply.get("error", reply))[:200])' 2>/dev/null \
        || echo "error: no reply from $ES_URL"
}

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
echo "Event Counts ($ES_URL):"
echo "  ESF Events: $(count 'macos-telemetry-esf-*')"
echo "  UL Events: $(count 'macos-telemetry-ul-*')"
echo ""
echo "========================================="
