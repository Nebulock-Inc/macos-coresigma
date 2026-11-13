#!/bin/bash
#
# coreSigma Bench Stack Setup
# Brings up Docker stacks and configures them for testing
#
# Usage: ./scripts/bench_up.sh [profile...]
#   Profiles: elastic splunk opensearch clickhouse
#   Example: ./scripts/bench_up.sh elastic splunk opensearch clickhouse

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  coreSigma Bench Stack Setup${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Ensure .env exists
ensure_env() {
    if [ ! -f "$ENV_FILE" ]; then
        print_info "Creating .env from .env.example"
        cp "$PROJECT_DIR/.env.example" "$ENV_FILE"

        # Generate random Kibana keys
        KIBANA_ENC=$(openssl rand -base64 32)
        KIBANA_SEC=$(openssl rand -base64 32)
        KIBANA_REP=$(openssl rand -base64 32)

        # | delimits: base64 keys contain / and +, never |
        sed -i.bak \
            -e "s|KIBANA_ENCRYPTION_KEY=.*|KIBANA_ENCRYPTION_KEY=$KIBANA_ENC|" \
            -e "s|KIBANA_SECURITY_KEY=.*|KIBANA_SECURITY_KEY=$KIBANA_SEC|" \
            -e "s|KIBANA_REPORTING_KEY=.*|KIBANA_REPORTING_KEY=$KIBANA_REP|" \
            "$ENV_FILE"
        rm -f "$ENV_FILE.bak"

        print_success "Created $ENV_FILE with random Kibana keys"
    fi

    chmod 600 "$ENV_FILE"  # it holds the bench passwords

    # Source the env file
    set -a
    source "$ENV_FILE"
    set +a
}

# Check if profile is requested
is_profile_requested() {
    local profile=$1
    shift
    for arg in "$@"; do
        if [ "$arg" = "$profile" ]; then
            return 0
        fi
    done
    return 1
}

# Build docker compose profile arguments
build_compose_args() {
    local args=""

    # elastic is always included (no profile)
    for profile in "$@"; do
        case "$profile" in
            elastic)
                # elastic has no profile, it's the default
                ;;
            splunk|opensearch|clickhouse)
                args="$args --profile $profile"
                ;;
            *)
                print_error "Unknown profile: $profile"
                echo "Valid profiles: elastic splunk opensearch clickhouse"
                exit 1
                ;;
        esac
    done

    echo "$args"
}

# Wait for service health
wait_for_health() {
    local service=$1
    local max_wait=${2:-120}

    echo "Waiting for $service to become healthy (max ${max_wait}s)..."

    local elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        if docker compose -f "$PROJECT_DIR/docker-compose.yml" ps "$service" 2>/dev/null | grep -q "(healthy)"; then
            print_success "$service is healthy"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    print_error "$service failed to become healthy after ${max_wait}s"
    docker compose -f "$PROJECT_DIR/docker-compose.yml" logs --tail=50 "$service"
    return 1
}

# Check Elasticsearch health
check_elasticsearch() {
    local url="http://localhost:9200"
    local user="elastic"
    local pass="${ELASTIC_PASSWORD:-changeme}"

    echo "Checking Elasticsearch health..."

    local health=$(curl -s -u "$user:$pass" "$url/_cluster/health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)

    if [ "$health" = "green" ] || [ "$health" = "yellow" ]; then
        print_success "Elasticsearch: $health"
        return 0
    else
        print_error "Elasticsearch: $health"
        return 1
    fi
}

# Setup Elasticsearch templates
setup_elasticsearch() {
    print_info "Setting up Elasticsearch templates..."

    local user="elastic"
    local pass="${ELASTIC_PASSWORD:-changeme}"

    ES_URL="http://localhost:9200" ES_USER="$user" ES_PASSWORD="$pass" \
        "$SCRIPT_DIR/setup_elasticsearch_templates.sh"
}

# Check Splunk health
check_splunk() {
    echo "Checking Splunk health..."

    if curl -s -k "http://localhost:8000/services/server/info" > /dev/null; then
        print_success "Splunk: OK"
        return 0
    else
        print_error "Splunk: Failed"
        return 1
    fi
}

# Setup Splunk HEC token and index
setup_splunk() {
    local user="admin"
    local pass="${SPLUNK_PASSWORD:-changeme}"
    local token_name="coresigma-bench"

    print_info "Setting up Splunk HEC token and index..."

    # Check if HEC token already exists via management API (port 8089)
    local existing=$(docker exec splunk curl -sk -u "$user:$pass" \
        "https://localhost:8089/servicesNS/nobody/splunk_httpinput/data/inputs/http/$token_name?output_mode=json" 2>/dev/null \
        | grep -o '"token":"[^"]*"' | cut -d'"' -f4 || true)

    if [ -n "$existing" ]; then
        # Reuse existing token
        print_info "HEC token already exists: $existing"
        if grep -q "^SPLUNK_HEC_TOKEN=" "$ENV_FILE"; then
            sed -i.bak "s/^SPLUNK_HEC_TOKEN=.*/SPLUNK_HEC_TOKEN=$existing/" "$ENV_FILE"
            rm -f "$ENV_FILE.bak"
        else
            echo "SPLUNK_HEC_TOKEN=$existing" >> "$ENV_FILE"
        fi
        return 0
    fi

    # Create new HEC token
    local new_token=$(uuidgen | tr '[:upper:]' '[:lower:]')

    # Create the HEC input via management API
    docker exec splunk curl -sk -u "$user:$pass" \
        -X POST "https://localhost:8089/servicesNS/nobody/splunk_httpinput/data/inputs/http" \
        -d "name=$token_name" \
        -d "token=$new_token" \
        -d "index=macos" \
        -d "indexes=macos" \
        -d "disabled=0" > /dev/null

    # Update .env with the token
    if grep -q "^SPLUNK_HEC_TOKEN=" "$ENV_FILE"; then
        sed -i.bak "s/^SPLUNK_HEC_TOKEN=.*/SPLUNK_HEC_TOKEN=$new_token/" "$ENV_FILE"
        rm -f "$ENV_FILE.bak"
    else
        echo "SPLUNK_HEC_TOKEN=$new_token" >> "$ENV_FILE"
    fi

    print_success "Created HEC token: $new_token"

    # Create macos index if it doesn't exist
    docker exec splunk curl -sk -u "$user:$pass" \
        -X POST "https://localhost:8089/services/data/indexes" \
        -d "name=macos" \
        -d "datatype=event" > /dev/null 2>&1 || true

    print_success "Ensured index 'macos' exists"
}

# Wait until HEC takes events: on a fresh Splunk it starts after the health check passes
wait_for_hec() {
    local max_wait=${1:-180}
    local elapsed=0
    echo "Waiting for Splunk HEC (max ${max_wait}s)..."
    while [ $elapsed -lt $max_wait ]; do
        if [ "$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' https://localhost:8088/services/collector/health)" = "200" ]; then
            print_success "Splunk HEC: ready"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    print_error "Splunk HEC: https://localhost:8088/services/collector/health not 200 after ${max_wait}s"
    return 1
}

# Check OpenSearch health
check_opensearch() {
    local url="http://localhost:9201"

    echo "Checking OpenSearch health..."

    if curl -s "$url" > /dev/null; then
        print_success "OpenSearch: OK"
        return 0
    else
        print_error "OpenSearch: Failed"
        return 1
    fi
}

# Setup OpenSearch templates
setup_opensearch() {
    print_info "Setting up OpenSearch templates..."

    ES_URL="http://localhost:9201" \
        "$SCRIPT_DIR/setup_elasticsearch_templates.sh"
}

# Check ClickHouse health
check_clickhouse() {
    echo "Checking ClickHouse health..."

    if docker exec clickhouse clickhouse-client --query "SELECT 1" > /dev/null 2>&1; then
        print_success "ClickHouse: OK"
        return 0
    else
        print_error "ClickHouse: Failed"
        return 1
    fi
}

# Setup ClickHouse database and table
setup_clickhouse() {
    print_info "Setting up ClickHouse database and table..."

    # Create database if not exists
    docker exec clickhouse clickhouse-client --query \
        "CREATE DATABASE IF NOT EXISTS coresigma"

    # Check if table exists
    local table_exists=$(docker exec clickhouse clickhouse-client --query \
        "EXISTS TABLE coresigma.events" 2>/dev/null || echo "0")

    if [ "$table_exists" = "1" ]; then
        print_info "Table coresigma.events already exists"
        # tables from before the column: the ClickHouse backend's correlations read it
        docker exec clickhouse clickhouse-client --query "ALTER TABLE coresigma.events ADD COLUMN IF NOT EXISTS \
            \`timestamp\` DateTime64(9, 'UTC') DEFAULT parseDateTime64BestEffort(\`@timestamp\`, 9, 'UTC') AFTER \`@timestamp\`"
        # btm.item.type was String before: numeric like signal.number; absent ('') reads 0, as in an Int64 column
        if [ "$(docker exec clickhouse clickhouse-client --query "SELECT type FROM system.columns WHERE \
                database = 'coresigma' AND table = 'events' AND name = 'btm.item.type'")" = "String" ]; then
            docker exec clickhouse clickhouse-client --query "ALTER TABLE coresigma.events \
                UPDATE \`btm.item.type\` = '0' WHERE \`btm.item.type\` = '' SETTINGS mutations_sync = 1"
            docker exec clickhouse clickhouse-client --query \
                "ALTER TABLE coresigma.events MODIFY COLUMN \`btm.item.type\` Int64"
        fi
        # tables from before the authentication, sudo, screen sharing, profile, OD, XProtect and Gatekeeper fields
        docker exec clickhouse clickhouse-client --query "ALTER TABLE coresigma.events \
            ADD COLUMN IF NOT EXISTS \`user.target.name\` String, \
            ADD COLUMN IF NOT EXISTS \`user.target.group.name\` String, \
            ADD COLUMN IF NOT EXISTS \`source.user.name\` String, \
            ADD COLUMN IF NOT EXISTS \`source.address\` String, \
            ADD COLUMN IF NOT EXISTS \`event.outcome\` String, \
            ADD COLUMN IF NOT EXISTS \`event.reason\` String, \
            ADD COLUMN IF NOT EXISTS \`authentication.type\` Int64, \
            ADD COLUMN IF NOT EXISTS \`screensharing.viewer_appleid\` String, \
            ADD COLUMN IF NOT EXISTS \`screensharing.existing_session\` Nullable(Bool), \
            ADD COLUMN IF NOT EXISTS \`profile.identifier\` String, \
            ADD COLUMN IF NOT EXISTS \`profile.display_name\` String, \
            ADD COLUMN IF NOT EXISTS \`profile.install_source\` Int64, \
            ADD COLUMN IF NOT EXISTS \`profile.scope\` String, \
            ADD COLUMN IF NOT EXISTS \`od.attribute_name\` String, \
            ADD COLUMN IF NOT EXISTS \`od.attribute_value\` String, \
            ADD COLUMN IF NOT EXISTS \`xprotect.malware_identifier\` String, \
            ADD COLUMN IF NOT EXISTS \`xprotect.incident_identifier\` String, \
            ADD COLUMN IF NOT EXISTS \`xprotect.action_type\` String, \
            ADD COLUMN IF NOT EXISTS \`file.hash.sha256\` String, \
            ADD COLUMN IF NOT EXISTS \`file.code_signature.signing_id\` String, \
            ADD COLUMN IF NOT EXISTS \`file.code_signature.team_id\` String"
        return 0
    fi

    # Create table with the specified columns
    docker exec clickhouse clickhouse-client --query "
    CREATE TABLE IF NOT EXISTS coresigma.events (
        \`@timestamp\` String,
        \`timestamp\` DateTime64(9, 'UTC') DEFAULT parseDateTime64BestEffort(\`@timestamp\`, 9, 'UTC'),  -- the ClickHouse backend's correlations read it
        \`event.action\` String,
        \`event.category\` String,
        \`event.type\` String,
        \`host.name\` String,
        \`process.executable\` String,
        \`process.command_line\` String,
        \`process.parent.executable\` String,
        \`process.pid\` Int64,
        \`process.parent.pid\` Int64,
        \`process.entity_id\` String,
        \`process.code_signature.signing_id\` String,
        \`process.code_signature.team_id\` String,
        \`process.code_signature.exists\` String,
        \`process.code_signature.trusted\` String,
        \`file.path\` String,
        \`file.Ext.original.path\` String,
        \`file.directory\` String,
        \`file.Ext.extattr\` String,
        \`Target.process.executable\` String,
        \`signal.number\` Int64,
        \`memory.protection\` Int64,
        \`xpc.service_name\` String,
        \`tcc.service\` String,
        \`tcc.identity\` String,
        \`tcc.right\` String,
        \`tcc.reason\` String,
        \`btm.item.url\` String,
        \`btm.item.type\` Int64,
        \`btm.executable_path\` String,
        \`user.target.id\` String,
        \`user.target.group.id\` String,
        \`kext.identifier\` String,
        \`user.name\` String,
        \`user.id\` String,
        \`user.target.name\` String,
        \`user.target.group.name\` String,
        \`source.user.name\` String,
        \`source.address\` String,
        \`event.outcome\` String,
        \`event.reason\` String,
        \`authentication.type\` Int64,
        \`screensharing.viewer_appleid\` String,
        \`screensharing.existing_session\` Nullable(Bool),
        \`profile.identifier\` String,
        \`profile.display_name\` String,
        \`profile.install_source\` Int64,
        \`profile.scope\` String,
        \`od.attribute_name\` String,
        \`od.attribute_value\` String,
        \`xprotect.malware_identifier\` String,
        \`xprotect.incident_identifier\` String,
        \`xprotect.action_type\` String,
        \`file.hash.sha256\` String,
        \`file.code_signature.signing_id\` String,
        \`file.code_signature.team_id\` String,
        \`unified_log.subsystem\` String,
        \`unified_log.category\` String,
        \`unified_log.sender_image_path\` String,
        \`message\` String,
        \`log.level\` String,
        \`raw\` String
    ) ENGINE = MergeTree()
    ORDER BY (\`@timestamp\`)
    "

    print_success "Created table coresigma.events"
}

#
# Main
#

print_header

if [ $# -eq 0 ]; then
    print_error "No profiles specified"
    echo "Usage: $0 <profile...>"
    echo "Profiles: elastic splunk opensearch clickhouse"
    exit 1
fi

ensure_env

cd "$PROJECT_DIR"

# Build compose arguments
COMPOSE_ARGS=$(build_compose_args "$@")

# Start services
print_info "Starting Docker Compose services..."
echo "Profiles: $*"

# shellcheck disable=SC2086
docker compose $COMPOSE_ARGS up -d

# Wait for services to become healthy and run setup
HEALTH_STATUS=0

# Elastic (always)
if is_profile_requested elastic "$@"; then
    wait_for_health elasticsearch 180 || HEALTH_STATUS=1
    wait_for_health kibana 180 || HEALTH_STATUS=1

    if [ $HEALTH_STATUS -eq 0 ]; then
        check_elasticsearch || HEALTH_STATUS=1
        setup_elasticsearch || HEALTH_STATUS=1
    fi
fi

# Splunk
if is_profile_requested splunk "$@"; then
    wait_for_health splunk 300 || HEALTH_STATUS=1

    if [ $HEALTH_STATUS -eq 0 ]; then
        # Splunk needs extra time even after health check
        sleep 10
        check_splunk || HEALTH_STATUS=1
        setup_splunk || HEALTH_STATUS=1
        wait_for_hec 180 || HEALTH_STATUS=1
    fi
fi

# OpenSearch
if is_profile_requested opensearch "$@"; then
    wait_for_health opensearch 180 || HEALTH_STATUS=1

    if [ $HEALTH_STATUS -eq 0 ]; then
        check_opensearch || HEALTH_STATUS=1
        setup_opensearch || HEALTH_STATUS=1
    fi
fi

# ClickHouse
if is_profile_requested clickhouse "$@"; then
    wait_for_health clickhouse 120 || HEALTH_STATUS=1

    if [ $HEALTH_STATUS -eq 0 ]; then
        check_clickhouse || HEALTH_STATUS=1
        setup_clickhouse || HEALTH_STATUS=1
    fi
fi

# Summary
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Health Check Summary${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

if [ $HEALTH_STATUS -eq 0 ]; then
    print_success "All requested stacks are healthy and configured"
    echo ""
    exit 0
else
    print_error "Some health checks failed"
    echo ""
    exit 1
fi
