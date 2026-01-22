#!/bin/bash
#
# coreSigma Credential Setup
# Sets up Elasticsearch/Kibana credentials using macOS Keychain
#
# Usage:
#   ./scripts/setup_credentials.sh              # Interactive setup
#   ./scripts/setup_credentials.sh --api-key    # Create API key (recommended)
#   ./scripts/setup_credentials.sh --test       # Test current authentication
#

set -e

KEYCHAIN_SERVICE="coreSigma-Elasticsearch"
ES_URL="${ES_URL:-http://localhost:9200}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  coreSigma Credential Setup${NC}"
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

# Check if credentials already exist
check_existing() {
    echo "Checking for existing credentials..."
    
    # Check keychain
    if security find-generic-password -s "$KEYCHAIN_SERVICE" -a "elastic" -w &>/dev/null; then
        print_success "Found credentials in macOS Keychain"
        return 0
    fi
    
    # Check environment
    if [[ -n "$ES_API_KEY" ]]; then
        print_success "Found ES_API_KEY in environment"
        return 0
    fi
    
    if [[ -n "$ES_USER" && -n "$ES_PASSWORD" ]]; then
        print_success "Found ES_USER/ES_PASSWORD in environment"
        return 0
    fi
    
    # Check config file
    if [[ -f "$HOME/.coresigma/config.yml" ]]; then
        print_success "Found config file at ~/.coresigma/config.yml"
        return 0
    fi
    
    print_info "No existing credentials found"
    return 1
}

# Store password in keychain
store_in_keychain() {
    local username="${1:-elastic}"
    local password="$2"
    
    # Delete existing entry if present
    security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$username" &>/dev/null || true
    
    # Add new entry
    security add-generic-password -s "$KEYCHAIN_SERVICE" -a "$username" -w "$password"
    
    print_success "Stored credentials for '$username' in macOS Keychain"
}

# Interactive password setup
setup_password() {
    echo ""
    echo "Setting up password authentication..."
    echo ""
    
    read -p "Username [elastic]: " username
    username="${username:-elastic}"
    
    read -sp "Password: " password
    echo ""
    
    if [[ -z "$password" ]]; then
        print_error "Password cannot be empty"
        exit 1
    fi
    
    store_in_keychain "$username" "$password"
    
    echo ""
    print_success "Credentials stored in macOS Keychain"
    echo ""
    echo "You can now run collectors without passing credentials:"
    echo "  python collectors/esf_collector.py --output elasticsearch"
    echo ""
}

# Create API key
create_api_key() {
    echo ""
    echo "Creating Elasticsearch API key..."
    echo ""
    
    # Need existing credentials first
    local auth_header=""
    
    # Try keychain first
    if password=$(security find-generic-password -s "$KEYCHAIN_SERVICE" -a "elastic" -w 2>/dev/null); then
        auth_header="elastic:$password"
    elif [[ -n "$ES_USER" && -n "$ES_PASSWORD" ]]; then
        auth_header="$ES_USER:$ES_PASSWORD"
    else
        echo "Need existing credentials to create API key."
        read -p "Username [elastic]: " username
        username="${username:-elastic}"
        read -sp "Password: " password
        echo ""
        auth_header="$username:$password"
    fi
    
    # Create API key with limited permissions
    response=$(curl -s -X POST "$ES_URL/_security/api_key" \
        -H "Content-Type: application/json" \
        -u "$auth_header" \
        -d '{
            "name": "coresigma-collector",
            "role_descriptors": {
                "coresigma_writer": {
                    "cluster": ["monitor"],
                    "index": [
                        {
                            "names": ["macos-telemetry-*", "macos-esf-*", "macos-ul-*"],
                            "privileges": ["write", "create_index", "auto_configure"]
                        }
                    ]
                }
            },
            "expiration": "365d"
        }')
    
    # Check for error
    if echo "$response" | grep -q '"error"'; then
        print_error "Failed to create API key:"
        echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
        exit 1
    fi
    
    # Extract encoded key
    encoded=$(echo "$response" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d['encoded'])" 2>/dev/null)
    
    if [[ -z "$encoded" ]]; then
        print_error "Failed to parse API key response"
        echo "$response"
        exit 1
    fi
    
    print_success "API key created successfully"
    echo ""
    echo "Add this to your shell profile (~/.zshrc or ~/.bash_profile):"
    echo ""
    echo -e "  ${GREEN}export ES_API_KEY=\"$encoded\"${NC}"
    echo ""
    echo "Or create ~/.coresigma/config.yml:"
    echo ""
    echo "  elasticsearch:"
    echo "    api_key: \"$encoded\""
    echo ""
    
    # Offer to store in config
    read -p "Create config file now? [y/N]: " create_config
    if [[ "$create_config" =~ ^[Yy]$ ]]; then
        mkdir -p "$HOME/.coresigma"
        cat > "$HOME/.coresigma/config.yml" << EOF
# coreSigma Configuration
elasticsearch:
  url: $ES_URL
  api_key: "$encoded"
EOF
        chmod 600 "$HOME/.coresigma/config.yml"
        print_success "Created ~/.coresigma/config.yml"
    fi
}

# Test authentication
test_auth() {
    echo ""
    echo "Testing Elasticsearch authentication..."
    echo ""
    
    cd "$(dirname "$0")/.."
    
    if [[ -d "venv" ]]; then
        source venv/bin/activate
    fi
    
    python3 -c "
from collectors.auth import get_elasticsearch_auth, create_elasticsearch_client, AuthenticationError

try:
    api_key, basic_auth = get_elasticsearch_auth()
    if api_key:
        print('✓ Using API key authentication')
    elif basic_auth:
        print(f'✓ Using basic auth (user: {basic_auth[0]})')
    
    client = create_elasticsearch_client()
    info = client.info()
    print(f'✓ Connected to cluster: {info[\"cluster_name\"]}')
    print(f'✓ Elasticsearch version: {info[\"version\"][\"number\"]}')
    print()
    print('Authentication working!')
except AuthenticationError as e:
    print(f'✗ {e}')
    exit(1)
except Exception as e:
    print(f'✗ Connection failed: {e}')
    exit(1)
"
}

# Show help
show_help() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --password    Store username/password in macOS Keychain (default)"
    echo "  --api-key     Create a limited-scope API key (recommended for production)"
    echo "  --test        Test current authentication configuration"
    echo "  --help        Show this help message"
    echo ""
    echo "Authentication Priority (highest to lowest):"
    echo "  1. ES_API_KEY environment variable"
    echo "  2. macOS Keychain"
    echo "  3. ES_USER/ES_PASSWORD environment variables"
    echo "  4. ~/.coresigma/config.yml"
    echo ""
}

# Main
print_header

case "${1:-}" in
    --api-key)
        create_api_key
        ;;
    --test)
        test_auth
        ;;
    --help|-h)
        show_help
        ;;
    --password|*)
        if check_existing; then
            echo ""
            read -p "Credentials exist. Overwrite? [y/N]: " overwrite
            if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
                echo "Keeping existing credentials."
                exit 0
            fi
        fi
        setup_password
        ;;
esac
