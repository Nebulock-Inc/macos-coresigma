#!/usr/bin/env python3
"""
Centralized authentication module for coreSigma collectors.

Supports multiple authentication methods:
1. Environment variables (ES_USER/ES_PASSWORD or ES_API_KEY)
2. macOS Keychain (recommended for local deployments)
3. Configuration file (~/.coresigma/config.yml)

Priority order:
1. ES_API_KEY environment variable (highest)
2. macOS Keychain
3. ES_USER/ES_PASSWORD environment variables
4. Config file (lowest)
"""

import os
import sys
import subprocess
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

# Optional imports
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# Constants
KEYCHAIN_SERVICE = "coreSigma-Elasticsearch"
CONFIG_DIR = Path.home() / ".coresigma"
CONFIG_FILE = CONFIG_DIR / "config.yml"


class AuthenticationError(Exception):
    """Raised when authentication cannot be established."""
    pass


def get_from_keychain(service: str, account: str) -> Optional[str]:
    """
    Retrieve a credential from macOS Keychain.
    
    Args:
        service: Keychain service name
        account: Account/username
        
    Returns:
        Password string or None if not found
    """
    if sys.platform != "darwin":
        return None
    
    try:
        result = subprocess.run(
            ["security", "find-generic-password", 
             "-s", service, "-a", account, "-w"],
            capture_output=True, 
            text=True, 
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None
    except FileNotFoundError:
        # security command not available
        return None


def store_in_keychain(service: str, account: str, password: str) -> bool:
    """
    Store a credential in macOS Keychain.
    
    Args:
        service: Keychain service name
        account: Account/username
        password: Password to store
        
    Returns:
        True if successful, False otherwise
    """
    if sys.platform != "darwin":
        return False
    
    try:
        # First try to delete existing entry (ignore errors)
        subprocess.run(
            ["security", "delete-generic-password", "-s", service, "-a", account],
            capture_output=True, check=False
        )
        
        # Add new entry
        subprocess.run(
            ["security", "add-generic-password", 
             "-s", service, "-a", account, "-w", password],
            capture_output=True, 
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def load_config_file() -> Optional[Dict[str, Any]]:
    """Load configuration from ~/.coresigma/config.yml"""
    if not HAS_YAML:
        return None
    
    if not CONFIG_FILE.exists():
        return None
    
    try:
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def get_elasticsearch_auth(
    es_url: str = "http://localhost:9200"
) -> Tuple[Optional[str], Optional[Tuple[str, str]]]:
    """
    Get Elasticsearch authentication credentials.
    
    Tries authentication methods in priority order:
    1. ES_API_KEY environment variable
    2. macOS Keychain
    3. ES_USER/ES_PASSWORD environment variables
    4. Config file
    
    Args:
        es_url: Elasticsearch URL (used for config file lookup)
        
    Returns:
        Tuple of (api_key, basic_auth) where one will be set and the other None
        
    Raises:
        AuthenticationError: If no valid authentication found
    """
    
    # 1. Check for API key in environment
    api_key = os.environ.get("ES_API_KEY")
    if api_key:
        return (api_key, None)
    
    # 2. Check macOS Keychain
    keychain_user = os.environ.get("ES_USER", "elastic")
    keychain_password = get_from_keychain(KEYCHAIN_SERVICE, keychain_user)
    if keychain_password:
        return (None, (keychain_user, keychain_password))
    
    # 3. Check environment variables
    es_user = os.environ.get("ES_USER")
    es_password = os.environ.get("ES_PASSWORD")
    if es_user and es_password:
        return (None, (es_user, es_password))
    
    # 4. Check config file
    config = load_config_file()
    if config:
        es_config = config.get("elasticsearch", {})
        
        # API key from config
        if es_config.get("api_key"):
            return (es_config["api_key"], None)
        
        # Basic auth from config
        if es_config.get("username") and es_config.get("password"):
            return (None, (es_config["username"], es_config["password"]))
    
    # No authentication found
    raise AuthenticationError(
        "No Elasticsearch authentication configured.\n\n"
        "Configure authentication using one of these methods:\n"
        "  1. Set ES_API_KEY environment variable (recommended)\n"
        "  2. Store in macOS Keychain:\n"
        "     security add-generic-password -s 'coreSigma-Elasticsearch' -a 'elastic' -w 'your_password'\n"
        "  3. Set ES_USER and ES_PASSWORD environment variables\n"
        "  4. Create config file at ~/.coresigma/config.yml\n"
    )


def create_elasticsearch_client(es_url: str = "http://localhost:9200"):
    """
    Create an authenticated Elasticsearch client.
    
    Args:
        es_url: Elasticsearch URL
        
    Returns:
        Configured Elasticsearch client
        
    Raises:
        ImportError: If elasticsearch module not installed
        AuthenticationError: If no valid authentication found
    """
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        raise ImportError(
            "elasticsearch module not found. Install with: pip install elasticsearch"
        )
    
    api_key, basic_auth = get_elasticsearch_auth(es_url)
    
    if api_key:
        return Elasticsearch([es_url], api_key=api_key)
    elif basic_auth:
        return Elasticsearch([es_url], basic_auth=basic_auth)
    else:
        raise AuthenticationError("No authentication method available")


def get_kibana_auth() -> Tuple[str, str]:
    """
    Get Kibana authentication (basic auth for API calls).
    
    Returns:
        Tuple of (username, password)
        
    Raises:
        AuthenticationError: If no valid authentication found
    """
    # API keys work differently for Kibana API calls
    # We need basic auth for most Kibana APIs
    
    # Check macOS Keychain
    keychain_user = os.environ.get("ES_USER", "elastic")
    keychain_password = get_from_keychain(KEYCHAIN_SERVICE, keychain_user)
    if keychain_password:
        return (keychain_user, keychain_password)
    
    # Check environment variables
    es_user = os.environ.get("ES_USER")
    es_password = os.environ.get("ES_PASSWORD")
    if es_user and es_password:
        return (es_user, es_password)
    
    # Check config file
    config = load_config_file()
    if config:
        es_config = config.get("elasticsearch", {})
        if es_config.get("username") and es_config.get("password"):
            return (es_config["username"], es_config["password"])
    
    raise AuthenticationError(
        "No Kibana authentication configured.\n"
        "Set ES_USER and ES_PASSWORD environment variables."
    )


# CLI for credential management
def main():
    """Command-line interface for credential management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="coreSigma Credential Manager")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Store command
    store_parser = subparsers.add_parser("store", help="Store credentials in Keychain")
    store_parser.add_argument("--username", "-u", default="elastic", help="Username")
    store_parser.add_argument("--password", "-p", help="Password (prompted if not provided)")
    
    # Test command
    subparsers.add_parser("test", help="Test current authentication")
    
    # Show command
    subparsers.add_parser("show", help="Show configured authentication method")
    
    args = parser.parse_args()
    
    if args.command == "store":
        password = args.password
        if not password:
            import getpass
            password = getpass.getpass("Enter Elasticsearch password: ")
        
        if store_in_keychain(KEYCHAIN_SERVICE, args.username, password):
            print(f"Stored credentials for '{args.username}' in macOS Keychain")
        else:
            print("Failed to store credentials. Are you on macOS?")
            sys.exit(1)
    
    elif args.command == "test":
        try:
            client = create_elasticsearch_client()
            info = client.info()
            print(f"Successfully connected to Elasticsearch cluster: {info['cluster_name']}")
        except AuthenticationError as e:
            print(f"Authentication failed: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Connection failed: {e}")
            sys.exit(1)
    
    elif args.command == "show":
        try:
            api_key, basic_auth = get_elasticsearch_auth()
            if api_key:
                print("Authentication method: API Key")
                print(f"  Source: {'Environment (ES_API_KEY)' if os.environ.get('ES_API_KEY') else 'Config file'}")
            elif basic_auth:
                user, _ = basic_auth
                sources = []
                if get_from_keychain(KEYCHAIN_SERVICE, user):
                    sources.append("macOS Keychain")
                if os.environ.get("ES_USER"):
                    sources.append("Environment variables")
                config = load_config_file()
                if config and config.get("elasticsearch", {}).get("username"):
                    sources.append("Config file")
                print("Authentication method: Basic Auth")
                print(f"  Username: {user}")
                print(f"  Source: {', '.join(sources) or 'Unknown'}")
        except AuthenticationError:
            print("No authentication configured")
            sys.exit(1)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
