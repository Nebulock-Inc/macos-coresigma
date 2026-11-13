#!/usr/bin/env python3
"""Check actual field mappings in Elasticsearch."""

import os
import sys
import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "collectors"))
from auth import AuthenticationError, get_elasticsearch_auth  # noqa: E402

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")

def main():
    try:  # the collectors' order: ES_API_KEY, the Keychain, ES_USER/ES_PASSWORD, ~/.coresigma/config.yml
        api_key, auth = get_elasticsearch_auth(ES_URL)
    except AuthenticationError as e:
        sys.exit(str(e))
    headers = {"Authorization": f"ApiKey {api_key}"} if api_key else {}
    
    # Get index mappings
    print("Checking field mappings in macos-telemetry-esf-* index...\n")
    
    resp = requests.get(f"{ES_URL}/macos-telemetry-esf-*/_mapping", auth=auth, headers=headers)
    if resp.status_code != 200:
        print(f"Error: {resp.text}")
        return
    
    mappings = resp.json()
    
    # Extract field names
    fields_with_keyword = []
    fields_without_keyword = []
    
    for index_name, index_data in mappings.items():
        print(f"Index: {index_name}")
        props = index_data.get("mappings", {}).get("properties", {})
        
        def extract_fields(properties, prefix=""):
            for field_name, field_config in properties.items():
                full_name = f"{prefix}{field_name}" if prefix else field_name
                field_type = field_config.get("type")
                
                if field_type:
                    # Check if it has .keyword subfield
                    has_keyword = "keyword" in field_config.get("fields", {})
                    if has_keyword or field_type == "keyword":
                        fields_with_keyword.append(full_name)
                    else:
                        fields_without_keyword.append((full_name, field_type))
                
                # Recurse into nested properties
                if "properties" in field_config:
                    extract_fields(field_config["properties"], f"{full_name}.")
        
        extract_fields(props)
        break  # Just check first index
    
    print("\n--- Fields that support .keyword aggregations ---")
    for f in sorted(fields_with_keyword):
        print(f"  {f}.keyword")
    
    print("\n--- Fields without .keyword (check type) ---")
    for f, t in sorted(fields_without_keyword):
        print(f"  {f} ({t})")
    
    # Specifically check process.parent fields
    print("\n--- Process parent fields ---")
    for f in sorted(fields_with_keyword + [x[0] for x in fields_without_keyword]):
        if "process.parent" in f:
            print(f"  {f}")

if __name__ == "__main__":
    main()
