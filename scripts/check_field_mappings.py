#!/usr/bin/env python3
"""Check actual field mappings in Elasticsearch."""

import os
import requests

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "changeme")

def main():
    auth = (ES_USER, ES_PASSWORD)
    
    # Get index mappings
    print("Checking field mappings in macos-telemetry-esf-* index...\n")
    
    resp = requests.get(f"{ES_URL}/macos-telemetry-esf-*/_mapping", auth=auth)
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
