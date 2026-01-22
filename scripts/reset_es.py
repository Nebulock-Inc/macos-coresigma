#!/usr/bin/env python3
"""Reset Elasticsearch indices and verify."""
import requests
import json
import subprocess
import time
import os

ES_URL = "http://localhost:9200"
ES_USER = "elastic"
ES_PASSWORD = "changeme"

def main():
    print("=" * 60)
    print("Resetting Elasticsearch Telemetry Data")
    print("=" * 60)
    
    # Delete indices
    print("\n1. Deleting macos-telemetry-* indices...")
    try:
        resp = requests.delete(
            f"{ES_URL}/macos-telemetry-*",
            auth=(ES_USER, ES_PASSWORD),
            timeout=10
        )
        print(f"   Response: {resp.status_code} - {resp.text[:100]}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Verify deletion
    print("\n2. Checking remaining indices...")
    try:
        resp = requests.get(
            f"{ES_URL}/_cat/indices/macos*?v",
            auth=(ES_USER, ES_PASSWORD),
            timeout=10
        )
        if resp.text.strip():
            print(f"   Remaining:\n{resp.text}")
        else:
            print("   No macos indices found (clean!)")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\n" + "=" * 60)
    print("Ready to start collector!")
    print("=" * 60)
    print("\nRun this command to start the collector:")
    print("  sudo python3 collectors/esf_collector.py --output elasticsearch --es-url http://localhost:9200")
    print("\nThen in another terminal, run test events:")
    print("  python3 scripts/generate_test_events.py")

if __name__ == "__main__":
    main()
