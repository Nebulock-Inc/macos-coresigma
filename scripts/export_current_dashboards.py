#!/usr/bin/env python3
"""Export current dashboards from Kibana to see user changes."""

import os
import requests

KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "changeme")

EXPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")


def export_dashboard(dashboard_id: str, title: str):
    """Export a dashboard with all its dependencies."""
    auth = (ES_USER, ES_PASSWORD)
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    
    resp = requests.post(
        f"{KIBANA_URL}/api/saved_objects/_export",
        headers=headers,
        auth=auth,
        json={
            "objects": [{"type": "dashboard", "id": dashboard_id}],
            "includeReferencesDeep": True
        }
    )
    
    if resp.status_code == 200:
        safe_title = title.replace(" ", "_").replace("/", "-")
        filename = f"{safe_title}_current.ndjson"
        filepath = os.path.join(EXPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(resp.text)
        
        print(f"  ✓ Exported: {filepath}")
        return filepath
    else:
        print(f"  ✗ Failed: {resp.text[:200]}")
        return None


def main():
    print("Exporting current dashboards from Kibana...")
    print(f"Export directory: {EXPORT_DIR}\n")
    
    os.makedirs(EXPORT_DIR, exist_ok=True)
    
    # Export macOS dashboards
    dashboards = [
        ("macos-security-dashboard", "macOS_Security_Dashboard"),
        ("macos-comprehensive-security-dashboard", "macOS_Comprehensive_Security_Dashboard"),
    ]
    
    for dash_id, title in dashboards:
        print(f"Exporting: {title}")
        export_dashboard(dash_id, title)
    
    print("\nDone!")


if __name__ == "__main__":
    main()
