#!/usr/bin/env python3
"""Export current dashboards from Kibana to see user changes.

Writes to $EXPORT_DIR (default ~/.coresigma/exports), outside the repository: an export carries your
dashboards' filters and queries, which can name your hosts and users. exports/ holds the shipped dashboards only.
"""

import os
import sys
import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "collectors"))
from auth import AuthenticationError, get_kibana_auth  # noqa: E402

KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")


def get_auth():
    """$ES_USER and $ES_PASSWORD, else the Keychain or ~/.coresigma/config.yml (collectors/auth.py)."""
    if os.environ.get("ES_USER") and os.environ.get("ES_PASSWORD"):
        return (os.environ["ES_USER"], os.environ["ES_PASSWORD"])
    try:
        return get_kibana_auth()
    except AuthenticationError:
        sys.exit("No Kibana credentials: set ES_USER and ES_PASSWORD, or store them with ./scripts/setup_credentials.sh")

EXPORT_DIR = os.environ.get("EXPORT_DIR", os.path.expanduser("~/.coresigma/exports"))


def export_dashboard(dashboard_id: str, title: str, auth):
    """Export a dashboard with all its dependencies."""
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
    auth = get_auth()
    print("Exporting current dashboards from Kibana...")
    print(f"Export directory: {EXPORT_DIR}\n")
    
    os.makedirs(EXPORT_DIR, mode=0o700, exist_ok=True)
    
    # Export macOS dashboards
    # the ids create_lens_dashboards_ndjson.py and exports/all_dashboards_latest.ndjson create
    dashboards = [
        ("macos-security-overview-dashboard", "macOS_Security_Dashboard"),
        ("macos-endpoint-security-dashboard", "macOS_Endpoint_Security_Dashboard"),
        ("macos-security-dashboard", "macOS_ESF_Telemetry_Overview"),
        ("macos-ul-dashboard", "macOS_Unified_Logging_Dashboard"),
        ("sigma-rules-dashboard", "Sigma_Rule_Triggers_Dashboard"),
    ]
    
    for dash_id, title in dashboards:
        print(f"Exporting: {title}")
        export_dashboard(dash_id, title, auth)
    
    print("\nDone!")


if __name__ == "__main__":
    main()
