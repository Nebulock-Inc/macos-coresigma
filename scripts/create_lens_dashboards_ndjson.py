#!/usr/bin/env python3
"""
Create Lens dashboards using NDJSON import - the most reliable method.

This approach:
1. Creates proper NDJSON structure matching Kibana's expected format
2. Uses the _import API which handles all the complexity
"""

import json
import os
import sys
import requests
import uuid
import tempfile
from datetime import datetime

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")
ES_URL = os.environ.get("ES_URL", "http://localhost:9200")


def get_auth():
    """Get authentication credentials using the auth module or environment."""
    # Try auth module first
    try:
        from collectors.auth import get_elasticsearch_auth, AuthenticationError
        api_key, basic_auth = get_elasticsearch_auth()
        if basic_auth:
            return basic_auth
        # If only API key, fall back to env vars for Kibana
    except (ImportError, Exception):
        pass
    
    # Fall back to environment variables (an API key alone isn't used for Kibana here)
    if os.environ.get("ES_USER") and os.environ.get("ES_PASSWORD"):
        return (os.environ["ES_USER"], os.environ["ES_PASSWORD"])
    sys.exit("No Elasticsearch credentials: set ES_USER and ES_PASSWORD, or store them with ./scripts/setup_credentials.sh")


def get_or_create_data_view():
    """Get or create the data view and return its ID."""
    auth = get_auth()
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    
    # Check existing data views
    try:
        resp = requests.get(f"{KIBANA_URL}/api/data_views", headers=headers, auth=auth, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"  Error connecting to Kibana: {e}")
        return None
    
    if resp.status_code == 401:
        print(f"  Authentication failed (401). Check your credentials.")
        print(f"  Run: ./scripts/setup_credentials.sh --sync-docker")
        return None
    
    if resp.status_code != 200:
        print(f"  Failed to get data views: {resp.status_code}")
        print(f"  Response: {resp.text[:500]}")
        return None
    
    # Parse response - handle both 'data_view' and 'data_views' keys
    data = resp.json()
    data_views = data.get("data_view", data.get("data_views", []))
    
    for dv in data_views:
        title = dv.get("title", "")
        if title == "macos-telemetry-*":  # not the ESF-only or UL-only views create_kibana_data_view.sh makes
            print(f"  Found existing data view: {title} (id: {dv.get('id')})")
            return dv.get("id")
    
    # No existing data view found - check if indices exist first
    try:
        es_resp = requests.get(f"{ES_URL}/macos-telemetry-*/_count", auth=auth, timeout=10)
        if es_resp.status_code == 404:
            print(f"  No macos-telemetry-* indices exist yet.")
            print(f"  Start a collector first to create indices:")
            print(f"    sudo /usr/bin/python3 collectors/esf_collector.py --output elasticsearch")
            return None
    except requests.exceptions.RequestException:
        pass
    
    # Create new data view
    print(f"  Creating new data view for macos-telemetry-*...")
    resp = requests.post(
        f"{KIBANA_URL}/api/data_views/data_view",
        headers=headers,
        auth=auth,
        timeout=10,
        json={
            "data_view": {
                "title": "macos-telemetry-*",
                "name": "macOS Telemetry Events",
                "timeFieldName": "@timestamp"
            }
        }
    )
    
    if resp.status_code in [200, 201]:
        data_view = resp.json().get("data_view", {})
        print(f"  Created data view: {data_view.get('id')}")
        return data_view.get("id")
    
    print(f"  Failed to create data view: {resp.status_code}")
    print(f"  Response: {resp.text[:500]}")
    return None


def create_lens_saved_object(vis_id: str, title: str, vis_type: str, layer_config: dict, data_view_id: str) -> dict:
    """Create a Lens saved object in NDJSON format."""
    layer_id = layer_config["layer_id"]
    
    return {
        "id": vis_id,
        "type": "lens",
        "version": "1",
        "coreMigrationVersion": "8.8.0",
        "typeMigrationVersion": "8.9.0",
        "managed": False,
        "attributes": {
            "title": title,
            "description": "",
            "visualizationType": vis_type,
            "state": {
                "visualization": layer_config["visualization"],
                "query": {"query": "", "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            layer_id: layer_config["layer"]
                        }
                    }
                },
                "internalReferences": [],
                "adHocDataViews": {}
            }
        },
        "references": [
            {
                "type": "index-pattern",
                "id": data_view_id,
                "name": f"indexpattern-datasource-layer-{layer_id}"
            }
        ]
    }


def create_metric_config(data_view_id: str) -> dict:
    """Create metric visualization config."""
    layer_id = str(uuid.uuid4())
    col_id = str(uuid.uuid4())
    
    return {
        "layer_id": layer_id,
        "visualization": {
            "layerId": layer_id,
            "layerType": "data",
            "metricAccessor": col_id
        },
        "layer": {
            "columnOrder": [col_id],
            "columns": {
                col_id: {
                    "label": "Count",
                    "dataType": "number",
                    "operationType": "count",
                    "isBucketed": False,
                    "scale": "ratio",
                    "sourceField": "___records___"
                }
            },
            "incompleteColumns": {}
        }
    }


def create_pie_config(field: str, top_n: int = 10) -> dict:
    """Create pie chart config."""
    layer_id = str(uuid.uuid4())
    bucket_col = str(uuid.uuid4())
    metric_col = str(uuid.uuid4())
    
    return {
        "layer_id": layer_id,
        "visualization": {
            "shape": "donut",
            "layers": [{
                "layerId": layer_id,
                "layerType": "data",
                "primaryGroups": [bucket_col],
                "metrics": [metric_col],
                "numberDisplay": "percent",
                "categoryDisplay": "default",
                "legendDisplay": "show",
                "nestedLegend": False
            }]
        },
        "layer": {
            "columnOrder": [bucket_col, metric_col],
            "columns": {
                bucket_col: {
                    "label": f"Top {top_n}",
                    "dataType": "string",
                    "operationType": "terms",
                    "scale": "ordinal",
                    "sourceField": field,
                    "isBucketed": True,
                    "params": {
                        "size": top_n,
                        "orderBy": {"type": "column", "columnId": metric_col},
                        "orderDirection": "desc",
                        "otherBucket": True,
                        "missingBucket": False
                    }
                },
                metric_col: {
                    "label": "Count",
                    "dataType": "number",
                    "operationType": "count",
                    "isBucketed": False,
                    "scale": "ratio",
                    "sourceField": "___records___"
                }
            },
            "incompleteColumns": {}
        }
    }


def create_timeline_config(split_field: str = None, top_n: int = 10) -> dict:
    """Create timeline (area chart) config."""
    layer_id = str(uuid.uuid4())
    date_col = str(uuid.uuid4())
    metric_col = str(uuid.uuid4())
    split_col = str(uuid.uuid4()) if split_field else None
    
    columns = {
        date_col: {
            "label": "@timestamp",
            "dataType": "date",
            "operationType": "date_histogram",
            "scale": "interval",
            "sourceField": "@timestamp",
            "isBucketed": True,
            "params": {"interval": "auto"}
        },
        metric_col: {
            "label": "Count",
            "dataType": "number",
            "operationType": "count",
            "isBucketed": False,
            "scale": "ratio",
            "sourceField": "___records___"
        }
    }
    column_order = [date_col]
    
    layer_viz = {
        "layerId": layer_id,
        "layerType": "data",
        "seriesType": "area_stacked",
        "accessors": [metric_col],
        "xAccessor": date_col
    }
    
    if split_field:
        columns[split_col] = {
            "label": split_field.split(".")[-1].replace(".keyword", ""),
            "dataType": "string",
            "operationType": "terms",
            "scale": "ordinal",
            "sourceField": split_field,
            "isBucketed": True,
            "params": {
                "size": top_n,
                "orderBy": {"type": "column", "columnId": metric_col},
                "orderDirection": "desc",
                "otherBucket": False,
                "missingBucket": False
            }
        }
        column_order.append(split_col)
        layer_viz["splitAccessor"] = split_col
    
    column_order.append(metric_col)
    
    return {
        "layer_id": layer_id,
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            "valueLabels": "hide",
            "preferredSeriesType": "area_stacked",
            "layers": [layer_viz]
        },
        "layer": {
            "columnOrder": column_order,
            "columns": columns,
            "incompleteColumns": {}
        }
    }


def create_table_config(fields: list, top_n: int = 20, ascending: bool = False) -> dict:
    """Create table config."""
    layer_id = str(uuid.uuid4())
    metric_col = str(uuid.uuid4())
    
    columns = {}
    column_order = []
    vis_columns = []
    
    for field in fields:
        col_id = str(uuid.uuid4())
        column_order.append(col_id)
        vis_columns.append({"columnId": col_id})
        columns[col_id] = {
            "label": field.split(".")[-1].replace(".keyword", ""),
            "dataType": "string",
            "operationType": "terms",
            "scale": "ordinal",
            "sourceField": field,
            "isBucketed": True,
            "params": {
                "size": top_n,
                "orderBy": {"type": "column", "columnId": metric_col},
                "orderDirection": "asc" if ascending else "desc",
                "otherBucket": False,
                "missingBucket": False
            }
        }
    
    column_order.append(metric_col)
    vis_columns.append({"columnId": metric_col})
    columns[metric_col] = {
        "label": "Count",
        "dataType": "number",
        "operationType": "count",
        "isBucketed": False,
        "scale": "ratio",
        "sourceField": "___records___"
    }
    
    return {
        "layer_id": layer_id,
        "visualization": {
            "layerId": layer_id,
            "layerType": "data",
            "columns": vis_columns
        },
        "layer": {
            "columnOrder": column_order,
            "columns": columns,
            "incompleteColumns": {}
        }
    }


def create_bar_config(field: str, top_n: int = 15, horizontal: bool = True) -> dict:
    """Create bar chart config."""
    layer_id = str(uuid.uuid4())
    bucket_col = str(uuid.uuid4())
    metric_col = str(uuid.uuid4())
    
    return {
        "layer_id": layer_id,
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            "valueLabels": "hide",
            "preferredSeriesType": "bar_horizontal" if horizontal else "bar",
            "layers": [{
                "layerId": layer_id,
                "layerType": "data",
                "seriesType": "bar_horizontal" if horizontal else "bar",
                "accessors": [metric_col],
                "xAccessor": bucket_col
            }]
        },
        "layer": {
            "columnOrder": [bucket_col, metric_col],
            "columns": {
                bucket_col: {
                    "label": field.split(".")[-1].replace(".keyword", ""),
                    "dataType": "string",
                    "operationType": "terms",
                    "scale": "ordinal",
                    "sourceField": field,
                    "isBucketed": True,
                    "params": {
                        "size": top_n,
                        "orderBy": {"type": "column", "columnId": metric_col},
                        "orderDirection": "desc",
                        "otherBucket": False,
                        "missingBucket": False
                    }
                },
                metric_col: {
                    "label": "Count",
                    "dataType": "number",
                    "operationType": "count",
                    "isBucketed": False,
                    "scale": "ratio",
                    "sourceField": "___records___"
                }
            },
            "incompleteColumns": {}
        }
    }


def create_dashboard_saved_object(dashboard_id: str, title: str, description: str, panels: list, vis_ids: list) -> dict:
    """Create a dashboard saved object."""
    # Build references matching Kibana's expected format: "{panelIndex}:panel_{panelIndex}"
    references = []
    for i, vis_id in enumerate(vis_ids):
        references.append({
            "type": "lens",
            "id": vis_id,
            "name": f"{i}:panel_{i}"
        })
    
    # Update panels to use matching panelRefName format
    updated_panels = []
    for panel in panels:
        updated_panel = panel.copy()
        # Extract panel index from the panelRefName (e.g., "panel_0" -> "0")
        if "panelRefName" in updated_panel:
            idx = updated_panel["panelRefName"].replace("panel_", "")
            updated_panel["panelRefName"] = f"panel_{idx}"
        updated_panels.append(updated_panel)
    
    return {
        "id": dashboard_id,
        "type": "dashboard",
        "version": "1",
        "coreMigrationVersion": "8.8.0",
        "typeMigrationVersion": "8.9.0",
        "managed": False,
        "attributes": {
            "title": title,
            "description": description,
            "version": 1,
            "panelsJSON": json.dumps(updated_panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True, "syncTooltips": False, "hidePanelTitles": False}),
            "refreshInterval": {"pause": True, "value": 60000},
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            }
        },
        "references": references
    }


def import_ndjson(objects: list, batch_name: str = "objects"):
    """Import objects using the Kibana import API."""
    auth = get_auth()
    
    # Create NDJSON content
    ndjson_lines = [json.dumps(obj) for obj in objects]
    ndjson_content = "\n".join(ndjson_lines)
    
    # Use multipart form upload
    with tempfile.NamedTemporaryFile(mode='w', suffix='.ndjson', delete=False) as f:
        f.write(ndjson_content)
        temp_path = f.name
    
    try:
        with open(temp_path, 'rb') as f:
            files = {'file': ('import.ndjson', f, 'application/ndjson')}
            resp = requests.post(
                f"{KIBANA_URL}/api/saved_objects/_import?overwrite=true",
                headers={"kbn-xsrf": "true"},
                auth=auth,
                files=files
            )
        
        if resp.status_code == 200:
            result = resp.json()
            if result.get("success"):
                return True, f"Imported {result.get('successCount', 0)} {batch_name}"
            else:
                errors = result.get("errors", [])
                error_details = []
                for err in errors[:3]:
                    error_details.append(f"{err.get('id')}: {err.get('error', {}).get('message', 'Unknown')}")
                return False, f"Errors: {'; '.join(error_details)}"
        else:
            return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
    finally:
        os.unlink(temp_path)


def main():
    print("=" * 70)
    print("Creating Lens Dashboards via NDJSON Import")
    print("=" * 70)
    print(f"Time: {datetime.now().isoformat()}")
    
    # Get data view
    print("\nGetting data view...")
    data_view_id = get_or_create_data_view()
    if not data_view_id:
        print("Cannot get/create data view!")
        sys.exit(1)
    print(f"  Data view ID: {data_view_id}")
    
    # Field names as the collectors write them; the index templates (setup_elasticsearch_templates.sh) map each
    # as keyword or wildcard, both aggregatable, so there are no .keyword subfields

    # ============================================================
    # Build all saved objects
    # ============================================================
    all_objects = []
    
    # --- Simple Dashboard Visualizations ---
    simple_vis = [
        ("lens-simple-total", "Total Events", "lnsMetric", create_metric_config(data_view_id)),
        ("lens-simple-actions", "Event Actions", "lnsPie", create_pie_config("event.action", 10)),
        ("lens-simple-users", "Users", "lnsPie", create_pie_config("user.name", 10)),
        ("lens-simple-timeline", "Events Over Time", "lnsXY", create_timeline_config("event.action", 8)),
        ("lens-simple-processes", "Top Processes", "lnsDatatable", create_table_config(["process.executable"], 15)),
    ]
    
    for vis_id, title, vis_type, config in simple_vis:
        obj = create_lens_saved_object(vis_id, title, vis_type, config, data_view_id)
        all_objects.append(obj)
    
    # Simple dashboard panels - updated layout from user export
    simple_panels = [
        {"type": "lens", "gridData": {"x": 0, "y": 0, "w": 12, "h": 12, "i": "0"}, "panelIndex": "0", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_0"},
        {"type": "lens", "gridData": {"x": 12, "y": 0, "w": 18, "h": 12, "i": "1"}, "panelIndex": "1", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_1"},
        {"type": "lens", "gridData": {"x": 30, "y": 0, "w": 18, "h": 12, "i": "2"}, "panelIndex": "2", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_2"},
        {"type": "lens", "gridData": {"x": 0, "y": 12, "w": 48, "h": 14, "i": "3"}, "panelIndex": "3", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_3"},
        {"type": "lens", "gridData": {"x": 0, "y": 26, "w": 48, "h": 12, "i": "4"}, "panelIndex": "4", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_4"},
    ]
    simple_vis_ids = [v[0] for v in simple_vis]
    
    simple_dashboard = create_dashboard_saved_object(
        "macos-security-overview-dashboard",  # not exports/'s macos-security-dashboard: importing one won't replace the other
        "macOS Security Dashboard (generated)",
        "Overview of macOS security events",
        simple_panels,
        simple_vis_ids
    )
    all_objects.append(simple_dashboard)
    
    # --- Comprehensive Dashboard Visualizations ---
    comp_vis = [
        ("lens-comp-total", "Total Events", "lnsMetric", create_metric_config(data_view_id)),
        ("lens-comp-categories", "Event Categories", "lnsPie", create_pie_config("event.category", 15)),
        ("lens-comp-actions", "Event Actions", "lnsPie", create_pie_config("event.action", 15)),
        ("lens-comp-users", "Users", "lnsPie", create_pie_config("user.name", 15)),
        ("lens-comp-groups", "Hosts", "lnsPie", create_pie_config("host.name", 15)),
        ("lens-comp-timeline", "Events Over Time", "lnsXY", create_timeline_config("event.action", 10)),
        ("lens-comp-event-types", "Event Types", "lnsPie", create_pie_config("event.type", 20)),
        ("lens-comp-security", "Security Events", "lnsXY", create_bar_config("event.action", 15)),
        ("lens-comp-cmdlines", "Top Command Lines", "lnsDatatable", create_table_config(["process.command_line"], 20)),
        ("lens-comp-executables", "Top Executables", "lnsDatatable", create_table_config(["process.executable"], 20)),
        ("lens-comp-parent-child", "Top Parent→Child Executables", "lnsDatatable", create_table_config(["process.parent.executable", "process.executable"], 15)),
        ("lens-comp-rare-exec", "Rare Executables", "lnsDatatable", create_table_config(["process.executable"], 30, ascending=True)),
        ("lens-comp-rare-proc", "Rare Users", "lnsDatatable", create_table_config(["user.name"], 30, ascending=True)),
        ("lens-comp-rare-cmd", "Rare Commands", "lnsDatatable", create_table_config(["process.command_line"], 30, ascending=True)),
        ("lens-comp-rare-parent", "Rare Parent→Child Executables", "lnsDatatable", create_table_config(["process.parent.executable", "process.executable"], 20, ascending=True)),
        ("lens-comp-files", "File Operations", "lnsXY", create_bar_config("file.path", 15)),
    ]
    
    for vis_id, title, vis_type, config in comp_vis:
        obj = create_lens_saved_object(vis_id, title, vis_type, config, data_view_id)
        all_objects.append(obj)
    
    # Comprehensive dashboard panels - updated layout from user export (2026-01-21)
    # Row 1: Total Events (0), Event Categories (1), Event Actions (2)
    # Row 2: Event Types (6), Users (3), Hosts (4)
    # Row 3: Events Over Time (5)
    # Row 4: Security Events (7)
    # Row 5: Top Command Lines (8), Top Executables (9)
    # Row 6: Parent → Child (10)
    # Row 7: Rare Executables (11), Rare Users (12)
    # Row 8: Rare Commands (13), Rare Parent→Child (14)
    # Row 9: File Operations (15)
    comp_panels = [
        # Row 1 - Overview metrics and pie charts
        {"type": "lens", "gridData": {"x": 0, "y": 0, "w": 8, "h": 14, "i": "0"}, "panelIndex": "0", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_0"},
        {"type": "lens", "gridData": {"x": 8, "y": 0, "w": 18, "h": 14, "i": "1"}, "panelIndex": "1", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_1"},
        {"type": "lens", "gridData": {"x": 26, "y": 0, "w": 22, "h": 14, "i": "2"}, "panelIndex": "2", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_2"},
        # Row 2 - Event Types, Users, Hosts
        {"type": "lens", "gridData": {"x": 0, "y": 14, "w": 16, "h": 12, "i": "6"}, "panelIndex": "6", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_6"},
        {"type": "lens", "gridData": {"x": 16, "y": 14, "w": 18, "h": 12, "i": "3"}, "panelIndex": "3", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_3"},
        {"type": "lens", "gridData": {"x": 34, "y": 14, "w": 14, "h": 12, "i": "4"}, "panelIndex": "4", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_4"},
        # Row 3 - Timeline
        {"type": "lens", "gridData": {"x": 0, "y": 26, "w": 48, "h": 12, "i": "5"}, "panelIndex": "5", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_5"},
        # Row 4 - Security Events bar chart
        {"type": "lens", "gridData": {"x": 0, "y": 38, "w": 48, "h": 12, "i": "7"}, "panelIndex": "7", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_7"},
        # Row 5 - Top Command Lines and Executables
        {"type": "lens", "gridData": {"x": 0, "y": 50, "w": 24, "h": 14, "i": "8"}, "panelIndex": "8", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_8"},
        {"type": "lens", "gridData": {"x": 24, "y": 50, "w": 24, "h": 14, "i": "9"}, "panelIndex": "9", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_9"},
        # Row 6 - Parent → Child
        {"type": "lens", "gridData": {"x": 0, "y": 64, "w": 48, "h": 14, "i": "10"}, "panelIndex": "10", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_10"},
        # Row 7 - Rare Executables, Rare Users
        {"type": "lens", "gridData": {"x": 0, "y": 78, "w": 35, "h": 14, "i": "11"}, "panelIndex": "11", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_11"},
        {"type": "lens", "gridData": {"x": 35, "y": 78, "w": 13, "h": 14, "i": "12"}, "panelIndex": "12", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_12"},
        # Row 8 - Rare Commands, Rare Parent→Child
        {"type": "lens", "gridData": {"x": 0, "y": 92, "w": 24, "h": 14, "i": "13"}, "panelIndex": "13", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_13"},
        {"type": "lens", "gridData": {"x": 24, "y": 92, "w": 24, "h": 14, "i": "14"}, "panelIndex": "14", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_14"},
        # Row 9 - File Operations
        {"type": "lens", "gridData": {"x": 0, "y": 106, "w": 48, "h": 12, "i": "15"}, "panelIndex": "15", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_15"},
    ]
    comp_vis_ids = [v[0] for v in comp_vis]
    
    comp_dashboard = create_dashboard_saved_object(
        "macos-endpoint-security-dashboard",
        "macOS Endpoint Security (ESF) Telemetry Overview (generated)",  # the export has the same title
        "Comprehensive security telemetry from macOS Endpoint Security Framework using Lens visualizations",
        comp_panels,
        comp_vis_ids
    )
    all_objects.append(comp_dashboard)
    
    # ============================================================
    # Import in batches for better error identification
    # ============================================================
    
    # Separate visualizations and dashboards
    vis_objects = [obj for obj in all_objects if obj.get("type") == "lens"]
    dash_objects = [obj for obj in all_objects if obj.get("type") == "dashboard"]
    
    print(f"\nImporting {len(vis_objects)} visualizations...")
    success, message = import_ndjson(vis_objects, "visualizations")
    failed = not success
    if success:
        print(f"  ✓ {message}")
    else:
        print(f"  ✗ {message}")
        # Try one by one to find the problem
        print("  Trying individual imports to identify problem...")
        for obj in vis_objects:
            s, m = import_ndjson([obj], f"viz {obj.get('id')}")
            if not s:
                print(f"    ✗ {obj.get('id')}: {m}")
    
    print(f"\nImporting {len(dash_objects)} dashboards...")
    success, message = import_ndjson(dash_objects, "dashboards")
    failed = failed or not success
    if success:
        print(f"  ✓ {message}")
    else:
        print(f"  ✗ {message}")
    if failed:
        sys.exit("Some saved objects failed to import (see above)")
    
    print("\n" + "=" * 70)
    print("Done! Refresh Kibana to see the dashboards.")
    print("=" * 70)


if __name__ == "__main__":
    main()
