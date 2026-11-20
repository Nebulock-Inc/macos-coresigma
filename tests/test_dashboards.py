"""The shipped dashboard export loads in Kibana 8: each panel has an embeddableConfig, and its reference is named panelIndex:panelRefName."""
import json
from pathlib import Path

EXPORT = Path(__file__).resolve().parent.parent / "exports" / "all_dashboards_latest.ndjson"


def test_dashboard_panel_references_resolve():
    dashboards = [o for o in map(json.loads, EXPORT.read_text().splitlines()) if o.get("type") == "dashboard"]
    assert dashboards
    for dash in dashboards:
        names = {r["name"] for r in dash["references"]}
        for panel in json.loads(dash["attributes"]["panelsJSON"]):
            assert "embeddableConfig" in panel, (dash["id"], panel["panelIndex"])
            assert f"{panel['panelIndex']}:{panel['panelRefName']}" in names, (dash["id"], panel["panelIndex"])
