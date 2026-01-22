#!/usr/bin/env python3
"""
coreSigma - Unified Logging Sigma Rule Deployment Script

Converts UL Sigma rules to Kibana Detection Rules and deploys them.
Works with the FREE Elastic Basic license.

Usage:
    python deploy_ul_rules.py [--dry-run] [--enable] [--rules-dir PATH]
"""

import argparse
import os
import sys
import requests
from pathlib import Path

# Add parent directory and pysigma-pipeline-macos-ul to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "pysigma-pipeline-macos-ul"))

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.elasticsearch import LuceneBackend
except ImportError:
    print("ERROR: pySigma not installed. Run: pip install pysigma pysigma-backend-elasticsearch")
    sys.exit(1)

# Try to import the UL pipeline
try:
    from sigma.pipelines.ul import ecs_macos_ul
except ImportError:
    # Fallback: import directly from local path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "pysigma-pipeline-macos-ul" / "sigma" / "pipelines" / "ul"))
    from macos_ul import ecs_macos_ul

# Configuration
KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601")
ES_INDEX_PATTERN = os.getenv("ES_INDEX_UL", "macos-telemetry-ul-*")
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

# Authentication
def get_auth():
    """Get authentication credentials."""
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent / "collectors"))
        from auth import get_kibana_auth
        return get_kibana_auth()
    except (ImportError, Exception):
        es_user = os.getenv("ES_USER")
        es_password = os.getenv("ES_PASSWORD")
        if es_user and es_password:
            return (es_user, es_password)
        raise ValueError(
            "No authentication configured.\n"
            "Set ES_USER and ES_PASSWORD environment variables."
        )

ES_AUTH = None

# Severity mapping
SEVERITY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical"
}

RISK_SCORE_MAP = {
    "informational": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 99
}


def load_sigma_rules(rules_dir: Path) -> list:
    """Load all Sigma rules from a directory."""
    rules = []
    
    for yaml_file in rules_dir.rglob("*.yml"):
        try:
            with open(yaml_file, 'r') as f:
                content = f.read()
            
            collection = SigmaCollection.from_yaml(content)
            for rule in collection.rules:
                rules.append({
                    "file": yaml_file,
                    "rule": rule,
                    "content": content
                })
        except Exception as e:
            print(f"  Warning: Failed to parse {yaml_file.name}: {e}")
    
    return rules


def convert_sigma_to_lucene(sigma_rule, yaml_content: str) -> str:
    """Convert a Sigma rule to Lucene query using the macOS UL pipeline."""
    try:
        collection = SigmaCollection.from_yaml(yaml_content)
        backend = LuceneBackend(ecs_macos_ul())
        queries = backend.convert(collection)
        
        if queries:
            return queries[0]
        return None
    except Exception as e:
        print(f"    Conversion error: {e}")
        return None


def get_mitre_mapping(sigma_rule) -> list:
    """Extract MITRE ATT&CK mappings from Sigma rule tags."""
    threats = []
    tags = sigma_rule.tags if hasattr(sigma_rule, 'tags') else []
    
    tactics = {}
    techniques = []
    
    for tag in tags:
        tag_str = str(tag).lower()
        if tag_str.startswith("attack."):
            part = tag_str.replace("attack.", "")
            
            tactic_map = {
                "reconnaissance": ("TA0043", "Reconnaissance"),
                "resource_development": ("TA0042", "Resource Development"),
                "initial_access": ("TA0001", "Initial Access"),
                "execution": ("TA0002", "Execution"),
                "persistence": ("TA0003", "Persistence"),
                "privilege_escalation": ("TA0004", "Privilege Escalation"),
                "defense_evasion": ("TA0005", "Defense Evasion"),
                "credential_access": ("TA0006", "Credential Access"),
                "discovery": ("TA0007", "Discovery"),
                "lateral_movement": ("TA0008", "Lateral Movement"),
                "collection": ("TA0009", "Collection"),
                "command_and_control": ("TA0011", "Command and Control"),
                "exfiltration": ("TA0010", "Exfiltration"),
                "impact": ("TA0040", "Impact"),
            }
            
            if part in tactic_map:
                tactic_id, tactic_name = tactic_map[part]
                tactics[tactic_id] = {
                    "id": tactic_id,
                    "name": tactic_name,
                    "reference": f"https://attack.mitre.org/tactics/{tactic_id}/"
                }
            elif part.startswith("t") and len(part) >= 5:
                tech_id = part.upper()
                techniques.append({
                    "id": tech_id,
                    "name": tech_id,
                    "reference": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                })
    
    for tactic_id, tactic in tactics.items():
        threat_entry = {
            "framework": "MITRE ATT&CK",
            "tactic": tactic,
            "technique": techniques if techniques else []
        }
        threats.append(threat_entry)
    
    if techniques and not tactics:
        threats.append({
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": "TA0002",
                "name": "Execution",
                "reference": "https://attack.mitre.org/tactics/TA0002/"
            },
            "technique": techniques
        })
    
    return threats


def create_detection_rule(sigma_rule, lucene_query: str, file_path: Path) -> dict:
    """Create a Kibana Detection Rule payload from a Sigma rule."""
    
    title = sigma_rule.title if hasattr(sigma_rule, 'title') else "Unnamed Rule"
    description = sigma_rule.description if hasattr(sigma_rule, 'description') else ""
    level = str(sigma_rule.level).lower() if hasattr(sigma_rule, 'level') else "medium"
    author = sigma_rule.author if hasattr(sigma_rule, 'author') else ["coreSigma"]
    
    rule_id = f"coresigma-ul-{file_path.stem.replace(' ', '-').lower()}"
    
    tags = ["macos", "sigma", "unified-logging", "ul"]
    if hasattr(sigma_rule, 'tags'):
        for tag in sigma_rule.tags:
            tag_str = str(tag)
            if not tag_str.startswith("attack."):
                tags.append(tag_str)
    
    detection_rule = {
        "name": f"Sigma UL: {title}",
        "description": description or f"Sigma UL rule: {title}",
        "enabled": False,
        "risk_score": RISK_SCORE_MAP.get(level, 50),
        "severity": SEVERITY_MAP.get(level, "medium"),
        "type": "query",
        "query": lucene_query,
        "language": "lucene",
        "index": [ES_INDEX_PATTERN],
        "from": "now-6m",
        "to": "now",
        "interval": "5m",
        "tags": tags,
        "author": author if isinstance(author, list) else [author],
        "license": "Sigma Rule License",
        "rule_id": rule_id,
        "threat": get_mitre_mapping(sigma_rule),
        "references": [],
        "false_positives": [],
        "max_signals": 100,
    }
    
    if hasattr(sigma_rule, 'references') and sigma_rule.references:
        detection_rule["references"] = list(sigma_rule.references)
    
    if hasattr(sigma_rule, 'falsepositives') and sigma_rule.falsepositives:
        detection_rule["false_positives"] = list(sigma_rule.falsepositives)
    
    return detection_rule


def deploy_rule(rule_payload: dict, dry_run: bool = False) -> tuple:
    """Deploy a detection rule to Kibana."""
    
    if dry_run:
        return True, "Dry run - would create rule"
    
    rule_id = rule_payload.get("rule_id")
    resp = requests.get(
        f"{KIBANA_URL}/api/detection_engine/rules?rule_id={rule_id}",
        headers=HEADERS,
        auth=ES_AUTH
    )
    
    if resp.status_code == 200:
        existing = resp.json()
        rule_payload["id"] = existing.get("id")
        resp = requests.put(
            f"{KIBANA_URL}/api/detection_engine/rules",
            headers=HEADERS,
            json=rule_payload,
            auth=ES_AUTH
        )
        action = "updated"
    else:
        resp = requests.post(
            f"{KIBANA_URL}/api/detection_engine/rules",
            headers=HEADERS,
            json=rule_payload,
            auth=ES_AUTH
        )
        action = "created"
    
    if resp.status_code in [200, 201]:
        result = resp.json()
        return True, f"Rule {action}: {result.get('id')}"
    else:
        try:
            error = resp.json()
            return False, f"Error: {error.get('message', resp.text[:100])}"
        except (ValueError, KeyError):
            return False, f"Error: {resp.status_code} - {resp.text[:100]}"


def enable_rules(rule_ids: list) -> int:
    """Enable a list of rules by their IDs."""
    enabled_count = 0
    
    for rule_id in rule_ids:
        resp = requests.patch(
            f"{KIBANA_URL}/api/detection_engine/rules/_bulk_action",
            headers=HEADERS,
            json={
                "action": "enable",
                "query": "",
                "ids": [rule_id]
            },
            auth=ES_AUTH
        )
        
        if resp.status_code == 200:
            enabled_count += 1
    
    return enabled_count


def main():
    global KIBANA_URL, ES_AUTH
    
    parser = argparse.ArgumentParser(description="Deploy UL Sigma rules to Kibana Detection Engine")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually deploy")
    parser.add_argument("--enable", action="store_true", help="Enable rules after deployment")
    parser.add_argument("--rules-dir", type=str, default="rules/ul", help="Directory containing UL Sigma rules")
    parser.add_argument("--kibana-url", type=str, help=f"Kibana URL (default: {KIBANA_URL})")
    args = parser.parse_args()
    
    if args.kibana_url:
        KIBANA_URL = args.kibana_url
    
    # Load authentication
    try:
        ES_AUTH = get_auth()
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    
    print("=" * 60)
    print("coreSigma - Unified Logging Sigma Rule Deployment")
    print("=" * 60)
    print(f"\nKibana URL: {KIBANA_URL}")
    print(f"Rules directory: {args.rules_dir}")
    print(f"Index pattern: {ES_INDEX_PATTERN}")
    print(f"Dry run: {args.dry_run}")
    print(f"Enable after deploy: {args.enable}")
    
    # Check Kibana connectivity
    print("\nChecking Kibana connectivity...")
    try:
        resp = requests.get(f"{KIBANA_URL}/api/status", headers=HEADERS, auth=ES_AUTH, timeout=5)
        if resp.status_code != 200:
            print(f"ERROR: Cannot connect to Kibana at {KIBANA_URL}")
            sys.exit(1)
        print("  Connected to Kibana")
    except Exception as e:
        print(f"ERROR: Cannot connect to Kibana: {e}")
        sys.exit(1)
    
    # Load Sigma rules
    rules_path = Path(args.rules_dir)
    if not rules_path.exists():
        # Try relative to script directory
        rules_path = Path(__file__).parent.parent / args.rules_dir
    
    if not rules_path.exists():
        print(f"ERROR: Rules directory not found: {rules_path}")
        sys.exit(1)
    
    print(f"\nLoading UL Sigma rules from {rules_path}...")
    sigma_rules = load_sigma_rules(rules_path)
    print(f"  Found {len(sigma_rules)} Sigma rules")
    
    if not sigma_rules:
        print("No rules found. Exiting.")
        sys.exit(0)
    
    # Process each rule
    print("\nProcessing rules...")
    success_count = 0
    failed_count = 0
    deployed_ids = []
    
    for rule_info in sigma_rules:
        file_path = rule_info["file"]
        sigma_rule = rule_info["rule"]
        
        title = sigma_rule.title if hasattr(sigma_rule, 'title') else file_path.stem
        print(f"\n  [{title}]")
        
        yaml_content = rule_info["content"]
        lucene_query = convert_sigma_to_lucene(sigma_rule, yaml_content)
        if not lucene_query:
            print("    SKIP: Could not convert to Lucene query")
            failed_count += 1
            continue
        
        print(f"    Query: {lucene_query[:80]}...")
        
        rule_payload = create_detection_rule(sigma_rule, lucene_query, file_path)
        
        success, message = deploy_rule(rule_payload, args.dry_run)
        if success:
            print(f"    OK: {message}")
            success_count += 1
            if ":" in message:
                rule_id = message.split(":")[-1].strip()
                deployed_ids.append(rule_id)
        else:
            print(f"    FAIL: {message}")
            failed_count += 1
    
    # Enable rules if requested
    if args.enable and deployed_ids and not args.dry_run:
        print(f"\nEnabling {len(deployed_ids)} rules...")
        enabled = enable_rules(deployed_ids)
        print(f"  Enabled {enabled} rules")
    
    # Summary
    print("\n" + "=" * 60)
    print("DEPLOYMENT SUMMARY")
    print("=" * 60)
    print(f"  Total rules processed: {len(sigma_rules)}")
    print(f"  Successfully deployed: {success_count}")
    print(f"  Failed: {failed_count}")
    
    if not args.dry_run:
        print("\nView rules in Kibana:")
        print(f"  {KIBANA_URL}/app/security/rules")
    
    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
