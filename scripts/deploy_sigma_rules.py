#!/usr/bin/env python3
"""
coreSigma - Sigma Rule Deployment Script

Automatically converts Sigma rules to Kibana Detection Rules and deploys them.
Works with the FREE Elastic Basic license.

Usage:
    python deploy_sigma_rules.py [--dry-run] [--enable] [--rules-dir PATH]
"""

import argparse
import os
import sys
import requests
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.elasticsearch import EqlBackend, LuceneBackend
    from sigma.pipelines.elasticsearch import ecs_macos_esf
    from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
    from sigma.processing.transformations import FieldMappingTransformation
    from sigma.processing.conditions import LogsourceCondition
except ImportError:
    print("ERROR: pySigma not installed. Run: pip install pysigma pysigma-backend-elasticsearch")
    sys.exit(1)


def ecs_macos_ul() -> ProcessingPipeline:
    """
    Simple field mapping for macOS Unified Logging rules.
    Maps Sigma field names to the UL collector's field names.
    """
    field_mappings = {
        "subsystem": "ul.subsystem",
        "category": "ul.category",
        # message is used as-is (text field for full-text search)
    }
    
    return ProcessingPipeline(
        name="macOS Unified Logging (UL) field mappings",
        priority=30,
        items=[
            ProcessingItem(
                identifier="ecs_macos_ul_field_mapping",
                transformation=FieldMappingTransformation(field_mappings),
                rule_conditions=[
                    LogsourceCondition(product="macos", service="unifiedlog")
                ],
            ),
        ]
    )

# Configuration
KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601")
ES_INDEX_ESF = os.getenv("ES_INDEX_ESF", "macos-telemetry-esf-*")
ES_INDEX_UL = os.getenv("ES_INDEX_UL", "macos-telemetry-ul-*")
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

# Authentication - try to use centralized auth module
def get_auth():
    """Get authentication credentials."""
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent / "collectors"))
        from auth import get_kibana_auth
        return get_kibana_auth()
    except (ImportError, Exception):
        # Fallback to environment variables
        es_user = os.getenv("ES_USER")
        es_password = os.getenv("ES_PASSWORD")
        if es_user and es_password:
            return (es_user, es_password)
        raise ValueError(
            "No authentication configured.\n"
            "Set ES_USER and ES_PASSWORD environment variables, or configure via:\n"
            "  python collectors/auth.py store -u elastic"
        )

ES_AUTH = None  # Lazy-loaded

# Severity mapping from Sigma to Elastic
SEVERITY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical"
}

# Risk score mapping
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
            
            # Parse the Sigma rule
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


def fix_eql_numeric_fields(query: str) -> str:
    """Fix EQL queries to use == instead of : for numeric fields.
    
    EQL requires == for numeric comparisons, but pySigma generates : for all fields.
    This function converts known numeric fields from:
      - field:value to field == value
      - field like~ (1, 2, 3) to field in (1, 2, 3)
    """
    import re
    
    # Known numeric fields in ESF/UL telemetry
    numeric_fields = [
        'esf.event_type',
        'process.pid',
        'process.parent.pid',
        'process.user.id',
        'process.real_user.id',
        'process.group.id',
        'process.real_group.id',
        'user.id',
        'user.target.id',
        'destination.port',
        'source.port',
        'signal.number',
        'ptrace.request',
    ]
    
    result = query
    for field in numeric_fields:
        # Fix single value: field:123 -> field == 123
        pattern = rf'({re.escape(field)}):(\d+)'
        result = re.sub(pattern, r'\1 == \2', result)
        
        # Fix list of values: field like~ (1, 2, 3) -> field in (1, 2, 3)
        pattern = rf'{re.escape(field)} like~ \(([0-9,\s]+)\)'
        result = re.sub(pattern, rf'{field} in (\1)', result)
    
    return result


def convert_sigma_rule(sigma_rule, yaml_content: str, is_ul_rule: bool = False) -> tuple:
    """Convert a Sigma rule to query language.
    
    Args:
        sigma_rule: The parsed Sigma rule object
        yaml_content: The raw YAML content of the rule
        is_ul_rule: True if this is a Unified Logging rule, False for ESF
        
    Returns:
        tuple: (query_string, query_type, query_language)
            - For ESF: (eql_query, "eql", "eql")
            - For UL: (lucene_query, "query", "lucene")
    """
    try:
        # Parse the YAML content directly
        collection = SigmaCollection.from_yaml(yaml_content)
        
        if is_ul_rule:
            # UL rules use Lucene backend (supports text field queries like 'message')
            # with UL-specific field mapping
            backend = LuceneBackend(ecs_macos_ul())
            queries = backend.convert(collection)
            
            if queries:
                return (queries[0], "query", "lucene")
        else:
            # ESF rules use EQL backend with ECS macOS ESF pipeline
            backend = EqlBackend(ecs_macos_esf())
            queries = backend.convert(collection)
            
            if queries:
                # Fix numeric field comparisons for EQL compatibility
                return (fix_eql_numeric_fields(queries[0]), "eql", "eql")
        
        return (None, None, None)
    except Exception as e:
        print(f"    Conversion error: {e}")
        return (None, None, None)


def get_mitre_mapping(sigma_rule) -> list:
    """Extract MITRE ATT&CK mappings from Sigma rule tags."""
    threats = []
    
    tags = sigma_rule.tags if hasattr(sigma_rule, 'tags') else []
    
    # Parse attack.tXXXX and attack.tXXXX.XXX patterns
    tactics = {}
    techniques = []
    
    for tag in tags:
        tag_str = str(tag).lower()
        if tag_str.startswith("attack."):
            part = tag_str.replace("attack.", "").replace("-", "_")  # accept attack.defense-impairment style too
            
            # Tactic mapping
            tactic_map = {
                "reconnaissance": ("TA0043", "Reconnaissance"),
                "resource_development": ("TA0042", "Resource Development"),
                "initial_access": ("TA0001", "Initial Access"),
                "execution": ("TA0002", "Execution"),
                "persistence": ("TA0003", "Persistence"),
                "privilege_escalation": ("TA0004", "Privilege Escalation"),
                "stealth": ("TA0005", "Stealth"),
                "defense_impairment": ("TA0112", "Defense Impairment"),
                # Legacy pre-v19 tag. Defense Evasion was retired in ATT&CK v19; TA0005 is now Stealth.
                "defense_evasion": ("TA0005", "Stealth"),
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
                # Technique ID like t1059 or t1059.001
                tech_id = part.upper()
                techniques.append({
                    "id": tech_id,
                    "name": tech_id,  # Would need lookup for actual name
                    "reference": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                })
    
    # Build threat array
    for tactic_id, tactic in tactics.items():
        threat_entry = {
            "framework": "MITRE ATT&CK",
            "tactic": tactic,
            "technique": techniques if techniques else []
        }
        threats.append(threat_entry)
    
    # If we have techniques but no tactics, add a generic entry
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


def create_detection_rule(sigma_rule, query: str, query_type: str, query_language: str, file_path: Path) -> dict:
    """Create a Kibana Detection Rule payload from a Sigma rule.
    
    Args:
        sigma_rule: The parsed Sigma rule object
        query: The converted query string
        query_type: The Kibana rule type ("eql" or "query")
        query_language: The query language ("eql" or "lucene")
        file_path: Path to the Sigma rule file
    """
    # Get rule metadata
    title = sigma_rule.title if hasattr(sigma_rule, 'title') else "Unnamed Rule"
    description = sigma_rule.description if hasattr(sigma_rule, 'description') else ""
    level = str(sigma_rule.level).lower() if hasattr(sigma_rule, 'level') else "medium"
    author = sigma_rule.author if hasattr(sigma_rule, 'author') else ["coreSigma"]
    
    # Determine if this is a UL or ESF rule based on file path
    # Check if the directory name is "ul" (not just contains "ul")
    is_ul_rule = file_path.parent.name.lower() == "ul"
    
    # Create unique rule ID from file path (include ul- prefix for UL rules)
    rule_prefix = "coresigma-ul-" if is_ul_rule else "coresigma-"
    rule_id = f"{rule_prefix}{file_path.stem.replace(' ', '-').lower()}"
    
    # Get tags and index pattern based on rule type
    if is_ul_rule:
        tags = ["macos", "sigma", "unified-logging"]
        index_pattern = ES_INDEX_UL
    else:
        tags = ["macos", "sigma", "esf"]
        index_pattern = ES_INDEX_ESF
    
    if hasattr(sigma_rule, 'tags'):
        for tag in sigma_rule.tags:
            tag_str = str(tag)
            if not tag_str.startswith("attack."):
                tags.append(tag_str)
    
    # Build the detection rule
    detection_rule = {
        "name": f"Sigma: {title}",
        "description": description or f"Sigma rule: {title}",
        "enabled": False,  # Start disabled for safety
        "risk_score": RISK_SCORE_MAP.get(level, 50),
        "severity": SEVERITY_MAP.get(level, "medium"),
        "type": query_type,
        "query": query,
        "language": query_language,
        "index": [index_pattern],
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
    
    # Add references if available
    if hasattr(sigma_rule, 'references') and sigma_rule.references:
        detection_rule["references"] = list(sigma_rule.references)
    
    # Add false positives if available
    if hasattr(sigma_rule, 'falsepositives') and sigma_rule.falsepositives:
        detection_rule["false_positives"] = list(sigma_rule.falsepositives)
    
    return detection_rule


def deploy_rule(rule_payload: dict, dry_run: bool = False) -> tuple:
    """Deploy a detection rule to Kibana."""
    
    if dry_run:
        return True, "Dry run - would create rule"
    
    # Check if rule already exists
    rule_id = rule_payload.get("rule_id")
    resp = requests.get(
        f"{KIBANA_URL}/api/detection_engine/rules?rule_id={rule_id}",
        headers=HEADERS,
        auth=ES_AUTH
    )
    
    if resp.status_code == 200:
        # Rule exists, update it
        existing = resp.json()
        # For updates, use 'id' only, remove 'rule_id' to avoid conflict
        update_payload = rule_payload.copy()
        update_payload["id"] = existing.get("id")
        update_payload.pop("rule_id", None)  # Remove rule_id for updates
        resp = requests.put(
            f"{KIBANA_URL}/api/detection_engine/rules",
            headers=HEADERS,
            json=update_payload,
            auth=ES_AUTH
        )
        action = "updated"
    else:
        # Create new rule - use rule_id only
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
    
    parser = argparse.ArgumentParser(description="Deploy Sigma rules to Kibana Detection Engine")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually deploy, just show what would happen")
    parser.add_argument("--enable", action="store_true", help="Enable rules after deployment")
    parser.add_argument("--rules-dir", type=str, default="rules/esf", help="Directory containing Sigma rules")
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
    print("coreSigma - Sigma Rule Deployment")
    print("=" * 60)
    print(f"\nKibana URL: {KIBANA_URL}")
    print(f"Rules directory: {args.rules_dir}")
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
        print(f"ERROR: Rules directory not found: {rules_path}")
        sys.exit(1)
    
    print(f"\nLoading Sigma rules from {rules_path}...")
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
        
        # Determine if this is a UL rule based on file path
        # Check if the directory name is "ul" (not just contains "ul")
        is_ul_rule = file_path.parent.name.lower() == "ul"
        
        # Convert to query language
        # - ESF rules: EQL with ECS field mapping (for structured queries)
        # - UL rules: Lucene (supports text field queries on 'message')
        yaml_content = rule_info["content"]
        query, query_type, query_language = convert_sigma_rule(sigma_rule, yaml_content, is_ul_rule=is_ul_rule)
        if not query:
            print(f"    SKIP: Could not convert to {query_language or 'query'}")
            failed_count += 1
            continue
        
        print(f"    [{query_language.upper()}]: {query[:80]}...")
        
        # Create detection rule payload
        rule_payload = create_detection_rule(sigma_rule, query, query_type, query_language, file_path)
        
        # Deploy
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
