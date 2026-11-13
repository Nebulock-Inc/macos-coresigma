#!/usr/bin/env python3
"""
coreSigma - Sigma Rule Deployment Script

Converts the Sigma rules with the macOS plugin pipelines (macos_esf_ecs, macos_ul_ecs) and deploys them.

--target elastic (default): Kibana detection rules, created disabled; a redeploy keeps each rule's enabled state.
    Works with the free Elastic Basic license. Rules and temporal_ordered correlations (as EQL sequences) are EQL
    rules; the other correlations (temporal, event_count, value_count) are ES|QL rules.
--target splunk: writes the Splunk app splunk/coresigma_app: one saved search per rule (disabled, since
    Splunk Free has no alerting or scheduling) and a starter overview dashboard.

A correlation's base rules (generate: false) are deployed only inside it; a correlation the target's backend
can't convert is skipped with the reason.

Usage:
    python deploy_sigma_rules.py [--target elastic|splunk] [--dry-run] [--enable] [--rules-dir PATH]
"""

import argparse
import copy
import json
import os
import re
import sys
import tempfile
import requests
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
SPLUNK_APP = ROOT / "splunk" / "coresigma_app"

try:
    import sigma.data.mitre_attack as attack
    from sigma.backends.elasticsearch import EqlBackend, ESQLBackend
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationConditionOperator, SigmaCorrelationRule, SigmaCorrelationType
    from sigma.exceptions import SigmaError
    from sigma.pipelines.macos import macos_esf_ecs, macos_ul_ecs
except ImportError:
    print("ERROR: pySigma, its backends or the macOS plugin are not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

# Configuration
KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601")
ES_INDEX_ESF = os.getenv("ES_INDEX_ESF", "macos-telemetry-esf-*")
ES_INDEX_UL = os.getenv("ES_INDEX_UL", "macos-telemetry-ul-*")
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
INTERVAL = 300  # seconds between rule runs; a correlation's look-back and closed_windows() depend on it

# Authentication - try to use centralized auth module
def get_auth():
    """Get authentication credentials."""
    try:
        sys.path.insert(0, str(ROOT / "collectors"))
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


def fix_eql(query: str) -> str:
    """pySigma's EQL, fixed where Elasticsearch rejects it.

    EQL compares numbers with == and in; pySigma writes : and like~ for every field. For the documents'
    numeric fields (long in the index templates, Int64 in ClickHouse):
      - field:value to field == value
      - field like~ (1, 2, 3) to field in (1, 2, 3)
    In strings, a backslash must begin an EQL escape (\\\\, \\", \\', \\n, \\r, \\t, \\u): pySigma passes |re patterns
    as they are (\\. stays \\.) and escapes / as \\/ (Lucene's regex delimiter). \\/ becomes /, any other backslash
    that begins no EQL escape is doubled, so the regex gets it.
    """
    for field in ("signal.number", "memory.protection", "btm.item.type"):
        query = re.sub(rf'({re.escape(field)}):(\d+)', r'\1 == \2', query)
        query = re.sub(rf'{re.escape(field)} like~ \(([0-9,\s]+)\)', rf'{field} in (\1)', query)
    return re.sub(r'"(?:[^"\\]|\\.)*"', lambda string: re.sub(
        r"\\(.)", lambda e: "/" if e[1] == "/" else e[0] if e[1] in "\\\"'nrtu" else "\\" + e[0], string[0]), query)


class EqlSequenceBackend(EqlBackend):
    """EqlBackend that also converts temporal_ordered correlations, to an EQL sequence:

        sequence by <group-by> with maxspan=<timespan>s [any where <base rule 1>] [any where <base rule 2>] ...

    Other correlation types still raise NotImplementedError: EQL has no aggregation, and no unordered sequence.
    Base rules convert first (convert_rule), as for any correlation; a sequence needs all of them, in order.
    """
    correlation_methods = {"default": "EQL sequence (temporal_ordered only)"}

    def convert_correlation_temporal_ordered_rule(self, rule, output_format=None, method="default"):
        if rule.aliases.aliases:
            raise NotImplementedError("EQL sequence: correlation field aliases aren't supported")
        if (rule.condition.op, rule.condition.count) != (SigmaCorrelationConditionOperator.GTE, len(rule.rules)):
            raise NotImplementedError("EQL sequence: only a condition that needs every rule (the default) converts")
        steps = []
        for ref in rule.rules:
            if isinstance(ref.rule, SigmaCorrelationRule):
                raise NotImplementedError("EQL sequence: a step can't be a correlation")
            queries = ref.rule.get_conversion_result()
            steps.append(queries[0] if len(queries) == 1 else " or ".join(f"({q})" for q in queries))
        by = f" by {', '.join(rule.group_by)}" if rule.group_by else ""
        return [f"sequence{by} with maxspan={rule.timespan.seconds}s" + "".join(f" [any where {s}]" for s in steps)]

    def finalize_query_default(self, rule, query, index, state):
        # the base class puts "any where " in front of every query; a sequence is a whole query already
        return query if isinstance(rule, SigmaCorrelationRule) else super().finalize_query_default(rule, query, index, state)


def correlation_fallback(rule, target: str):
    """A correlation with its declared fallback for target applied: (rule to convert, note), or (None, why not).

    `custom.coresigma.<target>` in the rule names a correlation type the backend converts in place of the
    rule's own (e.g. temporal for temporal_ordered), or `unsupported`. The fallback converts a copy; the rule
    itself is unchanged.
    """
    fallback = rule.custom_attributes.get("custom", {}).get("coresigma", {}).get(target)
    if fallback is None:
        return rule, None
    if fallback == "unsupported":
        return None, f"declared unsupported on {target} (custom.coresigma.{target})"
    try:
        fallback_type = SigmaCorrelationType[fallback.upper().replace("-", "_")]
    except KeyError:
        raise ValueError(f"{rule.title}: custom.coresigma.{target}: {fallback!r} is no correlation type") from None
    converted = copy.copy(rule)  # shares the resolved base rules and their queries
    converted.type = fallback_type
    original = rule.type.name.lower()
    return converted, (f"fallback: converted as {fallback} (custom.coresigma.{target}), not {original}"
                       + (": unordered, any order of the rules matches" if original == "temporal_ordered" else ""))


def convert_rules(target: str, collection) -> list:
    """(rule, query, note) for each rule with output of its own, converted for target: note is None, or says which
    declared fallback produced the query; (rule, None, why not) if it didn't convert.

    elastic: EQL for ESF and UL rules, case-insensitive like Sigma (Lucene wildcards on the templates' wildcard/keyword
    fields are case-sensitive), and temporal_ordered correlations as EQL sequences (EqlSequenceBackend); the other
    correlations as ES|QL (a query that starts with `from`), whose plain strings match case-sensitively. A correlation
    neither converts gets both reasons. splunk: SPL, correlations included.
    Base rules convert before the correlations that use their results; a correlation's base rule with
    generate: false converts to nothing and is left out. Correlations get their declared fallback.
    """
    pipeline = macos_esf_ecs() + macos_ul_ecs()
    if target != "elastic":
        return _convert(SplunkBackend(pipeline), target, collection.rules)
    # ES|QL converts only the correlations and their base rules, on a copy: conversion applies the pipeline to the
    # rules in place, and stores each base rule's query on it
    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    bases = {id(ref.rule) for c in correlations for ref in c.rules}
    rules = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule) or id(r) in bases]
    original = dict(zip(map(id, copied := copy.deepcopy(rules)), rules))
    esql = {id(original[id(rule)]): (rule, query, note)
            for rule, query, note in _convert(ESQLBackend(pipeline), target, copied)}
    results = []
    for rule, query, note in _convert(EqlSequenceBackend(pipeline), target, collection.rules):
        if query is None and isinstance(rule, SigmaCorrelationRule):
            esql_rule, esql_query, esql_note = esql[id(rule)]
            rule, query, note = (esql_rule, esql_query, esql_note) if esql_query else (
                rule, None, note if note == esql_note else f"EQL: {note}; ES|QL: {esql_note}")
        results.append((rule, query, note))
    return results


def _convert(backend, target: str, rules) -> list:
    """convert_rules' results for one backend."""
    results = []
    for rule in sorted(rules, key=lambda r: isinstance(r, SigmaCorrelationRule)):
        note = None
        try:
            if isinstance(rule, SigmaCorrelationRule):
                converted, note = correlation_fallback(rule, target)
                if converted is None:
                    results.append((rule, None, note))
                    continue
                queries = backend.convert_correlation_rule(converted)
            else:
                queries = backend.convert_rule(rule)
        except (SigmaError, NotImplementedError) as e:
            results.append((rule, None, str(e)))
            continue
        if queries:  # shortcut: one query per rule (every rule has one condition); join them if one ever has more
            results.append((rule, fix_eql(queries[0]) if isinstance(backend, EqlBackend) else queries[0], note))
    return results


def _attack_entry(technique_id: str) -> dict:
    return {"id": technique_id, "name": attack.mitre_attack_techniques[technique_id],
            "reference": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"}


def get_mitre_mapping(sigma_rule) -> list:
    """Elastic `threat` entries from the rule's ATT&CK technique tags, using pySigma's ATT&CK data.

    Tactics come from the techniques: each technique goes under each of its own ATT&CK tactics, never under
    another tactic the rule names, and a tactic tag adds nothing. A technique appears once per tactic, its
    tagged sub-techniques under it. Raises ValueError on a tactic or technique that ATT&CK doesn't have.
    """
    tactic_ids = {name: tid for tid, name in attack.mitre_attack_tactics.items()}
    techniques_of = {}  # tactic name -> {technique id: [sub-technique ids]}, in tag order
    for tag in sigma_rule.tags:
        if tag.namespace != "attack":
            continue
        name = tag.name.lower()
        if re.fullmatch(r"t\d{4}(\.\d{3})?", name):
            technique = name.upper()
            if technique not in attack.mitre_attack_techniques_tactics_mapping:
                raise ValueError(f"{sigma_rule.title}: unknown ATT&CK technique {technique}")
            parent = technique.split(".")[0]
            for tactic in attack.mitre_attack_techniques_tactics_mapping[technique]:
                subtechniques = techniques_of.setdefault(tactic, {}).setdefault(parent, [])
                if technique != parent and technique not in subtechniques:
                    subtechniques.append(technique)
        elif not re.fullmatch(r"[gs]\d{4}", name) and name not in tactic_ids:  # groups, software: not in `threat`
            raise ValueError(f"{sigma_rule.title}: unknown ATT&CK tactic {name}")
    return [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": tactic_ids[tactic],
                "name": " ".join(w if w == "and" else w.capitalize() for w in tactic.split("-")),
                "reference": f"https://attack.mitre.org/tactics/{tactic_ids[tactic]}/",
            },
            "technique": [
                {**_attack_entry(parent), **({"subtechnique": [_attack_entry(t) for t in subs]} if subs else {})}
                for parent, subs in techniques.items()
            ],
        }
        for tactic, techniques in techniques_of.items()
    ]


def closed_windows(timespan: int) -> str:
    """The where line that has an ES|QL correlation alert on each of its fixed windows (timebucket) once. Kibana gives
    an aggregating ES|QL alert a new id on every run, so a window would alert on every run whose look-back holds it.
    Each run takes the windows that closed 1 to 1 + INTERVAL/60 minutes ago, so consecutive runs INTERVAL apart take
    each window once, up to timespan + 6 minutes after it opened."""
    return (f"\n| where timebucket > now() - {timespan + 60 + INTERVAL} seconds"
            f" and timebucket <= now() - {timespan + 60} seconds")


def create_detection_rule(sigma_rule, query: str) -> dict:
    """A Kibana detection rule payload, created disabled, from a Sigma rule and its query: an EQL rule, or an ES|QL
    rule for an ES|QL query (it starts with `from`, which no EQL query does). A correlation runs on its base rules'
    indices and looks back its timespan more than a rule does, so a chain that ends in a run's 5 minutes is whole."""
    title = sigma_rule.title
    description = sigma_rule.description
    level = str(sigma_rule.level).lower() if sigma_rule.level else "medium"
    author = sigma_rule.author or ["coreSigma"]
    file_path = Path(sigma_rule.source.path)
    correlation = isinstance(sigma_rule, SigmaCorrelationRule)
    base = [ref.rule for ref in sigma_rule.rules] if correlation else [sigma_rule]  # the rules that pick out events
    esf = any(r.logsource.service != "unifiedlog" for r in base)
    ul = any(r.logsource.service == "unifiedlog" for r in base)

    # Create unique rule ID from file path (include ul- prefix for UL rules)
    rule_prefix = "coresigma-ul-" if ul and not esf else "coresigma-"
    rule_id = f"{rule_prefix}{file_path.stem.replace(' ', '-').lower()}"

    # Tags and index patterns from the documents the rule runs on
    tags, indices = ["macos", "sigma"], []
    if esf:
        tags.append("esf")
        indices.append(ES_INDEX_ESF)
    if ul:
        tags.append("unified-logging")
        indices.append(ES_INDEX_UL)
    if correlation:
        tags.append("correlation")

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
        "type": "eql",
        "query": query,
        "language": "eql",
        "index": indices,
        "from": f"now-{sigma_rule.timespan.seconds + 60 + INTERVAL}s" if correlation else "now-6m",
        "to": "now",
        "interval": f"{INTERVAL // 60}m",
        "tags": tags,
        "author": author if isinstance(author, list) else [author],
        "license": "Sigma Rule License",
        "rule_id": rule_id,
        "threat": get_mitre_mapping(sigma_rule),
        "references": [],
        "false_positives": [],
        "max_signals": 100,
    }
    
    if query.startswith("from "):  # ES|QL names its indices in the query
        query = re.sub(r"^from \*", f"from {','.join(indices)}", query)
        detection_rule.update(type="esql", language="esql", query=query + closed_windows(sigma_rule.timespan.seconds)
                              if correlation else query)
        del detection_rule["index"]

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
    
    existing = resp.json() if resp.status_code == 200 else None
    backup = None
    if existing and existing.get("type") != rule_payload.get("type"):
        # Kibana can't change a rule's type in place (1.x deployed Lucene query rules): export the old rule (with its
        # exceptions and actions), delete it, then create the new one below; a failed create re-imports the export
        backup = requests.post(f"{KIBANA_URL}/api/detection_engine/rules/_export?exclude_export_details=true",
                               headers=HEADERS, json={"objects": [{"rule_id": rule_id}]}, auth=ES_AUTH)
        gone = backup if backup.status_code != 200 else requests.delete(
            f"{KIBANA_URL}/api/detection_engine/rules?id={existing.get('id')}", headers=HEADERS, auth=ES_AUTH)
        if gone.status_code != 200:
            return False, f"Error: can't replace {existing.get('type')} rule {rule_id}: HTTP {gone.status_code}"
        rule_payload = {**rule_payload, "enabled": existing.get("enabled", False)}
        action = f"replaced (was {existing.get('type')}; Kibana gives it a new id)"
        existing = None

    if existing:
        # Rule exists, update it
        # For updates, use 'id' only, remove 'rule_id' to avoid conflict
        update_payload = rule_payload.copy()
        update_payload["id"] = existing.get("id")
        update_payload["enabled"] = existing.get("enabled", False)  # a redeploy doesn't switch rules on or off
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
        action = action if backup is not None else "created"

    if backup is not None and resp.status_code not in [200, 201]:
        restored = requests.post(f"{KIBANA_URL}/api/detection_engine/rules/_import?overwrite=true",
                                 headers={"kbn-xsrf": "true"}, files={"file": (f"{rule_id}.ndjson", backup.content)},
                                 auth=ES_AUTH)
        if restored.status_code == 200 and restored.json().get("success"):
            return False, f"Error: the new rule was rejected, the old one restored: HTTP {resp.status_code} - {resp.text[:200]}"
        saved = Path(tempfile.gettempdir()) / f"{rule_id}.ndjson"
        saved.write_bytes(backup.content)
        return False, (f"Error: the new rule was rejected (HTTP {resp.status_code} - {resp.text[:200]}) and the old one "
                       f"couldn't be restored (HTTP {restored.status_code}); its export is {saved}: import it in Kibana")
    
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
    """Enable rules by their Kibana ids in one bulk action. Returns how many Kibana enabled; prints the reply if
    it isn't 2xx (Kibana answers 500, with per-rule errors in the body, when some fail)."""
    resp = requests.post(
        f"{KIBANA_URL}/api/detection_engine/rules/_bulk_action",
        headers=HEADERS,
        json={"action": "enable", "ids": rule_ids},
        auth=ES_AUTH
    )
    if not resp.ok:
        print(f"  ERROR: enable: HTTP {resp.status_code}: {resp.text[:2000]}")
    try:
        return resp.json()["attributes"]["summary"]["succeeded"]
    except (ValueError, KeyError, TypeError):
        return 0


OVERVIEW_VIEW = """<form version="1.1">
  <label>coreSigma overview</label>
  <fieldset submitButton="false">
    <input type="time" token="window">
      <label>Time range</label>
      <default><earliest>-24h@h</earliest><latest>now</latest></default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Events by event.action</title>
      <chart>
        <search><query>index=macos | stats count by event.action | sort - count</query>
          <earliest>$window.earliest$</earliest><latest>$window.latest$</latest></search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <title>Top process.executable</title>
      <table>
        <search><query>index=macos | top limit=20 process.executable</query>
          <earliest>$window.earliest$</earliest><latest>$window.latest$</latest></search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Rule hits (each coreSigma saved search, run over the time range)</title>
      <table>
        <search><query>{hits}</query>
          <earliest>$window.earliest$</earliest><latest>$window.latest$</latest></search>
      </table>
    </panel>
  </row>
</form>
"""


def splunk_search(query: str) -> str:
    """An SPL query on one line, scoped to index=macos: in front of a plain search, else in each subsearch of the
    | multisearch a multi-rule correlation starts with (it has to be the first command)."""
    query = query.replace("\n", " ")
    return query.replace("[ search ", "[ search index=macos ") if query.startswith("|") else "index=macos " + query


def write_splunk_app(results: list, app_dir: Path) -> int:
    """Write the app's default/savedsearches.conf, one disabled saved search per converted rule (Splunk Free has
    no alerting or scheduling), and its overview dashboard. Returns the number of saved searches."""
    searches = [(f"coreSigma: {rule.title}", splunk_search(query), note) for rule, query, note in results if query]
    default = Path(app_dir) / "default"
    (default / "data" / "ui" / "views").mkdir(parents=True, exist_ok=True)
    (default / "savedsearches.conf").write_text("".join(
        (f"# {note}\n" if note else "") + f"[{name}]\nsearch = {search}\ncron_schedule = */5 * * * *\ndisabled = 1\n\n"
        for name, search, note in searches))
    per_rule = [f"{'' if search.startswith('|') else 'search '}{search} | stats count as hits | eval rule={json.dumps(name)}"
                for name, search, _ in searches]
    hits = per_rule[0] + "".join(f"\n| append [{q}]" for q in per_rule[1:]) + "\n| sort - hits | table rule hits"
    (default / "data" / "ui" / "views" / "coresigma_overview.xml").write_text(OVERVIEW_VIEW.replace("{hits}", escape(hits)))
    return len(searches)


def main():
    global KIBANA_URL, ES_AUTH
    
    parser = argparse.ArgumentParser(description="Deploy Sigma rules to Kibana's detection engine or a Splunk app")
    parser.add_argument("--target", choices=["elastic", "splunk"], default="elastic",
                        help="elastic (default): Kibana detection rules; splunk: write splunk/coresigma_app")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually deploy, just show what would happen")
    parser.add_argument("--enable", action="store_true", help="Enable rules after deployment")
    parser.add_argument("--rules-dir", type=str, default=str(ROOT / "rules"),
                        help="Directory of Sigma rules, searched recursively (default: rules/)")
    parser.add_argument("--kibana-url", type=str, help=f"Kibana URL (default: {KIBANA_URL})")
    args = parser.parse_args()
    
    if args.kibana_url:
        KIBANA_URL = args.kibana_url
    
    print("=" * 60)
    print("coreSigma - Sigma Rule Deployment")
    print("=" * 60)
    print(f"\nTarget: {args.target}")
    print(f"Rules directory: {args.rules_dir}")
    print(f"Dry run: {args.dry_run}")
    
    # Load Sigma rules
    rules_path = Path(args.rules_dir)
    if not rules_path.exists():
        print(f"ERROR: Rules directory not found: {rules_path}")
        sys.exit(1)
    
    print(f"\nLoading Sigma rules from {rules_path}...")
    try:
        collection = SigmaCollection.load_ruleset([rules_path])  # resolves correlations' rule references
    except SigmaError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    print(f"  Found {len(collection.rules)} Sigma rules")
    
    if not collection.rules:
        print("No rules found. Exiting.")
        sys.exit(0)
    
    results = convert_rules(args.target, collection)
    failed_count = skipped_count = 0
    for rule, query, note in results:
        if query is None and isinstance(rule, SigmaCorrelationRule):
            print(f"  SKIP [{rule.title}]: correlation not converted for {args.target}: {note}")
            skipped_count += 1
        elif query is None:
            print(f"  FAIL [{rule.title}]: {note}")
            failed_count += 1
        elif note:
            print(f"  NOTE [{rule.title}]: {note}")
    
    if args.target == "splunk":
        if args.dry_run:
            print(f"\nDry run: would write {len(results) - failed_count - skipped_count} saved searches to {SPLUNK_APP}")
        else:
            written = write_splunk_app(results, SPLUNK_APP)
            print(f"\nWrote {written} saved searches and the overview dashboard to {SPLUNK_APP}")
        return 0 if failed_count == 0 else 1
    
    # Load authentication
    try:
        ES_AUTH = get_auth()
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    
    print(f"\nKibana URL: {KIBANA_URL}")
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
    
    # Deploy each converted rule
    print("\nProcessing rules...")
    success_count = 0
    deployed_ids = []
    
    for sigma_rule, query, _ in results:
        if query is None:
            continue
        print(f"\n  [{sigma_rule.title}]")
        try:
            rule_payload = create_detection_rule(sigma_rule, query)
        except ValueError as e:  # an ATT&CK tag ATT&CK doesn't have
            print(f"    FAIL: {e}")
            failed_count += 1
            continue
        print(f"    [{rule_payload['language'].upper()}]: {rule_payload['query'][:80]}...")
        
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
        print(f"  Enabled {enabled} of {len(deployed_ids)} rules")
        failed_count += len(deployed_ids) - enabled
    
    # Summary
    print("\n" + "=" * 60)
    print("DEPLOYMENT SUMMARY")
    print("=" * 60)
    print(f"  Total rules processed: {len(results)}")
    print(f"  Successfully deployed: {success_count}")
    print(f"  Skipped (correlations {args.target} can't convert): {skipped_count}")
    print(f"  Failed: {failed_count}")
    
    if not args.dry_run:
        print("\nView rules in Kibana:")
        print(f"  {KIBANA_URL}/app/security/rules")
    
    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
