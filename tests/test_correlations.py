"""Correlation rules: exact definitions, named base rules, and conversion per backend support."""
import copy
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pytest
import yaml
from sigma.backends.crowdstrike import LogScaleBackend
from sigma.backends.elasticsearch import EqlBackend, ESQLBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationTimespan
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.macos import macos_esf_ecs, macos_falcon, macos_ul_ecs

from tests.test_ul_collector import categories_of

try:
    from sigma.backends.clickhouse import ClickhouseBackend
except ImportError:  # optional: requirements-clickhouse.txt (Python 3.13+)
    ClickhouseBackend = None
needs_clickhouse = pytest.mark.skipif(ClickhouseBackend is None, reason="pysigma-backend-clickhouse not installed "
                                      "(requirements-clickhouse.txt, Python 3.13+)")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collectors"))
sys.path.insert(0, str(ROOT / "scripts"))
from deploy_sigma_rules import EqlSequenceBackend  # noqa: E402
from esf_collector import ESFCollector  # noqa: E402
from outputs import _epoch  # noqa: E402
from ul_collector import ULCollector  # noqa: E402

RULES = {p: yaml.safe_load(p.read_text()) for p in sorted((ROOT / "rules").rglob("*.yml"))}
NAMES = Counter(r["name"] for r in RULES.values() if "name" in r)
BY_NAME = {r["name"]: r for r in RULES.values() if "name" in r}
CORRELATIONS = {p.stem: r for p, r in RULES.items() if "correlation" in r}

HOST_USER = ["host.name", "user.name"]
EXPECTED = {  # type, timespan, rules, group-by
    "paste_to_stealer": ("temporal_ordered", "15m", [
        "terminal_or_scripteditor_download_exec", "credential_capture_any", "launch_persistence_or_ditto_staging"], HOST_USER),
    "gatekeeper_evasion_staging": ("temporal_ordered", "30m", [
        "quarantine_removed", "adhoc_codesign", "apple_named_launchagent_or_partition_list_or_btm_kill"], HOST_USER),
    "package_manager_persistence": ("temporal", "30m", [
        "node_npm_spawns_shell", "launchagent_or_apple_binary_or_agent_config_write"], HOST_USER),
    "credential_path_fanout": ("value_count", "5m", ["credential_file_access"], ["host.name", "process.pid"]),
    "hidden_prompt_keychain_activity": ("temporal", "1m", [  # ESF + UL
        "osascript_hidden_answer_dialog", "osascript_securityd_log"], ["host.name", "process.pid", "process.executable"]),
}


def collection(corr):
    """The correlation plus the base rules it references."""
    return SigmaCollection.from_dicts(copy.deepcopy([BY_NAME[n] for n in corr["correlation"]["rules"]] + [corr]))


def pipeline():
    """ESF and UL, as deploy_sigma_rules.py converts: each base rule takes its own source's mapping."""
    return macos_esf_ecs() + macos_ul_ecs()


def custom(corr, backend):
    return ((corr.get("custom") or {}).get("coresigma") or {}).get(backend)


@pytest.mark.parametrize("stem", EXPECTED)
def test_correlation_definition_exact(stem):
    c = CORRELATIONS[stem]["correlation"]
    assert (c["type"], c["timespan"], c["rules"], c["group-by"]) == EXPECTED[stem]
    if c["type"] == "value_count":
        assert c["condition"] == {"field": "file.path", "gte": 3}


def test_base_rules_generate_false():
    """Every correlation sets generate: false; every rule it references exists once under that name."""
    for stem, corr in CORRELATIONS.items():
        assert corr["correlation"].get("generate") is False, stem
        for name in corr["correlation"]["rules"]:
            assert NAMES[name] == 1, f"{stem}: base rule {name} found {NAMES[name]} times"


@pytest.mark.parametrize("stem", EXPECTED)
def test_correlations_convert_splunk(stem):
    corr = CORRELATIONS[stem]
    if corr["correlation"]["type"] == "temporal_ordered":
        with pytest.raises(NotImplementedError, match="temporal_ordered"):
            SplunkBackend(pipeline()).convert(collection(corr))
        assert custom(corr, "splunk") == "temporal"
        corr = copy.deepcopy(corr)
        corr["correlation"]["type"] = "temporal"  # the fallback the matrix tool applies
    [query] = SplunkBackend(pipeline()).convert(collection(corr))  # base rules aren't generated
    group_by = " ".join(EXPECTED[stem][3])
    assert f"by _time {group_by}" in query
    if stem == "credential_path_fanout":
        assert "dc(file.path) as value_count" in query and "value_count >= 3" in query
    else:
        assert all(f'eval event_type="{n}"' in query for n in EXPECTED[stem][2])
        assert query.count("[ search ") == len(EXPECTED[stem][2])  # one | multisearch leg per base rule
        assert f"event_type_count >= {len(EXPECTED[stem][2])}" in query


ORDERED = [s for s, e in EXPECTED.items() if e[0] == "temporal_ordered"]


@pytest.mark.parametrize("stem", ORDERED)
def test_ordered_correlations_eql_sequence(stem):
    """temporal_ordered is an EQL sequence: by the group-by fields, maxspan the timespan in seconds, and one step per
    base rule in the rule's order, each step that base rule's own EQL."""
    _, timespan, names, group_by = EXPECTED[stem]
    [query] = EqlSequenceBackend(pipeline()).convert(collection(CORRELATIONS[stem]))
    steps = [EqlBackend(pipeline()).convert(SigmaCollection.from_dicts([copy.deepcopy(BY_NAME[n])]))[0] for n in names]
    assert query == (f"sequence by {', '.join(group_by)} with maxspan={SigmaCorrelationTimespan(timespan).seconds}s "
                     + " ".join(f"[{step}]" for step in steps))


TWO_RULES = """
title: a
name: rule_a
logsource: {product: macos, category: process_creation}
detection: {sel: {Image|endswith: /curl}, condition: sel}
---
title: b
name: rule_b
logsource: {product: macos, category: file_event}
detection: {sel: {TargetFilename|contains: /LaunchAgents/}, condition: sel}
---
title: c
"""


@pytest.mark.parametrize("correlation,error", [
    ("{type: temporal, rules: [rule_a, rule_b], group-by: [host.name], timespan: 1m}", "'temporal' is not supported"),
    ("{type: event_count, rules: [rule_a], group-by: [host.name], timespan: 1m, condition: {gt: 3}}", "'event_count'"),
    ("{type: temporal_ordered, rules: [rule_a, rule_b], group-by: [host.name], timespan: 1m, condition: {gte: 1}}",
     "needs every rule"),
    ("{type: temporal_ordered, rules: [rule_a, rule_b], group-by: [pid], timespan: 1m, "
     "aliases: {pid: {rule_a: ProcessId, rule_b: ProcessId}}}", "aliases"),
])
def test_eql_sequence_only_what_it_expresses(correlation, error):
    """EQL has no aggregation or unordered sequence; a sequence needs every step, joined on the same fields."""
    with pytest.raises(NotImplementedError, match=error):
        EqlSequenceBackend(pipeline()).convert(SigmaCollection.from_yaml(TWO_RULES + "correlation: " + correlation))


def test_eql_sequence_maps_group_by():
    """The pipeline maps the group-by fields (ProcessId: process.pid); a timespan in seconds stays exact."""
    [query] = EqlSequenceBackend(pipeline()).convert(SigmaCollection.from_yaml(
        TWO_RULES + "correlation: {type: temporal_ordered, rules: [rule_a, rule_b], group-by: [ProcessId], timespan: 90s}"))
    assert query.startswith('sequence by process.pid with maxspan=90s [any where (event.category:"process"')
    assert query.count("[any where ") == 2


@needs_clickhouse
@pytest.mark.parametrize("stem", ORDERED)
def test_ordered_correlations_convert_clickhouse(stem):
    [query] = ClickhouseBackend(pipeline()).convert(collection(CORRELATIONS[stem]))
    assert "rule_sequence" in query


@needs_clickhouse
def test_cross_source_converts_clickhouse_esql():
    """The ESF + UL correlation groups by its three join keys on ClickHouse and ES|QL too."""
    for backend, group_by in ((ClickhouseBackend, r"GROUP BY (.*?) HAVING"), (ESQLBackend, r"\| stats .* by (.*?)\n")):
        # a fresh collection each: conversion applies the pipeline to the rule objects in place
        [query] = backend(pipeline()).convert(collection(CORRELATIONS["hidden_prompt_keychain_activity"]))
        clause = re.search(group_by, query).group(1)
        assert all(f in clause for f in EXPECTED["hidden_prompt_keychain_activity"][3]), query


def test_cross_source_join_keys():
    """The real exec and securityd line of one osascript run (scrubbed fixtures), through the collectors,
    are kept and carry equal join keys of the same type, 54 ms apart."""
    fixtures = ROOT / "tests" / "fixtures"
    [esf_raw] = [json.loads(line) for line in (fixtures / "esf" / "exec.json").read_text().splitlines()
                 if "hidden answer" in line]
    [ul_raw] = [raw for raw in map(json.loads, (fixtures / "ul" / "com_apple_securityd.ndjson").read_text().splitlines())
                if raw["processImagePath"] == "/usr/bin/osascript"]
    esf = ESFCollector()
    assert esf.should_keep_event(esf_raw) and "securityd" in categories_of(ul_raw)
    esf_doc, ul_doc = esf.normalize_event(esf_raw), ULCollector().normalize_event(ul_raw)
    for field in CORRELATIONS["hidden_prompt_keychain_activity"]["correlation"]["group-by"]:
        assert esf_doc[field] == ul_doc[field] and type(esf_doc[field]) is type(ul_doc[field]), field
    gap = _epoch(ul_doc["@timestamp"]) - _epoch(esf_doc["@timestamp"])  # 3.10's fromisoformat takes no Z
    assert 0 < gap < 60  # inside timespan: 1m


@pytest.mark.parametrize("stem", EXPECTED)
def test_correlations_convert_logscale(stem):
    """LogScaleBackend 3.0.0 has no correlation support and macos_falcon only process_creation."""
    corr = CORRELATIONS[stem]
    assert custom(corr, "logscale") == "unsupported"
    rules = collection(corr)
    with pytest.raises(NotImplementedError, match="does not support correlation rules"):
        LogScaleBackend(macos_falcon()).convert_correlation_rule(rules.rules[-1])
    # converting the set fails earlier still: macos_falcon rejects the base rules' fields or categories
    with pytest.raises(SigmaTransformationError, match="not supported on Falcon macOS telemetry"):
        LogScaleBackend(macos_falcon()).convert(rules)
