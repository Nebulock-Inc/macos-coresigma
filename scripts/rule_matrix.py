#!/usr/bin/env python3
"""
Rule × target matrix: whether each rule converts for each target, and whether it fires on the bench.

Round 1 (convert): each rule with output of its own converts, fails (with the backend's reason), or is field-absent:
its query references a field that no replayed document on that target has (Elasticsearch/OpenSearch: _field_caps
fields some document has; Splunk: fieldsummary; ClickHouse: columns some row sets). defend is convert-only, with
coreSigma's ECS mapping: Elastic Defend 9.5.6 data from the test host exists, but no field check or verdict here yet
(the README's Known limitations has Defend's file-event gap). A correlation converts together with its base rules, as the type its
custom.coresigma.<target> declares if any; `unsupported` there fails it. elastic-eql and defend convert a temporal_ordered
correlation as an EQL sequence (deploy_sigma_rules.EqlSequenceBackend), the form Kibana deploys; elastic-esql converts
the other correlations, as Kibana deploys them. Known target limitations are reasons.

Round 2 (verdicts): each query runs on each live bench store (scripts/bench_up.sh, captures replayed with
scripts/replay_capture.py). fires: >=1 hit inside any clean simulation window (a window with a `rules` list counts
only for those rule ids: a hands-on window, where other GUI activity mustn't verify unrelated rules); noisy: more hits
per hour in the idle window than the rule's level allows (the capture harness's own commands left out); silent
otherwise. logscale, kusto and defend have no store here: not-run. A query a store rejects (HTTP 4xx) becomes `fails`
with the store's error; a store failure (5xx, 429) ends the run. matrix.json carries each live row's sim_hits and idle_per_hour.
--noise FILE adds another noise sample, the private laptop baseline (scripts/sample_private_baseline.py's noise.json,
read where it is, never copied): a rule's rate there counts when higher than its idle rate. That rate is the higher of
the rule's Elastic EQL count (ESF rules) and its Sigma-semantics count in process (every single rule, unified log ones
too), so a query a target can't express doesn't hide noise (load_noise); it is applied to every live store. --noise-only recomputes --matrix's
verdicts with it from the rows' own measures, without the stores. A later verdicts run without --noise FILE reverts
the verdicts the laptop sample made noisy: pass it on every run, render's too (it names the rules the sample didn't
count, the sample's hours, and a laptop-only noisy verdict's cause; never a rate).

render: docs/SUPPORT_MATRIX.md from matrix.json plus reports/verification.json (round 3's Falcon verdicts, the
reason each not-verified rule is not verified, rule notes); a Jamf Protect column is not-verified. --falcon FILE
computes the Falcon verdicts instead, from the read-only Falcon query results and their per-hit timestamps against
the current windows (falcon_verdicts; read where it is, never copied: its hits carry command lines). With
--write-rules, each rule's custom.coresigma gets its status (verified / not-verified) and verdict.<column>, and each
correlation base rule (it has no row) gets status base and base_of (the correlations' file stems); a rule that is no
longer a base rule loses them. The declared fallbacks (custom.coresigma.<target>) are left as they are.

Usage:
    rule_matrix.py convert [--rules-dir DIR] [--out reports/matrix.json]
    rule_matrix.py verdicts --windows reports/sim_windows.json [--rules-dir DIR] [--out reports/matrix.json]
        [--noise ~/.coresigma/private/noise.json]
    rule_matrix.py verdicts --noise-only --noise ~/.coresigma/private/noise.json [--matrix reports/matrix.json]
        [--out reports/matrix.json]
    rule_matrix.py render --windows reports/sim_windows.json [--matrix reports/matrix.json]
        [--notes reports/verification.json] [--falcon FALCON_RESULTS.json] [--out docs/SUPPORT_MATRIX.md]
        [--write-rules]
        [--noise ~/.coresigma/private/noise.json]
"""
import argparse
import copy
import json
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipelines" / "pysigma-pipeline-macos"))  # this checkout's plugin, not another install
sys.path.insert(0, str(ROOT / "collectors"))

import requests  # noqa: E402
import yaml  # noqa: E402
from deploy_sigma_rules import EqlSequenceBackend, fix_eql  # noqa: E402
from outputs import INDEX_PREFIX, SOURCETYPE, _epoch as iso_epoch  # noqa: E402
try:
    from sigma.backends.clickhouse import ClickhouseBackend  # noqa: E402
except ImportError:  # optional (requirements-clickhouse.txt): it needs Python 3.13+
    ClickhouseBackend = None
from sigma.backends.crowdstrike import LogScaleBackend  # noqa: E402
from sigma.backends.elasticsearch import ESQLBackend  # noqa: E402
from sigma.backends.kusto import KustoBackend  # noqa: E402
from sigma.backends.opensearch import OpensearchLuceneBackend  # noqa: E402
from sigma.backends.splunk import SplunkBackend  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType  # noqa: E402
from sigma.exceptions import SigmaError  # noqa: E402
from sigma.pipelines.macos import macos_esf_ecs, macos_falcon, macos_ul_ecs  # noqa: E402
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline  # noqa: E402
from sigma.rule import SigmaDetection  # noqa: E402
from sigma.types import SigmaRegularExpression  # noqa: E402

RULES = ROOT / "rules"
CH_TABLE = "coresigma.events"


def _clickhouse_backend():
    # SystemExit, not an exception convert() would record as every rule failing on clickhouse
    if ClickhouseBackend is None:
        raise SystemExit("the clickhouse target needs pysigma-backend-clickhouse (Python 3.13+): "
                         "pip install -r requirements-clickhouse.txt")
    return ClickhouseBackend(macos_esf_ecs() + macos_ul_ecs(), table_name=CH_TABLE)


BACKENDS = {
    "elastic-eql": lambda: EqlSequenceBackend(macos_esf_ecs() + macos_ul_ecs()),  # temporal_ordered: sequence
    "elastic-esql": lambda: ESQLBackend(macos_esf_ecs() + macos_ul_ecs()),
    "opensearch": lambda: OpensearchLuceneBackend(macos_esf_ecs() + macos_ul_ecs()),
    "splunk": lambda: SplunkBackend(macos_esf_ecs() + macos_ul_ecs()),
    "clickhouse": _clickhouse_backend,
    "logscale": lambda: LogScaleBackend(macos_falcon()),
    "kusto": lambda: KustoBackend(microsoft_xdr_pipeline()),
    "defend": lambda: EqlSequenceBackend(macos_esf_ecs()),
}
TARGETS = list(BACKENDS)
LIVE = ["elastic-eql", "elastic-esql", "opensearch", "splunk", "clickhouse"]  # the others have no store: not-run
NOISY_PER_HOUR = {"critical": 5, "high": 5, "medium": 20}  # idle hits/hour above which a rule is noisy
# The test host's capture harness (rotate.sh's gzip and aws runs) is in the idle captures: its commands aren't noise.
# shortcut: the documents carry no parent command line, so a harness child whose own command line lacks the path counts
HARNESS_EXCLUDE = ("/var/coresigma/",)
EQL_SIZE = 10000  # _eql/search returns at most this many events: a count of EQL_SIZE is a lower bound
# Elastic's detection-rules name these Defend events differently from eslogger
DEFEND_ACTIONS = ("event.action uses eslogger names; Elastic Defend reports gatekeeper_override / launch_daemon, "
                  "so this won't match Defend data as-is")
SPLUNK_BINS = ("pysigma-backend-splunk counts a correlation in fixed `bin` windows of its timespan: a chain that "
               "crosses a window boundary is missed")
CLICKHOUSE_ORDERED = ("ordered with windowFunnel within the timespan: the matrix tool rewrites pysigma-backend-clickhouse's "
                      "temporal_ordered HAVING, which checks neither the order nor a sliding window (clickhouse_ordered)")
ESQL_BUCKETS = ("pysigma-backend-elasticsearch counts a correlation in fixed date_trunc windows of its timespan: a chain "
                "that crosses a window boundary is missed")
DEFEND_CONVERT_ONLY = ("convert-only with coreSigma's ECS mapping, fields not checked (Elastic Defend 9.5.6 data "
                       "from the test host exists; for its file events see the README's Known limitations)")
DEFEND_RENAMED = ("gatekeeper_override", "background_task")  # the categories whose event.action that affects
XPROTECT_CASE = ("the unified_log.subsystem prefix match is case-sensitive here, and XProtect logs under both "
                 "com.apple.xprotect and com.apple.XProtect (com.apple.XProtectFramework...): the uppercase entries "
                 "are missed")


def setting(name, default):
    """The environment's value, else the one bench_up.sh wrote to .env, else default."""
    env = ROOT / ".env"
    found = [line.split("=", 1)[1] for line in (env.read_text().splitlines() if env.exists() else [])
             if line.startswith(name + "=")]
    return os.environ.get(name) or (found[0] if found else default)


ES_URL = setting("ES_URL", "http://localhost:9200")
ES_AUTH = ("elastic", setting("ELASTIC_PASSWORD", "changeme"))
OS_URL = setting("OS_URL", "http://localhost:9201")
CH_URL = setting("CH_URL", "http://localhost:8123")
INDEX = {source: f"{prefix}-*" for source, prefix in INDEX_PREFIX.items()}


@dataclass
class Result:
    status: str  # converts, fails or field-absent
    query: str
    reason: str


@dataclass
class SimWindow:
    name: str
    start: float  # epoch seconds
    end: float
    status: str | None = None  # a simulation's: success if clean (only that); an idle window's: complete once captured
    rules: tuple[str, ...] | None = None  # if set, the only rule ids whose hits count in this window

    def counts_for(self, rule_id):
        return self.rules is None or rule_id in self.rules


class QueryError(Exception):
    """A store rejected a query (HTTP 4xx, or a search error): the query's fault, not the store's."""


def _reply_error(store, status, message):
    """QueryError for a rejection (4xx but 429), RuntimeError for a store failure (5xx, 429), which ends the run."""
    return (QueryError if 400 <= status < 500 and status != 429 else RuntimeError)(f"{store}: HTTP {status}: {message}")


# --- round 1: conversion ------------------------------------------------------------------------------------------

def _units(rules_dir):
    """(rule id, the rule dicts to convert together: a rule, or a correlation's base rules and then it) for each rule
    with output of its own."""
    rules = [yaml.safe_load(p.read_text()) for p in sorted(Path(rules_dir).rglob("*.yml"))]
    by_ref = {rule[key]: rule for rule in rules for key in ("name", "id") if key in rule}
    bases = {ref for rule in rules if "correlation" in rule and not rule["correlation"].get("generate", False)
             for ref in rule["correlation"]["rules"]}
    return [(str(rule["id"]), [by_ref.get(ref, {}) for ref in rule["correlation"]["rules"]] + [rule]
             if "correlation" in rule else [rule])
            for rule in rules if "correlation" in rule or not {rule.get("name"), rule.get("id")} & bases]


def _source(logsource):
    """esf or ul: the documents a rule with this logsource (a dict or SigmaLogSource) runs on."""
    service = logsource.get("service") if isinstance(logsource, dict) else logsource.service
    return "ul" if service == "unifiedlog" else "esf"


def _sources(unit):
    """The sources a unit (from _units) runs on, sorted: ('esf',), ('ul',), or ('esf', 'ul') for a correlation over
    both, whose base rules' own conditions (event.action, unified_log.*) pick out their kind of document."""
    return tuple(sorted({_source(rule.get("logsource") or {})
                         for rule in (unit[:-1] if "correlation" in unit[-1] else unit)}))


def _items(rule):
    """Detection items of a (converted) rule, or of a correlation's base rules."""
    if isinstance(rule, SigmaCorrelationRule):
        for ref in rule.rules:
            yield from _items(ref.rule)
        return
    detections = list(rule.detection.detections.values())
    while detections:
        for item in detections.pop().detection_items:
            if isinstance(item, SigmaDetection):
                detections.append(item)
            else:
                yield item


def _fields(rule):
    """{source: target fields} a converted rule's query references in that source's documents: a correlation's, its
    base rules' fields, each in its own source, plus its group-by and value fields in every one of them."""
    if not isinstance(rule, SigmaCorrelationRule):
        return {_source(rule.logsource): {item.field for item in _items(rule) if item.field}}
    fieldref = getattr(rule.condition, "fieldref", None)
    shared = set(rule.group_by or []) | ({fieldref} if isinstance(fieldref, str) else set(fieldref or []))
    fields = {}
    for ref in rule.rules:
        for source, found in _fields(ref.rule).items():
            fields.setdefault(source, set(shared)).update(found)
    return fields


def _limitations(target, rule):
    """Reasons a converted rule may not behave on target as Sigma says: the targets' known limitations."""
    regexes = [str(value.regexp) for item in _items(rule) for value in item.value
               if isinstance(value, SigmaRegularExpression)]
    notes = []
    if target == "elastic-esql":
        notes.append("ES|QL matches plain strings case-sensitively (pysigma-backend-elasticsearch)")
    if target in ("elastic-eql", "elastic-esql", "opensearch", "defend") and any(
            re.search(r"(?<!\\)\$", regex) for regex in regexes):
        notes.append("$ in |re is literal in Lucene, EQL and ES|QL regular expressions: the pattern can't match")
    if target in ("elastic-eql", "defend") and regexes:
        notes.append("EQL's regex~ matches |re case-insensitively")
    if target == "opensearch" and regexes:
        notes.append("OpenSearch maps path and command fields as lowercase keyword: |re matches case-insensitively")
    logsource = getattr(rule, "logsource", None)
    # ES|QL's starts_with is case-sensitive; OpenSearch maps the subsystem as a plain keyword (no lowercase normalizer)
    if target in ("elastic-esql", "opensearch") and getattr(logsource, "service", None) == "unifiedlog" \
            and getattr(logsource, "category", None) == "xprotect":
        notes.append(XPROTECT_CASE)
    if target == "defend" and getattr(logsource, "category", None) in DEFEND_RENAMED:
        notes.append(DEFEND_ACTIONS)
    if target == "kusto":
        notes.append("product-agnostic Windows-schema mapping; macOS table population unverified")
    if target == "splunk" and isinstance(rule, SigmaCorrelationRule):
        notes.append(SPLUNK_BINS)
    if target == "elastic-esql" and isinstance(rule, SigmaCorrelationRule):
        notes.append(ESQL_BUCKETS)
    if target == "clickhouse" and isinstance(rule, SigmaCorrelationRule):
        notes.append(CLICKHOUSE_ORDERED if rule.type == SigmaCorrelationType.TEMPORAL_ORDERED else
                     "pysigma-backend-clickhouse groups the whole search range, not timespan windows")
    return notes


def clickhouse_ordered(query):
    """pysigma-backend-clickhouse's temporal_ordered query, ordered: its HAVING (every rule seen, last - first <= the
    timespan over the whole group, in any order) becomes windowFunnel, which needs the rules' events in their order
    within the timespan from a first rule's event; strict_increase: each step a later event, so one event that
    matches two rules can't fill two steps. Raises ValueError on a query without that HAVING."""
    having = re.search(r"HAVING rule_count >= (\d+) AND toUnixTimestamp\(last_event\) - toUnixTimestamp\(first_event\) "
                       r"<= (\d+)$", query)
    steps = re.findall(r"'((?:[^'\\]|\\.)*)' AS sigma_rule_id", query)  # one UNION ALL leg per rule, in order
    if not having or len(steps) != int(having[1]):
        raise ValueError(f"clickhouse: no temporal_ordered HAVING to order in {query[-200:]}")
    return query[:having.start()] + (f"HAVING windowFunnel({int(having[2]) * 10**9}, 'strict_increase')"
                                     "(toUInt64(toUnixTimestamp64Nano(timestamp)), "
                                     + ", ".join(f"sigma_rule_id = '{s}'" for s in steps) + f") = {len(steps)}")


def _why(error):
    """An exception's message, first line, without this checkout's path."""
    message = str(error.args[0]) if error.args else ""
    if not isinstance(error, (SigmaError, NotImplementedError)):
        message = f"{type(error).__name__}: {message}"
    return message.replace(str(ROOT) + "/", "").strip().splitlines()[0] if message.strip() else type(error).__name__


def convert(target, unit, available=None):
    """Result of converting unit (from _units) for target; available: {source: fields its documents have} (a source
    not in it, or None: unchecked)."""
    unit = copy.deepcopy(unit)
    rule = unit[-1]
    if target == "defend" and "ul" in _sources(unit):
        return Result("fails", "", "Elastic Defend data has no unified log events")
    notes = []
    declared = str(((rule.get("custom") or {}).get("coresigma") or {}).get(target) or "")
    if declared == "unsupported":
        return Result("fails", "", f"custom.coresigma.{target}: unsupported")
    if "correlation" in rule and declared.upper() in SigmaCorrelationType.__members__:
        notes.append(f"converted as {declared}, the rule's declared fallback for {rule['correlation']['type']}")
        rule["correlation"]["type"] = declared
    try:
        collection = SigmaCollection.from_dicts(unit)
        # a generate: true correlation's base rules come first; shortcut: one query per rule (one condition each)
        query = BACKENDS[target]().convert(collection)[-1 if "correlation" in rule else 0]
        if target == "clickhouse" and rule.get("correlation", {}).get("type") == "temporal_ordered":
            query = clickhouse_ordered(query)
    except Exception as e:  # whatever a backend or pipeline raises is this rule's result on target, not the run's end
        return Result("fails", "", _why(e))
    if target in ("elastic-eql", "defend"):
        query = fix_eql(query)
    converted = collection.rules[-1]
    notes += _limitations(target, converted)
    needed = _fields(converted)
    checked = {source: fields for source, fields in needed.items() if (available or {}).get(source) is not None}
    absent = sorted(set().union(*(fields - available[source] for source, fields in checked.items())))
    if absent:
        notes.insert(0, f"no replayed document has {', '.join(absent)}")
    if target == "defend":
        notes.insert(0, DEFEND_CONVERT_ONLY)
    elif len(checked) < len(needed):
        notes.append("field check skipped " + (f"for {', '.join(sorted(set(needed) - set(checked)))} "
                                               if checked else "") + "(no field list)")
    return Result("field-absent" if absent else "converts", query, "; ".join(notes))


def convert_all(rules_dir=RULES, fields=None):
    """{rule id: {target: Result}} for each rule with output of its own (not a correlation's generate: false base rule).
    fields: {target: {source (esf/ul): fields its replayed documents have}} (live_fields()); unlisted: unchecked."""
    matrix = {}
    for rule_id, unit in _units(rules_dir):
        matrix[rule_id] = {target: convert(target, unit, (fields or {}).get(target)) for target in TARGETS}
    return matrix


# --- the stores ---------------------------------------------------------------------------------------------------

def _post(url, body, auth=None):
    reply = requests.post(url, json=body, auth=auth, timeout=300)
    if not reply.ok:
        try:
            reason = reply.json()["error"]["root_cause"][0]["reason"]
        except (ValueError, KeyError, IndexError, TypeError):
            reason = reply.text[:500]
        raise _reply_error(url, reply.status_code, reason)
    return reply.json()


def _splunk(search, earliest=0, latest="now"):
    """Result rows of a Splunk search, through the bench container: Splunk Free refuses remote REST logins."""
    out = subprocess.run(
        ["docker", "exec", "splunk", "curl", "-sk", "-w", "\n%{http_code}", "-u",
         f"admin:{setting('SPLUNK_PASSWORD', 'changeme')}", "https://localhost:8089/services/search/jobs/export",
         "--data-urlencode", f"search={search}",
         "-d", "output_mode=json", "-d", "preview=false", "-d", f"earliest_time={earliest}", "-d", f"latest_time={latest}"],
        capture_output=True, text=True, check=True, timeout=600).stdout
    out, _, status = out.rpartition("\n")
    try:
        lines = [json.loads(line) for line in out.splitlines() if line.strip()]
    except ValueError:
        lines = [{"messages": [{"type": "ERROR", "text": out[:500]}]}]
    errors = [m["text"] for line in lines for m in line.get("messages") or [] if m.get("type") in ("ERROR", "FATAL")]
    if status == "200" and errors:  # a search error reported in the stream: the query's fault
        raise QueryError(f"splunk: {'; '.join(errors)}")
    if status != "200":
        raise _reply_error("splunk", int(status) if status.isdigit() else 500, "; ".join(errors) or out[:500])
    # a long search streams preview rows (preview: true) before its final ones: those are partial counts
    return [line["result"] for line in lines if "result" in line and not line.get("preview")]


def _clickhouse(sql):
    reply = requests.post(CH_URL, data=sql.encode(), timeout=300)
    if not reply.ok:
        raise _reply_error("clickhouse", reply.status_code, reply.text[:500].strip())
    return reply.text


def _ch_time(start, end):
    return f"toFloat64(parseDateTime64BestEffort(`@timestamp`, 9)) BETWEEN {start} AND {end}"


def hits(target, query, source, start, end, exclude=()):
    """How many hits query has on target's bench store in source's (esf, ul, or a tuple of them, from _sources)
    documents from start to end (epoch
    seconds; inclusive, but Splunk's latest_time, end, is exclusive), leaving out documents whose
    process.command_line contains one of exclude. Raises QueryError if the store rejects the query (4xx),
    RuntimeError if it fails (5xx, 429), ValueError if the query has no place for the scope."""
    sources = (source,) if isinstance(source, str) else tuple(source)
    index = ",".join(INDEX[s] for s in sources)
    if target in ("elastic-eql", "elastic-esql", "opensearch"):
        scope = {"filter": [{"range": {"@timestamp": {"gte": int(start * 1000), "lte": int(end * 1000),
                                                      "format": "epoch_millis"}}}],
                 "must_not": [{"wildcard": {"process.command_line": {"value": f"*{s}*", "case_insensitive": True}}}
                              for s in exclude]}
        if target == "elastic-eql":
            reply = _post(f"{ES_URL}/{index}/_eql/search",
                          {"query": query, "filter": {"bool": scope}, "size": EQL_SIZE}, ES_AUTH)["hits"]
            return len(reply.get("events") or reply.get("sequences") or [])
        if target == "elastic-esql":
            query = re.sub(r"^from \*", f"from {index}", query) + "\n| stats hits = count(*)"
            return _post(f"{ES_URL}/_query", {"query": query, "filter": {"bool": scope}}, ES_AUTH)["values"][0][0]
        return _post(f"{OS_URL}/{index}/_count",
                     {"query": {"bool": {"must": [{"query_string": {"query": query}}], **scope}}})["count"]
    if target == "splunk":
        types = " OR ".join(f"sourcetype={SOURCETYPE[s]}" for s in sources)
        scope = f"index=macos {types if len(sources) == 1 else f'({types})'}" + "".join(
            f' NOT process.command_line="*{s}*"' for s in exclude)
        query = query.replace("\n", " ")  # a multi-rule correlation starts | multisearch: scope each subsearch
        if query.startswith("|") and "[ search " not in query:
            raise ValueError(f"splunk: no subsearch to scope in {query[:200]}")
        search = query.replace("[ search ", f"[ search {scope} ") if query.startswith("|") else f"search {scope} {query}"
        rows = _splunk(f"{search} | stats count", start, end)
        if not rows:  # stats count always answers: no row means a cut-off stream, not 0
            raise RuntimeError(f"splunk: no result for {search[:200]}")
        return int(rows[-1]["count"])
    if target == "clickhouse":
        kind = f" AND `event.action` {'!=' if sources[0] == 'esf' else '='} ''" if len(sources) == 1 else ""
        scope = _ch_time(start, end) + kind + "".join(
            f" AND position(`process.command_line`, '{s}') = 0" for s in exclude)
        if f"FROM {CH_TABLE} WHERE" not in query:
            raise ValueError(f"clickhouse: no FROM {CH_TABLE} WHERE to scope in {query[:200]}")
        query = query.replace(f"FROM {CH_TABLE} WHERE", f"FROM (SELECT * FROM {CH_TABLE} WHERE {scope}) WHERE")
        return int(_clickhouse(f"SELECT count() FROM ({query})"))
    raise ValueError(f"{target} has no store")


def _es_fields(url, auth, source):
    names = [f for f in requests.get(f"{url}/{INDEX[source]}/_field_caps", params={"fields": "*"}, auth=auth,
                                     timeout=60).json().get("fields", {}) if not f.startswith("_")]
    reply = _post(f"{url}/{INDEX[source]}/_search",
                  {"size": 0, "aggs": {str(i): {"filter": {"exists": {"field": f}}} for i, f in enumerate(names)}}, auth)
    if not reply["hits"]["total"]["value"]:
        return None
    return {f for i, f in enumerate(names) if reply["aggregations"][str(i)]["doc_count"]}


def _splunk_fields(source):
    return {row["field"] for row in _splunk(f"search index=macos sourcetype={SOURCETYPE[source]} | fieldsummary maxvals=1"
                                            " | fields field")} or None


def _clickhouse_fields(source):
    columns = _clickhouse(f"SELECT name FROM system.columns WHERE database || '.' || table = '{CH_TABLE}'").split()
    counts = _clickhouse(
        f"SELECT count(), {', '.join(f'countIf(`{c}` != defaultValueOfArgumentType(`{c}`))' for c in columns)} "
        f"FROM {CH_TABLE} WHERE `event.action` {'!=' if source == 'esf' else '='} '' FORMAT TabSeparated").split()
    return {c for c, n in zip(columns, counts[1:]) if n != "0"} if counts[0] != "0" else None


def live_fields():
    """{target: {source: fields some replayed document has}} for each reachable bench store, for convert_all's
    field-absent check; a source without documents is left out, an unreachable store too (with a note)."""
    fetch = {"elastic-eql": lambda s: _es_fields(ES_URL, ES_AUTH, s), "opensearch": lambda s: _es_fields(OS_URL, None, s),
             "splunk": _splunk_fields, "clickhouse": _clickhouse_fields}
    found = {}
    for target, fields_of in fetch.items():
        try:
            found[target] = {source: fields for source in INDEX if (fields := fields_of(source))}
        except (requests.RequestException, subprocess.SubprocessError, OSError, QueryError) as e:
            print(f"{target}: no field list, field-absent unchecked ({_why(e)})", file=sys.stderr)
    if "elastic-eql" in found:
        found["elastic-esql"] = found["elastic-eql"]  # one store
    return found


# --- round 2: verdicts --------------------------------------------------------------------------------------------

def _epoch(iso):
    # outputs' parser: Python 3.10's fromisoformat takes neither Z nor nanoseconds
    epoch = iso_epoch(iso)
    if epoch is None:
        raise ValueError(f"not an ISO 8601 time: {iso!r}")
    return epoch


def load_windows(path):
    """The SimWindows of a sim_windows.json (simulations/run_sim.sh's records, plus the idle window)."""
    return [SimWindow(w["name"], _epoch(w["start"]), _epoch(w["end"]), w.get("status"),
                      tuple(w["rules"]) if "rules" in w else None)
            for w in json.loads(Path(path).read_text())]


def select_windows(windows):
    """(clean, idle): simulations with status success, idle windows with status complete. A whitelist: an entry with
    no status or any other (timeout, error, tainted, retest, planned, ...) is left out and named on stderr.
    Raises ValueError if there is no success or no complete window: verdicts would claim silence or quiet."""
    clean = [w for w in windows if w.status == "success"]
    idle = [w for w in windows if w.status == "complete"]
    for w in windows:
        if w.status not in ("success", "complete"):
            print(f"window excluded (status {w.status}): {w.name} "
                  f"{datetime.fromtimestamp(w.start, timezone.utc):%Y-%m-%dT%H:%M:%SZ}", file=sys.stderr)
    if not clean or not idle:
        raise ValueError(f"need >=1 window with status success and >=1 with status complete (idle); "
                         f"found {len(clean)} and {len(idle)}")
    if sum(w.end - w.start for w in idle) <= 0:
        raise ValueError("the idle windows last 0 seconds: no hits/hour")
    return clean, idle


def verdicts(matrix, windows, rules_dir=RULES, noise_rates=None, measures=None):
    """{rule id: {target: fires, silent, noisy or not-run}} from running matrix's queries on the live stores.

    fires: >=1 hit in any clean window (status success; see select_windows). noisy: hits/hour in the idle windows
    (status complete) over NOISY_PER_HOUR for the rule's level, harness commands left out; noise_rates, {rule id:
    hits/hour} from another sample (the laptop noise sample), counts when higher. noisy wins over fires.
    measures, a dict if given, gets {rule id: {target: {sim_hits, idle_per_hour, sim_hits_capped, idle_capped}}} for
    each live row run; *_capped: an EQL window reached EQL_SIZE, so the number is a lower bound.
    A query a store rejects becomes `fails` in matrix, with the store's error: not-run."""
    clean, idle = select_windows(windows)
    hours = sum(w.end - w.start for w in idle) / 3600
    units = dict(_units(rules_dir))
    found = {}
    for rule_id, row in matrix.items():
        source, limit = _sources(units[rule_id]), NOISY_PER_HOUR.get(str(units[rule_id][-1].get("level")))
        found[rule_id] = {}
        for target, result in row.items():
            verdict = "not-run"
            if target in LIVE and result.status != "fails":
                try:
                    sim = [hits(target, result.query, source, w.start, w.end) for w in clean if w.counts_for(rule_id)]
                    quiet = [hits(target, result.query, source, w.start, w.end, HARNESS_EXCLUDE) for w in idle]
                    sim_hits, per_hour = sum(sim), sum(quiet) / hours
                except QueryError as e:
                    row[target] = Result("fails", result.query, "; ".join(
                        filter(None, [f"{target} rejected the query: {' '.join(str(e).split())}", result.reason])))
                else:
                    if measures is not None:
                        eql = target == "elastic-eql"
                        measures.setdefault(rule_id, {})[target] = {
                            "sim_hits": sim_hits, "idle_per_hour": round(per_hour, 3),
                            "sim_hits_capped": eql and max(sim, default=0) >= EQL_SIZE, "idle_capped": eql and max(quiet) >= EQL_SIZE}
                    verdict = _verdict(limit, sim_hits, per_hour, (noise_rates or {}).get(rule_id, 0))
            found[rule_id][target] = verdict
    return found


def _verdict(limit, sim_hits, per_hour, noise_rate):
    """noisy if the higher of per_hour and noise_rate is over limit (None: never noisy), else fires if sim_hits, else
    silent."""
    return "noisy" if limit is not None and max(per_hour, noise_rate) > limit else "fires" if sim_hits else "silent"


@dataclass
class Noise:
    """The laptop noise sample (load_noise): each rule's EQL-counted and Sigma-semantics-counted hits/hour, the rules
    neither counted ({rule id: why}) and each sample's hours."""
    eql: dict
    sigma: dict
    uncounted: dict
    hours: dict

    @property
    def rates(self):
        """{rule id: hits/hour}, each counted rule's higher count: what verdicts and noise_only take."""
        return {r: max(self.eql.get(r, 0), self.sigma.get(r, 0)) for r in self.eql.keys() | self.sigma.keys()}


def load_noise(path):
    """A Noise from scripts/sample_private_baseline.py's noise.json: "rates" (counted with each rule's EQL query) and
    "sigma_rates" (counted with Sigma's semantics in process); a rule in "skipped" or "sigma_skipped" that neither
    counted is uncounted, not 0/h."""
    noise = json.loads(Path(path).expanduser().read_text())
    eql, sigma = noise["rates"], noise.get("sigma_rates", {})
    why = {**noise.get("skipped", {}), **noise.get("sigma_skipped", {})}
    samples = {**noise.get("samples", {}), **noise.get("sigma_samples", {})}
    return Noise(eql, sigma, {r: w for r, w in why.items() if r not in eql and r not in sigma},
                 {name: sample["hours"] for name, sample in samples.items()})


def noise_only(matrix, noise_rates, rules_dir=RULES):
    """A matrix.json's verdicts again, with noise_rates as verdicts takes them, from each row's own sim_hits and
    idle_per_hour: no store is queried. Returns a copy; only live rows that ran (fires, silent or noisy) change."""
    units = dict(_units(rules_dir))
    matrix = copy.deepcopy(matrix)
    for rule_id, row in matrix.items():
        limit = NOISY_PER_HOUR.get(str(units[rule_id][-1].get("level")))
        for cell in row.values():
            if cell.get("verdict") in ("fires", "silent", "noisy"):
                cell["verdict"] = _verdict(limit, cell["sim_hits"], cell["idle_per_hour"], noise_rates.get(rule_id, 0))
    return matrix


# --- the support matrix: docs/SUPPORT_MATRIX.md and each rule's custom.coresigma -----------------------------------

COLUMNS = TARGETS + ["jamf-protect"]
HEADINGS = {"elastic-eql": "Elastic EQL", "elastic-esql": "Elastic ES\\|QL", "opensearch": "OpenSearch",
            "splunk": "Splunk", "clickhouse": "ClickHouse", "logscale": "Falcon (LogScale)",
            "kusto": "Defender / Sentinel (KQL)", "defend": "Elastic Defend (EQL)", "jamf-protect": "Jamf Protect"}
MARK = {"fires": "✅ fires", "noisy": "🔶 noisy", "silent": "⚪ silent", "fails": "✗ fails",
        "field-absent": "field-absent", "converts": "converts", "not-verified": "not-verified", "not-run": "not-run"}
JAMF = "deferred to the next release"
LAPTOP_UNCOUNTED = "laptop: not counted"
SAMPLES = {"fresh": "an ESF capture", "slices": "slices of a longer ESF log", "ul": "unified log"}  # noise.json's names
SUPERSCRIPT = str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹")


FALCON_UNQUERIED = "Falcon wasn't queried in every success window, and the rule fires on another target"


def falcon_verdicts(results, windows, matrix):
    """{rule id: (verdict, reason)} for the Falcon (logscale) column from a read-only Falcon results file: "results"
    entries {kind, rule, window: "start/end" as queried, status, matches: [{ts}]}, whose query is the kind's
    ("converted": queries_as_run[rule], "diagnostic-tag": diagnostic_queries[rule]).

    Only results of the query matrix.json ships ("aid=<aid> | " + its logscale query) count, only in success windows
    that a queried window contains, and only hits whose ts falls in the window as it now stands (trimmed windows end
    before the cleanup). fires: such a hit. Otherwise silent, unless some success window wasn't queried and the rule
    fires on a live store: then not-run. matrix.json keeps no per-window hits for the stores, so "fires elsewhere in a
    window Falcon didn't query" is taken as "fires elsewhere"; that can only understate. A window with a rules list
    counts only for those rules, as in verdicts."""
    asked = {"converted": results.get("queries_as_run", {}), "diagnostic-tag": results.get("diagnostic_queries", {})}
    success = [w for w in windows if w.status == "success"]
    verdicts = {}
    for rule_id, row in matrix.items():
        query = f"aid=<aid> | {row['logscale']['query']}"
        runs = [r for r in results["results"] if r["rule"] == rule_id and r["status"] == "ok"
                and asked.get(r["kind"], {}).get(rule_id) == query]
        if row["logscale"]["status"] != "converts" or not runs:
            continue  # not queried as shipped: the column shows the conversion
        spans = [(r, *map(_epoch, r["window"].split("/"))) for r in runs]
        mine = [w for w in success if w.counts_for(rule_id)]
        queried = [w for w in mine if any(start <= w.start and w.end <= end for _, start, end in spans)]
        if any(w.start <= _epoch(m["ts"]) <= w.end for w in queried for r, start, end in spans
               if start <= w.start and w.end <= end for m in r["matches"]):
            verdicts[rule_id] = ("fires", "")
        elif len(queried) < len(mine) and any(row[t].get("verdict") == "fires" for t in LIVE):
            verdicts[rule_id] = ("not-run", FALCON_UNQUERIED)
        else:
            verdicts[rule_id] = ("silent", "")
    return verdicts


def final_cells(matrix, falcon, uncounted=()):
    """{rule id: {column: (word, reason)}} from a matrix.json: a live target's verdict, Falcon's (logscale) from round 3
    (falcon: {rule id: fires/silent, or (verdict, reason) from falcon_verdicts}), else the conversion status;
    jamf-protect is not-verified. A live verdict of a rule in uncounted (the laptop noise sample's) says the laptop
    didn't count it."""
    unknown = sorted(set(falcon) - {rid for rid, row in matrix.items() if row["logscale"]["status"] == "converts"})
    if unknown:
        raise ValueError(f"Falcon verdicts for rules that don't convert to LogScale: {unknown}")
    cells = {}
    for rule_id, row in matrix.items():
        cells[rule_id] = {}
        for target in TARGETS:
            result, word, extra = row[target], row[target]["status"], ""
            if word == "converts" and target == "logscale":
                verdict = falcon.get(rule_id, "converts")
                word, extra = (verdict, "") if isinstance(verdict, str) else verdict
            elif word == "converts":
                word = result.get("verdict") if result.get("verdict") in ("fires", "silent", "noisy") else "converts"
            reason = "; ".join(filter(None, [_short(target, result["reason"]), extra]))
            if rule_id in uncounted and target in LIVE and word in ("fires", "silent", "noisy"):
                reason = "; ".join(filter(None, [reason, LAPTOP_UNCOUNTED]))
            cells[rule_id][target] = (word, reason)
        cells[rule_id]["jamf-protect"] = ("not-verified", JAMF)
    return cells


def _short(target, reason):
    """A reason for the table: no field-check note for a target without a store (it never has a field list), and a
    message the tool cut at its first line loses its unfinished last sentence (one that ends in a colon)."""
    parts = [p for p in reason.split("; ") if not (target not in LIVE and p.startswith("field check skipped"))]
    return "; ".join(p.rsplit(". ", 1)[0] + "." if p.endswith(":") and ". " in p else p for p in parts)


def rule_status(cells):
    """verified: it fires on some target; else not-verified (silent, noisy or failing everywhere it ran)."""
    return "verified" if any(word == "fires" for word, _ in cells.values()) else "not-verified"


def _versions():
    """The pinned pySigma packages (requirements.txt, then requirements-clickhouse.txt) and the bench images
    (docker-compose.yml)."""
    pins = [line.strip() for name in ("requirements.txt", "requirements-clickhouse.txt")
            for line in (ROOT / name).read_text().splitlines() if "==" in line and not line.startswith("#")]
    images = sorted({line.split("image:", 1)[1].strip() for line in (ROOT / "docker-compose.yml").read_text().splitlines()
                     if line.strip().startswith("image:")})
    return pins, images


def _and(items):
    return ", ".join(items[:-1]) + (" and " if len(items) > 1 else "") + items[-1] if items else ""


def _utc(epoch):
    return f"{datetime.fromtimestamp(epoch, timezone.utc):%Y-%m-%d %H:%M:%S}"


def render(matrix, notes, windows, rules_dir=RULES, noise=None, falcon=None):
    """docs/SUPPORT_MATRIX.md's text, and {rule id: (status, {column: word})} for write_back.
    notes: {falcon: {rule id: verdict}, falcon_scope: text, windows_note: text, not_verified: {rule id: reason},
    notes: {rule id: text}}; "{noisy}" in a reason becomes the rule's idle rate and its level's limit (NOISY_PER_HOUR);
    every not-verified rule needs a reason, and a rule given one is not-verified even if it fires. windows: SimWindows
    (load_windows). noise: the laptop sample (load_noise) the verdicts took, if any: a rule noisy through it alone gets
    that as its {noisy}, and a not-verified reason also says when only Sigma's count made it noisy on a store whose query
    can't match; the rules it didn't count are marked; no rate is written. falcon: a Falcon results file
    (falcon_verdicts), which replaces notes' falcon verdicts."""
    verdicts = falcon_verdicts(falcon, windows, matrix) if falcon else notes.get("falcon", {})
    cells = final_cells(matrix, verdicts, noise.uncounted if noise else ())
    kinds = ("esf", "ul", "correlation")  # the rules/ directories, in table order
    found = {str(rule["id"]): (p.parent.name, rule["title"], str(rule.get("level")))
             for p in Path(rules_dir).rglob("*.yml") for rule in [yaml.safe_load(p.read_text())]}

    def laptop(rule_id):
        """Why the laptop sample alone made rule_id noisy ('' if it didn't): no rate, only the outcome and whose count."""
        level = found[rule_id][2]
        limit = NOISY_PER_HOUR.get(level)
        if not noise or limit is None or noise.rates.get(rule_id, 0) <= limit:
            return ""
        text = f"noisy on the private laptop sample, over the {limit}/h a {level}-level rule allows"
        if noise.eql.get(rule_id, 0) <= limit:  # Sigma's count alone
            blind = [HEADINGS[t] for t in LIVE if "can't match" in matrix[rule_id][t].get("reason", "")]
            text += " as Sigma's semantics count it" + (
                f", though the {_and(blind)} {'query' if len(blind) == 1 else 'queries'} can't match it"
                if blind else "")
        return text

    def noisy(rule_id):
        rates = [r.get("idle_per_hour", 0) for r in matrix[rule_id].values() if r.get("verdict") == "noisy"]
        if not rates:
            raise ValueError(f"{rule_id}: a {{noisy}} reason for a rule no store found noisy")
        level = found[rule_id][2]
        if max(rates) <= NOISY_PER_HOUR[level]:  # noisy through the laptop sample (--noise), not the idle window
            if laptop(rule_id):
                return laptop(rule_id)
            raise ValueError(f"{rule_id}: a {{noisy}} reason, but its idle rate is within the {level}-level limit")
        return (f"noisy: up to {round(max(rates), 1):g} hits/h in the idle window, over the {NOISY_PER_HOUR[level]}/h "
                f"a {level}-level rule allows")

    reasons = {rule_id: reason.replace("{noisy}", noisy(rule_id)) if "{noisy}" in reason else reason
               for rule_id, reason in notes.get("not_verified", {}).items()}
    for rule_id, reason in reasons.items():  # a store's query can't match, yet Sigma's laptop count made it noisy
        if "{noisy}" not in notes["not_verified"][rule_id] and "can't match" in laptop(rule_id) and any(
                r.get("verdict") == "noisy" for r in matrix[rule_id].values()):
            reasons[rule_id] = f"{reason}; {laptop(rule_id)}"
    # a reason given for a rule that fires overrides it: its hits aren't the behaviour (e.g. background lines)
    status = {rule_id: "not-verified" if rule_id in reasons else rule_status(cells[rule_id]) for rule_id in matrix}
    missing = sorted(rule_id for rule_id, s in status.items() if s == "not-verified" and rule_id not in reasons)
    if missing:
        raise ValueError(f"not-verified rules need a reason in the notes: {missing}")
    rows = sorted(matrix, key=lambda rid: (kinds.index(found[rid][0]) if found[rid][0] in kinds else len(kinds),
                                           found[rid][1].casefold()))
    footnotes = {}

    def mark(reason):
        return str(footnotes.setdefault(reason, len(footnotes) + 1)).translate(SUPERSCRIPT) if reason else ""

    table = ["| Rule | Status | " + " | ".join(HEADINGS[c] for c in COLUMNS) + " |",
             "|---|---|" + "---|" * len(COLUMNS)]
    for rule_id in rows:
        kind, title, _ = found[rule_id]
        rule = f"{title.replace('|', chr(92) + '|')} ({kind}){mark(notes.get('notes', {}).get(rule_id))}"
        state = status[rule_id] + (mark(reasons[rule_id]) if status[rule_id] == "not-verified" else "")
        table.append(f"| {rule} | {state} | " + " | ".join(f"{MARK[w]}{mark(r)}" for w, r in
                                                          (cells[rule_id][c] for c in COLUMNS)) + " |")
    clean, idle = select_windows(windows)
    pins, images = _versions()
    counts = Counter(status.values())
    text = [
        "# coreSigma support matrix",
        "",
        "Generated by `scripts/rule_matrix.py render` from `reports/matrix.json`, `reports/verification.json` and the "
        "simulation windows in `reports/sim_windows.json`. Don't edit it by hand.",
        "",
        f"{len(matrix)} rules with output of their own (a correlation's base rules have no row; their "
        "`custom.coresigma.status` is `base`): "
        f"{counts['verified']} verified, {counts['not-verified']} not-verified.",
        "",
        "## What the cells mean",
        "",
        "- **✅ fires**: the query had at least one hit inside at least one clean simulation window. This is not "
        "attribution to the simulated chain: a hit can come from anything the host did in those seconds.",
        "- **🔶 noisy**: in the idle window the query had more hits per hour than its level allows (critical and high: "
        f"{NOISY_PER_HOUR['high']}/h, medium: {NOISY_PER_HOUR['medium']}/h; low and informational are never noisy). "
        "The capture harness's own commands are left out." + (
            " Noise also counts a private laptop sample (" + _and([f"{h:.1f} h of {SAMPLES.get(n, n)}"
                                                                  for n, h in sorted(noise.hours.items())]) +
            "), each rule at the higher of its EQL and its Sigma-semantics count; no laptop data is published, only "
            f"each rule's noisy or quiet outcome, and `{LAPTOP_UNCOUNTED}` where the sample didn't count it."
            if noise else ""),
        "- **⚪ silent**: the query converts and runs, with no hit in any clean window and no noise.",
        "- **converts**: the query converts; there is no store here to run it.",
        "- **not-run** (Falcon): Falcon wasn't queried in every clean window, and the rule fires on another target, so "
        "no Falcon hit in the windows it was queried in doesn't make it silent.",
        "- **✗ fails**: the rule doesn't convert for the target, or the store rejected the query.",
        "- **field-absent**: the query uses a field that no replayed document has.",
        "- **not-verified** (Jamf Protect): " + JAMF + ".",
        "- **Status**: `verified` if the rule fires on at least one target (Falcon included); otherwise "
        "`not-verified`, with the reason in a footnote. A rule that is only noisy is not-verified, and so is a rule whose "
        "only hits are not the behaviour it looks for.",
        "",
        "## How it was measured",
        "",
        "Rounds 1 and 2: each rule was converted with the pinned backends and the `pysigma-pipeline-macos` pipelines, "
        "then run directly on each bench store. A correlation was converted together with its base rules, as the "
        "fallback type its `custom.coresigma.<target>` declares if it declares one. The stores held the test host's "
        "ESF and unified log captures, replayed with `scripts/replay_capture.py` through the collectors' own filters.",
        "",
        "Clean simulation windows (UTC):",
        "",
        *[f"- {w.name}: {_utc(w.start)} to {_utc(w.end)[11:]}"
          + (f" (counted only for {_and([found[r][1] for r in w.rules])})" if w.rules else "")  # KeyError: a typo'd id
          for w in clean],
        "",
        "Idle window, for noise (UTC): " + "; ".join(
            f"{_utc(w.start)} to {_utc(w.end)} ({(w.end - w.start) / 3600:g} h)" for w in idle) + ".",
        "",
        *([notes["windows_note"], ""] if notes.get("windows_note") else []),
        "Unified log capture level: the test host captured unified log lines at Default level until "
        "2026-11-11 14:55:54 UTC, and at Info level after that. So in the morning windows and the idle window, a rule "
        "whose evidence is an Info-level line reads silent: a capture limitation, not a rule miss.",
        "",
        "Round 3 (Falcon): " + notes.get("falcon_scope", "not counted: the Falcon column shows conversion only."),
        "",
        "Versions: " + ", ".join(f"`{p}`" for p in pins) + "; bench images " + ", ".join(f"`{i}`" for i in images) + ".",
        "",
        "## Target notes",
        "",
        "- Defender / Sentinel (KQL): converts with a product-agnostic Windows-schema mapping; whether Defender "
        "populates those tables for macOS is unverified.",
        "- Elastic Defend: convert-only, with coreSigma's ECS mapping; fields were not checked. Elastic Defend 9.5.6 "
        "data from the test host exists: Defend reports a new file only as a modification, so the file_event scope "
        "misses creates there (see the README's [Known limitations](../README.md#known-limitations)).",
        "- Elastic ES|QL matches plain Sigma strings case-sensitively (pysigma-backend-elasticsearch).",
        "- `$` in a `|re` pattern is literal in Lucene, EQL and ES|QL regular expressions, so such a pattern can't "
        "match there.",
        "- Elastic EQL's `regex~` matches `|re` case-insensitively.",
        "- OpenSearch maps the path and command fields as lowercase keywords, so `|re` matches case-insensitively "
        "there; plain keyword fields (unified_log.subsystem, signing IDs) match case-sensitively.",
        "- Kibana (`scripts/deploy_sigma_rules.py`) deploys each rule in the form that converts: an EQL rule for each "
        "single-event rule and each temporal_ordered correlation, an ES|QL rule for each other correlation. So the "
        "Elastic EQL and Elastic ES|QL columns together are what Kibana runs.",
        "- Order: Elastic EQL and ClickHouse enforce a temporal_ordered correlation's order. EQL runs it as a "
        "`sequence` with `maxspan`; on ClickHouse the matrix tool rewrites pysigma-backend-clickhouse's query, which "
        "checks no order, to use `windowFunnel` over the timespan (`clickhouse_ordered` in `scripts/rule_matrix.py`). "
        "ES|QL has no temporal_ordered, and Splunk runs it as temporal (the rule's declared fallback), in any order.",
        "- ClickHouse (pysigma-backend-clickhouse) groups the other correlations over the whole search range, not "
        "per timespan. A temporal correlation there needs last − first ≤ timespan over the whole group, so over a "
        "long range ClickHouse can also miss a chain and understate noise, as well as add fires. Either way it is a "
        "backend limit, not a rule bug.",
        "- Splunk and ES|QL correlations count in fixed windows of the timespan (`bin`, `date_trunc`): a chain that "
        "crosses a window boundary is missed. An EQL sequence's `maxspan` and ClickHouse's `windowFunnel` window "
        "start at each first event.",
        "",
        "## Matrix",
        "",
        *table,
        "",
        "## Notes",
        "",
        *[f"{n}. {reason}" for reason, n in footnotes.items()],
        "",
    ]
    return "\n".join(text), {rule_id: (status[rule_id], {c: cells[rule_id][c][0] for c in COLUMNS})
                             for rule_id in matrix}


WRITTEN = ("status", "verdict", "base_of")  # the custom.coresigma keys write_back owns


def base_rules(rules_dir=RULES):
    """{rule id: [file stems of the generate: false correlations it is a base rule of]}: the rules without a row."""
    rules = [(p, yaml.safe_load(p.read_text())) for p in sorted(Path(rules_dir).rglob("*.yml"))]
    by_ref = {rule[key]: str(rule["id"]) for _, rule in rules for key in ("name", "id") if key in rule}
    found = {}
    for path, rule in rules:
        if "correlation" in rule and not rule["correlation"].get("generate", False):
            for ref in rule["correlation"]["rules"]:
                if ref in by_ref:
                    found.setdefault(by_ref[ref], []).append(path.stem)
    return found


def _with_fields(text, fields):
    """A rule file's text with custom.coresigma's WRITTEN keys set to fields ({key: str, dict or list}), replacing an
    earlier write-back; everything else (the declared fallbacks, comments) is kept as written. With no fields, an emptied
    custom.coresigma is removed, and custom too if that empties it."""
    block = []
    for key, value in fields.items():
        if isinstance(value, dict):
            block += [f"    {key}:"] + [f"      {k}: {v}" for k, v in value.items()]
        elif isinstance(value, list):
            block += [f"    {key}:"] + [f"      - {v}" for v in value]
        else:
            block.append(f"    {key}: {value}")
    lines = text.rstrip("\n").split("\n")
    if "custom:" not in lines:
        return "\n".join(lines + ["custom:", "  coresigma:"] + block) + "\n"
    at = lines.index("custom:") + 1
    if lines[at:at + 1] != ["  coresigma:"]:
        lines.insert(at, "  coresigma:")
    at += 1
    kept, i = [], at
    while i < len(lines) and lines[i].startswith("    "):
        if lines[i].startswith(tuple(f"    {key}:" for key in WRITTEN)):
            i += 1
            while i < len(lines) and lines[i].startswith("      "):
                i += 1
            continue
        kept.append(lines[i])
        i += 1
    out = lines[:at] + block + kept + lines[i:]
    if not block and not kept:
        del out[at - 1]  # "  coresigma:"
        custom = out.index("custom:")
        if custom + 1 >= len(out) or not out[custom + 1].startswith("  "):
            del out[custom]
    return "\n".join(out) + "\n"


def write_back(results, rules_dir=RULES):
    """Write render's {rule id: (status, {column: word})} into each rule's custom.coresigma, and status base with
    base_of (base_rules) into each correlation base rule. Raises ValueError, before writing that file, if the edit would
    change anything else in it."""
    bases = base_rules(rules_dir)
    for path in sorted(Path(rules_dir).rglob("*.yml")):
        text = path.read_text()
        rule = yaml.safe_load(text)
        rule_id = str(rule.get("id"))
        coresigma = (rule.get("custom") or {}).get("coresigma") or {}
        if rule_id in results:
            fields = dict(zip(("status", "verdict"), results[rule_id]))
        elif rule_id in bases:
            fields = {"status": "base", "base_of": bases[rule_id]}
        elif coresigma.get("status") == "base" or "base_of" in coresigma:
            fields = {}  # no longer a base rule, and no row: clear the stale base status
        else:
            continue
        new = _with_fields(text, fields)
        expected = copy.deepcopy(rule)
        custom = dict(rule.get("custom") or {})
        merged = {**{k: v for k, v in coresigma.items() if k not in WRITTEN}, **fields}
        if merged:
            custom["coresigma"] = merged
        else:
            custom.pop("coresigma", None)
        if custom:
            expected["custom"] = custom
        else:
            expected.pop("custom", None)
        if yaml.safe_load(new) != expected:
            raise ValueError(f"{path}: the write-back would change more than custom.coresigma")
        path.write_text(new)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Rule × target conversion (round 1) and bench verdict (round 2) "
                                                 "matrix, and the support matrix rendered from it")
    parser.add_argument("round", choices=["convert", "verdicts", "render"])
    parser.add_argument("--windows", help="sim_windows.json, for verdicts and render")
    parser.add_argument("--rules-dir", default=str(RULES))
    parser.add_argument("--out", help="default: reports/matrix.json; render: docs/SUPPORT_MATRIX.md")
    parser.add_argument("--matrix", default=str(ROOT / "reports" / "matrix.json"), help="render's input")
    parser.add_argument("--notes", default=str(ROOT / "reports" / "verification.json"),
                        help="render's Falcon verdicts, not-verified reasons and rule notes")
    parser.add_argument("--falcon", help="render: the read-only Falcon query results (per-hit timestamps) to compute "
                                         "the Falcon column from, instead of --notes' falcon verdicts; read, never "
                                         "copied")
    parser.add_argument("--write-rules", action="store_true",
                        help="render: also write status and verdicts into each rule's custom.coresigma")
    parser.add_argument("--noise", help="verdicts and render: another noise sample, a JSON file whose \"rates\" and "
                                        "\"sigma_rates\" are {rule id: hits/hour} (the private laptop baseline; "
                                        "load_noise); read, never copied")
    parser.add_argument("--noise-only", action="store_true",
                        help="verdicts: recompute --matrix's verdicts with --noise, without the stores")
    args = parser.parse_args(argv)
    if args.noise_only and (args.round != "verdicts" or not args.noise):
        parser.error("--noise-only is for verdicts, with --noise")
    noise = load_noise(args.noise) if args.noise else None
    noise_rates = noise.rates if noise else None
    if args.noise_only:
        before = json.loads(Path(args.matrix).read_text())
        after = noise_only(before, noise_rates, args.rules_dir)
        out = Path(args.out or ROOT / "reports" / "matrix.json")
        out.write_text(json.dumps(after, indent=2, sort_keys=True) + "\n")
        for rule_id, row in after.items():
            for target, cell in row.items():
                if cell.get("verdict") != before[rule_id][target].get("verdict"):
                    print(f"{rule_id} {target}: {before[rule_id][target]['verdict']} -> {cell['verdict']}")
        print(f"{len(after)} rules -> {out}")
        return
    if args.round in ("verdicts", "render") and not args.windows:
        parser.error(f"{args.round} needs --windows")
    if args.round == "render":
        out = Path(args.out or ROOT / "docs" / "SUPPORT_MATRIX.md")
        try:
            text, results = render(json.loads(Path(args.matrix).read_text()), json.loads(Path(args.notes).read_text()),
                                   load_windows(args.windows), args.rules_dir, noise,
                                   json.loads(Path(args.falcon).read_text()) if args.falcon else None)
        except ValueError as e:
            parser.error(str(e))
        out.write_text(text)
        if args.write_rules:
            write_back(results, args.rules_dir)
        print(f"{Counter(s for s, _ in results.values())} -> {out}" + (" and the rules" if args.write_rules else ""))
        return
    args.out = args.out or str(ROOT / "reports" / "matrix.json")
    windows = []
    if args.round == "verdicts":
        try:  # before the long run; verdicts() then gets only the windows it uses, so nothing is reported twice
            windows = sum(select_windows(load_windows(args.windows)), [])
        except ValueError as e:
            parser.error(f"{args.windows}: {e}")
    matrix = convert_all(args.rules_dir, live_fields())
    measures = {}
    found = verdicts(matrix, windows, args.rules_dir, noise_rates, measures) if args.round == "verdicts" else {}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(
        {rule_id: {t: {**asdict(r), **({"verdict": found[rule_id][t]} if found else {}),
                       **measures.get(rule_id, {}).get(t, {})} for t, r in row.items()}
         for rule_id, row in matrix.items()}, indent=2, sort_keys=True) + "\n")
    for target in TARGETS:
        statuses = Counter(row[target].status for row in matrix.values())
        line = ", ".join(f"{s} {statuses[s]}" for s in ("converts", "fails", "field-absent"))
        if found:
            line += " | " + ", ".join(f"{v} {n}" for v, n in sorted(Counter(f[target] for f in found.values()).items()))
        print(f"{target:13} {line}")
    print(f"{len(matrix)} rules -> {args.out}")


if __name__ == "__main__":
    main()
