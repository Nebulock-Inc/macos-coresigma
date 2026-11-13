"""Rule × target matrix (scripts/rule_matrix.py): conversion, field checks and verdicts.

The bench tests replay generated exec events at a January 2026 time no capture covers into every live store
(scripts/bench_up.sh elastic splunk opensearch clickhouse), run the matrix's queries there, then delete them
(not from Splunk: its free license can't delete; they stay outside every simulation window, and each run's rules
match only its own events, by a marker in their command lines).
"""
import copy
import json
import random
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipelines" / "pysigma-pipeline-macos"))  # this checkout's plugin, as its tests' conftest
sys.path.insert(0, str(ROOT / "scripts"))
import replay_capture  # noqa: E402
import rule_matrix as rm  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
EXEC = {"product": "macos", "category": "process_creation"}
LIVE = ["elastic-eql", "opensearch", "splunk", "clickhouse"]  # the stores; elastic-esql (ES|QL on Elastic) is checked apart
# convert_all converts for every target, clickhouse included; its backend is optional (requirements-clickhouse.txt)
needs_clickhouse = pytest.mark.skipif(rm.ClickhouseBackend is None, reason="pysigma-backend-clickhouse not installed "
                                      "(requirements-clickhouse.txt, Python 3.13+)")


def write_rule(directory, stem, logsource, detection, level="medium", **extra):
    rule_id = str(uuid.uuid4())
    (directory / f"{stem}.yml").write_text(yaml.safe_dump(
        {"title": stem, "id": rule_id, "status": "experimental", "level": level,
         **({"logsource": logsource, "detection": detection} if logsource else {}), **extra}))
    return rule_id


def rule_id(path):
    return yaml.safe_load((ROOT / "rules" / path).read_text())["id"]


@needs_clickhouse
def test_absent_field_flagged(tmp_path):
    """A query on a field no replayed document on the target has is field-absent; a target, or a source, without a
    field list isn't checked."""
    xpc = write_rule(tmp_path, "xpc", {"product": "macos", "category": "xpc_connection"},
                     {"sel": {"XpcServiceName|startswith": "com.example."}, "condition": "sel"})
    docs = {"@timestamp", "event.action", "process.executable"}
    row = rm.convert_all(tmp_path, {"elastic-eql": {"esf": docs}, "clickhouse": {"esf": docs | {"xpc.service_name"}},
                                    "splunk": {"ul": docs}})[xpc]
    assert row["elastic-eql"].status == "field-absent" and "xpc.service_name" in row["elastic-eql"].reason
    assert "xpc.service_name" in row["elastic-eql"].query
    assert row["clickhouse"].status == "converts"
    assert row["splunk"].status == "converts"  # it has UL documents only: an ESF rule isn't checked
    assert row["opensearch"].status == "converts"


def test_clickhouse_backend_missing_ends_the_run(monkeypatch, tmp_path):
    """Without the optional backend, converting for clickhouse ends the run with how to install it, instead of
    recording every rule as failing there."""
    monkeypatch.setattr(rm, "ClickhouseBackend", None)
    write_rule(tmp_path, "r", EXEC, {"sel": {"Image|endswith": "/curl"}, "condition": "sel"})
    with pytest.raises(SystemExit, match="requirements-clickhouse.txt"):
        rm.convert_all(tmp_path)


@pytest.fixture(scope="module")
def shipped():
    if rm.ClickhouseBackend is None:
        pytest.skip("pysigma-backend-clickhouse not installed (requirements-clickhouse.txt, Python 3.13+)")
    return rm.convert_all()


def test_every_rule_every_target(shipped):
    """Each rule with output of its own (not a correlation's base rule) gets every target's status; a failure has a
    reason, a conversion a query. No rule crashes the tool."""
    rules = [yaml.safe_load(p.read_text()) for p in (ROOT / "rules").rglob("*.yml")]
    bases = {name for r in rules if "correlation" in r for name in r["correlation"]["rules"]}
    assert set(shipped) == {r["id"] for r in rules if r.get("name") not in bases}
    for row in shipped.values():
        assert list(row) == rm.TARGETS
        assert all(r.status != "field-absent" for r in row.values())  # no field lists given; defend has none
        for result in row.values():
            assert result.status in ("converts", "fails", "field-absent")
            assert result.reason and not result.query if result.status == "fails" else result.query


def test_correlations_with_base_rules_and_fallbacks(shipped):
    paste = shipped[rule_id("correlation/paste_to_stealer.yml")]
    assert paste["splunk"].status == "converts" and "temporal" in paste["splunk"].reason  # declared fallback
    assert "event_type_count >= 3" in paste["splunk"].query
    assert (paste["logscale"].status, paste["logscale"].reason) == ("fails", "custom.coresigma.logscale: unsupported")
    assert paste["clickhouse"].status == "converts" and "rule_sequence" in paste["clickhouse"].query
    assert paste["clickhouse"].query.endswith("HAVING windowFunnel(900000000000, 'strict_increase')(toUInt64(toUnixTimestamp64Nano("
                                              "timestamp)), sigma_rule_id = 'terminal\\_or\\_scripteditor\\_download"
                                              "\\_exec', sigma_rule_id = 'credential\\_capture\\_any', sigma_rule_id = "
                                              "'launch\\_persistence\\_or\\_ditto\\_staging') = 3")
    assert paste["clickhouse"].reason.startswith(rm.CLICKHOUSE_ORDERED)
    assert paste["elastic-esql"].status == "fails" and "temporal_ordered" in paste["elastic-esql"].reason
    assert paste["elastic-eql"].status == "converts"  # an EQL sequence, as Kibana deploys it
    assert paste["elastic-eql"].query.startswith("sequence by host.name, user.name with maxspan=900s [any where ")
    assert paste["defend"].query == paste["elastic-eql"].query
    assert rm.ESQL_BUCKETS not in paste["elastic-eql"].reason
    fanout = shipped[rule_id("correlation/credential_path_fanout.yml")]
    assert fanout["splunk"].status == "converts"
    assert fanout["splunk"].reason == f"{rm.SPLUNK_BINS}; field check skipped (no field list)"
    assert "dc(file.path)" in fanout["splunk"].query


def test_clickhouse_ordered():
    """windowFunnel replaces the unordered HAVING, one condition per UNION leg in order; anything else raises."""
    query = ("SELECT a, rule_count FROM (SELECT *, 'x\\_1' AS sigma_rule_id FROM t WHERE 1 UNION ALL SELECT *, 'y' AS "
             "sigma_rule_id FROM t WHERE 2) AS subquery GROUP BY a HAVING rule_count >= 2 AND toUnixTimestamp(last_event)"
             " - toUnixTimestamp(first_event) <= 60")
    assert rm.clickhouse_ordered(query) == query[:query.index("HAVING")] + (
        "HAVING windowFunnel(60000000000, 'strict_increase')(toUInt64(toUnixTimestamp64Nano(timestamp)), "
        "sigma_rule_id = 'x\\_1', "
        "sigma_rule_id = 'y') = 2")
    for wrong in (query.replace(">= 2", ">= 1"), query.replace("HAVING", "WHERE")):
        with pytest.raises(ValueError, match="no temporal_ordered HAVING"):
            rm.clickhouse_ordered(wrong)


@needs_clickhouse
def test_generate_true_correlation_row(tmp_path):
    """A generate: true correlation's row has the correlation's query, not its first base rule's; the base rule has
    a row of its own."""
    base = write_rule(tmp_path, "sigterm", {"product": "macos", "category": "process_signal"},
                      {"sel": {"SignalNumber": 15}, "condition": "sel"}, name="sigterm")
    corr = write_rule(tmp_path, "burst", None, None, "high", correlation={
        "type": "event_count", "rules": ["sigterm"], "group-by": ["host.name"], "timespan": "1m",
        "condition": {"gt": 10}, "generate": True})
    matrix = rm.convert_all(tmp_path)
    assert "event_count > 10" in matrix[corr]["splunk"].query and "COUNT" in matrix[corr]["clickhouse"].query.upper()
    assert "event_count" not in matrix[base]["splunk"].query


def test_correlation_legs_scoped(shipped, monkeypatch):
    """Each subsearch of a multisearch correlation (Splunk) and each UNION leg (ClickHouse) gets the time and source
    scope; a query with nowhere to put it raises instead of running unscoped."""
    paste, ran = shipped[rule_id("correlation/paste_to_stealer.yml")], []
    monkeypatch.setattr(rm, "_splunk", lambda search, start, end: ran.append(search) or [{"count": "0"}])
    monkeypatch.setattr(rm, "_clickhouse", lambda sql: ran.append(sql) or "0")
    rm.hits("splunk", paste["splunk"].query, "esf", 100, 200)
    rm.hits("clickhouse", paste["clickhouse"].query, "esf", 100, 200)
    splunk, clickhouse = ran
    assert splunk.startswith("| multisearch") and splunk.count("[ search ") == 3
    assert splunk.count("[ search index=macos sourcetype=coresigma:esf ") == 3
    assert clickhouse.count(f"FROM {rm.CH_TABLE} WHERE") == 3
    assert clickhouse.count(f"FROM (SELECT * FROM {rm.CH_TABLE} WHERE {rm._ch_time(100, 200)} AND `event.action` != '')") == 3
    with pytest.raises(ValueError, match="no subsearch"):
        rm.hits("splunk", "| multisearch [ index=macos ]", "esf", 100, 200)
    with pytest.raises(ValueError, match="to scope"):
        rm.hits("clickhouse", "SELECT * FROM logs WHERE 1", "esf", 100, 200)


@needs_clickhouse
def test_mixed_source_correlation(tmp_path, monkeypatch):
    """A correlation over an ESF and a UL rule runs on both sources' documents in every leg (each base rule's own
    conditions pick out its kind of document); each base rule's fields are checked against its own source's list."""
    write_rule(tmp_path, "dl", EXEC, {"sel": {"Image|endswith": "/curl"}, "condition": "sel"}, name="dl")
    write_rule(tmp_path, "fw", {"product": "macos", "service": "unifiedlog", "category": "firewall"},
               {"sel": {"message|contains": "disabled"}, "condition": "sel"}, name="fw")
    corr = write_rule(tmp_path, "both", None, None, "high", correlation={
        "type": "temporal", "rules": ["dl", "fw"], "group-by": ["host.name", "process.executable"], "timespan": "5m"})
    common = {"@timestamp", "host.name", "process.executable"}
    esf, ul = common | {"event.category", "event.type", "event.action"}, common | {"unified_log.subsystem", "message"}
    row = rm.convert_all(tmp_path, {"splunk": {"esf": esf, "ul": ul}, "clickhouse": {"esf": esf, "ul": ul - {"message"}},
                                    "elastic-esql": {"esf": esf}})[corr]
    assert row["splunk"].status == "converts" and "field check" not in row["splunk"].reason  # message: UL only
    assert row["clickhouse"].status == "field-absent"
    assert row["clickhouse"].reason.startswith("no replayed document has message;")
    assert row["elastic-esql"].reason.endswith("field check skipped for ul (no field list)")
    assert rm._sources(dict(rm._units(tmp_path))[corr]) == ("esf", "ul")

    ran = []
    monkeypatch.setattr(rm, "_splunk", lambda search, start, end: ran.append(search) or [{"count": "0"}])
    monkeypatch.setattr(rm, "_clickhouse", lambda sql: ran.append(sql) or "0")
    monkeypatch.setattr(rm, "_post", lambda url, body, auth=None: ran.append((url, body)) or {"values": [[0]], "count": 0})
    for target in ("splunk", "clickhouse", "elastic-esql", "opensearch"):
        rm.hits(target, row[target].query if row[target].query else "x", ("esf", "ul"), 100, 200)
    splunk, clickhouse, (esql_url, esql), (os_url, _) = ran
    assert splunk.startswith("| multisearch") and splunk.count("[ search ") == 2
    assert splunk.count("[ search index=macos (sourcetype=coresigma:esf OR sourcetype=coresigma:ul) ") == 2
    assert clickhouse.count(f"FROM {rm.CH_TABLE} WHERE") == 2 and "event.action` !=" not in clickhouse
    assert clickhouse.count(f"FROM (SELECT * FROM {rm.CH_TABLE} WHERE {rm._ch_time(100, 200)}) WHERE") == 2
    assert esql["query"].startswith("from macos-telemetry-esf-*,macos-telemetry-ul-* ")
    assert os_url.endswith("/macos-telemetry-esf-*,macos-telemetry-ul-*/_count")


@pytest.mark.parametrize("status,error", [(400, rm.QueryError), (404, rm.QueryError), (429, RuntimeError),
                                          (500, RuntimeError), (503, RuntimeError)])
def test_store_errors(monkeypatch, status, error):
    """A 4xx is the query's fault (the row fails); a 5xx or 429 is the store's and ends the run."""
    reply = SimpleNamespace(ok=False, status_code=status, text="busy", json=lambda: {"error": {"root_cause": [{"reason": "why"}]}})
    monkeypatch.setattr(rm.requests, "post", lambda *a, **kw: reply)
    with pytest.raises(error, match=f"HTTP {status}"):
        rm._post("http://store", {})
    with pytest.raises(error, match=f"HTTP {status}: busy"):
        rm._clickhouse("SELECT 1")


def test_target_limitations_are_reasons(shipped):
    dotfile = shipped[rule_id("esf/macos_esf_rename_to_hidden_dotfile.yml")]
    for target in ("elastic-eql", "elastic-esql", "opensearch", "defend"):
        assert "$ in |re is literal" in dotfile[target].reason, target
    assert "$" not in dotfile["splunk"].reason
    assert "lowercase keyword" in dotfile["opensearch"].reason
    assert "\\/" not in dotfile["elastic-eql"].query  # deploy's EQL fix
    curl = shipped[rule_id("esf/macos_http_tools_with_protocol_indicators.yml")]
    assert "case-sensitive" in curl["elastic-esql"].reason
    assert "unverified" in curl["kusto"].reason
    for path in ("esf/macos_http_tools_with_protocol_indicators.yml", "esf/macos_btm_launch_item_added.yml"):
        defend = shipped[rule_id(path)]["defend"]  # convert-only: Defend data exists, but no field check yet
        assert defend.status == "converts" and defend.reason.startswith(rm.DEFEND_CONVERT_ONLY)
        assert "9.5.6" in defend.reason and "no Elastic Defend data" not in defend.reason
    assert shipped[rule_id("ul/firewall_disabled.yml")]["defend"].reason == "Elastic Defend data has no unified log events"
    for path in ("esf/macos_gatekeeper_user_override.yml", "esf/macos_btm_launch_item_added.yml"):
        assert rm.DEFEND_ACTIONS in shipped[rule_id(path)]["defend"].reason, path
        assert rm.DEFEND_ACTIONS not in shipped[rule_id(path)]["elastic-eql"].reason
    assert rm.DEFEND_ACTIONS not in curl["defend"].reason
    assert rm.SPLUNK_BINS not in curl["splunk"].reason
    for path in (ROOT / "rules" / "correlation").glob("*.yml"):
        row = shipped[rule_id(f"correlation/{path.name}")]
        assert rm.SPLUNK_BINS in row["splunk"].reason, path.name
        assert row["elastic-esql"].status == "fails" or rm.ESQL_BUCKETS in row["elastic-esql"].reason, path.name
    assert rm.ESQL_BUCKETS not in curl["elastic-esql"].reason
    xprotect = shipped[rule_id("ul/macos_uls_quarantine_or_xprotect_detection.yml")]
    for target in rm.TARGETS:  # XProtect logs under com.apple.xprotect and com.apple.XProtect...
        assert (rm.XPROTECT_CASE in xprotect[target].reason) is (target in ("elastic-esql", "opensearch")), target
    assert rm.XPROTECT_CASE not in shipped[rule_id("esf/macos_xprotect_malware_detection.yml")]["elastic-esql"].reason


def test_load_windows():
    windows = rm.load_windows(FIXTURES / "sim_windows.json")
    assert [(w.name, w.status) for w in windows][:2] == [("Sim A", None), ("Sim A", "timeout")]
    assert windows[0].end - windows[0].start == 10 and windows[0].start == datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp()


def real_windows():
    """reports/sim_windows.json, the simulation windows the committed matrix was measured with."""
    return (ROOT / "reports" / "sim_windows.json").read_text()


def test_real_windows_selected(tmp_path, capsys):
    """The real file: the 3 clean 2026-11-11 morning simulations among the success windows (later live runs add more,
    each one a success entry), the complete idle windows (13.3 hours), and the rest named as excluded."""
    (tmp_path / "w.json").write_text(real_windows())
    windows = rm.load_windows(tmp_path / "w.json")
    clean, idle = rm.select_windows(windows)
    assert [w for w in clean] == [w for w in windows if w.status == "success"]
    starts = {datetime.fromtimestamp(w.start, timezone.utc).strftime("%H:%M:%S") for w in clean}
    assert {"05:29:38", "05:42:15", "06:06:17"} <= starts
    assert {w.status for w in idle} == {"complete"}  # the 6-hour window plus later idle windows: 13.3 hours in all
    assert round(sum(w.end - w.start for w in idle) / 3600, 1) == 13.3
    excluded = capsys.readouterr().err
    for status in ("timeout", "tainted", "error", "retest"):
        assert f"(status {status})" in excluded


@pytest.mark.parametrize("statuses", [[None, "complete"], ["success", "planned"], ["success", None, "retest"]])
def test_windows_fail_loudly(statuses):
    """No status isn't success, planned isn't idle: without both a success and a complete window, verdicts refuse."""
    windows = [rm.SimWindow("idle" if s in ("complete", "planned") else "sim", 0, 10, s) for s in statuses]
    with pytest.raises(ValueError, match="status success"):
        rm.select_windows(windows)
    with pytest.raises(ValueError):
        rm.verdicts({}, windows)


def test_idle_of_no_duration():
    with pytest.raises(ValueError, match="0 seconds"):
        rm.select_windows([rm.SimWindow("sim", 0, 10, "success"), rm.SimWindow("idle", 50, 50, "complete")])


@needs_clickhouse
def test_verdicts(tmp_path, monkeypatch):
    """fires: a hit in any simulation window with status success, only those (whitelist); noisy: idle hits/hour over
    the level's limit, harness commands left out; no store or no query: not-run."""
    windows = rm.load_windows(FIXTURES / "sim_windows.json")
    label = dict(zip((w.start for w in windows),
                     ["nostatus", "timeout", "error", "success", "idle", "planned", "retest"]))
    counts = {  # rule (level): hits per window; names are no substring of each other, nor have _ (ClickHouse escapes it)
        "hinoisy": ("high", {"idle": 31}),  # 5.17/h
        "hiok": ("high", {"idle": 30, "success": 1, "planned": 10**6}),  # 5/h
        "mednoisy": ("medium", {"idle": 121, "success": 1}),
        "medok": ("medium", {"idle": 120}),
        "lowlevel": ("low", {"idle": 10**6, "success": 2}),
        "failedonly": ("high", {"timeout": 9, "error": 9, "nostatus": 9}),
        "retestonly": ("medium", {"retest": 5}),  # a retest entry isn't a clean window
        "rejected": ("high", {}),
    }
    ids = {name: write_rule(tmp_path, name, EXEC, {"sel": {"Image|endswith": f"/{name}"}, "condition": "sel"}, level)
           for name, (level, _) in counts.items()}

    def hits(target, query, source, start, end, exclude=()):
        name = next(n for n in counts if n in query)
        if name == "rejected":
            raise rm.QueryError("no such index")
        assert (target in rm.LIVE, source, end - start) == (True, ("esf",), 6 * 3600 if label[start] == "idle" else 10)
        assert exclude == (rm.HARNESS_EXCLUDE if label[start] == "idle" else ())
        return counts[name][1].get(label[start], 0)

    monkeypatch.setattr(rm, "hits", hits)
    matrix, measures = rm.convert_all(tmp_path), {}
    found = rm.verdicts(matrix, windows, tmp_path, measures=measures)
    expected = {"hinoisy": "noisy", "hiok": "fires", "mednoisy": "noisy", "medok": "silent", "lowlevel": "fires",
                "failedonly": "silent", "retestonly": "silent", "rejected": "not-run"}
    for name, verdict in expected.items():
        assert found[ids[name]] == {**dict.fromkeys(rm.LIVE, verdict), **dict.fromkeys(("logscale", "kusto", "defend"), "not-run")}
    assert all(matrix[ids["rejected"]][t].status == "fails" and "rejected" in matrix[ids["rejected"]][t].reason
               for t in rm.LIVE)
    # both measures for every live row run, whatever the verdict
    exact = {"sim_hits_capped": False, "idle_capped": False}
    assert measures[ids["mednoisy"]]["clickhouse"] == {"sim_hits": 1, "idle_per_hour": round(121 / 6, 3), **exact}
    assert measures[ids["lowlevel"]]["splunk"] == {"sim_hits": 2, "idle_per_hour": round(10**6 / 6, 3), **exact}
    assert ids["rejected"] not in measures and set(measures[ids["medok"]]) == set(rm.LIVE)
    # the hook for another noise sample (the laptop noise sample): its rate counts when higher
    assert rm.verdicts(matrix, windows, tmp_path, noise_rates={ids["medok"]: 25})[ids["medok"]]["splunk"] == "noisy"


@needs_clickhouse
def test_verdicts_window_rules(tmp_path, monkeypatch):
    """A success window with a rules list (a hands-on window) counts only for those rules: another rule's hits there
    neither make it fire nor are asked for; windows without a list count for every rule."""
    target = write_rule(tmp_path, "target", EXEC, {"sel": {"Image|endswith": "/target"}, "condition": "sel"})
    other = write_rule(tmp_path, "other", EXEC, {"sel": {"Image|endswith": "/other"}, "condition": "sel"})
    path = tmp_path / "w.json"
    path.write_text(json.dumps([
        {"name": "sim", "start": "2026-01-02T00:00:00Z", "end": "2026-01-02T00:00:10Z", "status": "success"},
        {"name": "hands-on", "start": "2026-01-02T00:10:00Z", "end": "2026-01-02T00:10:10Z", "status": "success",
         "rules": [target]},
        {"name": "idle", "start": "2026-01-02T01:00:00Z", "end": "2026-01-02T02:00:00Z", "status": "complete"}]))
    windows = rm.load_windows(path)
    assert [w.rules for w in windows] == [None, (target,), None]
    hands_on = windows[1].start
    asked = []

    def hits(target_, query, source, start, end, exclude=()):
        asked.append(("other" if "/other" in query else "target", start))
        return 1 if start == hands_on else 0  # both rules hit only in the hands-on window

    monkeypatch.setattr(rm, "hits", hits)
    matrix = rm.convert_all(tmp_path)
    found = rm.verdicts(matrix, windows, tmp_path)
    assert {t: found[target][t] for t in rm.LIVE} == dict.fromkeys(rm.LIVE, "fires")
    assert {t: found[other][t] for t in rm.LIVE} == dict.fromkeys(rm.LIVE, "silent")
    assert ("other", hands_on) not in asked and ("target", hands_on) in asked


def test_noise_only(tmp_path, capsys):
    """--noise-only: matrix.json's verdicts again from its rows' own measures plus another sample's rates, no store;
    rows that didn't run keep theirs, and the rate counts only when over the rule's level limit."""
    high = write_rule(tmp_path, "high", EXEC, {"sel": {"Image|endswith": "/high"}, "condition": "sel"}, "high")
    low = write_rule(tmp_path, "low", EXEC, {"sel": {"Image|endswith": "/low"}, "condition": "sel"}, "low")
    quiet = {t.replace("-", "_"): {"sim_hits": 0, "idle_per_hour": 0.0} for t in rm.LIVE}  # every row that ran has both
    matrix = {rule: _row(**{**quiet, "elastic_eql": {"verdict": "fires", "sim_hits": 1, "idle_per_hour": 0.5},
                            "clickhouse": {"status": "fails", "verdict": "not-run"}}) for rule in (high, low)}
    assert rm.noise_only(matrix, {}, tmp_path) == matrix  # no other sample: the verdicts it had
    found = rm.noise_only(matrix, {high: 5.1, low: 10**6}, tmp_path)
    assert (found[high]["elastic-eql"]["verdict"], found[high]["splunk"]["verdict"]) == ("noisy", "noisy")
    assert found[high]["clickhouse"]["verdict"] == "not-run" and found[high]["logscale"]["verdict"] == "not-run"
    assert found[low] == matrix[low]  # low is never noisy
    assert rm.noise_only(matrix, {high: 5}, tmp_path) == matrix  # at the limit is not over it
    assert matrix[high]["elastic-eql"]["verdict"] == "fires"  # the input is left as it was

    (tmp_path / "matrix.json").write_text(json.dumps(matrix))
    (tmp_path / "noise.json").write_text(json.dumps({"rates": {high: 6}, "samples": {}}))
    rm.main(["verdicts", "--noise-only", "--noise", str(tmp_path / "noise.json"), "--matrix",
             str(tmp_path / "matrix.json"), "--out", str(tmp_path / "out.json"), "--rules-dir", str(tmp_path)])
    assert json.loads((tmp_path / "out.json").read_text())[high]["splunk"]["verdict"] == "noisy"
    assert f"{high} elastic-eql: fires -> noisy" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        rm.main(["verdicts", "--noise-only"])  # needs the sample

    (tmp_path / "noise.json").write_text(json.dumps({"rates": {high: 0.0, low: 7.0, "esf": 2.0},
                                                     "sigma_rates": {high: 25.0, low: 6.5, "ul": 1.5}}))
    assert rm.load_noise(tmp_path / "noise.json").rates == {high: 25.0, low: 7.0, "esf": 2.0, "ul": 1.5}
    rm.main(["verdicts", "--noise-only", "--noise", str(tmp_path / "noise.json"), "--matrix",
             str(tmp_path / "matrix.json"), "--out", str(tmp_path / "out.json"), "--rules-dir", str(tmp_path)])
    assert json.loads((tmp_path / "out.json").read_text())[high]["splunk"]["verdict"] == "noisy"
    (tmp_path / "noise.json").write_text(json.dumps({"rates": {high: 1.0}}))  # an EQL-only file, as before
    assert rm.load_noise(tmp_path / "noise.json").rates == {high: 1.0}


def test_load_noise_uncounted_and_hours(tmp_path):
    """A rule neither count took is uncounted, with its reason, not 0/h; one either count took is counted. Each
    sample's hours, the Sigma pass's where both have it."""
    (tmp_path / "noise.json").write_text(json.dumps({
        "rates": {"e": 0.0}, "skipped": {"ul": "unified log: the samples are ESF only", "corr": "eql fails",
                                         "both": "eql fails"},
        "samples": {"fresh": {"hours": 2.0}, "slices": {"hours": 0.25}},
        "sigma_rates": {"e": 1.0, "ul": 0.0}, "sigma_skipped": {"corr": "a correlation", "e2": "a correlation"},
        "sigma_samples": {"fresh": {"hours": 2.0}, "ul": {"hours": 2.6}}}))
    noise = rm.load_noise(tmp_path / "noise.json")
    assert noise.uncounted == {"corr": "a correlation", "both": "eql fails", "e2": "a correlation"}
    assert noise.rates == {"e": 1.0, "ul": 0.0} and noise.hours == {"fresh": 2.0, "slices": 0.25, "ul": 2.6}


@needs_clickhouse
def test_eql_cap_is_a_lower_bound(tmp_path, monkeypatch):
    """An EQL window count of EQL_SIZE (the _eql/search size) is marked capped; other stores' counts are exact."""
    rule = write_rule(tmp_path, "many", EXEC, {"sel": {"Image|endswith": "/many"}, "condition": "sel"}, "high")
    windows = [rm.SimWindow("sim", 0, 10, "success"), rm.SimWindow("idle", 100, 3700, "complete")]
    monkeypatch.setattr(rm, "hits", lambda target, query, source, start, end, exclude=():
                        rm.EQL_SIZE if (target, start) == ("elastic-eql", 100) else 3)
    measures = {}
    found = rm.verdicts(rm.convert_all(tmp_path), windows, tmp_path, measures=measures)[rule]
    assert measures[rule]["elastic-eql"] == {"sim_hits": 3, "idle_per_hour": rm.EQL_SIZE, "sim_hits_capped": False,
                                             "idle_capped": True}
    assert measures[rule]["splunk"]["idle_capped"] is False and found["elastic-eql"] == "noisy"


def test_harness_exclusion_constant():
    assert rm.HARNESS_EXCLUDE == ("/var/coresigma/",)


# --- bench: scripts/bench_up.sh elastic splunk opensearch clickhouse --------------------------------------------

def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.fixture(scope="module")
def bench(tmp_path_factory, monkeypatch_module):
    """Rules, windows and replayed documents: an exec of /Applications/foo at t0 (in a simulation window) and 12
    capture-harness gzip execs in the idle hour after it, all with this run's marker in their command lines."""
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp() + random.randrange(30 * 24) * 3600
    run = uuid.uuid4().hex[:12]  # Splunk keeps earlier runs' events: the rules and counts match this run's only
    windows = [rm.SimWindow("foo", t0 - 1, t0 + 1, "success"),
               rm.SimWindow("idle (bench)", t0 + 30, t0 + 3630, "complete")]
    base = json.loads((FIXTURES / "derived" / "exec_long_commandline.ndjson").read_text())

    def exec_event(path, args, t):
        raw = copy.deepcopy(base)
        raw["time"], raw["event"]["exec"]["args"] = iso(t), args
        raw["event"]["exec"]["target"]["executable"]["path"] = path
        return json.dumps(raw) + "\n"

    directory = tmp_path_factory.mktemp("matrix")
    capture = directory / "capture.json"
    capture.write_text(exec_event("/Applications/foo", ["foo", run], t0) + "".join(
        exec_event("/usr/bin/gzip", ["gzip", "-9", f"/var/coresigma/captures/{run}.{i}.json"], t0 + 60 + 60 * i)
        for i in range(12)))
    rules = directory / "rules"
    rules.mkdir()
    ids = {name: write_rule(rules, name, EXEC, {"sel": {"Image|endswith": image, "CommandLine|contains": run},
                                                "condition": "sel"}, level)
           for name, image, level in (("foo", "/Foo", "low"), ("gzip", "/gzip", "high"))}

    monkeypatch_module.setenv("ES_USER", rm.ES_AUTH[0])
    monkeypatch_module.setenv("ES_PASSWORD", rm.ES_AUTH[1])
    monkeypatch_module.setenv("SPLUNK_HEC_TOKEN", rm.setting("SPLUNK_HEC_TOKEN", ""))
    stores = {"elastic": rm.ES_URL, "opensearch": rm.OS_URL, "splunk": replay_capture.URLS["splunk"], "clickhouse": rm.CH_URL}
    span = {"range": {"@timestamp": {"gte": int(t0 - 1) * 1000, "lte": int(t0 + 3700) * 1000, "format": "epoch_millis"}}}
    try:
        for target, url in stores.items():
            replay_capture.replay([capture], lambda source: replay_capture.open_sender(target, source, url, True))
        for url, auth in ((rm.ES_URL, rm.ES_AUTH), (rm.OS_URL, None)):
            requests.post(f"{url}/macos-telemetry-*/_refresh", auth=auth).raise_for_status()
        deadline = time.time() + 120
        while int(rm._splunk(f'search index=macos sourcetype=coresigma:esf process.command_line="*{run}*" | stats count',
                             t0 - 1, t0 + 3700)[0]["count"]) < 13:
            assert time.time() < deadline, "Splunk didn't index the replayed events in 2 minutes"
            time.sleep(2)
        yield SimpleNamespace(rules=rules, ids=ids, windows=windows)
    finally:
        for url, auth in ((rm.ES_URL, rm.ES_AUTH), (rm.OS_URL, None)):
            requests.post(f"{url}/macos-telemetry-*/_delete_by_query?refresh=true", auth=auth, json={"query": span})
        rm._clickhouse(f"ALTER TABLE {rm.CH_TABLE} DELETE WHERE {rm._ch_time(t0 - 1, t0 + 3700)} SETTINGS mutations_sync = 1")


@pytest.fixture(scope="module")
def monkeypatch_module():
    with pytest.MonkeyPatch.context() as mp:
        yield mp


@pytest.mark.bench
def test_case_insensitive_paths_all_targets(bench):
    """Image|endswith /Foo fires on /Applications/foo on every live store but ES|QL: it runs, case-sensitively, and
    finds nothing (a reason says so)."""
    matrix = rm.convert_all(bench.rules)
    found = rm.verdicts(matrix, bench.windows, bench.rules)[bench.ids["foo"]]
    assert {t: found[t] for t in LIVE} == dict.fromkeys(LIVE, "fires")
    esql = matrix[bench.ids["foo"]]["elastic-esql"]
    assert (found["elastic-esql"], esql.status) == ("silent", "converts") and "case-sensitive" in esql.reason


@pytest.mark.bench
def test_harness_commands_not_noisy(bench):
    """A rule whose only idle hits are the capture harness's own commands (/var/coresigma/) isn't noisy."""
    matrix = rm.convert_all(bench.rules)
    gzip, idle = bench.ids["gzip"], bench.windows[1]
    for target in rm.LIVE:  # 12 in the idle hour, over high's 5/h, when counted
        assert rm.hits(target, matrix[gzip][target].query, "esf", idle.start, idle.end) == 12, target
    found = rm.verdicts(matrix, bench.windows, bench.rules)[gzip]
    assert {t: found[t] for t in rm.LIVE} == dict.fromkeys(rm.LIVE, "silent")


@pytest.mark.bench
def test_field_lists_from_documents(bench):
    """Field lists hold what replayed documents have, per source: not the templates' or ClickHouse's columns."""
    fields = rm.live_fields()
    for target in LIVE + ["elastic-esql"]:
        assert {"process.command_line", "event.action"} <= fields[target]["esf"], target
        assert "unified_log.subsystem" not in fields[target]["esf"], target


@pytest.mark.parametrize("stdout, error", [
    ('{"messages": [{"type": "ERROR", "text": "Unknown search command"}]}\n200', rm.QueryError),  # in-stream: the query's fault
    ("down\n503", RuntimeError),  # the store's fault: ends the run
])
def test_splunk_errors(monkeypatch, stdout, error):
    monkeypatch.setattr(rm.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=stdout))
    with pytest.raises(error):
        rm._splunk("search x")


def test_splunk_skips_preview_rows(monkeypatch):
    """A long export streams partial (preview) results first: only the final rows count."""
    stdout = ('{"preview":true,"offset":0,"result":{"count":"1300000"}}\n'
              '{"preview":false,"offset":0,"lastrow":true,"result":{"count":"1978494"}}\n200')
    monkeypatch.setattr(rm.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=stdout))
    assert rm._splunk("search x | stats count") == [{"count": "1978494"}]


def test_splunk_asks_for_no_preview_and_fails_on_no_count(monkeypatch):
    """The export is asked for final results only, and a count with no result row ends the run instead of reading 0."""
    calls = []
    monkeypatch.setattr(rm.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or SimpleNamespace(stdout="\n200"))
    assert rm._splunk("search x") == [] and "preview=false" in calls[0]
    with pytest.raises(RuntimeError, match="no result"):
        rm.hits("splunk", "a=1", "esf", 0, 10)


def _row(**cells):
    """A matrix.json row: every target silent (live) or converts, with no reason, but for cells: {target: changes}."""
    return {t: {"status": "converts", "query": "q", "reason": "", "verdict": "silent" if t in rm.LIVE else "not-run",
                **cells.get(t.replace("-", "_"), {})} for t in rm.TARGETS}


def test_falcon_verdicts_only_from_queried_windows_as_trimmed():
    """Falcon counts only the shipped query's hits inside a success window as it now stands (its end trimmed before
    the cleanup) that a queried window contains. A rule that fires elsewhere, with no such hit while some success
    window wasn't queried, is not-run, not silent."""
    W = rm.SimWindow
    t0 = rm._epoch("2026-01-02T00:00:00Z")
    windows = [W("Sim A", t0, t0 + 5.5, "success"),  # queried for its first 10 s, trimmed since
               W("Sim B", t0 + 600, t0 + 610, "success"),  # never queried
               W("Sim A", t0 + 1200, t0 + 1210, "timeout"), W("idle", t0 + 3600, t0 + 7200, "complete")]
    fires = {"elastic_eql": {"verdict": "fires"}}
    matrix = {"r1": _row(**fires), "r2": _row(**fires), "r3": _row(), "r4": _row(**fires), "r5": _row(),
              "r6": _row(logscale={"status": "fails"})}

    def run(rule, *ts, query="q", kind="diagnostic-tag"):
        return {"kind": kind, "rule": rule, "window": "2026-01-02T00:00:00Z/2026-01-02T00:00:10Z", "status": "ok",
                "matches": [{"ts": f"2026-01-02T00:00:0{t}+00:00"} for t in ts]}
    results = {"diagnostic_queries": {r: "aid=<aid> | q" for r in matrix}, "queries_as_run": {"r4": "aid=<aid> | old"},
               "results": [run("r1", "2.5"), run("r2", "6.0"),  # r2: a cleanup hit, after the trimmed end
                           run("r3"), run("r4", "2.0", kind="converted"), run("r5", "6.0"), run("r6", "1.0")]}
    assert rm.falcon_verdicts(results, windows, matrix) == {
        "r1": ("fires", ""), "r2": ("not-run", rm.FALCON_UNQUERIED), "r3": ("silent", ""), "r5": ("silent", "")}
    # r4's only results are another query's; r6 doesn't convert: neither gets a Falcon verdict
    queried_all = [w for w in windows if w.name != "Sim B"]
    assert rm.falcon_verdicts(results, queried_all, matrix)["r2"] == ("silent", "")
    cells = rm.final_cells(matrix, rm.falcon_verdicts(results, windows, matrix))
    assert cells["r2"]["logscale"] == ("not-run", rm.FALCON_UNQUERIED) and cells["r4"]["logscale"] == ("converts", "")
    assert rm.MARK["not-run"] == "not-run"


def test_falcon_verdicts_window_rules():
    """A hands-on window (a rules list) counts for Falcon only for its rules: another rule's Falcon hit there isn't a
    fire, and an unqueried hands-on window doesn't make another rule not-run."""
    W = rm.SimWindow
    t0 = rm._epoch("2026-01-02T00:00:00Z")
    windows = [W("Sim A", t0 + 600, t0 + 610, "success"), W("hands-on", t0, t0 + 10, "success", ("r1",)),
               W("idle", t0 + 3600, t0 + 7200, "complete")]
    fires = {"elastic_eql": {"verdict": "fires"}}
    matrix = {"r1": _row(), "r2": _row(), "r3": _row(**fires)}

    def run(rule, *ts, window="2026-01-02T00:00:00Z/2026-01-02T00:00:10Z"):
        return {"kind": "diagnostic-tag", "rule": rule, "window": window, "status": "ok",
                "matches": [{"ts": f"2026-01-02T00:00:0{t}+00:00"} for t in ts]}
    results = {"diagnostic_queries": {r: "aid=<aid> | q" for r in matrix},
               "results": [run("r1", "5"), run("r2", "5"),  # both hit in the hands-on window, which counts for r1 only
                           run("r3", window="2026-01-02T00:10:00Z/2026-01-02T00:10:10Z")]}  # r3: Sim A only, no hit
    assert rm.falcon_verdicts(results, windows, matrix) == {"r1": ("fires", ""), "r2": ("silent", ""),
                                                            "r3": ("silent", "")}


def test_short_reasons():
    assert rm._short("kusto", "mapping unverified; field check skipped (no field list)") == "mapping unverified"
    assert rm._short("splunk", "field check skipped (no field list)") == "field check skipped (no field list)"
    assert rm._short("kusto", "Invalid field: X. Please use the following fields:") == "Invalid field: X."
    assert rm._short("kusto", "Unable to determine table name from rule.  The query table is determined in order:") == \
        "Unable to determine table name from rule."


def test_render_and_write_back(tmp_path):
    """The support matrix: verdict cells, one footnote number per distinct reason, Falcon from round 3, Jamf
    not-verified, each rule's status with its reason; the write-back keeps declared fallbacks and comments."""
    rules = tmp_path / "rules"
    (rules / "esf").mkdir(parents=True)
    (rules / "correlation").mkdir()
    a = write_rule(rules / "esf", "a", EXEC, {"sel": {"Image|endswith": "/a"}, "condition": "sel"})
    b = write_rule(rules / "esf", "b", EXEC, {"sel": {"Image|endswith": "/b"}, "condition": "sel"})
    c = str(uuid.uuid4())
    corr = (f"title: c\nid: {c}\ncorrelation:\n  type: temporal\n  rules: [a, b]\n  group-by: [host.name]\n"
            "  timespan: 1m\ncustom:\n  coresigma:\n    splunk: temporal  # declared fallback\nlevel: medium\n")
    (rules / "correlation" / "c.yml").write_text(corr)
    write_rule(rules / "esf", "d", EXEC, {"sel": {"Image|endswith": "/d"}, "condition": "sel"}, name="d",
               custom={"coresigma": {"logscale": "unsupported"}})
    write_rule(rules / "esf", "f", EXEC, {"sel": {"Image|endswith": "/f"}, "condition": "sel"}, name="f")
    f_text = (rules / "esf" / "f.yml").read_text()
    (rules / "correlation" / "e.yml").write_text(  # d and f are its base rules: no row, status base
        f"title: e\nid: {uuid.uuid4()}\ncorrelation:\n  type: temporal\n  rules: [d, f]\n  group-by: [host.name]\n"
        "  timespan: 1m\nlevel: medium\n")
    case = {"reason": "ES|QL is case-sensitive"}
    matrix = {
        a: _row(elastic_eql={"verdict": "fires", "sim_hits": 2}, elastic_esql=case,
                splunk={"status": "fails", "reason": "splunk rejected it", "verdict": "not-run"}),
        b: _row(elastic_esql=case, logscale={"status": "fails", "reason": "no Falcon mapping"}),
        c: _row(clickhouse={"verdict": "noisy", "sim_hits": 3, "idle_per_hour": 30.54}),
    }
    notes = {"falcon": {a: "fires"}, "falcon_scope": "selector matches, three windows.", "windows_note": "Sim B ran twice.",
             "not_verified": {b: "no simulation exercised it", c: "{noisy}; its hits are background"}, "notes": {c: "ClickHouse groups the whole range"}}
    windows = rm.load_windows(FIXTURES / "sim_windows.json")
    text, results = rm.render(matrix, notes, windows, rules)
    lines = text.splitlines()
    assert "| a (esf) | verified | ✅ fires | ⚪ silent¹ | ⚪ silent | ✗ fails² | ⚪ silent | ✅ fires | converts | " \
           "converts | not-verified³ |" in lines
    assert "| b (esf) | not-verified⁴ | ⚪ silent | ⚪ silent¹ | ⚪ silent | ⚪ silent | ⚪ silent | ✗ fails⁵ | converts | " \
           "converts | not-verified³ |" in lines
    assert "| c (correlation)⁶ | not-verified⁷ | ⚪ silent | ⚪ silent | ⚪ silent | ⚪ silent | 🔶 noisy | converts | " \
           "converts | converts | not-verified³ |" in lines  # only noisy, even with simulation hits: not-verified
    for note in ("1. ES|QL is case-sensitive", "2. splunk rejected it", f"3. {rm.JAMF}",
                 "4. no simulation exercised it", "5. no Falcon mapping", "6. ClickHouse groups the whole range",
                 "7. noisy: up to 30.5 hits/h in the idle window, over the 20/h a medium-level rule allows; its hits "
                 "are background"):  # the limit comes from NOISY_PER_HOUR and the rule's level
        assert note in lines
    assert "- Sim B: 2026-01-02 00:30:00 to 00:30:10" in lines  # success windows only
    assert "Sim B ran twice." in lines
    assert "Sim A" not in text and "(6 h)" in text and "Round 3 (Falcon): selector matches, three windows." in lines
    assert "`pysigma==1.5.1`" in text and "1 verified, 2 not-verified" in text
    assert "laptop" not in text  # no --noise: no laptop sample claimed
    [defend_note] = [line for line in lines if line.startswith("- Elastic Defend:")]
    assert "9.5.6" in defend_note and "Known limitations" in defend_note and "no Elastic Defend data" not in text

    rm.write_back(results, rules)
    once = {p.name: p.read_text() for p in rules.rglob("*.yml")}
    rm.write_back(results, rules)
    assert once == {p.name: p.read_text() for p in rules.rglob("*.yml")}  # a second write-back changes nothing
    assert "    splunk: temporal  # declared fallback\n" in once["c.yml"]
    custom = yaml.safe_load(once["c.yml"])["custom"]["coresigma"]
    assert custom["splunk"] == "temporal" and custom["status"] == "not-verified" and custom["verdict"]["clickhouse"] == "noisy"
    assert yaml.safe_load(once["d.yml"])["custom"]["coresigma"] == {"logscale": "unsupported", "status": "base",
                                                                     "base_of": ["e"]}
    assert yaml.safe_load(once["f.yml"])["custom"]["coresigma"] == {"status": "base", "base_of": ["e"]}
    assert "custom" not in yaml.safe_load(once["e.yml"])  # no row, not a base rule: untouched
    b_custom = yaml.safe_load(once["b.yml"])["custom"]["coresigma"]
    assert b_custom["status"] == "not-verified" and list(b_custom["verdict"]) == rm.COLUMNS
    assert b_custom["verdict"]["logscale"] == "fails" and b_custom["verdict"]["jamf-protect"] == "not-verified"

    (rules / "correlation" / "e.yml").unlink()  # d and f are no longer base rules: their stale base status goes
    rm.write_back(results, rules)
    assert yaml.safe_load((rules / "esf" / "d.yml").read_text())["custom"]["coresigma"] == {"logscale": "unsupported"}
    assert (rules / "esf" / "f.yml").read_text() == f_text  # back to exactly what it was, no empty custom left

    demoted, _ = rm.render(matrix, {**notes, "not_verified": {**notes["not_verified"], a: "background hits"}}, windows, rules)
    assert "| a (esf) | not-verified¹ | ✅ fires |" in demoted and "1. background hits" in demoted  # a reason overrides fires

    with pytest.raises(ValueError, match="need a reason"):
        rm.render(matrix, {**notes, "not_verified": {}}, windows, rules)
    with pytest.raises(ValueError, match="no store found noisy"):
        rm.render(matrix, {**notes, "not_verified": {**notes["not_verified"], b: "{noisy}"}}, windows, rules)
    with pytest.raises(ValueError, match="don't convert to LogScale"):
        rm.render(matrix, {**notes, "falcon": {b: "fires"}}, windows, rules)
    # noisy through the laptop sample only: a {noisy} reason would state an idle rate over a limit it isn't over
    laptop = {**matrix, c: _row(clickhouse={"verdict": "noisy", "sim_hits": 3, "idle_per_hour": 20})}
    with pytest.raises(ValueError, match="within the medium-level limit"):
        rm.render(laptop, notes, windows, rules)

    # with the laptop sample: its hours, its uncounted rules marked, a laptop-only {noisy}, and a Sigma-only noisy
    # verdict on a store whose query can't match named in the reason; never a rate
    dollar = "$ in |re is literal in Lucene, EQL and ES|QL regular expressions: the pattern can't match"
    laptop[b] = _row(**{t.replace("-", "_"): {"verdict": "noisy", "sim_hits": 0, "idle_per_hour": 0.0,
                                              **({"reason": dollar} if t in ("elastic-eql", "opensearch") else {})}
                        for t in rm.LIVE})
    noise = rm.Noise(eql={a: 0.0, b: 0.0, c: 30.0}, sigma={a: 0.0, b: 25.3, c: 31.7}, uncounted={a: "a correlation"},
                     hours={"fresh": 2.02, "slices": 0.28, "ul": 2.6})
    text, _ = rm.render(laptop, notes, windows, rules, noise)
    lines = text.splitlines()
    assert ("Noise also counts a private laptop sample (2.0 h of an ESF capture, 0.3 h of slices of a longer ESF log "
            "and 2.6 h of unified log)") in text
    assert "| a (esf) | verified | ✅ fires¹ | ⚪ silent² | ⚪ silent¹ | ✗ fails³ | ⚪ silent¹ | ✅ fires |" in text
    assert "1. laptop: not counted" in lines and "2. ES|QL is case-sensitive; laptop: not counted" in lines
    assert ("no simulation exercised it; noisy on the private laptop sample, over the 20/h a medium-level rule allows "
            "as Sigma's semantics count it, though the Elastic EQL and OpenSearch queries can't match it") in text
    assert "noisy on the private laptop sample, over the 20/h a medium-level rule allows; its hits are background" in text
    assert not any(rate in text for rate in ("25.3", "31.7", "30.0", "hits/h on"))  # no laptop rate
