"""The private laptop baseline (scripts/sample_private_baseline.py): its guards, slicing, counting and output
containment, on synthetic data only, with no store."""
import json
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipelines" / "pysigma-pipeline-macos"))
sys.path.insert(0, str(ROOT / "scripts"))
import rule_matrix as rm  # noqa: E402
import sample_private_baseline as spb  # noqa: E402


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.parametrize("url", ["http://localhost:9200", "http://127.0.0.1:9200", "http://[::1]:9200"])
def test_local_elasticsearch_allowed(url, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rm, "ES_URL", url)
    monkeypatch.setattr(spb, "run", lambda log, fresh, out: None)
    spb.main(["--log", str(tmp_path / "log"), "--out", str(tmp_path / "private")])
    assert capsys.readouterr().out.startswith("done")


@pytest.mark.parametrize("url", ["http://es.example.com:9200", "https://10.0.0.5:9200", "http://localhost.example.com"])
def test_remote_elasticsearch_refused(url, tmp_path, monkeypatch, capsys):
    """The documents are private: no sink off this machine, refused before anything is written."""
    monkeypatch.setattr(rm, "ES_URL", url)
    monkeypatch.setattr(spb, "run", lambda log, fresh, out: pytest.fail("ran"))
    with pytest.raises(SystemExit):
        spb.main(["--log", str(tmp_path / "log"), "--out", str(tmp_path / "private")])
    assert "on this machine" in capsys.readouterr().err and not (tmp_path / "private").exists()


def test_output_contained(tmp_path, monkeypatch, capsys):
    """Everything the run prints, and a failure's traceback, goes to <out>/run.log (0600, in a 0700 out); the
    terminal gets one line naming it, with --out as given."""
    monkeypatch.setattr(rm, "ES_URL", "http://localhost:9200")
    given = str(tmp_path / "a" / ".." / "private")

    def run(log, fresh, out):
        print("stdout secret")
        print("stderr secret", file=sys.stderr)
        assert fresh == out / "fresh.json.gz"  # the default: the fresh capture beside the rest

    monkeypatch.setattr(spb, "run", run)
    spb.main(["--log", str(tmp_path / "log"), "--out", given])
    assert capsys.readouterr() == (f"done, see {given}/run.log\n", "")
    out = tmp_path / "private"
    assert "stdout secret" in (out / "run.log").read_text() and "stderr secret" in (out / "run.log").read_text()
    assert (mode(out), mode(out / "run.log")) == (0o700, 0o600)

    def failing(log, fresh, out):
        raise RuntimeError("store said: secret")

    monkeypatch.setattr(spb, "run", failing)
    with pytest.raises(SystemExit) as exit_:
        spb.main(["--log", str(tmp_path / "log"), "--out", given])
    assert exit_.value.code == 1 and capsys.readouterr() == (f"failed, see {given}/run.log\n", "")
    assert "RuntimeError: store said: secret" in (out / "run.log").read_text()


def test_measure_and_combined_rate(monkeypatch):
    """A sample's rate is all its hits over all its hours; a part with no documents isn't queried, a rejected query
    skips the rule in every sample, EQL_SIZE hits mark it capped; the laptop rate is the higher sample's."""
    monkeypatch.setattr(rm, "INDEX", dict(rm.INDEX))  # measure() points it at each part's index
    loads = {"slice00": ("p0", 0, 1800, 10), "slice01": ("p1", 10**4, 10**4 + 5400, 5), "slice02": ("p2", 0, 0, 0),
             "fresh": ("pf", 0, 7200, 100)}  # (index pattern, first, last, documents): 0.5 h, 1.5 h, empty, 2 h
    counts = {("p0", "q1"): 3, ("p0", "q2"): rm.EQL_SIZE, ("p1", "q1"): 1, ("p1", "q2"): 0,
              ("pf", "q1"): 10, ("pf", "q2"): 0}
    calls = []

    def hits(target, query, source, start, end, exclude=()):
        pattern = rm.INDEX["esf"]
        calls.append((target, source, pattern, start, end))
        if query == "q3":
            raise rm.QueryError("no such field")
        return counts[pattern, query]

    monkeypatch.setattr(spb, "load", lambda part, paths: loads[part])
    monkeypatch.setattr(rm, "hits", hits)
    found, skipped = {"r1": "q1", "r2": "q2", "r3": "q3"}, {}
    slices = spb.measure({p: [p] for p in ("slice00", "slice01", "slice02")}, found, skipped)
    assert (slices["hours"], slices["documents"]) == (2.0, 15)
    assert slices["parts"]["slice01"] == {"hours": 1.5, "documents": 5}
    assert slices["hits"] == {"r1": 4, "r2": rm.EQL_SIZE, "r3": 0} and slices["capped"] == ["r2"]
    assert slices["rates"]["r1"] == 2.0 and slices["rates"]["r2"] == rm.EQL_SIZE / 2
    assert "rejected" in skipped["r3"]
    assert ("elastic-eql", "esf", "p1", 10**4, 10**4 + 5400 + 1) in calls  # each part from its first to last event
    assert not any(c[2] == "p2" for c in calls)  # the empty part
    fresh = spb.measure({"fresh": ["fresh"]}, found, skipped)
    assert fresh["rates"] == {"r1": 5.0, "r2": 0.0, "r3": 0.0}
    assert sum(c[2] == "pf" for c in calls) == 2  # r3 already skipped: not run again
    assert spb.laptop_rates({"slices": slices, "fresh": fresh}, found, skipped) == {"r1": 5.0, "r2": rm.EQL_SIZE / 2}


def test_noise_json_owner_only(tmp_path, monkeypatch):
    """noise.json is written 0600, even over an existing file with a wider mode."""
    sample = {"hours": 1, "documents": 1, "parts": {}, "hits": {"r1": 3}, "capped": [], "rates": {"r1": 3.0}}
    monkeypatch.setattr(spb, "queries", lambda: ({"r1": "q1"}, {}))
    monkeypatch.setattr(spb, "write_slices", lambda log, out: {"slice00": [log]})
    monkeypatch.setattr(spb, "_es", lambda method, path, **kw: {"index_templates": [{"index_template": {}}]})
    monkeypatch.setattr(spb, "measure", lambda parts, found, skipped: sample)
    monkeypatch.setattr(spb, "delete_indices", lambda: None)
    (tmp_path / "noise.json").write_text("{}")
    (tmp_path / "noise.json").chmod(0o644)
    spb.run(tmp_path / "log", tmp_path / "absent.json.gz", tmp_path)
    assert mode(tmp_path / "noise.json") == 0o600
    assert json.loads((tmp_path / "noise.json").read_text())["rates"] == {"r1": 3.0}


def test_private_dir_refuses_any_checkout(tmp_path):
    for inside in (ROOT, ROOT / "reports", ROOT / "no" / "such" / "dir"):
        with pytest.raises(ValueError, match="git checkout"):
            spb.private_dir(inside)
    (tmp_path / "other" / ".git").mkdir(parents=True)
    with pytest.raises(ValueError, match="git checkout"):
        spb.private_dir(tmp_path / "other" / "private")
    assert spb.private_dir(tmp_path / "private") == (tmp_path / "private").resolve()
    with pytest.raises(SystemExit):  # refused before anything is read or written
        spb.main(["--log", str(tmp_path / "log"), "--out", str(ROOT / "reports")])
    with pytest.raises(SystemExit):
        spb.main(["--out", str(tmp_path / "private")])  # neither --log nor --ul


def test_slices_are_whole_lines_evenly_spaced(tmp_path):
    lines = [b"line%03d\n" % i for i in range(100)]  # 8 bytes each
    log = tmp_path / "log"
    log.write_bytes(b"".join(lines))
    ranges = spb.slice_ranges(800, n=4, length=50)
    assert ranges == [(0, 50), (250, 300), (500, 550), (750, 800)]  # first at the start, last at the end
    with open(log, "rb") as f:
        assert spb.cut(f, 0, 50) == b"".join(lines[:6])  # the line cut at 50 is left out
        assert spb.cut(f, 250, 300) == b"".join(lines[32:37])  # and the one cut at 250
        assert spb.cut(f, 248, 304) == b"".join(lines[31:38])  # starting and ending on line ends keeps both
        assert spb.cut(f, 250, 254) == b""  # inside one line: nothing
        assert spb.cut(f, 750, 800) == b"".join(lines[94:])
    assert spb.slice_ranges(800, n=4, length=200) == [(0, 800)]  # they'd touch: the whole file once


def test_matcher_semantics():
    """Sigma's semantics after the coreSigma pipelines: strings whole and case-insensitive with wildcards, |re
    unanchored and case-sensitive, a negated absent field matches, the category's conditions are added."""
    ul = {"title": "t", "logsource": {"product": "macos", "service": "unifiedlog", "category": "tcc"},
          "detection": {"selection": {"message|contains": "Access Denied", "Image|endswith": "/tccd"},
                        "filter": {"userID": 0}, "condition": "selection and not filter"}}
    match = spb.matcher(ul)
    doc = {"unified_log.subsystem": "com.apple.TCC", "message": "x access denied y", "process.executable": "/x/TCCD"}
    assert match(doc) and match({**doc, "user.id": "501"})
    assert not match({**doc, "user.id": "0"})  # the collectors' ids are text
    assert not match({**doc, "unified_log.subsystem": "com.apple.network"})  # tcc's subsystem condition
    assert not match({**doc, "process.executable": "/x/tccd2"})  # endswith: anchored at the end
    esf = {"title": "t", "logsource": {"product": "macos", "category": "file_rename"},
           "detection": {"selection": {"TargetFilename|re": "/\\.[^/]+$", "TargetFilename|startswith": "/Users/"},
                         "condition": "selection"}}
    match = spb.matcher(esf)
    doc = {"event.category": "file", "event.action": "rename", "file.path": "/Users/a/.hidden"}
    assert match(doc) and not match({**doc, "file.path": "/Users/a/visible"})
    assert match({**doc, "file.path": "/USERS/a/.hidden"})  # startswith ignores case
    assert not match({**doc, "event.action": "create"})  # file_rename's action condition
    def tcc(selection):
        return spb.matcher({"title": "t", "logsource": {"product": "macos", "service": "unifiedlog", "category": "tcc"},
                            "detection": {"sel": selection, "condition": "sel"}})

    doc = {"unified_log.subsystem": "com.apple.TCC", "message": "Access Denied"}
    assert tcc({"message|re": "Denied$"})(doc) and not tcc({"message|re": "denied$"})(doc)  # |re keeps case
    assert tcc({"message|re|i": "denied$"})(doc)
    assert tcc({"message|cased": "Access Denied"})(doc) and not tcc({"message|cased": "access denied"})(doc)
    assert tcc({"message|contains|cased": "Denied"})(doc) and not tcc({"message|contains|cased": "denied"})(doc)
    for unsupported in ({"message": None}, {"message|exists": True}):  # skipped with a reason, never read as 0
        with pytest.raises(NotImplementedError, match="SigmaNull|SigmaExists"):
            tcc(unsupported)
    keywords = {"title": "t", "logsource": {"product": "macos", "service": "unifiedlog", "category": "tcc"},
                "detection": {"keywords": ["denied"], "condition": "keywords"}}
    with pytest.raises(NotImplementedError):
        spb.matcher(keywords)


def test_every_rule_counted_in_process_or_skipped():
    """Every single rule is counted in process on its own documents (esf or ul); correlations are skipped with a
    reason. EQL still counts only the ESF rules."""
    found, skipped = spb.matchers()
    units = dict(rm._units(rm.RULES))
    assert found["esf"].keys() | found["ul"].keys() | skipped.keys() == units.keys()
    assert all(rm._sources(units[r]) == (source,) for source, rules in found.items() for r in rules)
    assert all("correlation" in units[r][-1] for r in skipped) and len(found["ul"]) >= 18
    eql_found, eql_skipped = spb.queries()
    assert not eql_found.keys() & found["ul"].keys() and found["ul"].keys() <= eql_skipped.keys()


def test_sigma_count_and_merge(tmp_path, monkeypatch):
    """A Sigma sample's rate is its hits over its parts' first-to-last hours; a rule's sigma rate is its highest
    sample's. noise.json keeps the EQL keys and an earlier Sigma sample this run doesn't replace, 0600."""
    docs = [{"@timestamp": t, "message": m} for t, m in [
        ("2026-11-12T10:00:00Z", "hit"), ("2026-11-12T10:30:00.123456Z", "miss"), ("2026-11-12T12:00:00Z", "hit")]]
    hit = {"r1": lambda d: d["message"] == "hit"}
    assert spb.count({"a": docs, "b": docs[:1]}, hit) == {
        "hours": 2.0, "documents": 4, "hits": {"r1": 3}, "rates": {"r1": 1.5},
        "parts": {"a": {"hours": 2.0, "documents": 3}, "b": {"hours": 0.0, "documents": 1}}}
    sample = tmp_path / "ul.ndjson"
    sample.write_text("".join(json.dumps(d) + "\n" for d in docs))
    eql = {"rates": {"e1": 0.0}, "samples": {"slices": {"hours": 1}}, "skipped": {"c1": "a correlation"}}
    earlier = {"hours": 1, "documents": 9, "parts": {}, "hits": {"e1": 25}, "rates": {"e1": 25.0}}
    (tmp_path / "noise.json").write_text(json.dumps({**eql, "sigma_samples": {"fresh": earlier, "ul": earlier}}))
    (tmp_path / "noise.json").chmod(0o644)
    monkeypatch.setattr(spb, "matchers", lambda: ({"esf": {}, "ul": {"u1": hit["r1"]}}, {"c1": "a correlation"}))
    spb.run_sigma(tmp_path / "absent.json.gz", sample, tmp_path)
    noise = json.loads((tmp_path / "noise.json").read_text())
    assert {k: noise[k] for k in eql} == eql  # the EQL count, untouched
    assert noise["sigma_rates"] == {"e1": 25.0, "u1": 1.0}  # the earlier fresh sample kept, ul replaced
    assert noise["sigma_samples"]["ul"]["documents"] == 3 and noise["sigma_skipped"] == {"c1": "a correlation"}
    assert mode(tmp_path / "noise.json") == 0o600


def test_ul_alone_needs_no_elasticsearch(tmp_path, monkeypatch, capsys):
    """--ul counts in this process: no Elasticsearch, so a remote ES_URL doesn't stop it, and the EQL count isn't run."""
    monkeypatch.setattr(rm, "ES_URL", "http://es.example.com:9200")
    monkeypatch.setattr(spb, "run", lambda log, fresh, out: pytest.fail("ran the EQL count"))
    ran = []
    monkeypatch.setattr(spb, "run_sigma", lambda fresh, ul, out: ran.append((fresh, ul)))
    spb.main(["--ul", str(tmp_path / "ul.ndjson"), "--out", str(tmp_path / "private")])
    assert capsys.readouterr().out.startswith("done")
    assert ran == [((tmp_path / "private" / "fresh.json.gz").resolve(), tmp_path / "ul.ndjson")]
