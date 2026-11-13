"""ESF collector normalizer tests, run against the real scrubbed eslogger fixtures in tests/fixtures/esf/."""
import copy
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from sigma.pipelines.macos.esf import macos_esf_ecs
from sigma.pipelines.macos.taxonomy import ESF_CATEGORIES, ESF_FIELDS
from sigma.processing.transformations import AddConditionTransformation
from sigma.rule import SigmaRule

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "collectors"))
from esf_collector import ESFCollector  # noqa: E402

EVENTS = [
    pytest.param(json.loads(line), id=f"{f.stem}[{i}]")
    for f in sorted((Path(__file__).parent / "fixtures" / "esf").glob("*.json"))
    for i, line in enumerate(f.read_text().splitlines())
    if line.strip()
]


def key_of(raw):
    return list(raw["event"])[0]


def by_key(key):
    events = [p.values[0] for p in EVENTS if key_of(p.values[0]) == key]
    assert events, f"no {key} fixture"
    return events


def category_condition(category):
    """The AddCondition dict macos_esf_ecs applies to a rule of this category."""
    rule = SigmaRule.from_yaml(f"""
title: t
logsource: {{product: macos, category: {category}}}
detection: {{sel: {{Image: /bin/sh}}, condition: sel}}
""")
    pipeline = macos_esf_ecs()
    pipeline.apply(rule)
    [condition] = [
        item.transformation.conditions
        for item in pipeline.items
        if isinstance(item.transformation, AddConditionTransformation) and rule.was_processed_by(item.identifier)
    ]
    return condition


def matches(doc, condition):
    """Evaluate an AddCondition: a dict's fields ANDed (a list value means any of); a list of dicts ORed."""
    if isinstance(condition, list):
        return any(matches(doc, c) for c in condition)
    return all(doc.get(f) in v if isinstance(v, list) else doc.get(f) == v for f, v in condition.items())


@pytest.fixture(scope="module")
def collector():
    return ESFCollector()


@pytest.fixture(scope="module")
def conditions():
    return {category: category_condition(category) for category in ESF_CATEGORIES}


def test_exec_target_fields(collector):
    for raw in by_key("exec"):
        raw = copy.deepcopy(raw)
        raw["event"]["exec"]["env"] = ["AWS_SECRET_ACCESS_KEY=leak"]  # fixtures are scrubbed to []
        target = raw["event"]["exec"]["target"]
        doc = collector.normalize_event(raw)
        assert doc["process.executable"] == target["executable"]["path"]
        assert doc["process.parent.executable"] == raw["process"]["executable"]["path"]
        assert doc["process.command_line"] == " ".join(raw["event"]["exec"]["args"])
        assert doc["process.code_signature.signing_id"] == target["signing_id"]
        assert doc["process.entity_id"] == f"{target['audit_token']['pid']}-{target['audit_token']['pidversion']}"
        assert not [k for k in doc if "env" in k.split(".")]
        assert "leak" not in json.dumps(doc)


def test_rename_both_destination_types(collector):
    seen = set()
    for raw in by_key("rename"):
        rename = raw["event"]["rename"]
        dest = rename["destination"]
        doc = collector.normalize_event(raw)
        if rename["destination_type"] == 1:
            expected = f"{dest['new_path']['dir']['path']}/{dest['new_path']['filename']}"
        else:
            expected = dest["existing_file"]["path"]
        assert doc["file.path"] == expected
        assert doc["file.Ext.original.path"] == rename["source"]["path"]
        seen.add(rename["destination_type"])
    assert seen == {0, 1}



def test_rename_is_file_event_at_destination(collector, conditions):
    """A rename doc is a file_event (and a file_rename) whose file.path, TargetFilename, is the destination."""
    for raw in by_key("rename"):
        doc = collector.normalize_event(raw)
        assert matches(doc, conditions["file_event"]) and matches(doc, conditions["file_rename"])
        assert doc["file.path"] != raw["event"]["rename"]["source"]["path"]


def test_file_event_stamps_stay_defend_shaped(collector):
    """file_event's scope (create or rename) isn't what the collector stamps: create keeps event.type creation,
    rename keeps file_rename's values and no event.type."""
    for raw in by_key("create"):
        assert collector.normalize_event(raw)["event.type"] == "creation"
    for raw in by_key("rename"):
        doc = collector.normalize_event(raw)
        assert "event.type" not in doc and doc["event.category"] == "file"


@pytest.mark.parametrize("doc,expected", [
    ({"event.category": "process", "event.type": "start", "event.action": "exec"}, True),
    ({"event.category": "process", "event.type": "start", "event.action": "fork"}, False),  # Defend fork
])
def test_process_creation_excludes_forks(conditions, doc, expected):
    """Defend writes forks as process + start too: process_creation takes only exec."""
    assert matches(doc, conditions["process_creation"]) is expected


@pytest.mark.parametrize("doc,expected", [
    ({"event.category": "file", "event.type": "creation", "event.action": "creation"}, True),  # Defend create
    ({"event.category": "file", "event.type": "change", "event.action": "rename"}, True),  # Defend rename
    ({"event.category": "file", "event.type": "change", "event.action": "modification"}, False),  # Defend write
    ({"event.category": "file", "event.type": "deletion", "event.action": "deletion"}, False),
])
def test_file_event_selects_defend_shapes(conditions, doc, expected):
    """file_event selects Defend-shaped creates and renames too, not only the collector's create and rename."""
    assert matches(doc, conditions["file_event"]) is expected


def test_file_attribute_change_excludes_content_writes(conditions):
    """file + change alone would match a Defend content write; the event names keep it out."""
    write = {"event.category": "file", "event.type": "change", "event.action": "write"}
    assert not matches(write, conditions["file_attribute_change"])


def test_setgid_target_group(collector):
    for raw in by_key("setgid"):
        assert collector.normalize_event(raw)["user.target.group.id"] == raw["event"]["setgid"]["gid"]

@pytest.mark.parametrize("raw", EVENTS)
def test_action_from_key(collector, raw):
    assert collector.normalize_event(raw)["event.action"] == key_of(raw)


@pytest.mark.parametrize("raw", EVENTS + [  # minimal events cover category events with no fixture yet
    pytest.param({"event": {e: {}}}, id=f"minimal-{e}")
    for e in sorted({e for cat in ESF_CATEGORIES.values() for e in cat.events})
])
def test_categories_match_pipeline(collector, conditions, raw):
    """A doc satisfies exactly the macos_esf_ecs category conditions of the categories its event is in."""
    doc = collector.normalize_event(raw)
    matched = {category for category, condition in conditions.items() if matches(doc, condition)}
    assert matched == {category for category, cat in ESF_CATEGORIES.items() if key_of(raw) in cat.events}


def acting_token(raw):
    """audit_token of the process process.* describes: the exec target, else the acting process."""
    return raw["event"]["exec"]["target"]["audit_token"] if key_of(raw) == "exec" else raw["process"]["audit_token"]


@pytest.mark.parametrize("raw", EVENTS)
def test_user_id_is_acting_euid_string(collector, raw):
    assert collector.normalize_event(raw)["user.id"] == str(acting_token(raw)["euid"])


def test_user_name_resolved_or_omitted(collector):
    raw = copy.deepcopy(by_key("exec")[0])
    acting_token(raw)["euid"] = 0
    assert collector.normalize_event(raw)["user.name"] == "root"
    acting_token(raw)["euid"] = 4242420  # no such user
    doc = collector.normalize_event(raw)
    assert doc["user.id"] == "4242420"
    assert "user.name" not in doc


def test_collector_runs_without_pysigma():
    """Collectors run as `sudo python3` on stock macOS (3.9, no pySigma): only the pure-dataclass taxonomy may load."""
    python = "/usr/bin/python3"
    if not os.path.exists(python):
        pytest.skip(f"{python} not present; it is the stock macOS interpreter the collectors target")
    collectors = str(Path(__file__).parent.parent / "collectors")
    code = (
        "import importlib.util, sys; assert importlib.util.find_spec('sigma') is None, 'pySigma visible'; "
        f"sys.path.insert(0, {collectors!r}); import esf_collector; "
        "assert 'sigma' not in sys.modules; print(len(esf_collector.ESLOGGER_EVENTS))"
    )
    # -S drops site-packages, so pySigma cannot be visible even if installed system-wide
    result = subprocess.run([python, "-I", "-S", "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "51"  # 42 + setegid, setregid and seven od_* events


def test_host_name_present(collector):
    for param in EVENTS:
        assert collector.normalize_event(param.values[0])["host.name"] == socket.gethostname()


def test_should_keep_event_by_name_and_path(collector):
    assert collector.should_keep_event(by_key("exec")[0])
    create = copy.deepcopy(by_key("create")[0])
    assert not collector.should_keep_event(create)  # /private/var/db/diagnostics/... is not a security path
    create["event"]["create"]["destination"]["existing_file"]["path"] = "/Library/LaunchAgents/x.plist"
    assert collector.should_keep_event(create)
    rename = copy.deepcopy(next(r for r in by_key("rename") if r["event"]["rename"]["destination_type"] == 1))
    rename["event"]["rename"]["destination"]["new_path"]["dir"]["path"] = "/Library/LaunchDaemons"
    assert collector.should_keep_event(rename)


@pytest.mark.parametrize("path,kept", [
    ("/bin/zsh", True),
    ("/usr/bin/python3.12", True),
    ("/usr/bin/perl5.34", True),
    ("/usr/local/bin/node", True),
    ("/usr/share/tool/helper", False),  # "sh" in the path, not the name
    ("/System/Library/CoreServices/Crash Reporter", False),  # "sh" inside the name
    ("/usr/libexec/syncdefaultsd", False),  # "nc"
    ("/Applications/Sublime Text.app/Contents/MacOS/sublime_text", False),  # "su"
])
def test_fork_sampling_keeps_by_process_name(path, kept):
    c = ESFCollector()
    c._random.random = lambda: 1.0  # never sampled in: only the name decides
    raw = copy.deepcopy(by_key("fork")[0])
    raw["process"]["executable"]["path"] = path
    assert c.should_keep_event(raw) is kept


@pytest.mark.parametrize("key,path,kept", [
    ("create", "/Users/user/Library/Application Support/Vendor/Frameworks/x.dylib", True),  # staging rule
    ("create", "/Applications/X.app/Contents/MacOS/icon.png", True),  # media-in-code rule
    ("create", "/Users/user/repo/.claude/settings.json", True),
    ("create", "/Users/user/repo/.vscode/tasks.json", True),
    ("create", "/Library/Caches/com.apple.act.mond", True),
    ("create", "/Users/user/Library/Caches/com.apple.Safari/x", False),  # per-user Apple caches stay out
    ("open", "/Users/user/.aws/credentials", True),
    ("open", "/Users/user/.ssh/id_ed25519", True),
    ("open", "/Users/user/Documents/notes.txt", False),
    ("open", "/Applications/X.app/Contents/Info.plist", False),  # create-only families stay out of opens
    ("open", "/Users/user/Library/Application Support/Google/Chrome/Default/Cookies", False),
    ("open", "/Users/user/.claude/projects/p/s.jsonl", False),
    ("open", "/Users/user/Library/Application Support/com.apple.TCC/TCC.db", True),
])
def test_should_keep_rule_paths(collector, key, path, kept):
    raw = copy.deepcopy(by_key(key)[0])
    target = raw["event"]["create"]["destination"]["existing_file"] if key == "create" else raw["event"]["open"]["file"]
    target["path"] = path
    assert collector.should_keep_event(raw) is kept


def test_should_keep_rename_to_hidden_name(collector):
    """The rename-to-dotfile rule's events survive the filter; moves into a hidden directory don't."""
    rename = copy.deepcopy(next(r for r in by_key("rename") if r["event"]["rename"]["destination_type"] == 1))
    rename["event"]["rename"]["source"]["path"] = "/Users/user/.config/x"
    new_path = rename["event"]["rename"]["destination"]["new_path"]
    new_path["dir"]["path"], new_path["filename"] = "/Users/user/.config", ".x"
    assert collector.should_keep_event(rename)
    new_path["dir"]["path"], new_path["filename"] = "/Users/user/.Trash", "x"
    assert not collector.should_keep_event(rename)


def test_daemon_loop_backs_off_and_stops(monkeypatch, tmp_path):
    import esf_collector
    results = iter([False] * 6 + [True])
    sleeps = []

    def fake_collect(self):
        started = next(results, None)
        if started is None:
            raise SystemExit("daemon loop did not stop")
        self.running = not started  # a signal arrives during the one run that started
        return started

    monkeypatch.setattr(esf_collector.ESFCollector, "collect", fake_collect)
    monkeypatch.setattr(esf_collector, "supported_events", lambda: esf_collector.ESLOGGER_EVENTS)
    monkeypatch.setattr(esf_collector, "daemonize", lambda *args: None)
    monkeypatch.setattr(esf_collector.time, "sleep", sleeps.append)
    monkeypatch.setattr(sys, "argv", ["esf_collector.py", "--daemon", "--pid-file", str(tmp_path / "pid")])
    esf_collector.main()
    assert sleeps == [5, 10, 20, 40, 60, 60]


def _list_events(monkeypatch, stdout="", returncode=0, stderr=""):
    """Mock `eslogger --list-events`: record the command, answer like subprocess.run(check=True) would."""
    import esf_collector
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if returncode:
            raise subprocess.CalledProcessError(returncode, cmd, stdout, stderr)
        return subprocess.CompletedProcess(cmd, 0, stdout, stderr)

    monkeypatch.setattr(esf_collector.subprocess, "run", run)
    return calls


def test_subscribes_to_the_events_this_release_lists(monkeypatch, capsys, tmp_path):
    """A shorter listing, as an older release has (here without tcc_modify and gatekeeper_user_override): main
    subscribes to the rest and names the two."""
    import esf_collector
    older = (Path(__file__).parent / "fixtures" / "eslogger_events.txt").read_text().split()
    older = [e for e in older if e not in ("tcc_modify", "gatekeeper_user_override")]
    calls = _list_events(monkeypatch, "\n".join(older) + "\n")
    subscribed = []

    def fake_collect(self):
        subscribed.append(self.events)
        self.running = False
        return True

    monkeypatch.setattr(esf_collector.ESFCollector, "collect", fake_collect)
    monkeypatch.setattr(sys, "argv", ["esf_collector.py", "--pid-file", str(tmp_path / "pid")])
    esf_collector.main()
    assert calls == [esf_collector._eslogger() + ["--list-events"]]
    assert subscribed == [[e for e in esf_collector.ESLOGGER_EVENTS if e not in ("gatekeeper_user_override", "tcc_modify")]]
    assert "Skipping 2 events this macOS release's eslogger doesn't support: gatekeeper_user_override, tcc_modify" \
        in capsys.readouterr().err


def test_every_event_listed_skips_none(monkeypatch, capsys):
    import esf_collector
    _list_events(monkeypatch, "\n".join(esf_collector.ESLOGGER_EVENTS + ["access"]))
    assert esf_collector.supported_events() == esf_collector.ESLOGGER_EVENTS
    assert "Skipping" not in capsys.readouterr().err


@pytest.mark.parametrize("answer, message", [
    ({"stdout": "access\nclose\n"}, "lists none of the events"),
    ({"returncode": 64, "stderr": "Not permitted"}, "failed (exit 64): Not permitted"),
])
def test_list_events_failure_is_clear(monkeypatch, answer, message):
    import esf_collector
    _list_events(monkeypatch, **answer)
    with pytest.raises(SystemExit, match=re.escape(message)):
        esf_collector.supported_events()


def test_daemon_logs_skipped_events(monkeypatch, capsys, tmp_path):
    """In daemon mode the skip line is on the terminal (the listing runs before daemonizing) and again in the log."""
    import io
    import esf_collector
    listed = [e for e in esf_collector.ESLOGGER_EVENTS if e != "tcc_modify"]
    _list_events(monkeypatch, "\n".join(listed))
    log = io.StringIO()

    def fake_daemonize(pid_file, log_file):
        monkeypatch.setattr(sys, "stderr", log)  # what daemonize does: stderr becomes the log file

    def fake_collect(self):
        self.running = False
        return True

    monkeypatch.setattr(esf_collector, "daemonize", fake_daemonize)
    monkeypatch.setattr(esf_collector.ESFCollector, "collect", fake_collect)
    monkeypatch.setattr(sys, "argv", ["esf_collector.py", "--daemon", "--pid-file", str(tmp_path / "pid")])
    esf_collector.main()
    line = "Skipping 1 events this macOS release's eslogger doesn't support: tcc_modify"
    assert line in capsys.readouterr().err and line in log.getvalue()


def test_already_running_checked_before_listing(monkeypatch, tmp_path):
    import esf_collector
    calls = _list_events(monkeypatch, "\n".join(esf_collector.ESLOGGER_EVENTS))
    pid_file = tmp_path / "pid"
    pid_file.write_text(str(os.getpid()))  # a live process
    monkeypatch.setattr(sys, "argv", ["esf_collector.py", "--daemon", "--pid-file", str(pid_file)])
    with pytest.raises(SystemExit) as exit_:
        esf_collector.main()
    assert exit_.value.code == 1 and calls == []


# Header-based synthetic events (tests/fixtures/derived/README.md): no capture has xprotect or Gatekeeper overrides
DERIVED = [json.loads(line) for name in ("xp_malware.ndjson", "gatekeeper_user_override.ndjson")
           for line in (Path(__file__).parent / "fixtures" / "derived" / name).read_text().splitlines()]

# The ECS keys the collector writes for the categories that had no fields, each from a path in the event body
CATEGORY_FIELDS = {
    "sudo": {"source.user.name": "from_username", "user.target.name": "to_username", "user.target.id": "to_uid",
             "Target.process.executable": "command", "event.outcome": "success",
             "event.reason": "reject_info.failure_message"},
    "su": {"source.user.name": "from_username", "user.target.name": "to_username", "user.target.id": "to_uid",
           "Target.process.executable": "shell", "event.outcome": "success", "event.reason": "failure_message"},
    "authentication": {"authentication.type": "type", "event.outcome": "success",
                       "user.target.name": "data.od.record_name",
                       "process.parent.executable": "data.od.instigator.executable.path"},
    "screensharing_attach": {"source.address": "source_address", "user.target.name": "authentication_username",
                             "event.outcome": "success", "screensharing.viewer_appleid": "viewer_appleid",
                             "screensharing.existing_session": "existing_session"},
    "screensharing_detach": {"source.address": "source_address", "screensharing.viewer_appleid": "viewer_appleid"},
    "profile_add": {"profile.identifier": "profile.identifier", "profile.display_name": "profile.display_name",
                    "profile.install_source": "profile.install_source", "profile.scope": "profile.scope",
                    "process.parent.executable": "instigator.executable.path"},
    "od_create_user": {"user.target.name": "user_name", "event.outcome": "error_code",
                       "process.parent.executable": "instigator.executable.path"},
    "od_group_add": {"user.target.name": "member.member_value", "user.target.group.name": "group_name",
                     "event.outcome": "error_code", "process.parent.executable": "instigator.executable.path"},
    "od_modify_password": {"user.target.name": "account_name", "event.outcome": "error_code",
                           "process.parent.executable": "instigator.executable.path"},
    "od_delete_user": {"user.target.name": "user_name", "event.outcome": "error_code",
                       "process.parent.executable": "instigator.executable.path"},
    "od_attribute_value_add": {"user.target.name": "record_name", "od.attribute_name": "attribute_name",
                               "od.attribute_value": "attribute_value", "event.outcome": "error_code",
                               "process.parent.executable": "instigator.executable.path"},
    "setowner": {"file.path": "target.path"},
    "setflags": {"file.path": "target.path"},
    "xp_malware_detected": {"xprotect.malware_identifier": "malware_identifier",
                            "xprotect.incident_identifier": "incident_identifier", "file.path": "detected_path"},
    "xp_malware_remediated": {"xprotect.malware_identifier": "malware_identifier",
                              "xprotect.incident_identifier": "incident_identifier",
                              "xprotect.action_type": "action_type", "event.outcome": "success",
                              "file.path": "remediated_path"},
    "gatekeeper_user_override": {"file.hash.sha256": "sha256", "file.code_signature.signing_id": "signing_info.signing_id",
                                 "file.code_signature.team_id": "signing_info.team_id"},
}


def _body_value(raw, path, present=False):
    """The value at path in the event body (None if absent); with present, whether the key is there at all."""
    value = raw["event"][key_of(raw)]
    *parents, last = path.split(".")
    for part in parents:
        value = value.get(part) if isinstance(value, dict) else None
    if not isinstance(value, dict):
        return False if present else None
    return last in value if present else value.get(last)


def _expected(ecs, value):
    """event.outcome is ECS's success/failure: from ESF's success flag, or an OD error code (0 is success).
    file.hash.sha256 is lowercase hex, as in ECS and Elastic Defend."""
    if ecs == "event.outcome" and value is not None:
        return "success" if (value if isinstance(value, bool) else value == 0) else "failure"
    return value.lower() if ecs == "file.hash.sha256" and value else value


@pytest.mark.parametrize("key", sorted(CATEGORY_FIELDS))
def test_category_fields_land_on_documents(collector, key):
    """Each key is written from the raw path (absent when ESF reports null), and each path is real: some fixture
    has the key. user.* stays the acting process's user."""
    events = [p.values[0] for p in EVENTS if key_of(p.values[0]) == key] + [r for r in DERIVED if key_of(r) == key]
    assert events, f"no {key} fixture"
    seen = set()
    for raw in events:
        doc = collector.normalize_event(raw)
        for ecs, path in CATEGORY_FIELDS[key].items():
            value = _body_value(raw, path)
            assert doc.get(ecs) == _expected(ecs, value), (ecs, path)
            seen.update([ecs] if _body_value(raw, path, present=True) else [])
        assert doc["user.id"] == str(raw["process"]["audit_token"]["euid"])
    unseen = set(CATEGORY_FIELDS[key]) - seen
    assert not unseen, f"no {key} fixture has {unseen}"


def test_rejected_sudo(collector):
    """A real rejected sudo (a non-sudoer, sudoers_policy) and its successful wrapper (root to that user): outcome and
    reason from success and reject_info.failure_message. A rejection still names the run-as user it asked for."""
    by_outcome = {doc["event.outcome"]: doc for doc in map(collector.normalize_event, by_key("sudo"))
                  if doc.get("source.user.name") == "testuser" or doc.get("user.target.name") == "testuser"}
    assert by_outcome["failure"]["event.reason"] == "user NOT in sudoers"
    assert (by_outcome["failure"]["source.user.name"], by_outcome["failure"]["user.target.name"]) == ("testuser", "root")
    assert "event.reason" not in by_outcome["success"] and by_outcome["success"]["source.user.name"] == "root"


def test_outcomes_cover_success_and_failure(collector):
    """The fixtures exercise both outcomes, from a flag (authentication) and from an OD error code."""
    for key in ("authentication", "od_create_user"):
        assert {collector.normalize_event(raw)["event.outcome"] for raw in by_key(key)} == {"success", "failure"}


def test_gatekeeper_file_path_from_either_union_arm(collector):
    """gatekeeper_user_override's file is an es_file_t, or the bare path when ESF couldn't resolve the file. Were the
    es_file_t nested under its arm name (file.file), file.path still gets the path, never the object."""
    raws = [raw for raw in DERIVED if key_of(raw) == "gatekeeper_user_override"]
    nested = copy.deepcopy(raws[0])
    body = nested["event"]["gatekeeper_user_override"]
    body["file"] = {"file": body["file"]}
    docs = [collector.normalize_event(raw) for raw in raws + [nested]]
    assert [doc["file.path"] for doc in docs] == ["/Users/user/Downloads/Example.app"] * 3
    assert "file.code_signature.signing_id" not in docs[1]  # unsigned: signing_info is null


def test_sha256_lowercased(collector):
    """eslogger writes hex in uppercase (as cdhash); ECS and Defend hashes are lowercase, and keyword matches are
    case-sensitive."""
    raw = next(raw for raw in DERIVED if key_of(raw) == "gatekeeper_user_override")
    upper = raw["event"]["gatekeeper_user_override"]["sha256"]
    assert upper == upper.upper() != upper.lower()
    assert collector.normalize_event(raw)["file.hash.sha256"] == upper.lower()


def test_od_attribute_set_values_joined(collector):
    """od_attribute_set reports a list of values: the document carries them joined, as exec args are."""
    raw = copy.deepcopy(by_key("od_attribute_value_add")[0])
    body = raw["event"].pop("od_attribute_value_add")
    body["attribute_values"], body["attribute_value_count"] = ["/bin/zsh", "/bin/sh"], 2
    del body["attribute_value"]
    raw["event"]["od_attribute_set"] = body
    doc = collector.normalize_event(raw)
    assert doc["od.attribute_value"] == "/bin/zsh /bin/sh"
    assert doc["od.attribute_name"] == body["attribute_name"] and doc["user.target.name"] == body["record_name"]


def test_store_schemas_map_every_field():
    """Every ECS key the collector writes has an Elasticsearch template mapping (an EQL query on an unmapped field
    fails) and a ClickHouse column (a replay drops unknown keys)."""
    scripts = Path(__file__).parent.parent / "scripts"
    template = (scripts / "setup_elasticsearch_templates.sh").read_text().split("# UL Template")[0]
    columns = (scripts / "bench_up.sh").read_text()
    written = {field.ecs for field in ESF_FIELDS.values() if field.raw} | {"user.id", "user.name"}
    assert not [ecs for ecs in sorted(written) if f'"{ecs}":' not in template]
    assert not [ecs for ecs in sorted(written) if f"\\`{ecs}\\`" not in columns]


def test_foreground_exit_status_when_eslogger_never_starts(monkeypatch, tmp_path):
    """Without --daemon (a LaunchDaemon runs it so), an eslogger that can't start (no Full Disk Access) exits 1."""
    import esf_collector
    monkeypatch.setattr(esf_collector.ESFCollector, "collect", lambda self: False)
    monkeypatch.setattr(esf_collector, "supported_events", lambda: esf_collector.ESLOGGER_EVENTS)
    monkeypatch.setattr(sys, "argv", ["esf_collector.py", "--pid-file", str(tmp_path / "pid")])
    with pytest.raises(SystemExit) as exit_:
        esf_collector.main()
    assert exit_.value.code == 1
