"""UL collector tests, run against the real scrubbed `log --style ndjson` fixtures in tests/fixtures/ul/."""
import io
import json
import os
import socket
import subprocess
import sys
import threading
from contextlib import redirect_stdout
from pathlib import Path

import pytest
from sigma.pipelines.macos.taxonomy import UL_CATEGORIES, UL_FIELDS

COLLECTORS = str(Path(__file__).parent.parent / "collectors")
sys.path.insert(0, COLLECTORS)
import ul_collector  # noqa: E402
from ul_collector import ULCollector  # noqa: E402

LINES = [
    line
    for f in sorted((Path(__file__).parent / "fixtures" / "ul").glob("*.ndjson"))
    for line in f.read_text().splitlines()
    if line.strip()
]
SUDO_LINES = (Path(__file__).parent / "fixtures" / "ul" / "sudo.ndjson").read_text().splitlines()
SIGMA_OPS = {"=": str.__eq__, "startswith": str.startswith, "endswith": str.endswith}


def categories_of(raw):
    """The UL_CATEGORIES a raw event is in, by Sigma's case-insensitive matching."""
    return {
        name for name, cat in UL_CATEGORIES.items()
        if any(SIGMA_OPS[mod](str(raw.get(field, "")).lower(), value.lower()) for field, mod, value in cat.raw)
    }


def docs_for(collector, lines):
    """What collect() prints for these raw lines."""
    return [json.dumps(collector.normalize_event(json.loads(line))) for line in lines]


class FakeProc:
    """A `log` process printing `lines`: by default it has exited by the time they are read;
    with exits=False it is a live stream that runs until terminated."""

    pid = 1

    def __init__(self, lines, exits=True):
        self.stdout = (line + "\n" for line in lines)  # a generator: iterable and closable, like the pipe
        self.returncode = 0 if exits else None
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def wait(self, timeout=None):
        return self.returncode


def run_collect(monkeypatch, collector, procs, capture_recent=False):
    """Run collect() over fake `log` processes; once they run out, stop it as a signal would.

    Returns the Popen argvs, what collect() printed, and its sleeps.
    """
    calls, sleeps, procs = [], [], iter(procs)

    def popen(cmd, **kwargs):
        calls.append(cmd)
        proc = next(procs, None)
        if proc is None:
            collector.running = False
            proc = FakeProc([])
        return proc

    monkeypatch.setattr(ul_collector.subprocess, "Popen", popen)
    monkeypatch.setattr(ul_collector.time, "sleep", sleeps.append)
    out = io.StringIO()
    with redirect_stdout(out):
        collector.collect(capture_recent=capture_recent)
    return calls, out.getvalue(), sleeps


def test_skipped_line_does_not_hang_stream(monkeypatch):
    """Regression (ported from the hotfix's filtered-event test): a line that yields no document must not stall
    the stream parser. The collector no longer filters; the lines it skips are log's header and broken events."""
    collector = ULCollector()
    raw = json.loads(SUDO_LINES[0])
    lines = [
        f'Filtering the log data using "{ul_collector.PREDICATE}"',
        json.dumps(dict(raw, eventMessage="skipped"))[:-30],  # truncated event
        json.dumps(dict(raw, eventMessage="kept")),
    ]
    result = {}

    def run():
        result["out"] = run_collect(monkeypatch, collector, [FakeProc(lines)])[1]

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=5)

    assert not t.is_alive(), "parser spun forever on a skipped line"
    assert '"kept"' in result["out"]
    assert '"skipped"' not in result["out"]


def test_ndjson_lines_parsed(monkeypatch):
    collector = ULCollector()
    stdout = [f'Filtering the log data using "{ul_collector.PREDICATE}"'] + SUDO_LINES
    out = run_collect(monkeypatch, collector, [FakeProc(stdout)])[1]
    docs = [json.loads(line) for line in out.splitlines()]
    assert len(docs) == 2
    assert docs == [collector.normalize_event(json.loads(line)) for line in SUDO_LINES]


def test_stream_restart_on_exit(monkeypatch):
    collector = ULCollector()
    calls = run_collect(monkeypatch, collector, [FakeProc(SUDO_LINES)])[0]
    assert len(calls) == 2
    assert calls[0] == calls[1] == ul_collector.LOG_STREAM
    assert calls[0][:4] == ["log", "stream", "--style", "ndjson"]
    assert calls[0][-2:] == ["--predicate", ul_collector.PREDICATE]


def test_restart_backs_off_until_events_arrive(monkeypatch):
    """A stream that dies at once is restarted after 1, 2, 4 ... 60 s; one that delivered events, after 1 s."""
    collector = ULCollector()
    procs = [FakeProc([]) for _ in range(7)] + [FakeProc(SUDO_LINES), FakeProc([])]
    sleeps = run_collect(monkeypatch, collector, procs)[2]
    assert sleeps == [1, 2, 4, 8, 16, 32, 60, 1, 2]


def test_log_show_ndjson_then_stream(monkeypatch):
    collector = ULCollector()
    calls, out, _ = run_collect(monkeypatch, collector, [FakeProc(SUDO_LINES)], capture_recent=True)
    assert calls[0] == ul_collector.LOG_SHOW
    assert calls[0][:4] == ["log", "show", "--style", "ndjson"]
    assert calls[0][-2:] == ["--predicate", ul_collector.PREDICATE]
    assert calls[1] == ul_collector.LOG_STREAM
    assert len(out.splitlines()) == 2


def test_every_in_scope_line_kept(monkeypatch):
    """`log` delivers only predicate matches and the collector emits every one: no category loses events."""
    in_scope = [line for line in LINES if categories_of(json.loads(line))]
    assert set().union(*(categories_of(json.loads(line)) for line in in_scope)) == set(UL_CATEGORIES)
    collector = ULCollector()
    assert run_collect(monkeypatch, collector, [FakeProc(in_scope)])[1].splitlines() == docs_for(collector, in_scope)


def test_bad_line_skipped_without_restart(monkeypatch, capsys):
    """A malformed line is counted and skipped; the stream keeps running, and log is reaped when a signal stops it."""
    collector = ULCollector()
    bad = json.dumps(dict(json.loads(SUDO_LINES[0]), timestamp="yesterday"))

    def stream():
        yield from (SUDO_LINES[0], bad, SUDO_LINES[1])
        collector.running = False  # SIGTERM while log stream is still running
        yield SUDO_LINES[0]

    proc = FakeProc(stream(), exits=False)
    calls, out, _ = run_collect(monkeypatch, collector, [proc])
    assert calls == [ul_collector.LOG_STREAM]  # not restarted
    assert out.splitlines() == docs_for(collector, SUDO_LINES)
    assert proc.terminated
    assert "Skipped 1 unparsable stream lines" in capsys.readouterr().err


def test_log_reaped_when_collect_fails(monkeypatch):
    """An error that ends collect() still terminates the log child instead of leaking it."""
    collector = ULCollector()

    def broken_output(doc):
        raise BrokenPipeError

    monkeypatch.setattr(collector, "_emit", broken_output)
    proc = FakeProc(SUDO_LINES, exits=False)
    with pytest.raises(BrokenPipeError):
        run_collect(monkeypatch, collector, [proc])
    assert proc.terminated


def test_predicate_real_names():
    predicate = ul_collector.PREDICATE
    assert "com.apple.Authorization" in predicate
    assert 'processImagePath ==[c] "/usr/bin/sudo"' in predicate
    assert "com.apple.alf" not in predicate
    assert "com.apple.sudo" not in predicate


def test_predicate_covers_every_category():
    """Every UL_CATEGORIES predicate, case-insensitive, ORed in table order."""
    ops = {"=": "==[c]", "startswith": "BEGINSWITH[c]", "endswith": "ENDSWITH[c]"}
    clauses = [f'{field} {ops[mod]} "{value}"' for cat in UL_CATEGORIES.values() for field, mod, value in cat.raw]
    assert ul_collector.PREDICATE.split(" OR ") == clauses


def test_normalize_maps_every_ul_field():
    """Every UL_FIELDS entry, aliases included, lands on its ECS key; user.id is a string, process.pid an int."""
    collector = ULCollector()
    allowed = {f.ecs for f in UL_FIELDS.values()} | {"@timestamp", "host.name"}
    for line in LINES:
        raw = json.loads(line)
        doc = collector.normalize_event(raw)
        assert set(doc) <= allowed, line
        assert doc["host.name"] == socket.gethostname()
        for name, field in UL_FIELDS.items():
            expected = raw.get(field.raw)
            if expected is not None and field.ecs == "user.id":
                expected = str(expected)
            assert doc.get(field.ecs) == expected, (name, line)
        assert isinstance(doc["user.id"], str) and isinstance(doc["process.pid"], int)


@pytest.mark.parametrize("timestamp,expected", [
    ("2026-11-11 04:39:47.120703+0000", "2026-11-11T04:39:47.120703+00:00"),
    ("2025-12-04 16:28:00.574185-0500", "2025-12-04T21:28:00.574185+00:00"),  # log show prints local time
])
def test_timestamp_iso_utc(timestamp, expected):
    raw = dict(json.loads(SUDO_LINES[0]), timestamp=timestamp)
    assert ULCollector().normalize_event(raw)["@timestamp"] == expected


def test_collector_runs_without_pysigma():
    """Collectors run as `sudo python3` on stock macOS (3.9, no pySigma): only the pure-dataclass taxonomy may load."""
    python = "/usr/bin/python3"
    if not os.path.exists(python):
        pytest.skip(f"{python} not present; it is the stock macOS interpreter the collectors target")
    code = (
        "import importlib.util, sys; assert importlib.util.find_spec('sigma') is None, 'pySigma visible'; "
        f"sys.path.insert(0, {COLLECTORS!r}); import ul_collector; "
        "assert 'sigma' not in sys.modules; print(ul_collector.PREDICATE)"
    )
    # -S drops site-packages, so pySigma cannot be visible even if installed system-wide
    result = subprocess.run([python, "-I", "-S", "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ul_collector.PREDICATE
