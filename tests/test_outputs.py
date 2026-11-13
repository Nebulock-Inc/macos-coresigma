"""Collector outputs: ES _bulk and Splunk HEC senders batch, retry, and spool instead of dropping;
credentials stay out of argv, logs and exception messages."""
import argparse
import base64
import fnmatch
import json
import re
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "collectors"))
import auth  # noqa: E402
import outputs  # noqa: E402

SECRET = "hunter2-Sekr3t"
DROPPED = object()  # a reply whose body breaks off: the connection drops mid-chunk


class FakeServer:
    """ES/HEC stand-in on 127.0.0.1: records each POST, answers from `replies` (status, json), then 200."""

    def __init__(self, replies=()):
        self.requests, self.replies = [], list(replies)
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                server.requests.append({"path": self.path, "headers": dict(self.headers), "body": body.decode()})
                status, reply = server.replies.pop(0) if server.replies else (200, server.ok(body))
                if reply is DROPPED:
                    self.send_response(status)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    self.wfile.write(b'100\r\n{"err')  # announces 256 bytes, sends 5, then the server closes
                    return
                data = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                server.requests.append({"path": self.path, "headers": dict(self.headers), "body": ""})
                status, reply = server.replies.pop(0) if server.replies else (200, {})
                data = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, args=(0.01,), daemon=True).start()

    @staticmethod
    def ok(body):
        return {"errors": False, "items": []} if body.startswith(b'{"create"') else {"text": "Success", "code": 0}

    def bulk_docs(self, i):
        """The documents of the i-th _bulk request (every second line)."""
        return [json.loads(line) for line in self.requests[i]["body"].splitlines()[1::2]]


@pytest.fixture
def server():
    s = FakeServer()
    yield s
    s.httpd.shutdown()


@pytest.fixture(autouse=True)
def spool(tmp_path, monkeypatch):
    path = tmp_path / "home" / ".coresigma" / "spool"
    monkeypatch.setattr(outputs, "SPOOL_DIR", str(path))
    return path


def spooled(spool):
    return [json.loads(line) for f in sorted(spool.glob("*.ndjson")) for line in f.read_text().splitlines()]


def bulk(server, **kwargs):
    sender = outputs.BulkSender(server.url, kwargs.pop("auth", None), "macos-telemetry-esf", flush_s=60, **kwargs)
    sender.backoff = 0
    return sender


def test_bulk_batches(server):
    sender = bulk(server)
    for i in range(1001):
        sender.send({"n": i})
    assert len(server.requests) == 2  # two full batches of 500 went at once
    sender.close()
    assert [len(server.bulk_docs(i)) for i in range(3)] == [500, 500, 1]
    assert [d["n"] for i in range(3) for d in server.bulk_docs(i)] == list(range(1001))
    assert {r["path"] for r in server.requests} == {"/_bulk"}
    assert server.requests[0]["headers"]["Content-Type"] == "application/x-ndjson"


def test_bulk_spools_after_retries(server, spool):
    server.replies = [(503, {"error": "unavailable"})] * 6
    sender = bulk(server)
    sender.send({"n": 1})
    sender.close()
    assert len(server.requests) == 6  # the first try and 5 retries
    assert spooled(spool) == [{"error": 'HTTP 503: {"error": "unavailable"}', "doc": {"n": 1}}]
    assert stat.S_IMODE(spool.stat().st_mode) == 0o700
    assert [stat.S_IMODE(f.stat().st_mode) for f in spool.glob("*.ndjson")] == [0o600]


def test_retry_recovers_without_spool(server, spool):
    server.replies = [(429, {}), (502, {})]
    sender = bulk(server)
    sender.send({"n": 1})
    sender.close()
    assert len(server.requests) == 3
    assert server.bulk_docs(2) == [{"n": 1}]
    assert not spool.exists()


def test_backoff_doubles(server, monkeypatch):
    sleeps = []
    monkeypatch.setattr(outputs.time, "sleep", sleeps.append)
    server.replies = [(500, {})] * 6
    sender = outputs.BulkSender(server.url, None, "macos-telemetry-esf", flush_s=60)
    sender.send({"n": 1})
    sender.close()
    assert sleeps == [0.5, 1, 2, 4, 8]


def test_bulk_4xx_spooled_with_error_not_retried(server, spool):
    """A 400 (e.g. a mapping error) would fail the same way again: spool the batch with the reason at once."""
    server.replies = [(400, {"error": {"type": "mapper_parsing_exception"}})]
    sender = bulk(server)
    sender.send({"n": 1})
    sender.close()
    assert len(server.requests) == 1
    [line] = spooled(spool)
    assert line["doc"] == {"n": 1} and "HTTP 400" in line["error"] and "mapper_parsing_exception" in line["error"]
    assert [f.name.endswith(".rejected.ndjson") for f in spool.glob("*.ndjson")] == [True]
    assert sender.unsent == {"rejected": 1}


PARTIAL = [((None, {"n": 1}), "e"), ((None, {"n": object()}), "e")]  # the 2nd can't be encoded: the write fails partway


def test_collector_keeps_a_partial_spool_file(spool, capsys):
    """A collector's spool write that fails partway (in practice a full disk) keeps what it wrote: the only copy."""
    sender = outputs.HecSender("http://127.0.0.1:9", SECRET, flush_s=60)
    sender._fail(PARTIAL)
    sender.close()
    assert spooled(spool) == [{"error": "e", "doc": {"n": 1}}] and sender.unsent == {"lost": 2}
    assert "LOST up to 2 documents" in capsys.readouterr().err


def test_resend_discards_a_partial_spool_file(server, spool, resend_spool, monkeypatch, capsys):
    """resend's source still holds the batch, so its sender removes a partial re-spool instead of keeping a copy."""
    senders, real = [], outputs.open_output
    monkeypatch.setattr(outputs, "open_output", lambda *a, **kw: senders.append(real(*a, **kw)) or senders[-1])
    assert resend_spool.main(["--es-url", server.url, str(spool_file(spool, [1]))]) == 0
    [sender] = senders
    assert sender.keep_partial_spool is False
    before = set(spool.iterdir())
    sender._fail(PARTIAL)
    assert set(spool.iterdir()) == before and sender.unsent == {"lost": 2}
    assert "LOST 2 documents" in capsys.readouterr().err


def test_bulk_401_spooled_for_resend_not_rejected(server, spool):
    """A 401 goes away once the credentials are fixed: a plain spool file, which resend_spool.py picks up."""
    server.replies = [(401, {"error": "unauthorized"})]
    sender = bulk(server)
    sender.send({"n": 1})
    sender.close()
    assert [f.name.endswith(".rejected.ndjson") for f in spool.glob("*.ndjson")] == [False]
    assert sender.unsent == {"spooled": 1}


def test_bulk_item_errors(server, spool):
    """_bulk answers 200 with per-item errors: a rejected item is spooled with its error, a 429 item retried."""
    server.replies = [(200, {"errors": True, "items": [
        {"create": {"status": 201}},
        {"create": {"status": 400, "error": {"type": "mapper_parsing_exception", "reason": "bad pid"}}},
        {"create": {"status": 429, "error": {"type": "es_rejected_execution_exception"}}},
    ]})]
    sender = bulk(server)
    for i in range(3):
        sender.send({"n": i})
    sender.close()
    assert len(server.requests) == 2
    assert server.bulk_docs(1) == [{"n": 2}]
    [line] = spooled(spool)
    assert line["doc"] == {"n": 1} and "bad pid" in line["error"]
    assert sender.unsent == {"rejected": 1}


def test_error_body_dropped_mid_read_spools(server, spool):
    """A 503 whose body breaks off mid-read is a retryable failure like any other: the batch is spooled, nothing
    escapes send/flush, and the sender keeps working."""
    server.replies = [(503, DROPPED)] * 6
    sender = bulk(server)
    sender.cooloff = 0
    sender.send({"n": 1})
    sender.flush()
    assert len(server.requests) == 6
    [line] = spooled(spool)
    assert line["doc"] == {"n": 1} and line["error"].startswith("HTTP 503: (body unreadable: ")
    sender.send({"n": 2})
    sender.close()
    assert server.bulk_docs(6) == [{"n": 2}]


def test_unexpected_delivery_error_spools(server, spool, monkeypatch):
    """Whatever goes wrong while delivering, flush() spools the batch instead of losing it with the exception."""
    sender = bulk(server)

    def broken(entries):
        raise RuntimeError("bug")

    monkeypatch.setattr(sender, "_deliver", broken)
    sender.send({"n": 1})
    sender.close()
    assert spooled(spool) == [{"error": "RuntimeError('bug')", "doc": {"n": 1}}]


def test_outage_cooloff(server, spool):
    """Once a batch is spooled for an outage, the next batches spool at once for `cooloff` s: no requests, so no
    retry stall for the eslogger/log reader. Then a single probe; a failed probe starts another cool-off."""
    now = [1000.0]
    sender = bulk(server)
    sender.clock = lambda: now[0]
    server.replies = [(503, {})] * 7
    sender.send({"n": 1})
    sender.flush()
    assert len(server.requests) == 6
    now[0] += 59
    sender.send({"n": 2})
    sender.flush()
    assert len(server.requests) == 6  # cooling off: spooled without a request
    now[0] += 2
    sender.send({"n": 3})
    sender.flush()
    assert len(server.requests) == 7  # one probe, still 503: spooled, cooling off again
    now[0] += 61
    sender.send({"n": 4})
    sender.close()
    assert len(server.requests) == 8 and server.bulk_docs(7) == [{"n": 4}]
    assert sorted(line["doc"]["n"] for line in spooled(spool)) == [1, 2, 3]
    assert all("HTTP 503" in line["error"] for line in spooled(spool))


def test_bulk_ids_stable_across_retry(server):
    """Each document gets its _id once, in send(): a resent create of a document ES already took is a 409,
    not a duplicate."""
    server.replies = [(503, {})]
    sender = bulk(server)
    sender.send({"n": 0})
    sender.send({"n": 1})
    sender.close()
    ids = [[json.loads(line)["create"]["_id"] for line in r["body"].splitlines()[0::2]] for r in server.requests]
    assert len(ids) == 2 and ids[0] == ids[1]
    assert len(set(ids[0])) == 2 and all(re.fullmatch("[0-9a-f]{32}", i) for i in ids[0])


def test_bulk_409_counts_as_done(server, spool):
    server.replies = [(200, {"errors": True, "items": [
        {"create": {"status": 409, "error": {"type": "version_conflict_engine_exception"}}},
        {"create": {"status": 201}},
    ]})]
    sender = bulk(server)
    sender.send({"n": 0})
    sender.send({"n": 1})
    sender.close()
    assert len(server.requests) == 1
    assert not spool.exists()


def test_spool_under_effective_users_home(server, tmp_path, monkeypatch):
    """sudo keeps $HOME: root (the ESF collector) must spool in its own home, not a root-owned dir in the user's."""
    monkeypatch.setattr(outputs, "SPOOL_DIR", None)
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.setattr(outputs.os, "geteuid", lambda: 0)
    monkeypatch.setattr(outputs.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(tmp_path / f"home-of-{uid}")))
    server.replies = [(400, {})]
    sender = bulk(server)
    sender.send({"n": 1})
    sender.close()
    assert [line["doc"] for line in spooled(tmp_path / "home-of-0" / ".coresigma" / "spool")] == [{"n": 1}]
    assert not (tmp_path / "user").exists()


def test_connection_refused_spools(spool):
    sender = outputs.BulkSender("http://127.0.0.1:9", None, "macos-telemetry-ul", flush_s=60)
    sender.backoff = 0
    sender.send({"n": 1})
    sender.close()
    [line] = spooled(spool)
    assert line["doc"] == {"n": 1} and "Connection refused" in line["error"]


def test_close_flushes_and_timer_flushes(server):
    sender = bulk(server)
    sender.send({"n": 1})
    assert server.requests == []
    sender.close()
    assert server.bulk_docs(0) == [{"n": 1}]

    timed = outputs.BulkSender(server.url, None, "macos-telemetry-esf", flush_s=0.05)
    timed.send({"n": 2})
    deadline = time.time() + 5
    while len(server.requests) < 2 and time.time() < deadline:
        time.sleep(0.01)
    assert server.bulk_docs(1) == [{"n": 2}]  # flushed by the timer, before close()
    timed.close()


def test_bulk_auth_headers(server):
    sender = bulk(server, auth="a2V5")
    sender.send({})
    sender.close()
    basic = bulk(server, auth=("elastic", SECRET))
    basic.send({})
    basic.close()
    assert server.requests[0]["headers"]["Authorization"] == "ApiKey a2V5"
    assert server.requests[1]["headers"]["Authorization"] == "Basic " + base64.b64encode(
        f"elastic:{SECRET}".encode()).decode()


def test_index_names_match_templates(server):
    """Live and replayed documents land in indices the setup_elasticsearch_templates.sh templates map."""
    templates = (ROOT / "scripts" / "setup_elasticsearch_templates.sh").read_text()
    patterns = dict(re.findall(r'"index_patterns": \["(macos-telemetry-(esf|ul)-\*)"\]', templates))
    patterns = {source: pattern for pattern, source in patterns.items()}
    assert set(patterns) == {"esf", "ul"}
    for source, prefix in outputs.INDEX_PREFIX.items():
        sender = outputs.BulkSender(server.url, None, prefix, flush_s=60)
        sender.send({})
        sender.close()
        index = json.loads(server.requests[-1]["body"].splitlines()[0])["create"]["_index"]
        assert fnmatch.fnmatch(index, patterns[source]), (index, patterns[source])
        assert not any(fnmatch.fnmatch(index, p) for s, p in patterns.items() if s != source)


def test_hec_payload(server):
    """One {"event", "sourcetype", "index", "time"} per line; time is @timestamp in epoch seconds, so Splunk's _time
    is the event's time, not arrival. Without a usable @timestamp, time is left out."""
    docs = [
        {"@timestamp": "2026-11-10T20:48:01.777072672Z", "event.action": "exec"},  # eslogger: nanoseconds, Z
        {"@timestamp": "2026-11-11T04:39:47.120703+00:00", "message": "two words"},  # UL collector
        {"@timestamp": "2025-12-04T16:28:00.5-05:00", "message": "offset"},
        {"message": "no timestamp"},
        {"@timestamp": "yesterday", "message": "unparsable"},
    ]
    times = [datetime(2026, 11, 10, 20, 48, 1, 777072, tzinfo=timezone.utc).timestamp(),
             datetime(2026, 11, 11, 4, 39, 47, 120703, tzinfo=timezone.utc).timestamp(),
             datetime(2025, 12, 4, 21, 28, 0, 500000, tzinfo=timezone.utc).timestamp()]
    sender = outputs.HecSender(server.url, SECRET, sourcetype="coresigma:ul", flush_s=60)
    for doc in docs:
        sender.send(doc)
    sender.close()
    [request] = server.requests
    assert request["path"] == "/services/collector/event"
    assert request["headers"]["Authorization"] == f"Splunk {SECRET}"
    events = [{"event": doc, "sourcetype": "coresigma:ul", "index": "macos"} for doc in docs]
    for event, t in zip(events, times):
        event["time"] = t
    assert request["body"] == "\n".join(json.dumps(event) for event in events)


def test_hec_spools_after_retries(server, spool):
    server.replies = [(503, {"text": "Server is busy", "code": 9})] * 6
    sender = outputs.HecSender(server.url, SECRET, flush_s=60)
    sender.backoff = 0
    sender.send({"n": 1})
    sender.close()
    assert len(server.requests) == 6
    assert [line["doc"] for line in spooled(spool)] == [{"n": 1}]
    assert all(f.name.startswith("coresigma-esf-") for f in spool.glob("*.ndjson"))


def test_no_secret_in_logs(server, spool, capsys):
    """Neither the password, its Basic encoding, nor the HEC token reaches stderr, the spool or an exception."""
    encoded = base64.b64encode(f"elastic:{SECRET}".encode()).decode()
    server.replies = [(401, {"error": "unable to authenticate user [elastic]"}), (403, {"text": "Invalid token"})]
    for sender in (bulk(server, auth=("elastic", SECRET)), outputs.HecSender(server.url, SECRET, flush_s=60)):
        sender.send({"n": 1})
        sender.close()
    with pytest.raises(ValueError) as url_error:
        outputs.BulkSender(f"http://elastic:{SECRET}@127.0.0.1:9200", None, "macos-telemetry-esf")
    logged = capsys.readouterr().err + "".join(f.read_text() for f in spool.glob("*.ndjson")) + str(url_error.value)
    assert "spooled" in logged
    assert SECRET not in logged and encoded not in logged


def test_no_secret_in_argv(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(auth.sys, "platform", "darwin")
    monkeypatch.setattr(auth.subprocess, "run", fake_run)
    assert auth.store_in_keychain("coreSigma-Elasticsearch", "elastic", SECRET)
    assert all(SECRET not in arg for argv, _ in calls for arg in argv)
    [(argv, kwargs)] = [c for c in calls if c[0][1] == "add-generic-password"]
    assert argv[-1] == "-w"  # last: security prompts for it (new + retype) instead of reading argv
    assert kwargs["input"] == f"{SECRET}\n{SECRET}\n"
    assert kwargs["start_new_session"]  # no controlling tty, so security's getpass reads stdin, not the terminal


def parse(argv):
    parser = argparse.ArgumentParser()
    outputs.add_args(parser)
    return parser.parse_args(argv)


def test_open_output_wiring(monkeypatch, tmp_path):
    monkeypatch.setenv("ES_API_KEY", "a2V5")
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", SECRET)
    senders = []
    for source in ("esf", "ul"):
        es = outputs.open_output(parse(["--output", "elasticsearch"]), source)
        hec = outputs.open_output(parse(["--output", "splunk", "--insecure"]), source)
        senders += [es, hec]
        assert isinstance(es, outputs.BulkSender) and es.index_prefix == f"macos-telemetry-{source}"
        assert isinstance(hec, outputs.HecSender) and hec.sourcetype == f"coresigma:{source}"
        assert hec.index == "macos"
    for sender in senders:
        sender.close()
    assert parse([]).output == "stdout"
    path = tmp_path / "out.ndjson"
    out = outputs.open_output(parse(["--output", "file", "--output-file", str(path)]), "ul")
    out.send({"n": 1})
    out.close()
    assert path.read_text() == '{"n": 1}\n'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    monkeypatch.delenv("SPLUNK_HEC_TOKEN")
    with pytest.raises(SystemExit, match="SPLUNK_HEC_TOKEN"):
        outputs.open_output(parse(["--output", "splunk"]), "esf")


@pytest.fixture
def resend_spool(monkeypatch):
    sys.path.insert(0, str(ROOT / "scripts"))
    import resend_spool
    monkeypatch.setattr(outputs._Sender, "backoff", 0)
    monkeypatch.setattr(auth, "get_elasticsearch_auth", lambda url=None: (None, None))
    return resend_spool


def spool_file(spool, ns):
    spool.mkdir(parents=True, exist_ok=True)
    f = spool / "macos-telemetry-esf-20261112T131118-42650-2.ndjson"
    f.write_text("".join(json.dumps({"error": "down", "doc": {"n": n, "@timestamp": "2026-11-12T13:11:18Z"}}) + "\n"
                         for n in ns))
    return f


def test_resend_spool_batches_and_deletes(server, spool, resend_spool):
    """scripts/resend_spool.py sends a spool file through the collectors' sender in batches; --delete removes it."""
    spool.mkdir(parents=True)
    f = spool / "macos-telemetry-ul-20261112T131118-42650-1.ndjson"
    f.write_text("".join(json.dumps({"error": "down", "doc": {"n": i, "@timestamp": "2026-11-12T13:11:18Z"}}) + "\n"
                         for i in range(1200)))
    assert resend_spool.main(["--es-url", server.url, "--delete", str(f)]) == 0
    assert [len(server.bulk_docs(i)) for i in range(len(server.requests))] == [500, 500, 200]
    assert re.search(r'"macos-telemetry-ul-\d{4}\.\d{2}\.\d{2}"', server.requests[0]["body"].splitlines()[0])  # the send day's index
    assert not f.exists()


def sent(server):
    return [d["n"] for i in range(len(server.requests)) for d in server.bulk_docs(i)]


def test_resend_spool_rejected_documents_are_not_resent(server, spool, resend_spool, capsys):
    """--delete removes the source after a partial failure; a 400-rejected document goes to .rejected.ndjson, which
    later runs leave alone (no new file each run) until it is named; they report it and exit 1 while it's there."""
    f = spool_file(spool, [1, 2])
    server.replies = [(200, {"errors": True, "items": [
        {"create": {"status": 201}}, {"create": {"status": 400, "error": {"type": "mapper_parsing_exception"}}}]})]
    assert resend_spool.main(["--es-url", server.url, "--delete", str(f)]) == 1
    [rejected] = spool.glob("*.ndjson")
    assert not f.exists() and rejected.name.endswith(".rejected.ndjson")
    capsys.readouterr()
    assert resend_spool.main(["--es-url", server.url, "--delete"]) == 1  # the whole spool directory: nothing to send,
    out = capsys.readouterr().out  # but the skipped .rejected file is named and fails the run
    assert "1 .rejected.ndjson files skipped" in out and "no spool files but the .rejected.ndjson ones" in out
    assert list(spool.glob("*.ndjson")) == [rejected] and sent(server) == [1, 2]
    assert resend_spool.main(["--es-url", server.url, "--delete", str(rejected)]) == 0  # named, once fixed
    assert not list(spool.glob("*.ndjson")) and sent(server) == [1, 2, 2]


def test_resend_spool_skips_unknown_targets(server, spool, resend_spool, capsys):
    """replay_capture's clickhouse spool sorts first; it is skipped and counted, and the others are still sent."""
    f = spool_file(spool, [1])
    other = spool / "clickhouse-20261112T131118-42650-1.ndjson"
    other.write_text(json.dumps({"error": "x", "doc": {"n": 9}}) + "\n")
    assert resend_spool.main(["--es-url", server.url, "--delete"]) == 0
    assert "1 spool files of other targets left alone" in capsys.readouterr().out
    assert sent(server) == [1] and not f.exists() and other.exists()
    with pytest.raises(SystemExit) as refused:  # named: refused before anything is sent
        resend_spool.main(["--es-url", server.url, str(other)])
    assert refused.value.code == 2 and "is not a spool file of --output elasticsearch" in capsys.readouterr().err
    assert sent(server) == [1]


def test_resend_spool_sends_only_its_outputs_files(server, spool, resend_spool, capsys, monkeypatch):
    """--output splunk --delete must not send (and delete) the Elasticsearch spool, and the other way round."""
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", SECRET)
    es = spool_file(spool, [1])
    hec = spool / "coresigma-esf-20261112T131118-42650-3.ndjson"
    hec.write_text(json.dumps({"error": "x", "doc": {"n": 2}}) + "\n")
    assert resend_spool.main(["--output", "splunk", "--hec-url", server.url, "--delete"]) == 0
    assert "1 spool files of other targets left alone" in capsys.readouterr().out
    assert es.exists() and not hec.exists()
    [request] = server.requests
    assert request["path"] == "/services/collector/event" and json.loads(request["body"])["event"] == {"n": 2}
    with pytest.raises(SystemExit) as refused:
        resend_spool.main(["--output", "splunk", "--hec-url", server.url, "--delete", str(es)])
    assert refused.value.code == 2 and "resend it with that" in capsys.readouterr().err
    assert es.exists() and len(server.requests) == 1
    assert resend_spool.main(["--es-url", server.url, "--delete", str(es)]) == 0 and not es.exists()


def test_resend_spool_sender_has_no_timer(server, spool, resend_spool, monkeypatch):
    """A timer flush of a part batch would put a batch's documents in two places; resend's sender has none."""
    opened, real = [], outputs.open_output
    monkeypatch.setattr(outputs, "open_output", lambda *a, **kw: opened.append(kw) or real(*a, **kw))
    threads = threading.active_count()
    assert resend_spool.main(["--es-url", server.url, str(spool_file(spool, [1]))]) == 0
    assert opened == [{"flush_s": None}] and threading.active_count() == threads
    sender = outputs.BulkSender(server.url, None, "macos-telemetry-esf", flush_s=None)
    assert threading.active_count() == threads
    sender.send({"n": 2})
    sender.close()
    assert sent(server) == [1, 2]


def test_resend_spool_rejects_malformed_lines_and_goes_on(server, spool, resend_spool):
    f = spool_file(spool, [1])
    bad = ["not json", '{"no_doc": 1}', '"a string"', '{"doc": "a string"}', "[1]"]
    f.write_text(f.read_text() + "\n".join(bad) + "\n" + json.dumps({"error": "x", "doc": {"n": 2}}) + "\n")
    assert resend_spool.main(["--es-url", server.url, "--delete", str(f)]) == 1
    assert sent(server) == [1, 2] and not f.exists()
    [rejected] = spool.glob("*.rejected.ndjson")
    lines = spooled(spool)
    assert [line["doc"] for line in lines] == bad and all(l["error"].startswith("malformed spool line") for l in lines)


def test_resend_spool_retryable_failure_resent_next_run(server, spool, resend_spool):
    f = spool_file(spool, [1, 2])
    server.replies = [(503, {"error": "unavailable"})] * 6
    assert resend_spool.main(["--es-url", server.url, "--delete", str(f)]) == 1
    [again] = spool.glob("*.ndjson")
    assert not f.exists() and not again.name.endswith(".rejected.ndjson")
    assert resend_spool.main(["--es-url", server.url, "--delete"]) == 0
    assert not list(spool.glob("*.ndjson")) and sent(server)[-2:] == [1, 2]


def test_resend_spool_stops_where_spooling_again_fails(server, spool, resend_spool, monkeypatch):
    """Batch 1 is spooled again, batch 2 can't be (a full disk): the source keeps batch 2 and the unread batch 3 only,
    so the next run sends every document once."""
    f = spool_file(spool, range(1200))
    real, calls = outputs._Sender._spool, []

    def full_disk_on_second_write(self, failed, rejected=False, keep_partial=True):
        calls.append(len(failed))
        return None if len(calls) == 2 else real(self, failed, rejected, keep_partial)
    monkeypatch.setattr(outputs._Sender, "_spool", full_disk_on_second_write)
    server.replies = [(503, {"error": "unavailable"})] * 6  # batch 1 fails retryably; batch 2 is spooled in cool-off
    assert resend_spool.main(["--es-url", server.url, "--delete", str(f)]) == 1
    assert calls == [500, 500]
    assert [json.loads(line)["doc"]["n"] for line in f.read_text().splitlines()] == list(range(500, 1200))
    assert len(list(spool.glob("*.ndjson"))) == 2 and not list(spool.glob("*.tmp"))
    requests_before = len(server.requests)
    assert resend_spool.main(["--es-url", server.url, "--delete"]) == 0
    assert sorted(sent(server)[sum(len(server.bulk_docs(i)) for i in range(requests_before)):]) == list(range(1200))
    assert not list(spool.glob("*.ndjson"))


def test_resend_spool_keeps_source_when_spooling_again_fails(server, spool, resend_spool, monkeypatch):
    f = spool_file(spool, [1])
    monkeypatch.setattr(outputs, "SPOOL_DIR", str(f))  # a file, not a directory: the new spool file can't be written
    server.replies = [(503, {"error": "unavailable"})] * 6
    assert resend_spool.main(["--es-url", server.url, "--delete", str(f)]) == 1
    assert [json.loads(line)["doc"]["n"] for line in f.read_text().splitlines()] == [1]


def test_cluster_info_uses_collector_credentials(server, monkeypatch):
    """auth.cluster_info (setup_credentials.sh --test) needs no client package: GET / with the collectors' auth."""
    monkeypatch.setattr(auth, "get_elasticsearch_auth", lambda url=None: (None, ("elastic", "pw")))
    server.replies = [(200, {"cluster_name": "bench", "version": {"number": "8.19.25"}})]
    assert auth.cluster_info(server.url)["cluster_name"] == "bench"
    assert server.requests[0]["headers"]["Authorization"] == "Basic " + base64.b64encode(b"elastic:pw").decode()
    server.replies = [(401, {"error": "unauthorized"})]
    with pytest.raises(auth.AuthenticationError):
        auth.cluster_info(server.url)
