#!/usr/bin/env python3
"""
Replay eslogger and `log --style ndjson` captures into a bench stack, as the collectors would have sent them.

Each line passes the live collector's own gate, then its normalize_event: ESF events the collector subscribes
to and keeps (should_keep_event), and UL lines its `log stream` predicate selects. @timestamp stays the
event's own time (HEC's `time` comes from it), so rules fire inside the capture's simulation windows.
Documents go to the indices/sourcetypes the collectors use (macos-telemetry-{esf,ul}-*, coresigma:{esf,ul}),
or to the ClickHouse table coresigma.events (scripts/bench_up.sh).

Usage:
    replay_capture.py FILE.json.gz... --target elastic|splunk|opensearch|clickhouse [--window START END]

Credentials as for the collectors: Elasticsearch from collectors/auth.py, the HEC token from
$SPLUNK_HEC_TOKEN (the bench's HEC needs --insecure). The bench OpenSearch and ClickHouse need none.

Every document is delivered, or the replay fails: documents a target refused (an outage, a 401, a rejected
_bulk item, a failed INSERT) are spooled to a temporary directory of this run, not the collectors' spool, and
the command exits 1 naming it (replay() raises ReplayError).
"""
import argparse
import gzip
import json
import os
import sys
import tempfile
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collectors"))
import esf_collector  # noqa: E402
import outputs  # noqa: E402
import ul_collector  # noqa: E402

URLS = {"elastic": "http://localhost:9200", "opensearch": "http://localhost:9201",
        "splunk": "https://localhost:8088", "clickhouse": "http://localhost:8123"}
UL_OPS = {"=": str.__eq__, "startswith": str.startswith, "endswith": str.endswith}
SEED = 0  # the ESF collector's fork sampling: the same capture replays to the same documents every time


class ReplayError(Exception):
    """Some documents didn't reach the target."""


def ul_selected(raw):
    """Whether the UL collector's `log stream --predicate` delivers this line (its [c] comparisons ignore case)."""
    return any(UL_OPS[modifier](str(raw.get(field) or "").lower(), value.lower())
               for category in ul_collector.UL_CATEGORIES.values() for field, modifier, value in category.raw)


def parse_window(start, end):
    """(start, end) epoch seconds from two ISO 8601 times; ValueError if either doesn't parse."""
    window = outputs._epoch(start), outputs._epoch(end)
    if None in window:
        raise ValueError(f"not ISO 8601 times: {start} {end}")
    return window


def documents(paths, window=None):
    """(source, document) for each event of the capture files that a collector would have sent, within window
    (inclusive) if given. The window applies after the collectors' gate, so a fork's sampling doesn't depend on it."""
    esf, ul = esf_collector.ESFCollector(seed=SEED), ul_collector.ULCollector()
    skipped = 0
    for path in paths:
        with (gzip.open if str(path).endswith(".gz") else open)(path, "rt") as f:
            for line in f:
                try:
                    raw = json.loads(line)
                    if isinstance(raw.get("event"), dict):
                        source = "esf"
                        if (next(iter(raw["event"])) not in esf_collector.ESLOGGER_EVENTS
                                or not esf.should_keep_event(raw)):
                            continue
                        doc = esf.normalize_event(raw)
                    else:
                        source = "ul"
                        if not ul_selected(raw):
                            continue
                        doc = ul.normalize_event(raw)
                except Exception:  # log's header line, a truncated last line: one bad line must not end a replay
                    skipped += 1
                    continue
                t = outputs._epoch(doc["@timestamp"])
                if window and (t is None or not window[0] <= t <= window[1]):
                    continue
                yield source, doc
    if skipped:
        print(f"replay: skipped {skipped} unparsable lines", file=sys.stderr)


def replay(paths, open_sender, window=None):
    """Send documents(paths, window) through open_sender(source), one sender per source. Returns counts by source;
    raises ReplayError if any document wasn't delivered (the senders spool instead of raising)."""
    senders, counts = {}, Counter()
    # shortcut: outputs.SPOOL_DIR is module-wide, so concurrent replays in one process share it; give each its own
    # if a harness ever runs them in threads
    spool_dir, outputs.SPOOL_DIR = outputs.SPOOL_DIR, tempfile.mkdtemp(prefix="coresigma-replay-spool-")
    try:
        try:
            for source, doc in documents(paths, window):
                if source not in senders:
                    senders[source] = open_sender(source)
                senders[source].send(doc)
                counts[source] += 1
        finally:
            for sender in senders.values():
                sender.close()  # flushes
        spooled = 0
        for name in os.listdir(outputs.SPOOL_DIR):
            with open(os.path.join(outputs.SPOOL_DIR, name)) as f:
                spooled += sum(1 for _ in f)
        lost = sum(getattr(s, "unsent", {}).get("lost", 0) for s in senders.values())  # spool write failed: no file
        if lost:
            raise ReplayError(f"{lost} of {sum(counts.values())} documents not delivered and not spooled (spool write "
                              f"failed); replay the capture again")
        if spooled:
            raise ReplayError(f"{spooled} of {sum(counts.values())} documents not delivered; they and the target's "
                              f"replies are in {outputs.SPOOL_DIR}")
        os.rmdir(outputs.SPOOL_DIR)
    finally:
        outputs.SPOOL_DIR = spool_dir
    return counts


class ClickHouseSender:
    """INSERTs documents into coresigma.events in batches; columns are the documents' keys. A failed batch is
    spooled like the collectors' senders do (no retries: replay() fails and the capture can be replayed again)."""

    tag = "clickhouse"

    def __init__(self, url, batch=10000):
        query = {"query": "INSERT INTO coresigma.events FORMAT JSONEachRow", "input_format_skip_unknown_fields": 1}
        self.url, self.batch, self.docs = f"{url.rstrip('/')}/?{urllib.parse.urlencode(query)}", batch, []
        self.unsent = Counter()  # as the collectors' senders count: "spooled", or "lost" if the spool write failed

    def send(self, doc):
        self.docs.append(doc)
        if len(self.docs) >= self.batch:
            self.close()

    def close(self):
        docs, self.docs = self.docs, []
        if not docs:
            return
        try:
            body = "\n".join(json.dumps(doc) for doc in docs).encode()
            urllib.request.urlopen(urllib.request.Request(self.url, data=body, method="POST"), timeout=60).close()
        except Exception as e:
            try:
                with e:  # an HTTPError: ClickHouse's body says why; closing it frees the connection
                    error = f"HTTP {e.code}: {e.read(500).decode('utf-8', 'replace')}"
            except Exception:  # not an HTTP error, or its body is unreadable
                error = repr(e)
            path = outputs._Sender._spool(self, [((None, doc), error) for doc in docs])  # the senders' spool format
            self.unsent["lost" if path is None else "spooled"] += len(docs)


def open_sender(target, source, url, insecure):
    """The sender for one source ('esf' or 'ul') on target, as the collectors open theirs."""
    if target == "elastic":
        return outputs.open_output(argparse.Namespace(output="elasticsearch", es_url=url, insecure=insecure), source)
    if target == "splunk":
        return outputs.open_output(argparse.Namespace(output="splunk", hec_url=url, insecure=insecure), source)
    if target == "opensearch":  # the bench's runs without the security plugin
        return outputs.BulkSender(url, None, outputs.INDEX_PREFIX[source], verify=not insecure)
    return ClickHouseSender(url)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Replay captures into a bench stack, keeping event timestamps")
    parser.add_argument("files", nargs="+", help="esf.*.json.gz / ul.*.json.gz captures (or uncompressed)")
    parser.add_argument("--target", required=True, choices=URLS)
    parser.add_argument("--window", nargs=2, metavar=("START", "END"),
                        help="only events from START to END (ISO 8601, inclusive)")
    parser.add_argument("--url", help="the target's URL (default: the bench's)")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification (the bench HEC's self-signed certificate)")
    args = parser.parse_args(argv)
    try:
        window = parse_window(*args.window) if args.window else None
    except ValueError as e:
        parser.error(str(e))
    url = args.url or URLS[args.target]
    try:
        counts = replay(args.files, lambda source: open_sender(args.target, source, url, args.insecure), window)
    except ReplayError as e:
        sys.exit(f"replay to {args.target} FAILED: {e}")
    print(f"replayed to {args.target}: {counts['esf']} ESF, {counts['ul']} UL documents")


if __name__ == "__main__":
    main()
