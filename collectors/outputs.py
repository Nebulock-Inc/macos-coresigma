#!/usr/bin/env python3
"""
Collector outputs: stdout, an NDJSON file, Elasticsearch `_bulk` (BulkSender) and Splunk HEC (HecSender).

Stdlib only and Python 3.9-compatible: the collectors run on stock macOS /usr/bin/python3.

The senders never drop a document silently. A batch that gets 429, 5xx or a connection error is retried
with doubling backoff (0.5 s .. 8 s) 5 times after the first try. Once those run out, or at once for a
reply that would fail the same way again (any other 4xx, e.g. a 401, or a _bulk item rejected with one),
or on any unexpected error, the documents go to ~/.coresigma/spool/<target>-<UTC time>-<pid>-<n>.ndjson,
one {"error": ..., "doc": ...} per line (dir 0700, files 0600), and a line on stderr names the file. A 400
(the batch or a _bulk item), where the target refused the documents themselves, goes to
<target>-<UTC time>-<pid>-<n>.rejected.ndjson instead, which scripts/resend_spool.py only re-sends by name.
~ is the effective user's home, not $HOME. Each sender counts what it spooled in `unsent`.

An outage (retries run out) starts a cool-off: for `cooloff` s later batches are spooled at once, without
requests, so the collector's reader isn't stalled behind retries; then one probe request decides.

Delivery is at-least-once. BulkSender gives each document a fixed _id when it is sent and indexes with
`create`, so a resend of a document Elasticsearch already took answers 409 and is not duplicated. HEC
cannot deduplicate: a batch Splunk took but whose reply was lost is sent again and indexed twice.
"""
import base64
import collections
import contextlib
import itertools
import json
import os
import pwd
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

SPOOL_DIR = None  # None: ~/.coresigma/spool of the effective user (_spool_dir)
# Must match the index_patterns of scripts/setup_elasticsearch_templates.sh, so documents get its mappings
INDEX_PREFIX = {"esf": "macos-telemetry-esf", "ul": "macos-telemetry-ul"}
SOURCETYPE = {"esf": "coresigma:esf", "ul": "coresigma:ul"}
_spool_seq = itertools.count()


def _retryable(status):
    return status == 429 or status >= 500


def _spool_dir():
    # Not $HOME: sudo keeps it, and root (the ESF collector) would make a root-only dir in the user's home
    return os.path.join(pwd.getpwuid(os.geteuid()).pw_dir, ".coresigma", "spool")


def _epoch(timestamp):
    """An ISO 8601 @timestamp as epoch seconds, or None. 3.9's fromisoformat needs 3 or 6 fraction digits and
    no Z; eslogger writes 9 and Z."""
    try:
        iso = re.sub(r"\.(\d+)", lambda m: "." + m.group(1).ljust(6, "0")[:6], timestamp).replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


class _Sender:
    """Buffers documents and POSTs them in batches of `batch`, at least every `flush_s` seconds (None: no timer,
    the caller flushes, as scripts/resend_spool.py does to know which batch each document went in)."""

    retries = 5  # after the first try
    backoff = 0.5  # seconds before the first retry, doubling
    cooloff = 60  # seconds batches are spooled unsent after an outage, before one probe
    timeout = 10
    clock = staticmethod(time.monotonic)

    def __init__(self, url, headers, tag, batch, flush_s, verify):
        if urllib.parse.urlsplit(url).username is not None:
            raise ValueError("credentials in the URL are not supported; use ES_API_KEY, the Keychain or ES_USER/ES_PASSWORD")
        self.url, self.headers, self.tag, self.batch, self.flush_s = url, headers, tag, batch, flush_s
        self._context = None if verify else ssl._create_unverified_context()
        self._buffer = []
        self._down_until = None  # clock() time an outage cool-off ends; None while the target is up
        self._down_error = None
        self.unsent = collections.Counter()  # documents "spooled", "rejected" (spooled to .rejected) or "lost"
        # A spool file whose write fails partway is kept: its lines are the only copy of those documents. False only
        # in scripts/resend_spool.py, whose source file still holds the whole batch.
        self.keep_partial_spool = True
        self._lock = threading.RLock()  # held while posting: a slow target slows the collector, nothing piles up
        self._closed = threading.Event()
        if flush_s is not None:
            threading.Thread(target=self._timer, daemon=True).start()

    def send(self, doc):
        with self._lock:
            self._buffer.append((uuid.uuid4().hex, doc))  # (_id, doc): the _id stays the same on every resend
            if len(self._buffer) >= self.batch:
                self.flush()

    def flush(self):
        with self._lock:
            entries, self._buffer = self._buffer, []
            if entries:
                try:
                    self._deliver(entries)
                except Exception as e:  # a bug or an unforeseen reply must not lose the batch or end the timer
                    self._fail([(entry, repr(e)) for entry in entries])

    def close(self):
        self._closed.set()
        self.flush()

    def _timer(self):
        while not self._closed.wait(self.flush_s):
            self.flush()

    def _deliver(self, entries):
        probing = self._down_until is not None
        if probing and self.clock() < self._down_until:
            self._fail([(entry, f"not sent, target down: {self._down_error}") for entry in entries])
            return
        self._down_until = None
        rejected = False
        for attempt in range(1 if probing else self.retries + 1):  # after a cool-off, one probe
            if attempt:
                time.sleep(self.backoff * 2 ** (attempt - 1))
            try:
                request = urllib.request.Request(self.url, data=self._body(entries), headers=self.headers, method="POST")
                with urllib.request.urlopen(request, timeout=self.timeout, context=self._context) as response:
                    entries = self._unfinished(entries, json.load(response))
                if not entries:
                    return
                error = "retryable item errors"
            except urllib.error.HTTPError as e:
                try:
                    detail = e.read(500).decode("utf-8", "replace")
                except Exception as read_error:  # e.g. the connection dropped mid-body
                    detail = f"(body unreadable: {read_error!r})"
                error = f"HTTP {e.code}: {detail}"
                if not _retryable(e.code):
                    rejected = e.code == 400  # the documents themselves; a 401 or 404 goes once the setup is fixed
                    break
            except Exception as e:  # refused/reset/timeout/TLS, a reply we can't read: retry, then spool, never lose
                error = repr(e)
        else:  # every try failed retryably: an outage, so don't stall the collector on the next batches
            self._down_until, self._down_error = self.clock() + self.cooloff, error
        self._fail([(entry, error) for entry in entries], rejected)

    def _unfinished(self, entries, reply):
        """The (_id, doc) entries of an accepted batch that still need sending."""
        return []

    def _fail(self, failed, rejected=False):
        """Spool [((_id, doc), error)] and count them in self.unsent."""
        path = self._spool(failed, rejected, self.keep_partial_spool)
        self.unsent["lost" if path is None else "rejected" if rejected else "spooled"] += len(failed)

    def _spool(self, failed, rejected=False, keep_partial=True):
        """Write [((_id, doc), error)] to a new spool file (.rejected.ndjson if rejected); returns its path, or None
        if the write failed (a partial file stays unless not keep_partial). Uses only self.tag:
        scripts/replay_capture.py calls it for its own sender."""
        fd = None
        try:
            spool_dir = SPOOL_DIR or _spool_dir()
            path = os.path.join(spool_dir, f"{self.tag}-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{os.getpid()}-"
                                           f"{next(_spool_seq)}{'.rejected' if rejected else ''}.ndjson")
            os.makedirs(spool_dir, mode=0o700, exist_ok=True)
            os.chmod(spool_dir, 0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with open(fd, "w") as f:
                f.writelines(json.dumps({"error": error, "doc": doc}) + "\n" for (_, doc), error in failed)
        except Exception as e:
            partial = fd is not None  # this call created the file (O_EXCL), and some lines may be in it
            if partial and not keep_partial:  # the caller has them all: a partial copy would be resent twice
                with contextlib.suppress(OSError):
                    os.remove(path)
                partial = False
            print(f"outputs: LOST {'up to ' if partial else ''}{len(failed)} documents for {self.tag}, spool failed: "
                  f"{e!r}{f'; the ones written are in {path}' if partial else ''}; send error: {failed[0][1]}",
                  file=sys.stderr)
            return
        print(f"outputs: spooled {len(failed)} documents for {self.tag} to {path}: {failed[0][1]}", file=sys.stderr)
        return path


class BulkSender(_Sender):
    """Elasticsearch/OpenSearch `_bulk` into `<index_prefix>-YYYY.MM.DD` (UTC). `auth`: API key, (user, password) or None."""

    def __init__(self, url, auth, index_prefix, batch=500, flush_s=2.0, verify=True):
        headers = {"Content-Type": "application/x-ndjson"}
        if isinstance(auth, tuple):
            headers["Authorization"] = "Basic " + base64.b64encode(":".join(auth).encode()).decode()
        elif auth:
            headers["Authorization"] = f"ApiKey {auth}"
        self.index_prefix = index_prefix
        super().__init__(url.rstrip("/") + "/_bulk", headers, index_prefix, batch, flush_s, verify)

    def _body(self, entries):
        # shortcut: the index is the date at each try, so a retry across 00:00 UTC lands under the same _id in the
        # next day's index (a duplicate); fix the index per document in send() if that ever matters
        index = f"{self.index_prefix}-{datetime.now(timezone.utc):%Y.%m.%d}"
        return "".join(json.dumps({"create": {"_index": index, "_id": _id}}) + "\n" + json.dumps(doc) + "\n"
                       for _id, doc in entries).encode()

    def _unfinished(self, entries, reply):
        """_bulk answers 200 even when items fail: spool the failed ones (a 400 as rejected), return the retryable."""
        if not reply.get("errors"):
            return []
        items = reply.get("items", [])
        retry, failed = entries[len(items):], {False: [], True: []}  # any unanswered entry is resent
        for entry, item in zip(entries, items):
            result = next(iter(item.values()))
            status = result.get("status", 500)
            if _retryable(status):
                retry.append(entry)
            elif status >= 300 and status != 409:  # 409: a resent create Elasticsearch already has
                failed[status == 400].append((entry, f"item {status}: {json.dumps(result.get('error'))}"))
        for rejected, entries_failed in failed.items():
            if entries_failed:
                self._fail(entries_failed, rejected)
        return retry


class HecSender(_Sender):
    """Splunk HTTP Event Collector: `url` is the HEC base (https://host:8088), `token` the HEC token.
    At-least-once: HEC can't deduplicate, so a batch resent after a lost reply is indexed twice."""

    def __init__(self, url, token, index="macos", sourcetype="coresigma:esf", batch=500, flush_s=2.0, verify=True):
        self.index, self.sourcetype = index, sourcetype
        super().__init__(url.rstrip("/") + "/services/collector/event", {"Authorization": f"Splunk {token}"},
                         sourcetype.replace(":", "-"), batch, flush_s, verify)

    def _body(self, entries):
        events = []
        for _, doc in entries:
            event = {"event": doc, "sourcetype": self.sourcetype, "index": self.index}
            t = _epoch(doc.get("@timestamp"))
            if t is not None:  # else Splunk's _time is arrival time
                event["time"] = t
            events.append(json.dumps(event))
        return "\n".join(events).encode()


class LineWriter:
    """stdout or file output: one JSON document per line."""

    def __init__(self, f=None):
        self.f = f  # None: sys.stdout as it is at each send

    def send(self, doc):
        print(json.dumps(doc), file=self.f)

    def close(self):
        if self.f:
            self.f.close()
        else:
            sys.stdout.flush()


def add_args(parser):
    """The output flags both collectors take."""
    parser.add_argument("--output", choices=["stdout", "file", "elasticsearch", "splunk"], default="stdout",
                        help="where documents go (default stdout)")
    parser.add_argument("--output-file", help="NDJSON file to append to (--output file)")
    parser.add_argument("--es-url", default="http://localhost:9200",
                        help="Elasticsearch URL (--output elasticsearch); credentials come from collectors/auth.py")
    parser.add_argument("--hec-url", default="https://localhost:8088",
                        help="Splunk HEC URL (--output splunk); the token comes from $SPLUNK_HEC_TOKEN")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification (the bench's self-signed certificates)")


def open_output(args, source, flush_s=2.0):
    """The output `args` (from add_args) name, for `source` ('esf' or 'ul') documents. Call after daemonizing.
    flush_s: the senders' timer (None: none)."""
    if args.output == "elasticsearch":
        import auth  # collectors/ sibling, on sys.path wherever outputs is
        api_key, basic_auth = auth.get_elasticsearch_auth(args.es_url)
        return BulkSender(args.es_url, api_key or basic_auth, INDEX_PREFIX[source], flush_s=flush_s,
                          verify=not args.insecure)
    if args.output == "splunk":
        token = os.environ.get("SPLUNK_HEC_TOKEN")
        if not token:
            raise SystemExit("--output splunk needs the HEC token in SPLUNK_HEC_TOKEN")
        return HecSender(args.hec_url, token, sourcetype=SOURCETYPE[source], flush_s=flush_s,
                         verify=not args.insecure)
    if args.output == "file":
        if not args.output_file:
            raise SystemExit("--output file needs --output-file PATH")
        fd = os.open(args.output_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        return LineWriter(open(fd, "a", buffering=1))
    return LineWriter()
