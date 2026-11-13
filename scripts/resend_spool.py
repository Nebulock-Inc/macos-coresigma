#!/usr/bin/env python3
"""Re-send collector spool files (see docs/INSTALLATION.md, Spool) through the collectors' own senders.

Batches of 500 with the collectors' retries, so a spool of any size goes through (one big _bulk request is rejected
over Elasticsearch's indexing-pressure limit, HTTP 429). Credentials come from collectors/auth.py, as the collectors'
do (ES_API_KEY, ES_USER/ES_PASSWORD, the Keychain or the config file); nothing goes on a command line.

A batch that fails again is spooled again, to a new file. Documents the target refuses with a 400, and malformed spool
lines (as they are), go to a <target>-...-<n>.rejected.ndjson file, which is re-sent only when named (once the cause is fixed), so they don't come
back on every run. With --delete, each source file is removed once its documents are sent or spooled again. If a
batch can't be spooled again (the spool directory unwritable, a full disk), the file's run stops there and, with
--delete, the file is rewritten to hold the batch it stopped on and everything after it; documents of that batch
that were already sent are sent again. Without --delete no file is removed or changed, so a later run sends them all again, the new files included.
Spool lines carry no _id, so a document Elasticsearch had indexed before the error is indexed again. Exits 1 if any
document was spooled again, rejected or not spooled, or if a default run skipped any .rejected.ndjson file. Stock python3 (3.9) is enough.

Usage:
    python3 scripts/resend_spool.py [--output elasticsearch|splunk] [--es-url URL | --hec-url URL] [--insecure]
        [--delete] [FILE ...]          # FILEs default to --output's spool files but the .rejected.ndjson ones
    sudo /usr/bin/python3 scripts/resend_spool.py ...   # for the ESF collector's root-owned spool
"""
import argparse
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "collectors"))
import outputs  # noqa: E402

# Each --output's spool file tags (outputs.INDEX_PREFIX, SOURCETYPE with - for :) and their sources
TARGETS = {"elasticsearch": {"macos-telemetry-esf": "esf", "macos-telemetry-ul": "ul"},
           "splunk": {"coresigma-esf": "esf", "coresigma-ul": "ul"}}


SPOOL_NAME = re.compile(r"(.+)-\d{8}T\d{6}-\d+-\d+(\.rejected)?\.ndjson")  # <target>-<UTC time>-<pid>-<n>


def output_of(path):
    """(the --output a spool file's name belongs to, 'esf' or 'ul'), or (None, None) for another target's file
    (replay_capture's clickhouse)."""
    m = SPOOL_NAME.fullmatch(os.path.basename(path))
    return next(((out, tags[m.group(1)]) for out, tags in TARGETS.items() if m and m.group(1) in tags), (None, None))


def resend(path, args):
    """Send one spool file's documents a batch at a time; returns (how many, sender.unsent, the lines neither sent nor
    spooled again). Stops at the first batch it couldn't spool again."""
    sender = outputs.open_output(args, output_of(path)[1], flush_s=None)  # no timer: only this loop flushes, per batch
    sender.keep_partial_spool = False  # a batch it can't spool whole stays in the source, so no partial copy
    try:
        with open(path) as f:
            lines = [line for line in f if line.strip()]
        done = 0
        while done < len(lines):
            malformed = []  # rejected, as the lines they are; the others still go
            for line in lines[done:done + sender.batch]:
                try:
                    doc = json.loads(line)["doc"]
                    if not isinstance(doc, dict):
                        raise TypeError(f"doc is a {type(doc).__name__}, not an object")
                except (ValueError, KeyError, TypeError) as e:
                    malformed.append(((None, line.rstrip("\n")), f"malformed spool line: {e!r}"))
                    continue
                sender.send(doc)
            if malformed:
                sender._fail(malformed, rejected=True)
            sender.flush()
            if sender.unsent["lost"]:  # keep this batch and the rest: they are nowhere else
                break
            done += sender.batch
    finally:
        sender.close()
    return len(lines), sender.unsent, lines[done:]


def keep_only(path, lines):
    """Rewrite path to hold just lines; if that fails too (a full disk), path stays whole. Returns a note."""
    tmp = path + ".tmp"
    try:
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.writelines(lines)
        os.replace(tmp, path)
        return f", kept with the {len(lines)} documents from the batch it stopped on"
    except OSError as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        return f", kept whole: rewriting it failed ({e!r}), so a later run sends again what this one spooled"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    outputs.add_args(parser)
    parser.set_defaults(output="elasticsearch")
    parser.add_argument("--delete", action="store_true",
                        help="delete each file once its documents are sent or spooled again; if some can't be "
                             "spooled again, rewrite it to hold just those and the ones not yet sent")
    parser.add_argument("files", nargs="*",
                        help="default: the spool directory's files for --output but the .rejected.ndjson ones")
    args = parser.parse_args(argv)
    if args.output not in ("elasticsearch", "splunk"):
        parser.error("--output must be elasticsearch or splunk")
    wrong = [(f, output_of(f)[0]) for f in args.files if output_of(f)[0] != args.output]
    if wrong:  # refused before anything is sent: another output's documents don't belong in this one
        parser.error("; ".join(f"{f} is a spool file of --output {out}, resend it with that" if out else
                               f"{f} is not a spool file of --output {args.output} ({', '.join(TARGETS[args.output])})"
                               for f, out in wrong))
    files, skipped = args.files, []
    if not files:
        found = sorted(glob.glob(os.path.join(outputs.SPOOL_DIR or outputs._spool_dir(), "*.ndjson")))
        others = [f for f in found if output_of(f)[0] != args.output]
        if others:  # another output's, or another target's (replay_capture's clickhouse): left where they are
            print(f"{len(others)} spool files of other targets left alone (--output {args.output} sends "
                  f"{', '.join(TARGETS[args.output])} only)")
        skipped = [f for f in found if f.endswith(".rejected.ndjson") and f not in others]
        files = [f for f in found if f not in skipped and f not in others]
    if skipped:  # not resent until named, but never silently
        print(f"{len(skipped)} .rejected.ndjson files skipped: name them to resend once their error is fixed")
    if not files:
        print("no spool files" + (" but the .rejected.ndjson ones" if skipped else ""))
        return 1 if skipped else 0
    status = 1 if skipped else 0
    for path in files:
        count, unsent, left = resend(path, args)
        status |= bool(sum(unsent.values()))
        note = ""
        if args.delete and left:
            note = keep_only(path, left)
        elif args.delete:
            os.remove(path)
            note = ", deleted"
        print(f"{path}: {count} documents, {unsent['spooled']} spooled again, {unsent['rejected']} rejected "
              f"(to .rejected.ndjson), {unsent['lost']} not spooled{note}")
    return status


if __name__ == "__main__":
    sys.exit(main())
