#!/usr/bin/env python3
"""
Private laptop noise baseline: each rule's hits per hour on a laptop's own telemetry, for
`rule_matrix.py verdicts --noise`. Two counts, each rule's higher one counting (rule_matrix.load_noise):

EQL, on a store (--log): reads only the laptop's eslogger log (ten evenly spaced 200 MB slices of it, cut at line ends,
written to <out>/slices) and a fresh eslogger capture if there is one (--fresh, default <out>/fresh.json.gz). Each
slice, and the fresh capture, replays through the ESF collector's own gate and normalize_event
(scripts/replay_capture.py, fork sampling seeded) into its own index, private-baseline-esf-<part>-*, on the local bench
Elasticsearch (scripts/bench_up.sh elastic), with the bench ESF template's mappings; the Elasticsearch (rule_matrix's
ES_URL) must be on this machine. Nothing goes into the bench's macos-telemetry-* indices. The private indices are
deleted at the end, whatever happens. Every ESF rule that converts for elastic-eql (rule_matrix's conversion) is
counted on each part, from its first to its last event.

Sigma, in this process (every run, nothing stored): each single rule (matcher(): Sigma's semantics over the coreSigma
pipelines' fields), ESF rules on the same ESF parts (<out>/slices, the fresh capture) through the same gate, and unified
log rules on --ul, a file of the UL collector's documents (ul_collector.py --output file), gated and normalized as it
sends them. It catches what a target's query can't express, e.g. a `$` anchor EQL reads literally.

Writes only under --out (made 0700, outside every git checkout): the slices, noise.json (0600), run.log (0600:
everything the run prints, store errors included, goes there, never to the terminal) and replay's spool of undelivered
documents. A run replaces in noise.json what it measures and keeps the rest (an earlier --ul sample, the EQL count of a
run without --log):
    {"rates": {ESF rule id: EQL hits/hour, the higher of the slices' (all their hits over all their hours) and the
               fresh capture's},
     "samples": {"slices" / "fresh": {"hours", "documents", "parts": {part: {"hours", "documents"}},
                                      "hits": {rule id: n}, "rates": {rule id: hits/hour},
                                      "capped": [rule ids with EQL_SIZE hits in a part: a lower bound]}},
     "skipped": {rule id: why EQL didn't count it},
     "sigma_rates": {rule id: Sigma hits/hour, the highest of its samples'},
     "sigma_samples": {"slices" / "fresh" / "ul": {"hours", "documents", "parts", "hits", "rates"}},
     "sigma_skipped": {rule id: why Sigma didn't count it}}
Its numbers come from private data and never go into the repo; only verdicts' noisy/quiet outcome does.

Usage:
    sample_private_baseline.py [--log FILE [--fresh FILE.json.gz]] [--ul FILE] [--out DIR]
"""
import argparse
import contextlib
import json
import os
import re
import sys
import tempfile
import traceback
from pathlib import Path
from urllib.parse import urlparse

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import replay_capture  # noqa: E402
import rule_matrix as rm  # noqa: E402  (puts this checkout's plugin on sys.path for the sigma imports below)
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR  # noqa: E402
from sigma.pipelines.macos import macos_esf_ecs, macos_ul_ecs  # noqa: E402
from sigma.types import SigmaCasedString, SigmaNumber, SigmaRegularExpression, SigmaString, SpecialChars  # noqa: E402

OUT = "~/.coresigma/private"  # as given: the one line main prints shows it unexpanded
SLICES, SLICE_BYTES = 10, 200 * 10**6
PREFIX = "private-baseline-esf"
LOCAL = {"localhost", "127.0.0.1", "::1"}  # the only Elasticsearch hosts the documents may go to


def private_dir(path):
    """path, absolute, if no git checkout (this repo included) contains it; ValueError otherwise."""
    path = Path(path).expanduser().resolve()
    if path.is_relative_to(rm.ROOT) or any((p / ".git").exists() for p in (path, *path.parents)):
        raise ValueError(f"{path} is inside a git checkout: private data stays out of every repo")
    return path


def slice_ranges(size, n=SLICES, length=SLICE_BYTES):
    """(start, end) byte ranges of n evenly spaced length-byte slices of a size-byte file, the first at its start and
    the last at its end; the whole file once if n slices of length don't fit apart in it."""
    if size <= n * length:
        return [(0, size)]
    return [(start, start + length) for start in (i * (size - length) // (n - 1) for i in range(n))]


def cut(f, start, end):
    """The whole lines of binary file f within bytes start to end: a line either end cuts is left out."""
    head = max(start - 1, 0)  # one byte early: a newline there means start begins a line
    f.seek(head)
    data = f.read(end - head)
    if start:
        data = data[data.find(b"\n") + 1:] if b"\n" in data else b""
    return data[:data.rfind(b"\n") + 1]


def write_slices(log, out):
    """log's slices as out/slices/sliceNN.json; returns {part: [path]}."""
    (out / "slices").mkdir(mode=0o700, exist_ok=True)
    parts = {}
    with open(log, "rb") as f:
        for i, (start, end) in enumerate(slice_ranges(Path(log).stat().st_size)):
            path = out / "slices" / f"slice{i:02}.json"
            path.write_bytes(cut(f, start, end))
            parts[path.stem] = [path]
    return parts


def _es(method, path, **kw):
    reply = requests.request(method, f"{rm.ES_URL}/{path}", auth=rm.ES_AUTH, timeout=300, **kw)
    reply.raise_for_status()
    return reply.json()


def queries():
    """({rule id: elastic-eql query} of each ESF rule that converts, {rule id: why not} for the others)."""
    found, skipped = {}, {}
    for rule_id, unit in rm._units(rm.RULES):
        if rm._sources(unit) != ("esf",):
            skipped[rule_id] = "unified log: the samples are ESF only"
            continue
        result = rm.convert("elastic-eql", unit)
        if result.status == "fails":
            skipped[rule_id] = f"doesn't convert for elastic-eql: {result.reason}"
        else:
            found[rule_id] = result.query
    return found, skipped


def load(part, paths):
    """Replay paths into the part's own index: (index pattern, first and last event epoch seconds, documents)."""
    index = f"{PREFIX}-{part}"

    def sender(source):
        if source != "esf":
            raise ValueError(f"{part}: a {source} document, but the samples are ESF only")
        return replay_capture.outputs.BulkSender(rm.ES_URL, rm.ES_AUTH, index)

    replay_capture.replay(paths, sender)
    _es("POST", f"{index}-*/_refresh")
    reply = _es("POST", f"{index}-*/_search", json={
        "size": 0, "track_total_hits": True,
        "aggs": {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}})
    span = [(reply["aggregations"][k]["value"] or 0) / 1000 for k in ("first", "last")]
    return f"{index}-*", *span, reply["hits"]["total"]["value"]


def measure(parts, found, skipped):
    """One sample, over its parts ({part: [paths]}): its hours, documents and each rule's hits and rate. A query the
    store rejects goes to skipped."""
    sample = {"hours": 0, "documents": 0, "parts": {}, "hits": dict.fromkeys(found, 0), "capped": []}
    for part, paths in parts.items():
        pattern, first, last, documents = load(part, paths)
        hours = (last - first) / 3600
        sample["parts"][part] = {"hours": hours, "documents": documents}
        sample["hours"] += hours
        sample["documents"] += documents
        rm.INDEX = {"esf": pattern}  # hits() takes its index from here: this part's only, and no ul
        for rule_id, query in found.items():
            if rule_id in skipped or not documents:
                continue
            try:
                n = rm.hits("elastic-eql", query, "esf", first, last + 1)
            except rm.QueryError as e:
                skipped[rule_id] = f"the private index rejected the query: {rm._why(e)}"
                continue
            sample["hits"][rule_id] += n
            if n >= rm.EQL_SIZE and rule_id not in sample["capped"]:
                sample["capped"].append(rule_id)
    sample["rates"] = {rule_id: n / sample["hours"] for rule_id, n in sample["hits"].items()} if sample["hours"] else {}
    return sample


def delete_indices():
    """Every private-baseline index, by name (Elasticsearch refuses a wildcard delete), and the template."""
    for index in _es("GET", f"_cat/indices/{PREFIX}-*", params={"format": "json"}):
        _es("DELETE", index["index"])
    requests.delete(f"{rm.ES_URL}/_index_template/{PREFIX}-template", auth=rm.ES_AUTH, timeout=60)


def laptop_rates(measured, found, skipped):
    """{rule id: the higher of its rates in the samples} for each counted rule that no sample rejected."""
    return {rule_id: max(s["rates"].get(rule_id, 0) for s in measured.values()) for rule_id in found
            if rule_id not in skipped}


def write_noise(out, **keys):
    """out/noise.json (0600) with these top-level keys replaced and the others kept."""
    path = out / "noise.json"
    noise = (json.loads(path.read_text()) if path.exists() else {}) | keys
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # an existing file keeps its old mode otherwise
    with open(fd, "w") as f:
        f.write(json.dumps(noise, indent=2, sort_keys=True) + "\n")


def run(log, fresh, out):
    """Slice, replay, count and write the ESF rules and samples to out/noise.json (see the module docstring)."""
    (out / "tmp").mkdir(mode=0o700, exist_ok=True)
    tempfile.tempdir = str(out / "tmp")  # replay()'s spool of undelivered documents: private too
    found, skipped = queries()
    samples = {"slices": write_slices(log, out)}
    if fresh.exists():
        samples["fresh"] = {"fresh": [fresh]}
    body = _es("GET", "_index_template/macos-telemetry-esf-template")["index_templates"][0]["index_template"]
    _es("PUT", f"_index_template/{PREFIX}-template", json={**body, "index_patterns": [f"{PREFIX}-*"]})  # bench mappings
    try:
        measured = {name: measure(parts, found, skipped) for name, parts in samples.items()}
    finally:
        delete_indices()
    rates = laptop_rates(measured, found, skipped)
    write_noise(out, rates=rates, samples=measured, skipped=skipped)
    print(f"{len(rates)} ESF rules counted with EQL on {', '.join(measured)}, {len(skipped)} skipped -> {out / 'noise.json'}")


# --- Sigma: counted in this process, nothing stored ---------------------------------------------------------------

def _value_test(value):
    """A test of one document value against a Sigma value: a string whole, with its * and ? wildcards, ignoring case
    unless |cased; |re unanchored (re.search) with its own flags; a number by its text (the collectors' ids are text).
    NotImplementedError for any other (null, |exists, |cidr, ...): the rule is skipped, not miscounted."""
    if isinstance(value, SigmaString):
        wildcards = {SpecialChars.WILDCARD_MULTI: ".*", SpecialChars.WILDCARD_SINGLE: "."}
        if any(isinstance(p, SpecialChars) and p not in wildcards for p in value.s):
            raise NotImplementedError(f"a placeholder in {value}")
        flags = re.DOTALL if isinstance(value, SigmaCasedString) else re.IGNORECASE | re.DOTALL
        pattern = re.compile("".join(wildcards.get(p) or re.escape(p) for p in value.s), flags)
        return lambda v: v is not None and pattern.fullmatch(str(v)) is not None
    if isinstance(value, SigmaRegularExpression):
        flags = sum(value.sigma_to_python_flags[f] for f in value.flags)
        pattern = re.compile(str(value.regexp), flags)
        return lambda v: v is not None and pattern.search(str(v)) is not None
    if isinstance(value, SigmaNumber):
        return lambda v: v is not None and str(v) == str(value)
    raise NotImplementedError(f"{type(value).__name__} values")


def _condition_test(node):
    """A test of a document against a parsed Sigma condition (its detection items already resolved)."""
    if isinstance(node, (ConditionAND, ConditionOR)):
        tests, combine = [_condition_test(arg) for arg in node.args], all if isinstance(node, ConditionAND) else any
        return lambda doc: combine(test(doc) for test in tests)
    if isinstance(node, ConditionNOT):
        test = _condition_test(node.args[0])
        return lambda doc: not test(doc)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        field, test = node.field, _value_test(node.value)
        return lambda doc: test(doc.get(field))
    raise NotImplementedError(f"{type(node).__name__} in a condition")  # keywords: no rule has any


def matcher(rule):
    """match(document) for one rule dict (not a correlation), after the coreSigma pipelines map its fields and add its
    category's conditions. NotImplementedError for a value or condition _value_test and _condition_test don't take,
    a SigmaError if the pipelines refuse the rule."""
    converted = SigmaCollection.from_dicts([rule]).rules[0]
    (macos_esf_ecs() + macos_ul_ecs()).apply(converted)
    tests = [_condition_test(condition.parsed) for condition in converted.detection.parsed_condition]
    return lambda doc: any(test(doc) for test in tests)


def matchers():
    """({source: {rule id: match}} of each single rule, by the documents it runs on (esf, ul), {rule id: why not} for
    the others: correlations, and rules matcher() can't take)."""
    found, skipped = {"esf": {}, "ul": {}}, {}
    for rule_id, unit in rm._units(rm.RULES):
        if "correlation" in unit[-1]:
            skipped[rule_id] = "a correlation: counted in this process as single rules only"
            continue
        try:
            found[rm._sources(unit)[0]][rule_id] = matcher(unit[-1])
        except Exception as e:  # this rule's result, not the run's end
            skipped[rule_id] = f"not counted in this process: {rm._why(e)}"
    return found, skipped


def count(parts, found):
    """One sample counted in this process, over its parts ({part: documents}): its hours (each part from its first to
    its last document), documents and each rule's hits and rate."""
    sample = {"hours": 0, "documents": 0, "parts": {}, "hits": dict.fromkeys(found, 0)}
    for part, docs in parts.items():
        documents, first, last = 0, None, None
        for doc in docs:
            t = rm.iso_epoch(doc["@timestamp"])
            first, last = (t, t) if first is None else (min(first, t), max(last, t))
            documents += 1
            for rule_id, match in found.items():
                sample["hits"][rule_id] += match(doc)
        hours = (last - first) / 3600 if documents else 0
        sample["parts"][part] = {"hours": hours, "documents": documents}
        sample["hours"] += hours
        sample["documents"] += documents
    sample["rates"] = {rule_id: n / sample["hours"] for rule_id, n in sample["hits"].items()} if sample["hours"] else {}
    return sample


def _esf_documents(path):
    """An eslogger capture's documents as the ESF collector would send them (the EQL count's replay, in process)."""
    return (doc for _, doc in replay_capture.documents([path]))


def _ul_documents(path):
    with open(path) as f:
        for line in f:
            yield json.loads(line)


def run_sigma(fresh, ul, out):
    """Count each single rule in this process on the ESF parts there are (<out>/slices, fresh) and on ul if given, and
    write them to out/noise.json, with the earlier Sigma samples this run doesn't replace (an earlier ul)."""
    found, skipped = matchers()
    samples = {}
    slices = sorted((out / "slices").glob("slice*.json"))
    if slices:
        samples["slices"] = count({path.stem: _esf_documents(path) for path in slices}, found["esf"])
    if fresh.exists():
        samples["fresh"] = count({"fresh": _esf_documents(fresh)}, found["esf"])
    if ul:
        samples["ul"] = count({"ul": _ul_documents(ul)}, found["ul"])
    path = out / "noise.json"
    measured = (json.loads(path.read_text()) if path.exists() else {}).get("sigma_samples", {}) | samples
    rates = {}
    for sample in measured.values():
        for rule_id in sample["hits"]:
            rates[rule_id] = max(rates.get(rule_id, 0), sample["rates"].get(rule_id, 0))
    write_noise(out, sigma_rates=rates, sigma_samples=measured, sigma_skipped=skipped)
    print(f"{len(rates)} rules counted in process on {', '.join(measured)}, {len(skipped)} skipped -> {path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Private laptop noise baseline for rule_matrix.py verdicts --noise")
    parser.add_argument("--log", type=Path, help="the laptop's eslogger log, sliced (read only)")
    parser.add_argument("--fresh", type=Path, help="a fresh eslogger capture, whole (read only; default "
                                                   "<out>/fresh.json.gz); skipped if absent")
    parser.add_argument("--ul", type=Path, help="the UL collector's documents (--output file), whole (read only)")
    parser.add_argument("--out", default=OUT, help=f"the private directory, outside every git checkout (default {OUT})")
    args = parser.parse_args(argv)
    if not (args.log or args.ul):
        parser.error("give --log, --ul or both")
    try:
        out = private_dir(args.out)
    except ValueError as e:
        parser.error(str(e))
    if args.log and urlparse(rm.ES_URL).hostname not in LOCAL:
        parser.error(f"Elasticsearch must be on this machine ({', '.join(sorted(LOCAL))}): the documents are private")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    failed = False
    log = open(os.open(out / "run.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a")
    with log, contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
        try:
            if args.log:
                run(args.log, (args.fresh or out / "fresh.json.gz").expanduser(), out)
            run_sigma((args.fresh or out / "fresh.json.gz").expanduser(), args.ul and args.ul.expanduser(), out)
        except Exception:  # its message may name private paths or quote the store: the log only
            traceback.print_exc()
            failed = True
    print(f"{'failed' if failed else 'done'}, see {args.out}/run.log")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
