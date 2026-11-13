"""Tests for the macos_ul_ecs and macos_ul_raw pipelines."""
import pytest
from sigma.backends.elasticsearch import ESQLBackend, LuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

from sigma.pipelines.macos import pipelines
from sigma.pipelines.macos.taxonomy import UL_CATEGORIES, UL_FIELDS


def _rule(logsource, selection="eventMessage|contains: x"):
    return f"""
title: Test
logsource:
    {logsource}
detection:
    selection:
        {selection}
    condition: selection
"""


def _lucene(pipeline, rule):
    return LuceneBackend(processing_pipeline=pipelines[pipeline]()).convert(SigmaCollection.from_yaml(rule))[0]


def test_sudo_by_process():
    rule = _rule("product: macos\n    service: unifiedlog\n    category: sudo", "message|contains: 'COMMAND='")
    assert _lucene("macos_ul_ecs", rule) == r"process.executable:\/usr\/bin\/sudo AND message:*COMMAND\=*"


def test_firewall_prefix():
    rule = _rule("product: macos\n    service: unifiedlog\n    category: firewall")
    assert _lucene("macos_ul_ecs", rule) == "unified_log.subsystem:com.apple.ALF* AND message:*x*"


def test_raw_native_names():
    rule = _rule("product: macos\n    service: unifiedlog\n    category: sudo", "message|contains: 'COMMAND='")
    assert _lucene("macos_ul_raw", rule) == r"processImagePath:\/usr\/bin\/sudo AND eventMessage:*COMMAND\=*"


@pytest.mark.parametrize("category,ecs,raw", [
    # ORed predicates across two fields, and the endswith modifier
    ("gatekeeper",
     r"(unified_log.subsystem:com.apple.syspolicy* OR process.executable:\/usr\/libexec\/syspolicyd)",
     r"(subsystem:com.apple.syspolicy* OR processImagePath:\/usr\/libexec\/syspolicyd)"),
    ("mdm", r"process.executable:*\/mdmclient", r"processImagePath:*\/mdmclient"),
])
def test_category_predicates(category, ecs, raw):
    rule = _rule(f"product: macos\n    service: unifiedlog\n    category: {category}")
    assert _lucene("macos_ul_ecs", rule) == f"{ecs} AND message:*x*"
    assert _lucene("macos_ul_raw", rule) == f"{raw} AND eventMessage:*x*"


@pytest.mark.parametrize("category", UL_CATEGORIES)
def test_every_category_predicate(category):
    """Every predicate of every category lands in both pipelines under that pipeline's field name."""
    rule = _rule(f"product: macos\n    service: unifiedlog\n    category: {category}")
    for pipeline, column in (("macos_ul_ecs", "ecs"), ("macos_ul_raw", "raw")):
        query = _lucene(pipeline, rule)
        for field, modifier, value in UL_CATEGORIES[category].raw:
            value = value.replace("/", r"\/")  # Lucene escape
            pattern = {"=": value, "startswith": value + "*", "endswith": "*" + value}[modifier]
            assert f"{getattr(UL_FIELDS[field], column)}:{pattern}" in query


@pytest.mark.parametrize("field,ecs,raw", [
    ("message", "message", "eventMessage"),
    ("Message", "message", "eventMessage"),
    ("Image", "process.executable", "processImagePath"),
    ("senderImagePath", "unified_log.sender_image_path", "senderImagePath"),
    ("messageType", "log.level", "messageType"),
    ("processID", "process.pid", "processID"),
    ("userID", "user.id", "userID"),
    ("category", "unified_log.category", "category"),
])
def test_field_mapping(field, ecs, raw):
    rule = _rule("product: macos\n    service: unifiedlog", f"{field}: v")
    assert _lucene("macos_ul_ecs", rule) == f"{ecs}:v"
    assert _lucene("macos_ul_raw", rule) == f"{raw}:v"


@pytest.mark.parametrize("field,ecs", [("userID", "user.id"), ("processID", "process.pid")])
def test_ids_are_strings(field, ecs):
    """The UL template maps user.id and process.pid keyword, so macos_ul_ecs queries them as strings."""
    rule = _rule("product: macos\n    service: unifiedlog", f"{field}: 0")
    assert _lucene("macos_ul_ecs", rule) == f"{ecs}:0"
    esql = ESQLBackend(processing_pipeline=pipelines["macos_ul_ecs"]()).convert(SigmaCollection.from_yaml(rule))[0]
    assert f'{ecs}=="0"' in esql
    raw = ESQLBackend(processing_pipeline=pipelines["macos_ul_raw"]()).convert(SigmaCollection.from_yaml(rule))[0]
    assert f"{field}==0" in raw  # raw `log` lines keep native ints


def test_numeric_compare_on_keyword_id():
    """gt/gte/lt/lte on a keyword id fails on macos_ul_ecs; raw `log` lines keep native ints, so raw converts."""
    rule = _rule("product: macos\n    service: unifiedlog", "userID|gt: 500")
    with pytest.raises(SigmaTransformationError, match="numeric comparison .* keyword string"):
        _lucene("macos_ul_ecs", rule)
    assert _lucene("macos_ul_raw", rule) == "userID:>500"


@pytest.mark.parametrize("pipeline", ["macos_ul_ecs", "macos_ul_raw"])
def test_unknown_category_fails(pipeline):
    rule = _rule("product: macos\n    service: unifiedlog\n    category: process_creation")
    with pytest.raises(SigmaTransformationError, match="category not supported on macOS unified log"):
        _lucene(pipeline, rule)


@pytest.mark.parametrize("pipeline", ["macos_ul_ecs", "macos_ul_raw"])
@pytest.mark.parametrize("selection", ["DestinationHostname: evil.com", "eventMessage|fieldref: Foo"])
def test_unknown_field_fails(pipeline, selection):
    """An unknown field (or field reference) fails instead of converting to a query that never matches."""
    rule = _rule("product: macos\n    service: unifiedlog\n    category: tcc", selection)
    with pytest.raises(SigmaTransformationError, match="Field not supported in macOS unified log mapping"):
        _lucene(pipeline, rule)


@pytest.mark.parametrize("pipeline", ["macos_ul_ecs", "macos_ul_raw"])
def test_keywords_still_convert(pipeline):
    """Keyword items have no field: they stay full-text searches."""
    rule = "title: t\nlogsource: {product: macos, service: unifiedlog, category: tcc}\n" \
           "detection:\n    keywords: [denied]\n    condition: keywords\n"
    assert _lucene(pipeline, rule).endswith("AND *denied*")


def test_event_type_raw_only():
    """eventType is a native ndjson key: macos_ul_raw passes it through; the collector's ECS documents don't carry it."""
    rule = _rule("product: macos\n    service: unifiedlog\n    category: tcc", "eventType: activityCreateEvent")
    assert _lucene("macos_ul_raw", rule) == "subsystem:com.apple.TCC* AND eventType:activityCreateEvent"
    with pytest.raises(SigmaTransformationError,
                       match="eventType is not carried by the coreSigma collector's ECS documents"):
        _lucene("macos_ul_ecs", rule)


@pytest.mark.parametrize("logsource,message", [
    ("product: MacOS\n    service: unifiedlog\n    category: tcc", "logsource product 'MacOS' must be lowercase"),
    ("product: macos\n    service: UnifiedLog\n    category: tcc", "logsource service 'UnifiedLog' must be lowercase"),
    ("product: macos\n    service: unifiedlog\n    category: TCC", "logsource category 'TCC' must be lowercase"),
])
def test_wrong_case_fails(logsource, message):
    with pytest.raises(SigmaTransformationError, match=message):
        _lucene("macos_ul_ecs", _rule(logsource))


@pytest.mark.parametrize("logsource", [
    "product: macos\n    category: sudo",  # ESF rule in a category UL shares
    "product: macos\n    service: endpointsecurity\n    category: process_creation",
    "product: windows\n    category: process_creation",
    "product: linux",
])
def test_non_ul_rules_untouched(logsource):
    rule = _rule(logsource, "Image: /x\n        DestinationHostname: y")  # mapped and unknown fields alike
    expected = LuceneBackend().convert(SigmaCollection.from_yaml(rule))
    for name in ("macos_ul_ecs", "macos_ul_raw"):
        assert LuceneBackend(processing_pipeline=pipelines[name]()).convert(SigmaCollection.from_yaml(rule)) == expected


@pytest.mark.parametrize("pipeline", ["macos_ul_ecs", "macos_ul_raw"])
def test_unknown_field_outside_detection_fails(pipeline):
    """fields: and a correlation's group-by take UL Sigma names, the pipeline's targets and host.name."""
    base = _rule("product: macos\n    service: unifiedlog\n    category: sudo").replace("title: Test", "title: S\nname: s")
    corr = "\n---\ntitle: C\ncorrelation:\n  type: event_count\n  rules: s\n  group-by: [{}]\n  timespan: 5m\n" \
           "  condition: {{gte: 3}}"
    backend = SplunkBackend(processing_pipeline=pipelines[pipeline]())
    for group_by in ("userID", "host.name", {"macos_ul_ecs": "user.id", "macos_ul_raw": "userID"}[pipeline]):
        backend.convert(SigmaCollection.from_yaml(base + corr.format(group_by)))
    backend.convert(SigmaCollection.from_yaml(base + "fields: [message, processImagePath]\n"))
    for name in ("Hostname", "user.name"):  # UL documents carry no user.name
        for rules in (base + corr.format(name), base + f"fields: [message, {name}]\n"):
            with pytest.raises(SigmaTransformationError, match=f"Field not supported in macOS unified log mapping: {name}"):
                SplunkBackend(processing_pipeline=pipelines[pipeline]()).convert(SigmaCollection.from_yaml(rules))


def test_correlation_group_by_mapped():
    rules = """
title: Sudo
name: ul_sudo
logsource:
    product: macos
    service: unifiedlog
    category: sudo
detection:
    selection:
        message|contains: 'incorrect password'
    condition: selection
---
title: Many Sudo Failures
correlation:
    type: event_count
    rules: ul_sudo
    group-by: userID
    timespan: 5m
    condition:
        gte: 3
"""
    backend = SplunkBackend(processing_pipeline=pipelines["macos_ul_ecs"]())
    assert backend.convert(SigmaCollection.from_yaml(rules)) == [
        'process.executable="/usr/bin/sudo" message="*incorrect password*"\n\n'
        "| bin _time span=5m\n| stats count as event_count by _time user.id\n\n| search event_count >= 3"
    ]
