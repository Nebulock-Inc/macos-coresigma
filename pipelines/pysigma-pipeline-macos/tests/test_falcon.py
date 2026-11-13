"""Tests for the macos_falcon pipeline (LogScale / FDR)."""
from pathlib import Path

import pytest
from sigma.backends.crowdstrike import LogScaleBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

import sigma.pipelines.macos as plugin
from sigma.pipelines.macos import pipelines

assert Path(plugin.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1]), plugin.__file__


def convert(logsource: str, selection: str) -> str:
    rule = f"""
title: T
logsource:
{logsource}
detection:
    selection:
{selection}
    condition: selection
"""
    backend = LogScaleBackend(processing_pipeline=pipelines["macos_falcon"]())
    return backend.convert(SigmaCollection.from_yaml(rule))[0]


PC = "    product: macos\n    category: process_creation"


def test_falcon_process_creation():
    out = convert(PC, "        Image|endswith: /osascript")
    assert r"#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/" in out
    assert r"ImageFileName=/\/osascript$/i" in out
    assert "event_platform=/^Mac$/i" in out


def test_falcon_endpointsecurity_service_converts():
    out = convert(PC + "\n    service: endpointsecurity", "        CommandLine|contains: foo")
    assert "CommandLine=" in out


def test_falcon_parent_image_basename():
    out = convert(PC, "        ParentImage: /usr/bin/python3")
    assert "ParentBaseFileName=" in out and "python3" in out and "/usr/bin" not in out


def test_falcon_tcc_unsupported():
    with pytest.raises(SigmaTransformationError, match="not supported on Falcon macOS telemetry"):
        convert("    product: macos\n    category: tcc_modification", "        Image|endswith: /x")


def test_falcon_unifiedlog_unsupported():
    with pytest.raises(SigmaTransformationError, match="not supported on Falcon macOS telemetry"):
        convert("    product: macos\n    service: unifiedlog", "        Image|endswith: /x")


def test_falcon_signingid_unsupported():
    with pytest.raises(SigmaTransformationError):
        convert(PC, "        SigningID: com.apple.foo")


def test_falcon_wrong_case_fails():
    with pytest.raises(SigmaTransformationError, match="lowercase"):
        convert("    product: MacOS\n    category: process_creation", "        Image|endswith: /x")


def test_falcon_non_macos_untouched():
    out = convert("    product: windows\n    category: process_creation", "        Image|endswith: x.exe")
    assert "ProcessRollup2" not in out


def test_falcon_correlation_does_not_crash():
    rules = """
title: Base
name: base
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: /osascript
    condition: selection
---
title: Corr
correlation:
    type: event_count
    rules: [base]
    group-by: [Image]
    timespan: 1h
    condition:
        gte: 3
"""
    # LogScale has no correlation support, so exercise the pipeline directly.
    collection = SigmaCollection.from_yaml(rules)
    pipelines["macos_falcon"]().apply(collection.rules[1])


def test_falcon_keyword_fails_clearly():
    rule = "title: T\nlogsource: {product: macos, category: process_creation}\ndetection:\n  k: [osascript]\n  condition: k\n"
    with pytest.raises(SigmaTransformationError, match="keyword search isn't supported for Falcon macOS process_creation"):
        LogScaleBackend(processing_pipeline=pipelines["macos_falcon"]()).convert(SigmaCollection.from_yaml(rule))


BASE = "title: Base\nname: base\nlogsource: {product: macos, category: process_creation}\n" \
       "detection:\n  selection: {Image|endswith: /osascript}\n  condition: selection\n"


@pytest.mark.parametrize("extra,error", [
    ("fields: [Image, CommandLine, ImageFileName]\n", None),
    ("fields: [Image, User]\n", None),  # a rule's fields: aren't checked: LogScaleBackend ignores them
    ("---\ntitle: C\ncorrelation: {type: event_count, rules: [base], group-by: [Image], timespan: 1h,"
     " condition: {gte: 3}}\nfields: [User]\n", "User"),
    ("---\ntitle: C\ncorrelation: {type: event_count, rules: [base], group-by: [ParentImage, ParentBaseFileName],"
     " timespan: 1h, condition: {gte: 3}}\n", None),
    ("---\ntitle: C\ncorrelation: {type: event_count, rules: [base], group-by: [host.name], timespan: 1h,"
     " condition: {gte: 3}}\n", "host.name"),  # no host field mapped
])
def test_falcon_fields_and_group_by_checked(extra, error):
    """A correlation's group-by and fields: take the mapping's Sigma names and Falcon targets only."""
    collection = SigmaCollection.from_yaml(BASE + extra)
    pipeline = pipelines["macos_falcon"]()
    if error is None:
        pipeline.apply(collection.rules[-1])
    else:
        with pytest.raises(SigmaTransformationError, match=f"Field not supported in Falcon macOS mapping: {error}"):
            pipeline.apply(collection.rules[-1])


@pytest.mark.parametrize("group_by,error", [("Image", None), ("host.name", "host.name")])
def test_falcon_correlation_without_rules_key(group_by, error):
    """An extended correlation with no rules: key (its rules only in the condition) is still checked, not a TypeError."""
    rules = BASE + "---\n" + BASE.replace("name: base", "name: base2") + \
        f"---\ntitle: C\ncorrelation: {{type: temporal, group-by: [{group_by}], timespan: 1h, condition: base and base2}}\n"
    collection = SigmaCollection.from_yaml(rules)
    assert collection.rules[-1].rules is None
    if error is None:
        pipelines["macos_falcon"]().apply(collection.rules[-1])
    else:
        with pytest.raises(SigmaTransformationError, match=f"Field not supported in Falcon macOS mapping: {error}"):
            pipelines["macos_falcon"]().apply(collection.rules[-1])


def test_falcon_parent_image_exact_and_endswith():
    assert "ParentBaseFileName=/^Terminal$/i" in convert(PC, "        ParentImage: /System/Applications/Utilities/Terminal.app/Terminal")
    assert "ParentBaseFileName=/^zsh$/i" in convert(PC, "        ParentImage|endswith: /bin/zsh")


@pytest.mark.parametrize(
    "selection,needle",
    [
        ("ParentImage|contains: '/Applications/'", "SigmaContainsModifier"),
        ("ParentImage|startswith: '/usr/'", "SigmaStartswithModifier"),
        ("ParentImage|startswith: '/usr/bin/'", "SigmaStartswithModifier"),
        ("ParentImage|contains: '/'", "SigmaContainsModifier"),
        ("ParentImage|contains|all: ['/a/', '/b/']", "SigmaContainsModifier"),
        ("ParentImage|contains: 'Applications/Foo'", "SigmaContainsModifier"),
        ("ParentImage|endswith: '/'", "empty"),
        ("ParentImage: '/usr/bin/'", "empty"),
        ("ParentImage: '/usr/*'", "wildcard-only basename"),
        ("ParentImage|endswith: '/*'", "wildcard-only basename"),
        ("ParentImage|re: '^/usr/.*'", "SigmaRegularExpressionModifier"),
    ],
)
def test_falcon_parent_image_unsupported(selection, needle):
    with pytest.raises(SigmaTransformationError, match="ParentImage") as e:
        convert(PC, "        " + selection)
    assert needle in str(e.value)


def test_falcon_parent_image_partial_wildcard_converts():
    assert "ParentBaseFileName=" in convert(PC, "        ParentImage: '/usr/bin/z*'")


def _negated(filter_):
    rule = f"""
title: T
logsource:
{PC}
detection:
    sel:
        Image|endswith: /curl
    filter:
{filter_}
    condition: sel and not filter
"""
    return LogScaleBackend(processing_pipeline=pipelines["macos_falcon"]()).convert(SigmaCollection.from_yaml(rule))[0]


@pytest.mark.parametrize(
    "filter_",
    [
        "        ParentImage: /usr/local/jamf/bin/jamf",
        "        ParentImage|endswith: /usr/libexec/xpcproxy",
        "        ParentImage: jamf",
        "        ParentImage|endswith:\n            - /bin/zsh\n            - xpcproxy",
    ],
)
def test_falcon_parent_image_path_under_not_rejected(filter_):
    with pytest.raises(SigmaTransformationError, match="under 'not'"):
        _negated(filter_)


@pytest.mark.parametrize("value", ["jamf", "/jamf", "*/jamf"])
def test_falcon_parent_image_name_under_not_converts(value):
    assert "not ParentBaseFileName=" in _negated(f"        ParentImage|endswith: '{value}'")


def test_falcon_parent_image_path_positive_still_converts():
    assert "ParentBaseFileName=/^jamf$/i" in convert(PC, "        ParentImage: /usr/local/jamf/bin/jamf")
