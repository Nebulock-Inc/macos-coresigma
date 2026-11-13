"""Tests for the macOS taxonomy."""
import pytest
from pathlib import Path

from sigma.backends.elasticsearch import EqlBackend, ESQLBackend
from sigma.rule import SigmaRule

from sigma.pipelines.macos.taxonomy import ESF_CATEGORIES, UL_CATEGORIES


def test_every_category_event_is_real():
    """Every event name in ESF_CATEGORIES must appear in eslogger --list-events output."""
    # Load the fixture from repo root
    fixture_path = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures" / "eslogger_events.txt"
    with open(fixture_path) as f:
        real_events = {line.strip() for line in f if line.strip()}

    # Check every event in every category
    for category, cat_data in ESF_CATEGORIES.items():
        for event in cat_data.events:
            assert event in real_events, f"Event '{event}' in category '{category}' not found in eslogger output"


# Spellings the UL table uses; Sigma semantics (case-insensitive unless "|cased").
UL_MODIFIERS = {"=": "", "startswith": "|startswith", "endswith": "|endswith"}


def test_ul_predicate_modifiers():
    """Every UL predicate uses a documented spelling; none is |cased (case never matters)."""
    for category, cat in UL_CATEGORIES.items():
        for _field, modifier, _value in cat.raw:
            assert modifier in UL_MODIFIERS, f"{category}: undocumented modifier {modifier!r}"


def _convert(backend, field, modifier, value):
    rule = SigmaRule.from_dict({
        "title": "t", "logsource": {"category": "x"},
        "detection": {"s": {field + modifier: value}, "condition": "s"},
    })
    return backend().convert_rule(rule)[0]


def _predicates():
    return [(c, *p) for c, cat in UL_CATEGORIES.items() for p in cat.raw]


@pytest.mark.parametrize("category,field,modifier,value", _predicates())
def test_ul_predicates_are_case_insensitive_in_eql(category, field, modifier, value):
    # EQL ":" is its case-insensitive operator; "==" is the case-sensitive one (|cased).
    out = _convert(EqlBackend, field, UL_MODIFIERS[modifier], value)
    pattern = {"=": value, "startswith": value + "*", "endswith": "*" + value}[modifier]
    assert out == f'any where {field}:"{pattern}"'
    cased = _convert(EqlBackend, field, UL_MODIFIERS[modifier] + "|cased", value)
    assert "==" in cased and ":" not in cased.split("where")[1].split("==")[0]


@pytest.mark.parametrize("category,field,modifier,value", _predicates())
def test_ul_predicates_convert_to_esql(category, field, modifier, value):
    # pysigma-backend-elasticsearch 2.1.0 ES|QL emits ==/starts_with/ends_with, which ES|QL
    # evaluates case-sensitively, and rejects |cased. Pin what it emits; see task-2 report.
    out = _convert(ESQLBackend, field, UL_MODIFIERS[modifier], value)
    expr = {"=": f'{field}=="{value}"',
            "startswith": f'starts_with({field}, "{value}")',
            "endswith": f'ends_with({field}, "{value}")'}[modifier]
    assert out == f"from * metadata _id, _index, _version | where {expr}"


def test_no_event_numbers_in_rules():
    """No rule should contain esf.event_type or event_type: (event numbers)."""
    rules_dir = Path(__file__).parent.parent.parent.parent / "rules"
    violations = []

    for rule_file in rules_dir.rglob("*.yml"):
        content = rule_file.read_text()
        if "esf.event_type" in content or "event_type:" in content:
            violations.append(str(rule_file.relative_to(rules_dir)))

    assert not violations, f"Rules contain event_type references: {violations}"
