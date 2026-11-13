"""macOS Unified Log pipelines: macos_ul_ecs (ECS documents) and macos_ul_raw (native `log --style ndjson` keys)."""

from __future__ import annotations

from dataclasses import dataclass

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import IncludeFieldCondition, RuleProcessingCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    ConvertTypeTransformation,
    DetectionItemFailureTransformation,
    FieldMappingTransformation,
    RuleFailureTransformation,
    Transformation,
)
from sigma.rule import SigmaRule

from .esf import (
    FieldNameCheck,
    KeywordCompareFailure,
    MacOSServiceCheck,
    UnknownFieldCondition,
    require_lowercase_logsource,
)
from .taxonomy import UL_CATEGORIES, UL_FIELDS, UL_RAW_ONLY_FIELDS

# UL_CATEGORIES modifier spellings as Sigma field suffixes (see the taxonomy header).
# shortcut: no "|cased" spellings (none in the table; test_taxonomy rejects them), add them here when one is.
MODIFIERS = {"=": "", "startswith": "|startswith", "endswith": "|endswith"}


@dataclass
class MacOSULCondition(RuleProcessingCondition):
    """Match macOS unified log rules: product macos, service unifiedlog.

    category None matches any category or none; unknown=True matches only a category
    missing from UL_CATEGORIES. A correlation matches when a resolved referenced rule does.
    """

    category: str | None = None
    unknown: bool = False

    def match(self, rule) -> bool:
        if isinstance(rule, SigmaCorrelationRule):
            return any(hasattr(ref, "rule") and self.match(ref.rule) for ref in rule.referenced_rules)
        ls = rule.logsource
        # Rules of the other family pass through untouched: coreSigma stacks macos_ul_ecs with macos_esf_ecs.
        if ls.product != "macos" or ls.service != "unifiedlog":
            return False
        if self.unknown:
            return ls.category is not None and ls.category not in UL_CATEGORIES
        return self.category is None or ls.category == self.category


class MacOSULCaseCheckTransformation(Transformation):
    """Fail a macOS unified log rule with a wrong-case logsource, which MacOSULCondition would skip."""

    def apply(self, rule) -> None:
        if not isinstance(rule, SigmaRule):  # correlations have no logsource
            return
        ls = rule.logsource
        if (ls.product or "").lower() == "macos" and (ls.service or "").lower() == "unifiedlog":
            require_lowercase_logsource(rule, "macOS unified log")


def _ul_pipeline(name: str, column: str) -> ProcessingPipeline:
    """Category predicates are in native names; the final mapping takes UL_FIELDS.<column>."""
    items = [
        ProcessingItem(identifier=f"{name}_unknown_service", transformation=MacOSServiceCheck()),
        ProcessingItem(identifier=f"{name}_lowercase_logsource", transformation=MacOSULCaseCheckTransformation()),
        ProcessingItem(
            identifier=f"{name}_fail_unknown_category",
            transformation=RuleFailureTransformation(
                f"category not supported on macOS unified log (supported: {', '.join(UL_CATEGORIES)})"
            ),
            rule_conditions=[MacOSULCondition(unknown=True)],
        ),
    ]
    mapping = {k: getattr(f, column) for k, f in UL_FIELDS.items()}
    names = mapping | ({f: f for f in UL_RAW_ONLY_FIELDS} if column == "raw" else {})  # raw-only keys pass as they are
    if column == "ecs":
        items.append(ProcessingItem(
            identifier=f"{name}_raw_only_field_failure",
            transformation=DetectionItemFailureTransformation(
                f"{', '.join(UL_RAW_ONLY_FIELDS)} is not carried by the coreSigma collector's ECS documents "
                "(macos_ul_raw has it)"
            ),
            rule_conditions=[MacOSULCondition()],
            field_name_conditions=[IncludeFieldCondition(list(UL_RAW_ONLY_FIELDS))],
        ))
    items.append(ProcessingItem(
        identifier=f"{name}_unmapped_field_failure",
        transformation=DetectionItemFailureTransformation("Field not supported in macOS unified log mapping"),
        rule_conditions=[MacOSULCondition()],
        field_name_conditions=[UnknownFieldCondition(list(names))],
    ))
    items.append(ProcessingItem(
        identifier=f"{name}_field_name_check",
        transformation=FieldNameCheck("macOS unified log", names, MacOSULCondition()),
        rule_conditions=[MacOSULCondition()],
    ))
    for category, cat in UL_CATEGORIES.items():
        items.append(ProcessingItem(
            identifier=f"{name}_category_{category}",
            # a list of one-key dicts ORs the predicates
            transformation=AddConditionTransformation(
                [{field + MODIFIERS[modifier]: value} for field, modifier, value in cat.raw]
            ),
            rule_conditions=[MacOSULCondition(category=category)],
        ))
    items.append(ProcessingItem(
        identifier=f"{name}_field_mapping",
        transformation=FieldMappingTransformation(mapping),
        rule_conditions=[MacOSULCondition()],
    ))
    if column == "ecs":  # the collector's ids are keyword in the UL template, as in ESF documents
        items.append(ProcessingItem(
            identifier=f"{name}_keyword_compare_failure",
            transformation=KeywordCompareFailure(),
            field_name_conditions=[IncludeFieldCondition(["user.id", "process.pid"])],
            rule_conditions=[MacOSULCondition()],
        ))
        items.append(ProcessingItem(
            identifier=f"{name}_string_conversion",
            transformation=ConvertTypeTransformation("str"),
            field_name_conditions=[IncludeFieldCondition(["user.id", "process.pid"])],
            rule_conditions=[MacOSULCondition()],
        ))
    return ProcessingPipeline(name=name, priority=20, items=items)


def macos_ul_ecs() -> ProcessingPipeline:
    """product: macos, service: unifiedlog rules over the UL collector's ECS documents."""
    return _ul_pipeline("macos_ul_ecs", "ecs")


def macos_ul_raw() -> ProcessingPipeline:
    """product: macos, service: unifiedlog rules over raw `log --style ndjson` lines."""
    return _ul_pipeline("macos_ul_raw", "raw")
