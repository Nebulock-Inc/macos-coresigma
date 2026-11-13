"""macOS ESF pipeline for ECS backends."""

from dataclasses import dataclass

from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaTransformationError
from sigma.processing.conditions import (
    FieldNameProcessingCondition,
    IncludeFieldCondition,
    RuleProcessingCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    ConvertTypeTransformation,
    DetectionItemFailureTransformation,
    FieldMappingTransformation,
    RuleFailureTransformation,
    Transformation,
)
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.rule import SigmaRule
from sigma.types import SigmaBool, SigmaCompareExpression, SigmaString

from .taxonomy import ESF_CATEGORIES, ESF_FIELDS

MACOS_SERVICES = ("endpointsecurity", "unifiedlog")  # besides none


@dataclass
class MacOSESFCondition(RuleProcessingCondition):
    """Match macOS ESF rules: product macos, no service or service endpointsecurity.

    LogsourceCondition can't express "service is None"; a service-less one matches
    every service, including unifiedlog rules in categories shared with ESF.
    category None matches any category.
    """

    category: str | None = None

    def match(self, rule) -> bool:
        if isinstance(rule, SigmaCorrelationRule):
            # As LogsourceCondition: a correlation matches when a resolved referenced rule does.
            return any(hasattr(ref, "rule") and self.match(ref.rule) for ref in rule.referenced_rules)
        ls = rule.logsource
        # Rules of the other family pass through untouched: coreSigma stacks macos_esf_ecs with macos_ul_ecs.
        return (
            ls.product == "macos"
            and ls.service in (None, "endpointsecurity")
            and (self.category is None or ls.category == self.category)
        )


@dataclass
class UnknownFieldCondition(FieldNameProcessingCondition):
    """A field not in fields. Keyword items (no field) don't match: they are full-text searches, not unknown fields."""

    fields: list[str]

    def match_field_name(self, field: str | None) -> bool:
        return field is not None and field not in self.fields


def require_lowercase_logsource(rule: SigmaRule, kind: str) -> None:
    """Fail a rule whose logsource product, service or category isn't lowercase.

    The macOS conditions match exact lowercase values, so a wrong-case value would
    convert without the field mapping and category condition.
    """
    for name in ("product", "service", "category"):
        value = getattr(rule.logsource, name)
        if value and value != value.lower():
            raise SigmaTransformationError(
                f"logsource {name} '{value}' must be lowercase ('{value.lower()}') for {kind} rules",
                source=rule.source
            )


class KeywordCompareFailure(DetectionItemTransformation):
    """Fail gt/gte/lt/lte on a field the documents carry as a keyword string: the store would compare strings."""

    def apply_detection_item(self, detection_item) -> None:
        if any(isinstance(value, SigmaCompareExpression) for value in detection_item.value):
            raise SigmaTransformationError(
                f"numeric comparison (gt/gte/lt/lte) on '{detection_item.field}' not supported: "
                "the documents carry it as a keyword string",
                source=detection_item.source,
            )


class SuccessOutcome(DetectionItemTransformation):
    """Success true/false as the ECS event.outcome values the documents carry: success, failure."""

    def apply_detection_item(self, detection_item) -> None:
        if not all(isinstance(value, SigmaBool) for value in detection_item.value):
            raise SigmaTransformationError("Success takes true or false", source=detection_item.source)
        detection_item.value = [SigmaString("success" if value else "failure") for value in detection_item.value]


class MacOSServiceCheck(Transformation):
    """Fail a macOS rule whose service no pipeline knows: it would convert with no scope and no field check.

    Case is left to each family's lowercase check.
    """

    def apply(self, rule) -> None:
        ls = rule.logsource if isinstance(rule, SigmaRule) else None
        if ls and (ls.product or "").lower() == "macos" and ls.service and ls.service.lower() not in MACOS_SERVICES:
            raise SigmaTransformationError(
                f"logsource service '{ls.service}' not supported for macOS (known: none, {', '.join(MACOS_SERVICES)})",
                source=rule.source,
            )


class FieldNameCheck(Transformation):
    """Fail a rule's fields: list, or a correlation's group-by, alias fields or condition field, outside known names.

    Known: the mapping's Sigma names and its targets, plus extra (host.name by default), which pass through unchanged. Alias names pass
    in group-by and as the condition field; alias fields are checked only for the referenced rules of family (in a
    mixed correlation, each pipeline checks its own source's rules). Each stacked pipeline checks in stacking order,
    so a name an earlier pipeline maps reaches a later pipeline's check mapped.
    """

    def __init__(self, kind: str, mapping: dict[str, str], family: RuleProcessingCondition, extra=("host.name",)):
        super().__init__()
        self.kind, self.family = kind, family
        self.known = {*mapping, *mapping.values(), *extra}

    def apply(self, rule) -> None:
        names = list(rule.fields)
        if isinstance(rule, SigmaCorrelationRule):
            aliases = {alias.alias for alias in rule.aliases}
            fieldref = getattr(rule.condition, "fieldref", None)  # an extended (boolean) condition has none
            fieldrefs = [fieldref] if isinstance(fieldref, str) else fieldref or []
            names += [name for name in [*(rule.group_by or []), *fieldrefs] if name not in aliases]
            # rules is None when an extended condition names the rules instead of a rules: key; referenced_rules isn't
            refs = {ref.reference: ref.rule for ref in rule.referenced_rules or []
                    if hasattr(ref, "rule")}
            names += [field for alias in rule.aliases for ref, field in alias.mapping.items()
                      if ref.reference in refs and self.family.match(refs[ref.reference])]
        unknown = sorted(set(names) - self.known)
        if unknown:
            raise SigmaTransformationError(f"Field not supported in {self.kind} mapping: {', '.join(unknown)}",
                                           source=rule.source)


class MacOSESFCategoryCheckTransformation(Transformation):
    """Fail a macOS ESF rule (no service or endpointsecurity) whose category is missing or not in ESF_CATEGORIES.

    Product, service and category match case-insensitively, so a wrong-case ESF rule (MacOS, Process_Creation)
    fails here instead of silently skipping the exact-match MacOSESFCondition items.
    Correlation rules have no logsource; their referenced rules are checked themselves.
    """

    def apply(self, rule: SigmaRule) -> None:
        if not isinstance(rule, SigmaRule):
            return
        ls = rule.logsource
        product, service, category = (v.lower() if v else None for v in (ls.product, ls.service, ls.category))
        if product != "macos" or service not in (None, "endpointsecurity"):
            return
        if category is None:
            raise SigmaTransformationError("category missing; required for macOS ESF rules", source=rule.source)
        if category not in ESF_CATEGORIES:
            raise SigmaTransformationError(
                f"category '{ls.category}' not supported on macOS ESF", source=rule.source
            )
        require_lowercase_logsource(rule, "macOS ESF")


def macos_esf_ecs() -> ProcessingPipeline:
    """
    Pipeline for macOS ESF rules targeting ECS-compliant backends.

    Converts product: macos rules (with no service or service: endpointsecurity)
    into queries over Defend-shaped ECS documents.
    It emits process.pid and process.parent.pid values as strings, to match the coreSigma collector's keyword
    mapping; Elastic Defend's long-typed pid fields aren't supported in this release.
    """
    items = [ProcessingItem(identifier="macos_esf_ecs_unknown_service", transformation=MacOSServiceCheck())]

    # Fail rules with known unsupported categories first
    unsupported_categories = ["network_connection", "dns_query"]
    for unsupported in unsupported_categories:
        items.append(
            ProcessingItem(
                identifier=f"macos_esf_ecs_fail_{unsupported}",
                transformation=RuleFailureTransformation(
                    f"category '{unsupported}' not supported on macOS ESF"
                ),
                rule_conditions=[MacOSESFCondition(category=unsupported)]
            )
        )

    # Fail ESF rules with unknown/missing categories (not in ESF_CATEGORIES)
    # Custom transformation that checks:
    # - product=macos AND
    # - service missing or endpointsecurity AND
    # - (category missing OR category not in ESF_CATEGORIES)
    # Does NOT fail non-macOS or non-ESF-service rules (they pass through untouched)
    # Because it fails first, the category-less MacOSESFCondition() items below only see known categories.
    items.append(
        ProcessingItem(
            identifier="macos_esf_ecs_fail_unknown_category",
            transformation=MacOSESFCategoryCheckTransformation()
        )
    )

    # Fail on unmapped Sigma fields (fields not in ESF_FIELDS with ecs values)
    # This must come BEFORE field mapping and AddCondition items
    # Only applies to ESF rules (no service or service: endpointsecurity)
    mapped_sigma_fields = list(ESF_FIELDS)

    items.append(
        ProcessingItem(
            identifier="macos_esf_ecs_unmapped_field_failure",
            transformation=DetectionItemFailureTransformation(
                "Field not supported in macOS ESF ECS mapping"
            ),
            rule_conditions=[MacOSESFCondition()],
            field_name_conditions=[UnknownFieldCondition(mapped_sigma_fields)],
        )
    )

    items.append(ProcessingItem(
        identifier="macos_esf_ecs_field_name_check",
        transformation=FieldNameCheck("macOS ESF ECS", {f: d.ecs for f, d in ESF_FIELDS.items()}, MacOSESFCondition()),
        rule_conditions=[MacOSESFCondition()],
    ))

    # Build per-category conditions from taxonomy
    def condition(scope):  # AddConditionTransformation ORs a list's values and a list of dicts
        return {field: list(value) if isinstance(value, tuple) else value for field, value in scope.items()}

    for category, cat_data in ESF_CATEGORIES.items():
        scope = cat_data.scope or cat_data.ecs
        conditions = [condition(s) for s in scope] if isinstance(scope, list) else condition(scope)
        items.append(
            ProcessingItem(
                identifier=f"macos_esf_ecs_category_{category}",
                transformation=AddConditionTransformation(conditions),
                rule_conditions=[MacOSESFCondition(category=category)],
            )
        )

    items.append(ProcessingItem(
        identifier="macos_esf_ecs_success_outcome",
        transformation=SuccessOutcome(),
        field_name_conditions=[IncludeFieldCondition(["Success"])],
        rule_conditions=[MacOSESFCondition()],
    ))

    # Build field mapping from taxonomy
    # Scoped to ESF rules only (no service or service: endpointsecurity)
    field_mappings = {sigma_field: field_data.ecs for sigma_field, field_data in ESF_FIELDS.items()}

    items.append(
        ProcessingItem(
            identifier="macos_esf_ecs_field_mapping",
            transformation=FieldMappingTransformation(field_mappings),
            rule_conditions=[MacOSESFCondition()],
        )
    )

    # Convert specific fields to string type
    # Scoped to ESF rules only (no service or service: endpointsecurity)
    string_fields = ["user.id", "user.target.id", "user.target.group.id", "process.pid", "process.parent.pid"]
    items.append(ProcessingItem(
        identifier="macos_esf_ecs_keyword_compare_failure",
        transformation=KeywordCompareFailure(),
        field_name_conditions=[IncludeFieldCondition(string_fields)],
        rule_conditions=[MacOSESFCondition()],
    ))
    items.append(
        ProcessingItem(
            identifier="macos_esf_ecs_string_conversion",
            transformation=ConvertTypeTransformation("str"),
            field_name_conditions=[
                IncludeFieldCondition(string_fields)
            ],
            rule_conditions=[MacOSESFCondition()],
        )
    )


    return ProcessingPipeline(
        name="macos_esf_ecs",
        priority=20,
        items=items
    )
