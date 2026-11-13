"""Structural linter for rules/**/*.yml."""
import importlib.util
import re
import sys
import uuid
from collections import Counter
from pathlib import Path

import yaml
from sigma.rule import SigmaRuleTag
from sigma.validators.core.tags import ATTACKTagValidator

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "cs_lint_taxonomy", ROOT / "pipelines/pysigma-pipeline-macos/sigma/pipelines/macos/taxonomy.py"
)
tax = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tax  # dataclasses needs it registered
_spec.loader.exec_module(tax)

FILES = sorted((ROOT / "rules").rglob("*.yml"))
RULES = {p: yaml.safe_load(p.read_text()) for p in FILES}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"verified", "converts", "not-verified", "base"}  # base: a correlation's base rule

_atk = ATTACKTagValidator()
_atk.rule = None  # validate_tag only touches self.rule when building an issue


def offenders(check):
    """Aggregate per check (not per rule): the assertion message lists every offending rule."""
    out = []
    for p, r in RULES.items():
        msg = check(p, r)
        if msg:
            out.append(f"{p.relative_to(ROOT)}: {msg}")
    assert not out, "\n" + "\n".join(out)


def _uuid4(s):
    try:
        return uuid.UUID(str(s)).version == 4 and str(s) == str(uuid.UUID(str(s)))
    except ValueError:
        return False


def _sequential(s):
    """Hand-sequenced placeholder: many +1 (mod 16) steps between hex digits i and i+1, or i and i+2.
    Over 100k random uuid4s the max is 10 of 31/30; every placeholder in rules/ scores >= 15."""
    d = [int(c, 16) for c in str(s).replace("-", "")]
    return max(sum((d[i + k] - d[i]) % 16 == 1 for i in range(32 - k)) for k in (1, 2)) >= 13


def test_sequential_heuristic_no_false_positives():
    assert not any(_sequential(uuid.uuid4()) for _ in range(100_000))
    assert _sequential("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")


def test_rules_found():
    assert FILES


def test_id_is_uuid4():
    offenders(
        lambda p, r: None
        if _uuid4(r.get("id")) and not _sequential(r["id"])
        else f"id={r.get('id')} (not v4 or hand-sequenced)"
    )


def test_id_unique():
    n = Counter(r.get("id") for r in RULES.values())
    offenders(lambda p, r: f"duplicate id {r.get('id')}" if n[r.get("id")] > 1 else None)


def _dates(p, r):
    date, mod = str(r.get("date", "")), r.get("modified")
    if not DATE_RE.match(date):
        return f"date={date}"
    if mod is not None and not (DATE_RE.match(str(mod)) and str(mod) >= date):
        return f"modified={mod} date={date}"


def test_dates_format_and_order():
    offenders(_dates)


def test_logsource_product():
    offenders(lambda p, r: None if "correlation" in r or r.get("logsource", {}).get("product") == "macos" else "product != macos")


def _category(p, r):
    if "correlation" in r:  # correlation rules have no logsource; their base rules are checked
        return None
    ls = r.get("logsource", {})
    cat = ls.get("category")
    if ls.get("service") == "unifiedlog":
        ok = cat is None or cat in tax.UL_CATEGORIES
    else:
        ok = cat in tax.ESF_CATEGORIES
    return None if ok else f"category={cat} service={ls.get('service')}"


def test_logsource_category():
    offenders(_category)


def test_no_timeframe():
    # Sigma puts timeframe under detection; check both levels
    offenders(lambda p, r: "has timeframe" if "timeframe" in r or "timeframe" in (r.get("detection") or {}) else None)


def _tags(p, r):
    bad = [
        t for t in r.get("tags", [])
        if t.startswith("attack.") and _atk.validate_tag(SigmaRuleTag.from_str(t))
    ]
    return f"invalid tags {bad}" if bad else None


def test_attack_tags_valid():
    offenders(_tags)


def test_level():
    offenders(lambda p, r: None if r.get("level") in LEVELS else f"level={r.get('level')}")


def _fp(p, r):
    if "correlation" in r:  # correlation rules are exempt
        return None
    fp = r.get("falsepositives")
    return None if isinstance(fp, list) and fp else "falsepositives missing/not a list"


def test_falsepositives():
    offenders(_fp)


def _status(p, r):
    st = ((r.get("custom") or {}).get("coresigma") or {}).get("status")
    return None if st is None or st in STATUSES else f"status={st}"


def test_custom_status():
    offenders(_status)
