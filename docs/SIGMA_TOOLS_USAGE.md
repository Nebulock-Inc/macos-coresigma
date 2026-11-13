# Converting coreSigma Rules with sigma-cli and pySigma

coreSigma rules are plain Sigma. The `pysigma-pipeline-macos` plugin maps them onto each backend: it scopes each rule by its `logsource` and maps Sigma field names to the field names of the target's data.

## Install

`setup.sh` installs everything in `requirements.txt` (Python 3.10 to 3.14): pySigma 1.5.1, sigma-cli 3.1.0, the pinned backends and the plugin from `pipelines/pysigma-pipeline-macos`. The ClickHouse backend needs Python 3.13+ and is separate: `pip install -r requirements-clickhouse.txt`. To add the plugin to another environment:

```bash
pip install pySigma-pipeline-macos              # from PyPI, released after coreSigma 2.0
pip install -e pipelines/pysigma-pipeline-macos # or this repository's copy
```

> Don't install `sigmatools`; it conflicts with `sigma-cli`.

## Pipelines

| Pipeline | For | Notes |
|---|---|---|
| `macos_esf_ecs` | ESF rules, on the ECS documents the coreSigma ESF collector writes (Elastic Defend's field names) | A rule needs a `category`; `service: endpointsecurity` is optional. Fields outside the taxonomy fail conversion. |
| `macos_ul_ecs` | Unified Log rules (`service: unifiedlog`), on the coreSigma UL collector's documents | Adds the category's subsystem or process predicate. |
| `macos_ul_raw` | Unified Log rules, on native `log --style ndjson` keys (`subsystem`, `eventMessage`, ...) | Same categories as `macos_ul_ecs`. |
| `macos_falcon` | CrowdStrike Falcon (LogScale) | `process_creation` only, with the fields Falcon's macOS process telemetry fills (`Image`, `CommandLine`, `ParentImage` by basename). A directory in a `ParentImage` value is dropped, so a positive selection matches that file name anywhere; under `not`, where that would widen an exclusion, only `ParentImage\|endswith` with the file name alone (`name`, `/name` or `*/name`) converts. LogScale only: FDR data outside LogScale names the field `event_simpleName` without the `#`, so the queries don't match there. |

Each pipeline scopes only its own family and passes the other's rules through unmapped, so stack `macos_esf_ecs` and `macos_ul_ecs` when converting ESF and UL rules together. [FIELD_NAME_ORIGINS.md](FIELD_NAME_ORIGINS.md) lists the field mappings; `pipelines/pysigma-pipeline-macos/sigma/pipelines/macos/taxonomy.py` is their source.

## Converting

```bash
# One ESF rule to EQL
sigma convert -t eql -p macos_esf_ecs rules/esf/macos_dscl_authonly_password_check.yml

# A directory of UL rules to Splunk SPL
sigma convert -t splunk -p macos_esf_ecs -p macos_ul_ecs rules/ul/

# ES|QL, OpenSearch Lucene, ClickHouse
sigma convert -t esql -p macos_esf_ecs -p macos_ul_ecs rules/esf/
sigma convert -t opensearch_lucene -p macos_esf_ecs -p macos_ul_ecs rules/ul/firewall_disabled.yml
sigma convert -t clickhouse -p macos_esf_ecs -p macos_ul_ecs rules/ul/   # needs requirements-clickhouse.txt

# Falcon LogScale: process_creation rules only
sigma convert -t log_scale -p macos_falcon rules/esf/process_execution_suspicious.yml
```

What the scripts add on top of plain conversion:

- `scripts/deploy_sigma_rules.py` post-processes EQL for Elasticsearch: numeric fields (`signal.number`, `memory.protection`, `btm.item.type`) compare with `==` and `in` instead of `:` and `like~`, and backslashes that don't start an EQL escape are doubled. `sigma convert -t eql` output doesn't have these fixes.
- Both `deploy_sigma_rules.py` and `scripts/rule_matrix.py` apply a correlation's declared fallback (below), and convert a `temporal_ordered` correlation to an EQL sequence (`EqlSequenceBackend` in `deploy_sigma_rules.py`). `rule_matrix.py` also orders ClickHouse's `temporal_ordered` query with `windowFunnel` (`clickhouse_ordered`).

## Correlations

Convert a correlation together with its base rules, as the deploy and matrix scripts do, and convert one correlation (with its base rules) per `sigma convert` run on the pinned sigma-cli. sigma-cli resolves a correlation's `rules:` only within one input path: give it a directory that holds the correlation and the base rules it names. Passing the files as separate arguments fails with `Rule '...' not found in rule collection`.

```bash
mkdir /tmp/pkg && cp rules/correlation/package_manager_persistence.yml \
  rules/esf/macos_node_spawns_shell_or_downloader.yml \
  rules/esf/macos_launchagent_apple_cache_or_agent_config_create.yml /tmp/pkg/
sigma convert -t splunk -p macos_esf_ecs -p macos_ul_ecs /tmp/pkg
```

Each base rule's `custom.coresigma.base_of` names the correlations that use it, and a correlation's `rules:` lists the base rules' `name:` values. A base rule converted on its own still produces a query, but it is meant to run inside its correlation (a correlation's base rules have `generate: false` by default, so they produce no output of their own next to it).

Backends differ:

- pysigma-backend-elasticsearch's EQL backend and OpenSearch Lucene have no correlations. coreSigma's `EqlSequenceBackend` (`scripts/deploy_sigma_rules.py`) adds `temporal_ordered` to EQL as `sequence by <group-by> with maxspan=<timespan>` with one step per base rule; `sigma convert -t eql` doesn't have it.
- ES|QL has no `temporal_ordered`.
- pysigma-backend-splunk 2.1.0 has no `temporal_ordered` either. The two ordered rules declare `custom.coresigma.splunk: temporal`, an unordered fallback that the deploy and matrix scripts apply; sigma-cli doesn't, so for Splunk change `type: temporal_ordered` to `temporal` in your copy. Splunk counts in fixed `bin` windows of the timespan: a chain that crosses a window boundary is missed.
- ClickHouse groups a correlation over the whole search range, not per timespan, and doesn't check order (`scripts/rule_matrix.py` rewrites a `temporal_ordered` query to use `windowFunnel`).
- A correlation with `custom.coresigma.logscale: unsupported` isn't converted for Falcon: pysigma-backend-crowdstrike 3.0.0 has no correlation support.

## Python

```python
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.macos import macos_esf_ecs, macos_ul_ecs

rules = SigmaCollection.load_ruleset([Path("rules/esf")])  # directories are searched recursively
backend = SplunkBackend(macos_esf_ecs() + macos_ul_ecs())
queries = backend.convert(rules)
```

`scripts/deploy_sigma_rules.py` converts each rule with `convert_rule` (base rules before their correlations) and `convert_correlation_rule`, rather than converting the whole collection at once.

## Pinned versions

`requirements.txt` pins `pysigma==1.5.1`, `sigma-cli==3.1.0`, `pysigma-backend-elasticsearch==2.1.0`, `pysigma-backend-splunk==2.1.0`, `pysigma-backend-crowdstrike==3.0.0`, `pysigma-backend-kusto==1.0.1` and `pysigma-backend-opensearch==2.0.3`, and `requirements-clickhouse.txt` pins `pysigma-backend-clickhouse==1.1.1`: the set the support matrix was measured with. On pysigma-backend-elasticsearch 2.1.0, a `|re` that matches a backslash (`\\`) converts wrong (no shipped rule has one; an escape such as `\.` is fine).
