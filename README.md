# macOS coreSigma

**coreSigma** is a set of Sigma detection rules for macOS Endpoint Security (ESF) and Unified Log (UL) telemetry, the pySigma pipeline plugin that maps them onto several SIEM and EDR backends, collectors that turn `eslogger` and `log stream` output into ECS documents, and a support matrix that records which rules were seen firing.

## Status of 2.0

<!-- MATRIX-COUNT: the verified count, from docs/SUPPORT_MATRIX.md. Update it here and in CHANGELOG.md. -->
**40 of 69 rules are verified live.** The rest are marked not-verified, each with its reason.

A rule is *verified* when it fired on at least one target inside a clean simulation window on the test host (macOS 26.7). Not-verified covers rules no simulation exercised, rules that convert but whose data isn't collected, rules that were only noisy, and rules whose only hits weren't the behaviour they look for. Noise counts both 13.3 idle hours on the test host and a private laptop sample (ESF and unified log rules, each at the higher of its EQL and Sigma-semantics count; correlations aren't counted there); no laptop data is published, only each rule's noisy or quiet outcome. The per-rule, per-target results and every reason are in [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md), which `scripts/rule_matrix.py` generates. Each rule also carries its status in `custom.coresigma.status`.

## What's here

| Path | Contents |
|---|---|
| `rules/esf/` | 55 Sigma rules on ESF events (`product: macos`, a `category`; `service: endpointsecurity` is optional) |
| `rules/ul/` | 20 Sigma rules on Unified Log lines (`product: macos`, `service: unifiedlog`) |
| `rules/correlation/` | 7 Sigma correlation rules, one of them across ESF and UL |
| `pipelines/pysigma-pipeline-macos/` | The pySigma plugin: `macos_esf_ecs`, `macos_ul_ecs`, `macos_ul_raw`, `macos_falcon` |
| `collectors/` | `esf_collector.py` (eslogger) and `ul_collector.py` (`log stream`), output to stdout, a file, Elasticsearch or Splunk HEC |
| `scripts/` | Deployment (`deploy_sigma_rules.py`), the Docker bench (`bench_up.sh`), capture replay and the support matrix |
| `splunk/coresigma_app/` | The generated Splunk app: one saved search per rule |
| `filters/examples/` | Sigma filters for tuning (see [docs/TUNING_GUIDE.md](docs/TUNING_GUIDE.md)) |
| `simulations/` | Atomic simulations and `run_sim.sh` |
| `exports/` | Kibana dashboards |

Of the 82 rule files, 13 are base rules: each exists for a correlation and has no output of its own (`custom.coresigma.status: base`). That leaves the 69 rules in the matrix. Rules carry no ESF event numbers; the plugin scopes them from the `logsource`.

## Requirements

- **macOS 13 or later** for `eslogger`. Older macOS releases list fewer eslogger events. At startup the ESF collector subscribes to the events the running release lists (`eslogger --list-events`) and names the ones it skips on stderr; rules on skipped events can't fire on that Mac. The collector has been run on macOS 26 and unit-tested against shorter listings. Converting rules doesn't depend on the macOS release.
- **Full Disk Access** for the app that runs the ESF collector (Terminal, iTerm2, or the Python interpreter of a LaunchDaemon), and root.
- **Python**: the collectors use only the standard library and run on the stock macOS `python3` (3.9). The conversion and deploy tooling in `requirements.txt` needs Python 3.10 to 3.14 (pySigma 1.5.1; 3.15 has no PyYAML wheel yet); `setup.sh` builds its venv with the newest of `python3.14` … `python3.10` on your `PATH`, else `python3` if it's in that range, and rebuilds a venv made with a Python outside it. The ClickHouse backend needs Python 3.13 or later and is installed separately: `pip install -r requirements-clickhouse.txt`.
- **Docker**, for the optional bench: Elasticsearch and Kibana 8.19.25, and Splunk, OpenSearch and ClickHouse with `./scripts/bench_up.sh splunk opensearch clickhouse`.

## Install

```bash
git clone https://github.com/Nebulock-Inc/macos-coresigma.git
cd macos-coresigma
./setup.sh                  # venv with requirements.txt, including the plugin from pipelines/
source venv/bin/activate
pytest -q
```

### The pipeline plugin on its own

The plugin is also released on its own, on PyPI, after this release:

```bash
pip install pySigma-pipeline-macos
```

Until that package is out, or if it isn't available to you, install the copy in this repository instead: `pip install -e pipelines/pysigma-pipeline-macos`. Both register the same four pipelines with sigma-cli.

## Targets

These are the targets the support matrix covers, with the pinned backends (`requirements.txt`; the ClickHouse backend in `requirements-clickhouse.txt`).

| Target | Backend and pipeline | How 2.0 measured it |
|---|---|---|
| Elastic EQL | pysigma-backend-elasticsearch 2.1.0, `macos_esf_ecs` + `macos_ul_ecs` | Live on the bench (Elasticsearch 8.19.25) with replayed test-host captures. Correlations: only `temporal_ordered`, as an EQL `sequence` (coreSigma's `EqlSequenceBackend`). |
| Elastic ES\|QL | same | Live. Plain strings match case-sensitively. Correlations except `temporal_ordered`, counted in fixed time windows. |
| OpenSearch | pysigma-backend-opensearch 2.0.3, same pipelines | Live (OpenSearch 2.19.1). No correlations. |
| Splunk | pysigma-backend-splunk 2.1.0, same pipelines | Live (Splunk 9.4). Correlations count in fixed time bins. |
| ClickHouse | pysigma-backend-clickhouse 1.1.1 (Python 3.13+, installed separately), same pipelines | Live (ClickHouse 25.8). Correlations group the whole search range; the matrix orders `temporal_ordered` with `windowFunnel`. |
| CrowdStrike Falcon (LogScale) | pysigma-backend-crowdstrike 3.0.0, `macos_falcon` | `process_creation` rules only. Read-only matches of the converted queries on Falcon's ProcessRollup2 telemetry from the test host: not Falcon alerts. |
| Microsoft Defender / Sentinel (KQL) | pysigma-backend-kusto 1.0.1, its Windows-schema `microsoft_xdr_pipeline` | Matrix: converts only. Spot-checked live on Defender for Endpoint on the test host; see [EDR spot checks](#edr-spot-checks). |
| Elastic Defend (EQL) | pysigma-backend-elasticsearch 2.1.0, `macos_esf_ecs` | Matrix: converts only. Spot-checked live on Elastic Defend 9.5.6 on the test host, and its file events differ from the plugin's scopes; see [EDR spot checks](#edr-spot-checks) and [Known limitations](#known-limitations). |
| Jamf Protect | none | Not verified; deferred to the next release. |

The matrix footnotes give the limits of each target. The main ones are listed under [Known limitations](#known-limitations).

### EDR spot checks

Elastic Defend 9.5.6 (detect mode) and Microsoft Defender for Endpoint (passive mode) ran on the test host while the attack-chain simulations ran again, followed by an idle hour each. These results aren't in the support matrix, whose Defend and Kusto columns stay convert-only.

- **Elastic Defend, with coreSigma's shipped EQL unchanged.** Process rules fire on Defend's data: the paste-to-stealer chain, `osascript`, `dscl`, `ditto`, HTTP tools, the SSH login and suspicious process execution. Rules for new files stay silent, because Defend reports a new file only as a modification. 26 rules are rejected: all 18 unified log rules, which have no Defend data, and 8 that need fields only ESF has (XPC service, signal, background task, memory protection, target user, kext).
- **Defender for Endpoint, with `microsoft_xdr_pipeline`.** Process rules fire (HTTP tools, the SSH login, suspicious process execution). File-path rules stay silent: on macOS, Defender recorded only script and binary creates, so plist and settings writes never reach its tables.
- **Noise:** no rule was noisy on either product over its idle hours (Defend 1 h, Defender 1.9 h), which are far shorter than the matrix's 13.3.

## Bench and collection

```bash
# Elasticsearch and Kibana in Docker: writes .env (bench password, random Kibana keys), waits until healthy,
# and creates the index templates
./scripts/bench_up.sh elastic

# Credentials for the scripts and collectors: the bench password from .env
# (or store them in the macOS Keychain with ./scripts/setup_credentials.sh)
export ES_USER=elastic ES_PASSWORD="$(grep '^ELASTIC_PASSWORD=' .env | cut -d= -f2-)"

# Detection rules into Kibana (created disabled; --enable enables them)
python3 scripts/deploy_sigma_rules.py

# Dashboards
python3 scripts/create_lens_dashboards_ndjson.py
```

`deploy_sigma_rules.py` creates all 69 rules in Kibana: the 62 single-event rules and the two `temporal_ordered` correlations (as EQL sequences) as EQL rules, and the other five correlations as ES|QL rules. `--target splunk` writes the 69 searches to `splunk/coresigma_app` instead (see [docs/SPLUNK_SETUP.md](docs/SPLUNK_SETUP.md)). Kibana rules look back 6 minutes every 5 minutes (a correlation: its timespan more), so they alert on new events, not on replayed history.

### ESF collector

```bash
# sudo drops environment variables: keep the credentials with --preserve-env
sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY /usr/bin/python3 collectors/esf_collector.py --output elasticsearch

# Background: restarts eslogger whenever it exits (log in /var/log/coresigma-esf.log)
sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY /usr/bin/python3 collectors/esf_collector.py --output elasticsearch --daemon
```

Under sudo the Keychain lookup runs as root, not as you, so pass the credentials through the environment as above. `--no-filtering` turns off the ESF filter described in [docs/FILTERING_CONFIGURATION.md](docs/FILTERING_CONFIGURATION.md).

### UL collector

```bash
python3 collectors/ul_collector.py --output elasticsearch

# Background: the default pid and log paths are in /var/run and /var/log, which only root can write
python3 collectors/ul_collector.py --output elasticsearch --daemon \
  --pid-file "$HOME/Library/Logs/coresigma-ul.pid" --log-file "$HOME/Library/Logs/coresigma-ul.log"
```

Both collectors also take `--output splunk` (HEC; the token in `SPLUNK_HEC_TOKEN`) and `--output file --output-file PATH`. Documents the collectors can't deliver are kept in a local spool; see [Spool](docs/INSTALLATION.md#spool).

### Dashboards

`create_lens_dashboards_ndjson.py` generates two dashboards on the `macos-telemetry-*` data view, titled "(generated)". Alternatively, import `exports/all_dashboards_latest.ndjson`, which has three: the ESF telemetry overview, the Unified Logging overview, and Sigma rule triggers (read from `.alerts-security.alerts-default`).

```bash
curl -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" -u "elastic:$ES_PASSWORD" \
  -F file=@exports/all_dashboards_latest.ndjson
```

### Authentication

Where each tool looks for Elasticsearch and Kibana credentials, first match wins:

| Tools | Order |
|---|---|
| The collectors, `check_field_mappings.py` | `ES_API_KEY`; the macOS Keychain; `ES_USER` / `ES_PASSWORD`; `~/.coresigma/config.yml` |
| `deploy_sigma_rules.py`, `create_lens_dashboards_ndjson.py` (Kibana, user and password only) | the Keychain; `ES_USER` / `ES_PASSWORD`; `~/.coresigma/config.yml` |
| The shell scripts (`check_collection_status.sh`, `create_kibana_data_view.sh`, `start_collectors.sh`, `wipe_elasticsearch.sh`, `setup_elasticsearch_templates.sh`) | `ES_API_KEY`; `ES_USER` / `ES_PASSWORD`; the Keychain |
| `export_current_dashboards.py` | `ES_USER` / `ES_PASSWORD`; the Keychain; `~/.coresigma/config.yml` |
| `bench_up.sh` | `ELASTIC_PASSWORD` in `.env` |
| `rule_matrix.py`, `sample_private_baseline.py` | `ELASTIC_PASSWORD` from the environment, else `.env` (the bench) |

`./scripts/setup_credentials.sh` stores the Keychain entry (service `coreSigma-Elasticsearch`; `--api-key` creates an API key). Because the collectors and the Kibana tools try the Keychain before `ES_USER` / `ES_PASSWORD`, a stale Keychain entry wins over the environment: update or delete it (see [Troubleshooting](docs/TROUBLESHOOTING.md#8-authentication-error-401)). The config file is read only where PyYAML is installed, as in the venv.

## Converting rules

```bash
# One ESF rule to EQL
sigma convert -t eql -p macos_esf_ecs rules/esf/macos_dscl_authonly_password_check.yml

# Unified Log rules need macos_ul_ecs; stack both pipelines to convert ESF and UL rules together
sigma convert -t splunk -p macos_esf_ecs -p macos_ul_ecs rules/ul/

# Falcon LogScale: process_creation rules only
sigma convert -t log_scale -p macos_falcon rules/esf/process_execution_suspicious.yml
```

Convert a correlation together with its base rules, as the deploy and matrix scripts do, and convert one correlation (with its base rules) per `sigma convert` run on the pinned sigma-cli. sigma-cli resolves a correlation's `rules:` only within one input path, so put the correlation and its base rules in one directory and pass that directory. A base rule converted on its own produces a query, but it is meant to run inside its correlation. [docs/SIGMA_TOOLS_USAGE.md](docs/SIGMA_TOOLS_USAGE.md) has more.

> Don't install `sigmatools`; it conflicts with `sigma-cli`.

## Simulations

`simulations/atomics/` holds 36 Atomic Red Team-style simulations. Six are attack chains: paste-to-stealer, npm postinstall persistence, Gatekeeper quarantine strip and ad-hoc signing, an SSH key login to localhost, a writable-and-executable memory request, and a quarantine strip, ad-hoc signing and keychain partition-list change in a row (the Gatekeeper evasion correlation). Twenty-seven are single benign steps, one per rule: zip/tar archiving, `openssl enc`, a `dig` lookup, `nc` to localhost, an `scp` copy, a command under `expect`, an `aws s3 cp --dryrun`, a partition list on a throwaway keychain, booting out a dummy launch job, an SMB mount attempt, an image written into a dummy app bundle's code directory, XPC from a binary in `/tmp` and to a dummy `.test.` service, SIGKILL and SIGTERM of stand-in processes named like a security tool and BackgroundTaskManagementAgent, fifteen dummy processes terminated from one shell, credential-named dummy files read by a `node` stand-in, an admin authorization right requested without interaction, `spctl` assessing an unsigned binary, a throwaway local account created and deleted, a `sudo` refused for a throwaway non-sudoer, the firewall switched on and back off, a `csrutil disable` refused outside recoveryOS, a copy of `echo` with a broken signature run, a dummy file written and deleted in `/private/etc`, `perl` sending SIGTERM to a dummy process, and a failed lookup and wrong-password unlock on a throwaway keychain. Three are hands-on windows: a person connects with Screen Sharing, clicks Open Anyway for a quarantined test app, or runs a one-line script in Script Editor, and each window counts only for its one rule (the window's `rules` list in `reports/sim_windows.json`). Hands-on windows run longer than the 120 s the run script waits by default: set `SIM_TIMEOUT` (seconds, at most 540). Each one cleans up after itself. `simulations/run_sim.sh <atomic-name> <test-index>` runs one on an EC2 Mac over SSM and records its time window in `reports/sim_windows.json`, from the host's clock and ending before the cleanup. Copy `simulations/sim.env.example` to `simulations/sim.env` (gitignored) and fill in the instance, the AWS account the script checks before sending anything, and the profile. `DRY_RUN=true` prints what it would run instead of running it.

Run simulations only on a dedicated test host. Never run them on a production, managed or MDR-monitored Mac: they fetch and run payloads, prompt for passwords, and write persistence.

## Known limitations

Each of these is a footnote in the support matrix, where it applies to a rule.

- **Case**: ES|QL matches plain strings case-sensitively. OpenSearch's plain keyword fields (`unified_log.subsystem`, signing IDs) match case-sensitively; XProtect logs under both `com.apple.xprotect` and `com.apple.XProtect…`, so the uppercase lines are missed there.
- **`$` in `|re`** is a literal character in Lucene, EQL and ES|QL regular expressions, so a pattern that uses it as an anchor can't match on those targets.
- **Correlations**: Elastic EQL enforces `temporal_ordered` as a `sequence`, and the matrix's ClickHouse query orders it with `windowFunnel` (plain pysigma-backend-clickhouse output doesn't check order). Splunk runs the two ordered rules as their declared unordered `temporal` fallback, and ES|QL can't convert them. ClickHouse groups the other correlations over the whole search range, not per timespan. Splunk and ES|QL count in fixed windows of the timespan, so a chain that crosses a window boundary is missed. Kibana has no source event to deduplicate an ES|QL correlation's alert on, so each ES|QL rule alerts only on the windows that closed 1 to 6 minutes before its run: one alert per window, up to the timespan plus 6 minutes late. OpenSearch has no correlations.
- **Renames**: `file_event` rules also take the destination of a rename, but the ESF collector keeps only some renames (security paths, hidden destinations); renames into the paths it keeps only on create are dropped. Rename coverage is measured only that far.
- **Unified Log collection**: `log stream` never delivers `/sbin/launchd` lines, and the collector has no category for `com.apple.xpc` or `com.apple.network` (DNS), so those rules see only lines that other categories select. On hosts whose sudoers has `Defaults !log_allowed`, sudo logs only denials. Info-level lines arrive only with `--level info`, which the collector uses; a capture made without it reads those rules as silent.
- **Elastic Defend**: the `gatekeeper_override` and `background_task` categories match eslogger's event names (`gatekeeper_user_override`, `btm_launch_item_add` / `btm_launch_item_remove`), but Defend writes `gatekeeper_override` and `launch_daemon`, so rules on them won't match Defend data as-is. On macOS, Defend reports a new file only as a `modification` (observed on 9.5.6), so the `file_event` scope (a creation or a rename) misses file creates in Defend data. No `open` events were seen there, so `file_access` rules may not match Defend data either. The plugin emits pid values as strings, so Defend's long-typed pids aren't supported.
- **Setuid/setgid**: the privilege-escalation rule matches on the caller's effective uid. It fires on every live store, but on sshd's privilege restoration, not on sudo: during the SSH login simulation, sshd-auth and sshd-session call setuid/setgid(0) to return to root after dropping privileges, and their effective uid isn't 0 yet. sudo's setuid events carry euid 0, which the rule excludes. The next release will decide between real and effective uid.
- **Older macOS**: older releases list fewer eslogger events. The ESF collector skips the ones the running release doesn't list (named at startup), so rules on them stay silent there. It has been run on macOS 26 and unit-tested against shorter listings.
- **Backend pin**: `pysigma-backend-elasticsearch` is pinned to 2.1.0. On 2.1.0 a `|re` that matches a backslash (`\\`) converts wrong; no shipped rule has one (an escape such as `\.` is fine). 2.1.1 doubles regex backslashes, which `deploy_sigma_rules.py` handles too.

## Documentation

- [Installation](docs/INSTALLATION.md) and [Quick start](docs/QUICKSTART.md)
- [Support matrix](docs/SUPPORT_MATRIX.md)
- [Converting rules](docs/SIGMA_TOOLS_USAGE.md) and [field names](docs/FIELD_NAME_ORIGINS.md)
- [Tuning](docs/TUNING_GUIDE.md), [ESF filtering](docs/FILTERING_CONFIGURATION.md), [Unified Log collection](docs/UL_TELEMETRY_TUNING.md)
- [Kibana](docs/KIBANA_SETUP.md), [Kibana alerts](docs/KIBANA_ALERTS_SETUP.md), [Splunk](docs/SPLUNK_SETUP.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Changelog](CHANGELOG.md)

## Contributing

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License; see [LICENSE](LICENSE).

## Acknowledgments

- [SigmaHQ](https://github.com/SigmaHQ): the Sigma specification and pySigma
- [Elastic](https://www.elastic.co/): the Elastic Common Schema
- [Apple](https://developer.apple.com/documentation/endpointsecurity): Endpoint Security
- The contributors named in the [changelog](CHANGELOG.md)

## Contact

- **Organization**: [Nebulock Inc.](https://github.com/Nebulock-Inc)
- **Issues**: [GitHub Issues](https://github.com/Nebulock-Inc/macos-coresigma/issues)

## Author

Created by Eric Brown © 2025
