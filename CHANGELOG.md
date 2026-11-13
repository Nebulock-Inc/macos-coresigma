# Changelog

## 2.0 - 2026-11-13

coreSigma 2.0 rebuilds the pipeline around eslogger's event names, ships the pySigma plugin, and measures each of the 69 rules against replayed captures from a live test host.

<!-- MATRIX-COUNT: the verified count, from docs/SUPPORT_MATRIX.md. Update it here and in README.md. -->
**40 of 69 rules are verified live.** The others are marked not-verified, each with its reason, in [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) and in the rule's `custom.coresigma.status`.

### Thanks

- **Doug Metz** (#2–#4): the ATT&CK v19 remap of the Defense Evasion rules to Stealth and Defense Impairment, and those tactics in the deploy script.
- **Sydney Marrone (THOR Collective)** (#5): the osascript hidden password prompt rule (AMOS), shipped as `rules/esf/macos_osascript_hidden_password_prompt.yml`.

### Upgrading from 1.x

- **Rule IDs.** 20 rules had placeholder or colliding IDs (two pairs shared one) and now have real UUIDs; the two rules that became correlations have new IDs too. Anything keyed on rule IDs needs the new ones:

  | Rule | 1.x ID | 2.0 ID |
  |---|---|---|
  | `rules/esf/connection_to_suspicious_xpc_service.yml` | `d2e3f4a5-b6c7-4d8e-9f0a-1b2c3d4e5f6a` | `76268965-b31d-4aee-8098-12b72f696481` |
  | `rules/esf/file_creation_persistence.yml` | `b2c3d4e5-f6a7-8901-bcde-f23456789012` | `18d6dc1e-8440-4894-9f48-988bf438b694` |
  | `rules/esf/macos_data_destruction_tools.yml` | `e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b` | `d17e46cc-8609-4896-95f5-5721382d5ffe` |
  | `rules/esf/macos_encryption_tool_usage.yml` | `f2a3b4c5-d6e7-4f8a-9b0c-1d2e3f4a5b6c` | `e7f60a2b-0f79-40d6-b951-d18c4b290906` |
  | `rules/esf/macos_file_transfer_tool_execution.yml` | `b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e` | `aad51ad2-735f-4dd2-b31b-447eb5987b0a` |
  | `rules/esf/macos_gatekeeper_user_override.yml` | `a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d` | `61a63a62-a6c7-432c-af13-01a28270790e` |
  | `rules/esf/macos_ssh_connection_detection.yml` | `a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d` | `336e30d8-4ced-44db-8c78-abb0b1ad13bb` |
  | `rules/esf/process_execution_suspicious.yml` | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` | `25a227ce-e25a-4954-9063-84b6837a5a05` |
  | `rules/ul/keychain_access_suspicious.yml` | `d4e5f6a7-b8c9-4012-def0-123456789012` | `88fbd60c-cf76-4783-88b6-d541268bc269` |
  | `rules/ul/macos_uls_gatekeeper_block_spctl.yml` | `2f1b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d` | `396eaead-b849-4099-b19c-2cffb07fcc73` |
  | `rules/ul/macos_uls_quarantine_or_xprotect_detection.yml` | `0a1b2c3d-4e5f-4789-abcd-ef0123456789` | `4d7fca29-035f-426a-b810-4346f2a30d95` |
  | `rules/ul/macos_uls_tcc_access_denied.yml` | `5b6d7e8f-1a2b-4c3d-9e0f-1a2b3c4d5e6f` | `86ad3b68-a4dd-40c5-9b6a-0c4e48a24878` |
  | `rules/ul/mdm_profile_manipulation.yml` | `c3d4e5f6-a7b8-4901-cdef-012345678901` | `033bca8a-e5a9-4f5f-b015-31cb2cabce76` |
  | `rules/ul/persistence_launchd.yml` | `b2c3d4e5-f6a7-4890-bcde-f01234567890` | `dab925a3-8900-441b-bb61-8601c2e164c9` |
  | `rules/ul/sip_modification_attempt.yml` | `a7b8c9d0-e1f2-4345-0123-456789012345` | `efc5235a-2413-4c33-96dd-3c85d810cc07` |
  | `rules/ul/sudo_execution.yml` | `d4e5f6a7-b8c9-0123-def4-456789012345` | `2f4dc432-e8f0-4c61-9f01-05195a9fd73a` |
  | `rules/ul/sudo_failed_attempts.yml` | `f6a7b8c9-d0e1-4234-f012-345678901234` | `dbc5f4c6-c281-4662-8eb2-9addcecaa40d` |
  | `rules/ul/tcc_bypass_attempt.yml` | `a1b2c3d4-e5f6-4789-abcd-ef0123456789` | `2d942254-d897-4724-9833-1d6570711ecc` |
  | `rules/ul/tcc_unusual_access.yml` | `c3d4e5f6-a7b8-9012-cdef-345678901234` | `c5bc993c-4a74-4a2d-8b33-156e53705579` |
  | `rules/ul/xpc_service_abuse.yml` | `e5f6a7b8-c9d0-4123-ef01-234567890123` | `80dd24d2-717b-4f4d-a127-a587eed69627` |
  | `rules/correlation/mass_process_termination.yml` (was `rules/esf/`) | `8c803e5c-91b8-42f0-8557-f93308c263b9` | `b7cb963c-d75b-4c2b-8f07-fdca09e712e1` |
  | `rules/correlation/dns_resolution_failure_spike.yml` (was `rules/ul/`) | `b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e` | `9c0d5fc2-6cf8-4868-bcd6-fade4f78fc9e` |

- **Mass Process Termination's old ID moved.** `8c803e5c-91b8-42f0-8557-f93308c263b9` now belongs to the low-level base rule `rules/esf/process_termination_signal.yml` (one SIGKILL or SIGTERM), not to the correlation. Something keyed on the old ID would now follow single signals.
- **Correlations moved to `rules/correlation/`.** Mass Process Termination and DNS Resolution Failure Spike had a `timeframe` inside `detection`, which Sigma ignores, so they alerted on every single event. Each is now a Sigma `event_count` correlation over a base rule (`process_termination_signal.yml`, `rules/ul/dns_resolution_failure.yml`).
- **Stale Kibana rules.** Kibana rule IDs come from file names. After deploying 2.0, delete the rules of the files that were removed: `coresigma-macos_esf_suspicious_curl_download`, `coresigma-kernel_extension_loaded_from_temporary_directory`, `coresigma-unsigned_kernel_extension_load_attempt` and `coresigma-macos_code_signature_invalidation`.
- **The two rules that became correlations keep their Kibana rule IDs.** `coresigma-mass_process_termination` and `coresigma-ul-dns_resolution_failure_spike` are now the ES|QL correlation rules; don't delete them. A redeploy replaces the 1.x rule in place: the script exports it, deletes it and creates the new rule (re-importing the export if Kibana rejects the new one), and the new rule keeps the old one's enabled state. Kibana gives it a new internal id, and its exceptions and actions don't carry over.
- **Fields.** The collectors write flat Elastic Defend-shaped ECS. `esf.*` (including `esf.event_type`), `process.name`, `process.args`, `process.user.*`, `process.group.*`, `data_stream.*` and `event.dataset` are gone; the user is `user.id` / `user.name`. Saved searches and dashboards on those fields need the new names (see [docs/FIELD_NAME_ORIGINS.md](docs/FIELD_NAME_ORIGINS.md)). The index templates changed: re-run `scripts/setup_elasticsearch_templates.sh`; existing daily indices keep their old mappings.
- **Your own rules.** A macOS ESF rule now needs a `category`, and fields outside the taxonomy (such as `esf.event_type` or `event.action`) fail conversion instead of converting to a query that never matches. `service: endpointsecurity` is optional.
- **Deployment.** `deploy_sigma_rules.py` now deploys all of `rules/` (1.x deployed `rules/esf` only), correlations included, and `--enable` works.

### Rules

- **Event names, not numbers.** No rule carries an ESF event number. The plugin scopes each rule from its `logsource` (`product: macos`, a `category`, plus `service: unifiedlog` for UL rules), and `event.action` is eslogger's event name. Many of the 1.x numbers were wrong, in the rules and in the collector's event map.
- **New rules** (2026 macOS stealer and supply-chain tradecraft):
  - Apple-Named LaunchAgent Created in a User Library
  - Background Task Management Agent Killed
  - Launch Agent or Daemon Registered from a User or Temporary Location
  - Ditto Zips Data in a Temporary Directory
  - Local Password Checked with dscl -authonly
  - macOS ESF Osascript Hidden Password Prompt (#5, Sydney Marrone (THOR Collective))
  - Node or Bun Creates AI-Agent or IDE Task Configuration
  - Script Editor Spawns a Shell or Downloader
  - Keychain Partition List Changed with security
  - Executable File Staged in Application Support Frameworks Directory
  - Media File Created in Code or Framework Directory
- **New correlations**: Paste-to-Stealer Chain, Package Manager Payload to Persistence, Gatekeeper Evasion Staging, Credential File Fan-Out by Node or Bun, and Fake Password Prompt Then Keychain Activity in the Same Process. The last joins an ESF exec with a Unified Log line from the same process; its UL leg is logged by every osascript run, so it shows the cross-source join working rather than adding selectivity.
- **Base rules.** 13 rules exist only for a correlation (`custom.coresigma.status: base`, with `base_of`) and have no output of their own.
- **`process_creation`** takes `exec` events only.
- **`file_event`** takes file creates and the destination of renames (`TargetFilename` is the new path).
- **`file_attribute_change`** is scoped on its event names: `setextattr`, `deleteextattr`, `setmode`, `setowner`, `setflags`.
- **`user_account_change`** covers 13 Open Directory events: user create, delete, password change, disable and enable; attribute value add and remove and attribute set; group create, delete, add, remove and set. macOS User Account Manipulation therefore also fires on disabling and enabling a user and on group changes. The widened scope isn't measured for noise: the test host's captures didn't subscribe to the newer events.
- **Narrowed UL categories.** `xprotect` is the `com.apple.xprotect` subsystems (1.x matched XProtect wording in any collected line), and `mdm` is lines from `mdmclient` (1.x: the `com.apple.ManagedClient` subsystem).
- **Fixes** to rule logic: `/private/etc` and `/private/var` paths, `~/Library/LaunchAgents`, `bootout` in service disruption, `put` as a word in cloud storage, `dd of=/dev/null` excluded, `-R` matched by a regex in data destruction (case-sensitive except on EQL and OpenSearch, which match `|re` case-insensitively), the setgid branch on `TargetGroupId`, the rename-to-dotfile rule anchored on the file name, sshd `-t`/`-T` configuration tests excluded, and dscl `authonly` with or without the dash. Two Unified Log rules match what macOS 26.7 logs: Firewall Disabled also matches `turning firewall off`, and securityd CodeSignature Failure also matches `-67061` (errSecCSSignatureFailed). The duplicate IDs and the dangling `timeframe` blocks are gone.
- **ATT&CK tags** are hyphenated and pass pySigma's bundled ATT&CK data (TA0005 Stealth, TA0112 Defense Impairment); `attack.defense_evasion` is remapped per technique.
- **Removed**:
  - `rules/esf/macos_esf_suspicious_curl_download.yml` (`9d3885a1-0b3e-4e07-bd1d-0897b6f75819`): duplicate of `macos_http_tools_with_protocol_indicators.yml`, which converts to the same query.
  - `rules/esf/kernel_extension_loaded_from_temporary_directory.yml` (`a65d0810-117a-487e-9ea3-50d754277d6e`): the ESF kextload event carries only the kext identifier, never its path, so the rule can't fire on any target.
  - `rules/esf/unsigned_kernel_extension_load_attempt.yml` (`7e7a1a47-45dd-4f97-8205-1d6aea67f682`): kextload carries no signing data for the kext; the rule's `TeamID` check tested the loading process (kernelmanagerd), not the kext.
  - `rules/esf/macos_code_signature_invalidation.yml` (`b0115e23-4ad1-4f98-82b3-9815cb826906`): `cs_invalidated` isn't in any `product: macos` category the pipelines support. The example Jamf filter now targets the encryption tool rule.

### Plugin

- **pySigma-pipeline-macos** is vendored in `pipelines/pysigma-pipeline-macos` (installed by `requirements.txt`), and released on its own on PyPI as `pySigma-pipeline-macos` after this release. Pipelines: `macos_esf_ecs`, `macos_ul_ecs`, `macos_ul_raw`, `macos_falcon` (CrowdStrike LogScale, `process_creation` only).
- One taxonomy (`taxonomy.py`) defines the categories and fields; the collectors and the pipelines both read it, so collected documents and converted rules agree.
- Unknown categories, services and fields fail conversion with a clear error instead of producing a query that never matches.
- Fields for the seven macOS ESF categories that had none of their own (`authentication`, `sudo`, `screen_sharing`, `configuration_profile`, `user_account_change`, `xprotect`, `gatekeeper_override`): `SourceUser`, `TargetUser`, `TargetGroup`, `Success`, `FailureReason`, `AuthenticationType`, `SourceAddress`, `ViewerAppleID`, `ExistingSession`, `ProfileIdentifier`, `ProfileDisplayName`, `ProfileInstallSource`, `ProfileScope`, `OdAttributeName`, `OdAttributeValue`, `MalwareIdentifier`, `MalwareIncidentIdentifier`, `RemediationAction`, `FileSha256`, `FileSigningID` and `FileTeamID`. `TargetUserId`, `TargetImage`, `InstigatorImage` and `TargetFilename` now also cover these events, and `TargetFilename` covers `setowner` and `setflags`. `Success` is a boolean in rules and ECS `event.outcome` (`success` or `failure`) in the documents. The rest come from captured events. These come from Apple's Endpoint Security headers instead, because no capture has the events yet:
  - `MalwareIdentifier`, `MalwareIncidentIdentifier`, `RemediationAction`, and `TargetFilename` and `Success` on `xp_malware_detected` and `xp_malware_remediated`;
  - `FileSha256`, `FileSigningID`, `FileTeamID`, and `TargetFilename` on `gatekeeper_user_override`;
  - the `Profile*` fields and `InstigatorImage` on `profile_remove`;
  - `TargetUser`, `TargetGroup`, `OdAttributeName`, `OdAttributeValue`, `Success` and `InstigatorImage` on the OD events `od_create_group`, `od_delete_group`, `od_group_remove`, `od_group_set`, `od_disable_user`, `od_enable_user`, `od_attribute_value_remove` and `od_attribute_set`.

  The `profile_remove` and OD paths use the member names of the captured events in the same family.

### Collectors

- The ESF collector asks `eslogger --list-events` at startup and subscribes only to the events the running macOS release lists, naming the ones it skips. Older releases list fewer events; the collector has been run on macOS 26 and unit-tested against shorter listings.
- The ESF collector writes flat Elastic Defend-shaped ECS documents (`process.executable`, `process.parent.executable`, `file.path`, `user.name`, ...), with `event.action` set to eslogger's event name. Its eslogger subscription comes from the taxonomy. It no longer copies the raw event, so exec environments aren't indexed.
- The UL collector streams `log stream --style ndjson --level info` with a predicate built from the taxonomy's UL categories.
- New outputs: Elasticsearch `_bulk` and Splunk HEC, with retries and a local spool for documents that can't be delivered (see [docs/INSTALLATION.md](docs/INSTALLATION.md#spool)).

### Deployment, bench and matrix

- `deploy_sigma_rules.py` deploys the 7 correlations to Kibana: the two `temporal_ordered` ones as EQL `sequence` rules, which enforce the order, and the other five as ES|QL rules that alert once per fixed window, up to the timespan plus 6 minutes after it opens.
- `deploy_sigma_rules.py --target splunk` generates the Splunk app `splunk/coresigma_app`: one saved search per rule, disabled (Splunk Free has no alerting or scheduling), and an overview dashboard.
- Dependencies are pinned in `requirements.txt` (Python 3.10 to 3.14). The ClickHouse backend, which needs Python 3.13+, is in `requirements-clickhouse.txt`, installed separately; `scripts/rule_matrix.py` needs it for its ClickHouse column.
- `scripts/bench_up.sh` runs the Docker bench: Elasticsearch and Kibana 8.19.25, plus Splunk 9.4, OpenSearch 2.19.1 and ClickHouse 25.8 on request. Ports bind to 127.0.0.1, and `.env` gets random Kibana encryption keys.
- `scripts/rule_matrix.py` converts every rule for every target, runs the queries on the bench stores against replayed test-host captures, and renders [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md). Noise counts both 13.3 idle hours on the test host and a private laptop sample (ESF and unified log rules, each at the higher of its EQL and Sigma-semantics count, from `scripts/sample_private_baseline.py`; correlations aren't counted there); no laptop data is published, only each rule's noisy or quiet outcome. `scripts/replay_capture.py` replays captures through the collectors' own filters.
- `simulations/` holds 36 atomic simulations and `run_sim.sh`, for dedicated test hosts only: six attack chains (paste-to-stealer, npm postinstall persistence, Gatekeeper quarantine strip and ad-hoc signing, SSH key login, writable-and-executable memory, and the full Gatekeeper evasion staging sequence), twenty-seven single benign steps, one per rule, and three hands-on windows for rules only a person's action can trigger (listed in the README's Simulations section). A hands-on window counts only for the rules in its `rules` list, on every store and on Falcon. A window runs on the host's clock and ends before the simulation's cleanup.
- Spot checks on Elastic Defend 9.5.6 and Microsoft Defender for Endpoint, on the test host: process rules fire on both, new-file and file-path rules are silent, and 26 rules can't run on Defend data. See the README's EDR spot checks; the matrix's Defend and Kusto columns stay convert-only.
- The Kibana dashboards and `exports/all_dashboards_latest.ndjson` use the collectors' field names; the export no longer carries Kibana-managed objects or duplicate data views.
- `scripts/generate_rule_trigger_events.py` is removed; the simulations replace it.

### Known issues

- `pysigma-backend-elasticsearch` is pinned to 2.1.0. On 2.1.0 a `|re` that matches a backslash (`\\`) converts wrong; no shipped rule has one (an escape such as `\.` is fine). 2.1.1 doubles regex backslashes, which `deploy_sigma_rules.py` handles too.
- The coverage limits in the README's Known limitations section, and per rule in the support matrix footnotes.
