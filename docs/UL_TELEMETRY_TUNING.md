# Unified Log Collection

## What the UL collector collects

`collectors/ul_collector.py` runs:

```bash
log stream --style ndjson --level info --predicate '<every UL category, ORed>'
```

On startup it also reads the last 5 minutes with `log show` (`--no-recent` skips that). There is no message filter in the collector: every line the predicate delivers is sent.

The predicate comes from `UL_CATEGORIES` in `pipelines/pysigma-pipeline-macos/sigma/pipelines/macos/taxonomy.py`, the same table `macos_ul_ecs` turns a rule's `category` into. The collector's comparisons are case-insensitive (`[c]`).

| Category | Lines selected |
|---|---|
| `tcc` | subsystem starts with `com.apple.TCC` |
| `authorization` | subsystem `com.apple.Authorization` |
| `sudo` | process `/usr/bin/sudo` (sudo logs with an empty subsystem) |
| `firewall` | subsystem starts with `com.apple.ALF` |
| `gatekeeper` | subsystem starts with `com.apple.syspolicy`, or process `/usr/libexec/syspolicyd` |
| `launchd` | process `/sbin/launchd` |
| `xprotect` | subsystem starts with `com.apple.xprotect` (both casings: `com.apple.XProtectFramework...` too) |
| `securityd` | subsystem `com.apple.securityd` (Security.framework logging, from any process) |
| `opendirectory` | subsystem starts with `com.apple.opendirectoryd` |
| `mdm` | process path ends with `/mdmclient` |

A UL rule without a `category` (`product: macos`, `service: unifiedlog` only) isn't scoped to any of these; it runs on everything the collector sent.

## What it doesn't collect

These limits are in the [support matrix](SUPPORT_MATRIX.md) footnotes for the rules they affect.

- **launchd**: `log stream` never delivers `/sbin/launchd`'s lines (`log show` does). Rules on the `launchd` category can't fire on live collection.
- **XPC and DNS**: there is no category for `com.apple.xpc` or `com.apple.network`, so macOS XPC Service Abuse and the DNS resolution failure rules see only lines that another category happens to select.
- **sudo on some hosts**: where sudoers sets `Defaults !log_allowed`, sudo logs only denials, so rules on successful sudo runs see nothing.
- **Info level**: some lines are logged at Info level and arrive only with `--level info`, which the collector uses. A capture made without it reads those rules as silent.
- **Case on some targets**: the collector selects both XProtect casings, but ES|QL and OpenSearch match `unified_log.subsystem` case-sensitively, so a rule's `com.apple.xprotect` prefix misses the uppercase lines there.

## Adding a source

To collect another subsystem or process, add a category to `UL_CATEGORIES` in `taxonomy.py`, for example:

```python
"managedclient": UlCategory(raw=[("subsystem", "=", "com.apple.ManagedClient")]),
```

The collector's predicate and the pipelines' category scope both follow. Rules can then use `category: managedclient`. Volume grows with every category, and `log stream` doesn't deliver every process's lines (launchd above), so check that lines arrive (`log stream --style ndjson --predicate 'subsystem == "com.apple.ManagedClient"'`) before writing rules on them.

## Noise

Tune noisy UL rules with Sigma filters ([TUNING_GUIDE.md](TUNING_GUIDE.md)), not by dropping lines in the collector, so other rules keep their data.
