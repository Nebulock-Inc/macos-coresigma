# ESF Event Filtering

The ESF collector subscribes eslogger to the events the taxonomy's categories use, plus `fork` and `exit`, that this macOS release's eslogger lists; it names the ones it skips at startup. Most of them are sent as they come. A few high-volume events are filtered in `ESFCollector.should_keep_event` (`collectors/esf_collector.py`). `scripts/replay_capture.py` applies the same filter, so the support matrix measured rules on what the collector keeps.

## What is filtered

| Event | Kept when |
|---|---|
| `mprotect` | The new protection is both writable and executable (W+X). |
| `open` | The path is a security path (below). |
| `create` | The path is a security path, starts with `/Library/Caches/com.apple.`, or contains a create-only path (below). |
| `rename` | The source or the destination is a security path, or the destination's file name starts with `.` (hidden files). A rename whose paths can't be read is kept unless the process is `log`, `tr`, `sed`, `jq` or `wc`. |
| `setextattr` | The attribute name contains `quarantine`, or the path is a security path. |
| `fork` | The forking process's path contains `bash`, `sh`, `zsh`, `python`, `perl`, `ruby`, `node`, `curl`, `wget`, `nc`, `ssh`, `scp`, `sudo`, `su` or `launchd`; otherwise a random 10% of forks. |
| everything else | Always: `exec`, `exit`, `signal`, `unlink`, `kextload`, `tcc_modify`, the `btm_*`, `od_*`, `profile_*`, `setuid`-family, `sudo`/`su`, XProtect and authentication events, and the rest. |

**Security paths** (`SECURITY_PATHS`): a path is one when it contains an entry (`~` is read as `/Users`, and `*` is dropped):

- launch items and startup: `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `/System/Library/LaunchAgents`, `/System/Library/LaunchDaemons`, `/Library/StartupItems`, `/etc/periodic`
- kernel extensions: `/Library/Extensions`, `/System/Library/Extensions`
- system configuration: `/private/etc`, `/etc/sudoers`, `/etc/pam.d`, `/etc/ssh`, `/var/db/auth.db`, `/var/db/sudo`
- TCC databases: `/Library/Application Support/com.apple.TCC` (system and per-user)
- login items, managed preferences and profiles: `com.apple.loginitems.plist`, `/Library/Managed Preferences`, `/var/db/ConfigurationProfiles`
- firewall and security preferences: `/Library/Preferences/com.apple.alf.plist`, `/Library/Preferences/com.apple.security`
- credential files: `/.aws/`, `/.ssh/`

**Create-only paths** (`CREATE_PATHS`): `/Library/Application Support/`, `.app/Contents/`, `/.claude/`, `/.vscode/`. Creates there are kept for the staging, media-in-code and agent-configuration rules; opens and renames there are not.

## What this means for rules

- **Renames.** `file_event` rules also take the destination of a rename, but only renames the filter keeps reach the stores: renames into security paths and to hidden names. Renames into the create-only paths and into `/Library/Caches/com.apple.` are dropped, so that half of those rules' scope isn't covered by collected data. The support matrix notes it on each affected rule.
- **Forks** are sampled, so process trees built from `fork` events have gaps. `exec` events are all kept, and each carries its parent's executable.
- **Opens** outside the security paths are dropped, so a `file_access` rule on another path sees nothing.

The filter's volume reduction hasn't been measured on the current collector; check it on your own hosts (below).

## Configuration

### Disable filtering

```bash
sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY python3 collectors/esf_collector.py --output elasticsearch --no-filtering
```

This keeps every subscribed event; expect far more `mprotect`, `open`, `rename`, `create` and `fork` volume.

### Customize the paths

Edit `SECURITY_PATHS` or `CREATE_PATHS` in `collectors/esf_collector.py`, then restart the collector:

```python
SECURITY_PATHS = {
    "/Library/LaunchAgents", "/Library/LaunchDaemons",
    # ...
    "/Library/MyCompany/Agents",  # your addition
}
```

### Adjust fork sampling

The rate is the `0.1` in the `fork` branch of `should_keep_event`:

```python
should_keep = self._random.random() < 0.1  # change 0.1 to the rate you want (0.0-1.0)
```

## Verification

Count documents per event:

```bash
curl -s -u "elastic:$ES_PASSWORD" "http://localhost:9200/macos-telemetry-esf-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d '{"aggs":{"events":{"terms":{"field":"event.action","size":60}}}}'
```

Compare a run with `--no-filtering` (or `--output file` on both) to see what the filter removes on your hosts.

## Troubleshooting

**Missing events in detections**
- Check the table above: is the event filtered, and is its path a security path?
- Add the path to `SECURITY_PATHS` (or `CREATE_PATHS` for creates only)
- Run with `--no-filtering` for a while to confirm the event arrives at all

**An event never arrives, filtered or not**
- The ESF collector subscribes only to the events in the taxonomy (and `fork`, `exit`) that this macOS release's eslogger lists; see [FIELD_NAME_ORIGINS.md](FIELD_NAME_ORIGINS.md)
- The `Skipping N events ...` line at startup names the taxonomy events your release doesn't have (`eslogger --list-events` shows what it does)
