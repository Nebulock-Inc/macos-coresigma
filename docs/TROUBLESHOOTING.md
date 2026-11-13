# Troubleshooting Guide

## Kibana Error: "@timestamp is of the wrong type"

**Symptom**: Kibana shows error "Field @timestamp is of the wrong type" when trying to use the time picker or sort by time.

**Cause**: Elasticsearch mapped `@timestamp` as a text field instead of a date field, usually because the index was created before index templates were configured.

**Solution**:

1. **Delete indices with wrong mapping** (they will recreate correctly):
   ```bash
   # Delete today's index (it will recreate with correct mapping); indices are named by UTC date
   curl -u "elastic:$ES_PASSWORD" -X DELETE http://localhost:9200/macos-telemetry-ul-$(date -u +%Y.%m.%d)
   curl -u "elastic:$ES_PASSWORD" -X DELETE http://localhost:9200/macos-telemetry-esf-$(date -u +%Y.%m.%d)
   ```

2. **Verify templates are active**:
   ```bash
   curl -u "elastic:$ES_PASSWORD" http://localhost:9200/_index_template/macos-telemetry-*
   ```

3. **Wait for new events**: The collector will recreate the index with the correct mapping when it indexes the next event.

4. **Refresh Kibana**: 
   - Go to Stack Management → Data Views
   - Select your data view
   - Click "Refresh field list"
   - Or delete and recreate the data view

**Prevention**: `bench_up.sh` creates the index templates. With your own Elasticsearch, run the template script before starting the collectors.

**Setup Templates**:
```bash
# Run this after starting Elasticsearch
bash scripts/setup_elasticsearch_templates.sh
```

---

## Common Issues and Solutions

### 1. Elasticsearch Indices Not Wiping Properly

**Problem:** Old indices persist after running wipe commands.

**Solution:**
```bash
# Use the dedicated wipe script for thorough deletion (asks before deleting; --yes skips the question)
bash scripts/wipe_elasticsearch.sh

# Or manually delete each index
INDICES=$(curl -s -u "elastic:$ES_PASSWORD" "http://localhost:9200/_cat/indices/macos-telemetry-*?h=index")
for index in $INDICES; do
    curl -s -u "elastic:$ES_PASSWORD" -X DELETE "http://localhost:9200/$index?ignore_unavailable=true"
done
sleep 5
curl -s -u "elastic:$ES_PASSWORD" -X POST "http://localhost:9200/_refresh"
```

**Note:** If indices keep reappearing, stop any running collectors first:
```bash
sudo pkill -f esf_collector.py   # it runs as root
pkill -f ul_collector.py
```
They flush what they still hold before exiting, which can take a few seconds; wait until `pgrep -f _collector.py` prints nothing.

---

### 2. Kibana Error: "undefined: undefined" (400 Bad Request)

**Problem:** Getting this error when trying to view alerts or detection rules in Kibana.

**Causes:**
- Duplicate data views with conflicting configurations
- Broken references in detection rules/alerts
- Missing or incorrect index patterns

**Solution:**

**Manual Fix:**
1. Go to Kibana → Stack Management → Data Views
2. Delete all duplicate `macos-telemetry-*` data views
3. Create fresh data views:
   - Title: `macos-telemetry-esf-*`
   - Title: `macos-telemetry-ul-*`
   - Time field: `@timestamp`
4. Hard refresh browser (Cmd+Shift+R or Ctrl+Shift+R)

---

### 3. No Data Showing in Kibana Discover

**Problem:** Kibana Discover shows "No results found" even though Elasticsearch has data.

**Solutions:**

1. **Check time range:**
   - In Kibana Discover, set time range to "Last 7 days" or "Last 15 minutes"
   - Use absolute time range if needed

2. **Verify data view configuration:**
   ```bash
   # Check if data views exist
   curl -s -u "elastic:$ES_PASSWORD" "http://localhost:5601/api/data_views" -H 'kbn-xsrf: true' | \
     python3 -m json.tool | grep macos-telemetry
   ```
   
   If missing, create data views in Kibana: Stack Management → Data Views

3. **Verify Elasticsearch has data:**
   ```bash
   curl -s -u "elastic:$ES_PASSWORD" "http://localhost:9200/macos-telemetry-esf-*/_count?pretty"
   curl -s -u "elastic:$ES_PASSWORD" "http://localhost:9200/macos-telemetry-ul-*/_count?pretty"
   ```

4. **Generate fresh test data** (benign local commands that a few rules match, while the ESF collector runs):
   ```bash
   python3 scripts/generate_test_events.py
   ```

---

### 4. Detection Rules/Alerts Showing Errors

**Problem:** Alerts or detection rules fail with query errors.

**Solutions:**

1. **Delete and recreate broken alerts:**
   - Go to Kibana → Stack Management → Rules and Connectors
   - Delete broken rules
   - Recreate with correct index pattern: `macos-telemetry-esf-*` or `macos-telemetry-ul-*`

2. **Fix query syntax:**
   - Use KQL (Kibana Query Language) or Lucene syntax
   - Ensure field names match (use Discover to verify field names)

3. **Verify data view exists:**
   Go to Kibana → Stack Management → Data Views and ensure your index pattern exists.

---

### 5. High Log Volume from ESF

**Problem:** ESF collector generating too many events.

**Solution:** Filtering is on by default in `collectors/esf_collector.py`:
- `mprotect` events: W+X only
- `open`, `rename` and `setextattr` events: security paths (and quarantine attributes) only
- `create` events: security paths, the create-only paths (`/Library/Application Support/`, `.app/Contents/`, `/.claude/`, `/.vscode/`) and `/Library/Caches/com.apple.`
- `fork` events: shells and a few tools, plus a 10% sample of the rest
- Everything else (exec, setuid, malware, ...) is kept

If filtering is on and volume is still too high, narrow `SECURITY_PATHS` or the fork sample. See [FILTERING_CONFIGURATION.md](FILTERING_CONFIGURATION.md). `--no-filtering` turns the filter off.

---

### 6. Collectors Not Starting

**Problem:** ESF or UL collectors fail to start.

**Solutions:**

1. **`eslogger --list-events failed`:** the collector asks eslogger which events this macOS release has before it starts, and stops if that fails (eslogger needs macOS 13 or later) or lists none of its events. A line `Skipping N events this macOS release's eslogger doesn't support: ...` is not an error: those events are newer than the running release.

2. **`AuthenticationError` under sudo:** sudo drops `ES_USER`/`ES_PASSWORD`, and the Keychain lookup runs as root. Start it with `sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY ...`.

3. **Check Elasticsearch is running:**
   ```bash
   curl -u "elastic:$ES_PASSWORD" http://localhost:9200
   ```

4. **A UL daemon that exits at once:** as a normal user it can't write the default `/var/run` and `/var/log` paths. Give `--pid-file` and `--log-file` paths you can write.

5. **View collector logs:**
   ```bash
   # ESF collector logs (daemon mode; root-only)
   sudo tail -f /var/log/coresigma-esf.log
   
   # UL collector logs (daemon mode): the --log-file you gave it
   tail -f "$HOME/Library/Logs/coresigma-ul.log"
   ```

---

### 7. ESF Collector: Full Disk Access Error

**Problem:** ESF collector fails with:
```
ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED
```
or
```
Failed to create ES client: Not permitted to create an ES Client, responsible process needs TCC Full Disk Access authorization
```
(`ES` here is Apple's Endpoint Security, not Elasticsearch.)

**Cause:** Apple's Endpoint Security Framework requires Full Disk Access (FDA) permission.

**Solution:**

1. Open **System Settings** → **Privacy & Security** → **Full Disk Access**
2. Click the lock icon and authenticate
3. Click **+** and add your terminal application:
   - **Terminal.app**: `/Applications/Utilities/Terminal.app`
   - **iTerm2**: `/Applications/iTerm.app`
   - **VS Code**: Add the IDE application itself
4. **Restart your terminal** (quit and reopen)
5. Verify FDA is working:
   ```bash
   sudo eslogger exec | head -1
   ```
   This should output a JSON event, not an error.

**Note:** If running collectors as a LaunchDaemon, the daemon itself needs FDA. Add the Python interpreter the plist runs to Full Disk Access:
```
/path/to/macos-coresigma/venv/bin/python3
```

---

### 8. Authentication Error (401)

**Problem:** Collectors fail with:
```
AuthenticationException(401, 'security_exception', 'unable to authenticate user [elastic]')
```

**Cause:** The password stored in Keychain doesn't match the Elasticsearch password. The collectors and the Kibana tools (`deploy_sigma_rules.py`, the Lens script) try the Keychain before `ES_USER`/`ES_PASSWORD`, so a stale Keychain entry wins even when the environment has the right password. (The shell scripts and `export_current_dashboards.py` try the environment first. The README's [Authentication](../README.md#authentication) table has each tool's order.)

**Solution:**

1. **A stale Keychain entry:** update it (`./scripts/setup_credentials.sh --password`) or delete it, so the environment's credentials are used:
   ```bash
   security delete-generic-password -s coreSigma-Elasticsearch -a elastic   # -a: the user name you stored
   ```

2. **For the Docker bench**, the password is `ELASTIC_PASSWORD` in `.env`. Export it (`export ES_USER=elastic ES_PASSWORD="$(grep '^ELASTIC_PASSWORD=' .env | cut -d= -f2-)"`) or store that value in the Keychain:
   ```bash
   ./scripts/setup_credentials.sh --password
   ```

3. **Test credentials:**
   ```bash
   ./scripts/setup_credentials.sh --test
   ```

4. **If using custom password**, ensure Docker and Keychain are in sync:
   ```bash
   # This updates both .env (for Docker) and Keychain (for collectors)
   ./scripts/setup_credentials.sh --sync-docker
   # Then restart the bench
   ./scripts/bench_up.sh elastic
   ```

---

## Quick Diagnostic Commands

```bash
# Check Elasticsearch health
curl -u "elastic:$ES_PASSWORD" http://localhost:9200/_cluster/health?pretty

# List all indices
curl -u "elastic:$ES_PASSWORD" http://localhost:9200/_cat/indices?v

# Count events (and whether collectors are running)
./scripts/check_collection_status.sh

# Check Kibana status
curl -u "elastic:$ES_PASSWORD" http://localhost:5601/api/status

# List Kibana data views
curl -s -u "elastic:$ES_PASSWORD" "http://localhost:5601/api/data_views" -H 'kbn-xsrf: true' | \
  python3 -m json.tool | grep -A 5 "macos-telemetry"

# Spooled (undelivered) documents
sudo ls -l /var/root/.coresigma/spool/ ; ls -l ~/.coresigma/spool/
```

**Note**: If you've configured credentials in Keychain (`./scripts/setup_credentials.sh`), the collectors and the scripts in `scripts/` find them without environment variables, except `bench_up.sh`, `rule_matrix.py` and `sample_private_baseline.py`, which use `ELASTIC_PASSWORD` (environment or `.env`). Each tool's order is in the README's [Authentication](../README.md#authentication) table. The `curl` commands above need `$ES_PASSWORD`.

---

---

## Unified Logging (UL) Collector Issues

### How UL Collector Works

The UL collector uses macOS `log stream` command, which:
- Captures NEW events in real-time
- Does NOT capture historical events
- Only shows events that happen WHILE the collector is running

### Why You Might Not See UL Data

**1. No Matching Events Are Happening**

`log stream` only shows events as they occur. If no security-relevant events happen, there's nothing to collect.

**Generate test activity:**
```bash
# TCC event - try to access Photos
open -a Photos

# Sudo event - a failed sudo (hosts with `Defaults !log_allowed` log only denials)
sudo -k; sudo -n true

# Gatekeeper event - check app assessment
spctl --assess --verbose /Applications
```

**2. Collector Stopped Running**

```bash
# Check status
ps aux | grep ul_collector

# Restart if needed (credentials from the Keychain or env vars)
python3 collectors/ul_collector.py --output elasticsearch &
```

**3. The Lines Aren't Selected**

The collector's `log stream` predicate selects only the Unified Log categories in the taxonomy (TCC, Authorization, sudo, the firewall, Gatekeeper/syspolicy, launchd, XProtect, securityd, Open Directory, mdmclient). Lines from other subsystems aren't collected, and `log stream` never delivers launchd's lines. See [UL_TELEMETRY_TUNING.md](UL_TELEMETRY_TUNING.md).

### UL vs ESF Collector Comparison

| Feature | ESF Collector | UL Collector |
|---------|---------------|--------------|
| Data Source | `eslogger` (real-time) | `log stream` (real-time) |
| Historical Events | No | Last 5 minutes on startup (`--no-recent` skips) |
| Selection | Subscribed events, filtered | The taxonomy's UL categories |

---

## Getting Help

If issues persist:
1. Check collector logs: `/var/log/coresigma-esf.log` (ESF daemon), the `--log-file` you gave a UL daemon, or `/tmp/ul_collector.log` (`start_collectors.sh`)
2. Check Elasticsearch logs (if using Docker)
3. Check Kibana browser console for JavaScript errors
4. Verify all services are running and accessible

