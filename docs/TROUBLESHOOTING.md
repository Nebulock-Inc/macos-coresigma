# Troubleshooting Guide

## Kibana Error: "@timestamp is of the wrong type"

**Symptom**: Kibana shows error "Field @timestamp is of the wrong type" when trying to use the time picker or sort by time.

**Cause**: Elasticsearch mapped `@timestamp` as a text field instead of a date field, usually because the index was created before index templates were configured.

**Solution**:

1. **Delete indices with wrong mapping** (they will recreate correctly):
   ```bash
   # Delete today's index (it will recreate with correct mapping)
   curl -u elastic:changeme -X DELETE http://localhost:9200/macos-telemetry-ul-$(date +%Y.%m.%d)
   curl -u elastic:changeme -X DELETE http://localhost:9200/macos-telemetry-esf-$(date +%Y.%m.%d)
   ```

3. **Verify templates are active**:
   ```bash
   curl -u elastic:changeme http://localhost:9200/_index_template/macos-telemetry-*
   ```

4. **Wait for new events**: The collector will recreate the index with the correct mapping when it indexes the next event.

5. **Refresh Kibana**: 
   - Go to Stack Management → Index Patterns
   - Select your index pattern
   - Click "Refresh field list"
   - Or delete and recreate the index pattern

**Prevention**: Index templates are now configured automatically. New indices will always have the correct `@timestamp` mapping as a date field.

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
# Use the dedicated wipe script for thorough deletion
bash scripts/wipe_elasticsearch.sh

# Or manually delete each index
INDICES=$(curl -s -u elastic:changeme "http://localhost:9200/_cat/indices/macos-telemetry-*?h=index")
for index in $INDICES; do
    curl -s -u elastic:changeme -X DELETE "http://localhost:9200/$index?ignore_unavailable=true"
done
sleep 5
curl -s -u elastic:changeme -X POST "http://localhost:9200/_refresh"
```

**Note:** If indices keep reappearing, stop any running collectors first:
```bash
pkill -f esf_collector.py
pkill -f ul_collector.py
```

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
   curl -s -u elastic:changeme "http://localhost:5601/api/data_views" -H 'kbn-xsrf: true' | \
     python3 -m json.tool | grep macos-telemetry
   ```
   
   If missing, create data views in Kibana: Stack Management → Data Views

3. **Verify Elasticsearch has data:**
   ```bash
   curl -s -u elastic:changeme "http://localhost:9200/macos-telemetry-esf-*/_count?pretty"
   curl -s -u elastic:changeme "http://localhost:9200/macos-telemetry-ul-*/_count?pretty"
   ```

4. **Generate fresh test data:**
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

**Problem:** ESF collector generating too many events (1M+ per day).

**Solution:** Intelligent filtering is enabled by default in `collectors/esf_collector.py`:
- Filters `mprotect` events to W+X only
- Filters `rename` events to security paths only
- Samples `fork` events at 10%
- Always keeps critical security events (exec, setuid, malware, etc.)

To disable filtering:
```python
# In collectors/esf_collector.py
ENABLE_FILTERING = False
```

Or use command-line flag:
```bash
python3 collectors/esf_collector.py --output elasticsearch --no-filtering
```

---

### 6. Collectors Not Starting

**Problem:** ESF or UL collectors fail to start.

**Solutions:**

1. **Check dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Check Elasticsearch is running:**
   ```bash
   curl -u elastic:changeme http://localhost:9200
   ```

3. **View collector logs:**
   ```bash
   # ESF collector logs (daemon mode)
   tail -f /var/log/coresigma-esf.log
   
   # UL collector logs (daemon mode)
   tail -f /var/log/coresigma-ul.log
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
   eslogger exec --format json | head -1
   ```
   This should output a JSON event, not an error.

**Note:** If running collectors as a LaunchDaemon, the daemon itself needs FDA. Add the Python interpreter path to Full Disk Access:
```
/path/to/macos-coresigma/venv/bin/python3
```

---

### 8. Authentication Error (401)

**Problem:** Collectors fail with:
```
AuthenticationException(401, 'security_exception', 'unable to authenticate user [elastic]')
```

**Cause:** The password stored in Keychain doesn't match the Elasticsearch password.

**Solution:**

1. **For local Docker setup**, reset to default password:
   ```bash
   ./scripts/setup_credentials.sh --sync-docker
   ```
   Enter `changeme` (the default Docker password) or your custom password.

2. **Test credentials:**
   ```bash
   ./scripts/setup_credentials.sh --test
   ```

3. **If using custom password**, ensure Docker and Keychain are in sync:
   ```bash
   # This updates both .env (for Docker) and Keychain (for collectors)
   ./scripts/setup_credentials.sh --sync-docker
   # Then restart Docker
   docker-compose down && docker-compose up -d
   ```

---

## Quick Diagnostic Commands

```bash
# Check Elasticsearch health
curl -u elastic:changeme http://localhost:9200/_cluster/health?pretty

# List all indices
curl -u elastic:changeme http://localhost:9200/_cat/indices?v

# Count events
curl -u elastic:changeme "http://localhost:9200/macos-telemetry-esf-*/_count?pretty"
curl -u elastic:changeme "http://localhost:9200/macos-telemetry-ul-*/_count?pretty"

# Check Kibana status
curl -u elastic:changeme http://localhost:5601/api/status

# List Kibana data views
curl -s -u elastic:changeme "http://localhost:5601/api/data_views" -H 'kbn-xsrf: true' | \
  python3 -m json.tool | grep -A 5 "macos-telemetry"

# Check running collectors
ps aux | grep -E "esf_collector|ul_collector"
```

**Note**: If you've configured credentials in Keychain (`./scripts/setup_credentials.sh`), scripts will use those automatically.

---

---

## Unified Logging (UL) Collector Issues

### How UL Collector Works

The UL collector uses macOS `log stream` command, which:
- Captures NEW events in real-time
- Does NOT capture historical events
- Only shows events that happen WHILE the collector is running

### Why You Might Not See UL Data

**1. No Security Events Are Happening**

`log stream` only shows events as they occur. If no security-relevant events happen, there's nothing to collect.

**Generate test activity:**
```bash
# TCC event - try to access Photos
open -a Photos

# Sudo event - run sudo command
sudo -n echo test

# Gatekeeper event - check app assessment
spctl --assess --verbose /Applications
```

**2. Collector Stopped Running**

```bash
# Check status
ps aux | grep ul_collector

# Restart if needed (credentials from Keychain or env vars)
python3 collectors/ul_collector.py --output elasticsearch &
```

**3. Events Are Being Filtered**

The collector only monitors these security subsystems:
- `com.apple.TCC`
- `com.apple.sudo`
- `com.apple.gatekeeper`
- `com.apple.syspolicy`
- `com.apple.securityd`
- `com.apple.alf`
- `com.apple.opendirectoryd`
- `com.apple.authorization`

Events from other subsystems won't be collected.

### UL vs ESF Collector Comparison

| Feature | ESF Collector | UL Collector |
|---------|---------------|--------------|
| Data Source | `eslogger` (real-time) | `log stream` (real-time) |
| Historical Events | No | No (captures last 5 min on startup) |
| Event Frequency | Very high (filtered) | Lower (security events only) |
| Volume | ~30K events/day (filtered) | ~100-1000 events/day |

---

## Getting Help

If issues persist:
1. Check collector logs: `/tmp/esf_collector.log`, `/tmp/ul_collector.log`
2. Check Elasticsearch logs (if using Docker)
3. Check Kibana browser console for JavaScript errors
4. Verify all services are running and accessible

