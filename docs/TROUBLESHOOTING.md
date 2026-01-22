# Troubleshooting Guide

## Kibana Error: "@timestamp is of the wrong type"

**Symptom**: Kibana shows error "Field @timestamp is of the wrong type" when trying to use the time picker or sort by time.

**Cause**: Elasticsearch mapped `@timestamp` as a text field instead of a date field, usually because the index was created before index templates were configured.

**Solution**:

1. **Run the fix script**:
   ```bash
   ./scripts/fix_timestamp_mapping.sh
   ```
   This will:
   - Delete existing indices with wrong mapping
   - Verify index templates are configured correctly
   - Let collectors recreate indices with correct mapping

2. **Or manually fix**:
   ```bash
   # Delete today's index (it will recreate with correct mapping)
   curl -X DELETE http://localhost:9200/macos-telemetry-ul-$(date +%Y.%m.%d)
   curl -X DELETE http://localhost:9200/macos-telemetry-esf-$(date +%Y.%m.%d)
   ```

3. **Verify templates are active**:
   ```bash
   curl http://localhost:9200/_index_template/macos-telemetry-*
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
INDICES=$(curl -s "http://localhost:9200/_cat/indices/macos-telemetry-*?h=index")
for index in $INDICES; do
    curl -s -X DELETE "http://localhost:9200/$index?ignore_unavailable=true"
done
sleep 5
curl -s -X POST "http://localhost:9200/_refresh"
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
```bash
# Run the comprehensive fix script
bash scripts/fix_all_kibana_issues.sh

# This will:
# 1. Force delete all old indices
# 2. Clean up duplicate data views
# 3. Create fresh data views
# 4. Check for broken detection rules
```

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
   curl -s "http://localhost:5601/api/data_views" -H 'kbn-xsrf: true' | \
     python3 -m json.tool | grep macos-telemetry
   
   # Fix data views
   bash scripts/fix_kibana_errors.sh
   ```

3. **Verify Elasticsearch has data:**
   ```bash
   curl -s "http://localhost:9200/macos-telemetry-esf-*/_count?pretty"
   curl -s "http://localhost:9200/macos-telemetry-ul-*/_count?pretty"
   ```

4. **Generate fresh test data:**
   ```bash
   bash scripts/e2e_test_all_event_types.sh
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
   ```bash
   bash scripts/fix_all_kibana_issues.sh
   ```

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

1. **Check permissions:**
   ```bash
   # ESF collector requires Full Disk Access
   # UL collector should work without special permissions
   ```

2. **Check dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Check Elasticsearch is running:**
   ```bash
   curl http://localhost:9200
   ```

4. **View collector logs:**
   ```bash
   # ESF collector logs
   tail -f /tmp/esf_collector.log
   
   # UL collector logs
   tail -f /tmp/ul_collector.log
   ```

---

## Quick Diagnostic Commands

```bash
# Check Elasticsearch health
curl http://localhost:9200/_cluster/health?pretty

# List all indices
curl http://localhost:9200/_cat/indices?v

# Count events
curl "http://localhost:9200/macos-telemetry-esf-*/_count?pretty"
curl "http://localhost:9200/macos-telemetry-ul-*/_count?pretty"

# Check Kibana status
curl http://localhost:5601/api/status

# List Kibana data views
curl -s "http://localhost:5601/api/data_views" -H 'kbn-xsrf: true' | \
  python3 -m json.tool | grep -A 5 "macos-telemetry"

# Check running collectors
ps aux | grep -E "esf_collector|ul_collector"
```

---

## Getting Help

If issues persist:
1. Check collector logs: `/tmp/esf_collector.log`, `/tmp/ul_collector.log`
2. Check Elasticsearch logs (if using Docker)
3. Check Kibana browser console for JavaScript errors
4. Verify all services are running and accessible

