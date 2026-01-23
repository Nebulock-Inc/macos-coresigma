# Kibana Alerts Setup Guide

## Two Approaches to Alerts

There are two ways to set up alerts for Sigma rules in Kibana:

### 1. Saved Searches (Recommended - No Permissions Required) ✅
**Pros:**
- No Elastic Security/Detection Engine required
- No special permissions needed
- Easy to create and use
- Can be converted to alerts via Rules and Connectors

**Cons:**
- Not as feature-rich as Detection Engine
- Requires manual alert rule creation

### 2. Detection Engine (Elastic Security) ⚠️
**Pros:**
- Advanced threat detection features
- Built-in correlation and investigation tools
- Automated alert management

**Cons:**
- Requires Elastic Security license/configuration
- Requires special permissions
- More complex setup

---

## Current Status: Saved Searches Approach

We've already created saved searches for all Sigma rules. These work **without** Detection Engine permissions.

### View Saved Searches

1. **In Kibana Discover:**
   - Go to: `http://localhost:5601/app/discover`
   - Click "Open" → Select a saved search
   - You'll see searches like:
     - "Sigma Alert: Suspicious Process Execution (ESF)"
     - "Sigma Alert: File Creation Persistence (ESF)"
     - "Critical: Code Signature Invalidation (ESF)"
     - "Sigma Alert: Unusual TCC Access (UL)"
     - "Sigma Alert: Sudo Command Execution (UL)"

2. **Run the script to list all:**
   ```bash
   curl -s -u elastic:changeme "http://localhost:5601/api/saved_objects/_find?type=search&search=Sigma" \
     -H 'kbn-xsrf: true' | python3 -m json.tool
   ```

### Convert Saved Searches to Alerts

1. Go to: **Stack Management → Rules and Connectors → Rules**
2. Click **"Create rule"**
3. Select **"Elasticsearch query"**
4. Configure:
   - **Index:** `macos-telemetry-esf-*` or `macos-telemetry-ul-*`
   - **Query:** Copy the KQL query from a saved search
   - **Schedule:** Every 5 minutes
   - **Actions:** Add email/Slack/webhook connector

---

## Fixing "Detection Engine Permissions" Error

### Option 1: Use Saved Searches (Recommended)

**The saved searches we created work without Detection Engine!**

- Go to **Discover** instead of **Security** or **Detections**
- Open a saved search
- No permissions required ✅

### Option 2: Enable Detection Engine (If You Want It)

Detection Engine requires Elastic Security, which needs:

1. **Elastic Security License** (Free tier available but limited)
2. **Elastic Security Plugin** enabled
3. **Proper user roles** with detection permissions

**To check if available:**
```bash
curl -s -u elastic:changeme "http://localhost:5601/api/features" -H 'kbn-xsrf: true' | \
  python3 -c "import sys, json; features = json.load(sys.stdin).get('features', []); \
  security = [f for f in features if 'security' in f.get('id', '').lower()]; \
  print('Security features:', [f.get('id') for f in security[:5]])"
```

**If Elastic Security is not available:**
- Use saved searches (already set up ✅)
- Or install Elastic Security (requires license/setup)

---

## Fixing "undefined: undefined" Error

This error usually means:
1. A broken data view reference
2. An attempt to access Detection Engine endpoints that don't exist
3. A missing index pattern

### Solution:

1. **Hard refresh browser:**
   - Mac: `Cmd + Shift + R`
   - Windows/Linux: `Ctrl + Shift + R`

2. **Delete and recreate data views:**
   - Go to: Kibana → Stack Management → Data Views
   - Delete any broken `macos-telemetry-*` data views
   - Create fresh data views with `@timestamp` as the time field

3. **Use Discover instead of Security/Detections:**
   - Go to: `http://localhost:5601/app/discover`
   - Select a saved search (no Detection Engine needed)

4. **If using Detection Engine is required:**
   - Make sure Elastic Security is properly configured
   - Check user has `detections_user` or `detections_admin` role

---

## Quick Reference

### View Alerts (Saved Searches)
```bash
# List all saved searches
curl -s -u elastic:changeme "http://localhost:5601/api/saved_objects/_find?type=search&per_page=20" \
  -H 'kbn-xsrf: true' | python3 -m json.tool | grep -A 3 "Sigma"
```

### Test a Query
```bash
# Test ESF query
curl -s -u elastic:changeme "http://localhost:9200/macos-telemetry-esf-*/_search?q=event.action:exec&size=1&pretty"

# Test UL query
curl -s -u elastic:changeme "http://localhost:9200/macos-telemetry-ul-*/_search?q=ul.subsystem:com.apple.sudo&size=1&pretty"
```

**Note**: If you've set up credentials in Keychain using `./scripts/setup_credentials.sh`, you can omit `-u elastic:changeme` from curl commands by using environment variables or the auth helper.

---

## Recommended Workflow

**For most users (no Detection Engine):**
1. ✅ Use saved searches (already created)
2. ✅ View in Discover
3. ✅ Create alert rules from saved searches (Rules and Connectors)
4. ✅ Configure email/Slack notifications

**For advanced users (with Detection Engine):**
1. Enable Elastic Security
2. Import Sigma rules as Detection Engine rules
3. Use Security dashboard for correlation

---

## Troubleshooting

### "Detection engine permissions required"
→ Use saved searches instead (Discover → Open saved search)

### "undefined: undefined"
→ Delete and recreate data views in Stack Management → Data Views
→ Hard refresh browser (Cmd+Shift+R)

### No data in saved searches
→ Check time range in Discover (set to "Last 7 days")
→ Verify events exist: `curl -u elastic:changeme "http://localhost:9200/macos-telemetry-esf-*/_count?pretty"`

### Saved searches show errors
→ Recreate data views in Stack Management → Data Views
→ Hard refresh browser

