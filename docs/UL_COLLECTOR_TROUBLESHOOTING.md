# Unified Logging Collector Troubleshooting

## How UL Collector Works

The UL collector uses macOS `log stream` command, which:
- ✅ Captures NEW events in real-time
- ❌ Does NOT capture historical events
- ⚠️ Only shows events that happen WHILE the collector is running

## Why You Might Not See New Data

### 1. No Security Events Are Happening

`log stream` only shows events as they occur. If no security-relevant events happen, there's nothing to collect.

**Solution**: Generate some test activity:
```bash
# TCC event - try to access Photos
open -a Photos

# Sudo event - run sudo command
sudo -n echo test

# Gatekeeper event - check app assessment
spctl --assess --verbose /Applications
```

### 2. Collector Stopped Running

The collector process may have stopped.

**Check status**:
```bash
ps aux | grep ul_collector
```

**Restart if needed**:
```bash
python3 collectors/ul_collector.py --output elasticsearch --es-url http://localhost:9200 &
```

### 3. Events Are Being Filtered

The collector only monitors 8 security subsystems:
- com.apple.TCC
- com.apple.sudo
- com.apple.gatekeeper
- com.apple.syspolicy
- com.apple.securityd
- com.apple.alf
- com.apple.opendirectoryd
- com.apple.authorization

Events from other subsystems won't be collected.

## Recent Updates

The collector has been updated to:
1. **Capture recent events on startup**: Captures last 5 minutes of events before starting real-time stream
2. **Debug logging**: Shows event counts every 10 events
3. **Better error handling**: Skips non-JSON lines gracefully

## Testing the Collector

### Step 1: Restart Collector

```bash
# Stop existing collector
pkill -f ul_collector.py

# Start fresh
python3 collectors/ul_collector.py --output elasticsearch --es-url http://localhost:9200 > /tmp/ul_collector.log 2>&1 &
```

### Step 2: Generate Test Activity

```bash
# Generate TCC event
open -a Photos

# Generate sudo event (will prompt, but generates log)
sudo -n echo test 2>&1

# Generate gatekeeper event
spctl --assess --verbose /Applications 2>&1 | head -5
```

### Step 3: Check for New Events

```bash
# Wait 5 seconds, then check
python3 << 'EOF'
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone

es = Elasticsearch(['http://localhost:9200'])
now = datetime.now(timezone.utc)
recent = now - timedelta(minutes=1)

response = es.search(
    index='macos-telemetry-ul-*',
    body={
        "query": {"range": {"@timestamp": {"gte": recent.isoformat()}}},
        "size": 10,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
)

count = response['hits']['total']['value'] if isinstance(response['hits']['total'], dict) else response['hits']['total']
print(f"Events in last minute: {count}")

if count > 0:
    print("\nRecent events:")
    for hit in response['hits']['hits']:
        event = hit['_source']
        print(f"  {event.get('@timestamp', 'N/A')[:19]} - {event.get('subsystem', 'N/A')}")
EOF
```

### Step 4: Check Collector Logs

```bash
# Check if collector is processing events
tail -20 /tmp/ul_collector.log
```

You should see:
- "Captured X recent events" (on startup)
- "Processed X UL events..." (every 10 events)
- Any error messages

## Expected Behavior

### Normal Operation

1. **On startup**: Collector captures last 5 minutes of events
2. **Then**: Switches to real-time streaming
3. **As events happen**: They're normalized and sent to Elasticsearch
4. **Debug output**: Shows event counts every 10 events

### If No Events

- Collector is running but waiting
- No security events are happening
- This is normal - UL events are less frequent than ESF events

## Comparison with ESF Collector

| Feature | ESF Collector | UL Collector |
|---------|---------------|--------------|
| Data Source | `eslogger` (real-time) | `log stream` (real-time) |
| Historical Events | No | No (but now captures last 5 min on startup) |
| Event Frequency | Very high (filtered) | Lower (security events only) |
| Volume | ~30K events/day (filtered) | ~100-1000 events/day |

## Summary

✅ **Collector is configured correctly**
✅ **It's running and monitoring 8 security subsystems**
⚠️ **It only captures NEW events in real-time**
💡 **Generate activity to test, or wait for real security events**

The collector will capture events when they happen. If you're not seeing data, it likely means no security-relevant events are occurring right now.

