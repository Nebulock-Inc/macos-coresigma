# Kibana Access Guide

## Current Status

**❌ Kibana is NOT currently running**
**❌ Elasticsearch is NOT currently running**

Both services need to be started before you can access Kibana.

---

## Quick Start (Recommended)

### Option 1: Using Docker Compose (Easiest)

```bash
cd /Users/ebrown/macos-coresigma
docker-compose up -d
```

This will start both Elasticsearch and Kibana automatically.

**Wait 30-60 seconds** for services to start, then:
- **Kibana URL**: http://localhost:5601
- **Elasticsearch URL**: http://localhost:9200

### Option 2: Using Start Scripts

```bash
# Start Elasticsearch first
./scripts/start_elasticsearch.sh  # (if exists) or use docker-compose

# Then start Kibana
./scripts/start_kibana.sh
```

### Option 3: Manual Docker Commands

**Start Elasticsearch:**
```bash
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
  docker.elastic.co/elasticsearch/elasticsearch:8.11.0
```

**Start Kibana:**
```bash
docker run -d \
  --name kibana \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://host.docker.internal:9200" \
  docker.elastic.co/kibana/kibana:8.11.0
```

---

## Accessing Kibana

### 1. Wait for Services to Start

- **Elasticsearch**: Usually takes 10-20 seconds
- **Kibana**: Usually takes 30-60 seconds

Check if services are ready:
```bash
# Check Elasticsearch
curl http://localhost:9200

# Check Kibana
curl http://localhost:5601/api/status
```

### 2. Open Kibana in Browser

**URL**: http://localhost:5601

You should see the Kibana welcome screen.

### 3. Create Index Patterns

Before you can explore data, you need to create index patterns:

#### For ESF Events:

1. Go to **Stack Management** → **Index Patterns** (or **Settings** → **Index Patterns**)
2. Click **Create index pattern**
3. Index pattern name: `macos-telemetry-esf-*`
4. Click **Next step**
5. Time field: Select `@timestamp`
6. Click **Create index pattern**

#### For UL Events:

Repeat the same process with:
- Index pattern: `macos-telemetry-ul-*`
- Time field: `@timestamp`

**Or use the automated script:**
```bash
./scripts/setup_kibana_index_patterns.sh
```

---

## Verify Setup

### Check Service Status

```bash
# Check if containers are running
docker ps | grep -E "(elasticsearch|kibana)"

# Check Elasticsearch health
curl http://localhost:9200/_cluster/health

# Check Kibana status
curl http://localhost:5601/api/status
```

### Check Data Availability

```bash
# Check if ESF data exists
curl "http://localhost:9200/macos-telemetry-esf-*/_count"

# Check if UL data exists
curl "http://localhost:9200/macos-telemetry-ul-*/_count"
```

---

## Using Kibana

### Discover View

1. Go to **Discover** (left sidebar)
2. Select your index pattern from dropdown:
   - `macos-telemetry-esf-*` (for ESF events)
   - `macos-telemetry-ul-*` (for UL events)
3. You should see events with:
   - `@timestamp` - Event timestamp
   - `event_name` - Event type (exec, fork, create, etc.)
   - `Image` - Process path
   - `CommandLine` - Command line
   - `ProcessId` - Process ID
   - `User` / `user.name` - Username
   - `UserId` / `user.id` - User ID

### Dev Tools (Query Interface)

Go to **Dev Tools** (left sidebar) to run Elasticsearch queries:

**Get recent exec events:**
```json
GET macos-telemetry-esf-*/_search
{
  "query": {
    "term": {"event_name": "exec"}
  },
  "size": 10,
  "sort": [{"@timestamp": {"order": "desc"}}]
}
```

**Search by process:**
```json
GET macos-telemetry-esf-*/_search
{
  "query": {
    "match": {"Image": "/usr/bin/curl"}
  },
  "size": 10
}
```

**Use converted Sigma query:**
```json
GET macos-telemetry-esf-*/_search
{
  "query": {
    "query_string": {
      "query": "event_type:17 AND event_name:kextload AND NOT kext.team_id:*"
    }
  }
}
```

---

## Troubleshooting

### Kibana Won't Start

1. **Check if Elasticsearch is running:**
   ```bash
   curl http://localhost:9200
   ```
   Kibana requires Elasticsearch to be running first.

2. **Check Docker logs:**
   ```bash
   docker logs kibana
   docker logs elasticsearch
   ```

3. **Check port conflicts:**
   ```bash
   lsof -i :5601  # Kibana port
   lsof -i :9200  # Elasticsearch port
   ```

### Kibana Can't Connect to Elasticsearch

1. **If using Docker Compose:**
   - Make sure both services are in the same network
   - Check `ELASTICSEARCH_HOSTS` environment variable

2. **If using separate containers:**
   - Use `host.docker.internal:9200` for Elasticsearch on host
   - Or use Docker network linking

3. **Check Elasticsearch is accessible:**
   ```bash
   curl http://localhost:9200
   ```

### No Data in Kibana

1. **Check if collectors are running:**
   ```bash
   ps aux | grep -E "(esf_collector|ul_collector)"
   ```

2. **Check if data exists in Elasticsearch:**
   ```bash
   curl "http://localhost:9200/macos-telemetry-esf-*/_count"
   ```

3. **Verify index patterns are created:**
   - Go to Stack Management → Index Patterns
   - Check if patterns exist and are correct

### Index Pattern Not Found

1. **Create index patterns manually** (see "Create Index Patterns" above)
2. **Or use automated script:**
   ```bash
   ./scripts/setup_kibana_index_patterns.sh
   ```

---

## Quick Reference

| Service | URL | Status |
|---------|-----|--------|
| Kibana | http://localhost:5601 | ❌ Not running |
| Elasticsearch | http://localhost:9200 | ❌ Not running |

**To Start:**
```bash
docker-compose up -d
```

**To Stop:**
```bash
docker-compose down
```

**To View Logs:**
```bash
docker-compose logs -f
```

---

## Next Steps After Setup

1. ✅ Start Elasticsearch and Kibana
2. ✅ Create index patterns
3. ✅ Start collectors (if not already running):
   ```bash
   sudo python3 collectors/esf_collector.py --output elasticsearch
   python3 collectors/ul_collector.py --output elasticsearch
   ```
4. ✅ Explore data in Kibana Discover
5. ✅ Create visualizations (see `docs/KIBANA_VISUALIZATIONS.md`)
6. ✅ Set up alerts (see `docs/KIBANA_ALERTS_SETUP.md`)

---

*Last Updated: 2025-01-15*
*Status: Services need to be started*


