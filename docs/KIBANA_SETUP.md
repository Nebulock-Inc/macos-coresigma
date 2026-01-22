# Kibana Setup Guide

Kibana provides a web-based UI to visualize and explore your macOS telemetry data.

## Quick Start

### Start Kibana

```bash
./scripts/start_kibana.sh
```

This script will:
1. Check if Elasticsearch is running
2. Start Kibana container
3. Configure it to connect to your Elasticsearch instance

### Manual Start

If you prefer to start manually:

```bash
docker run -d \
  --name kibana \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://host.docker.internal:9200" \
  docker.elastic.co/kibana/kibana:8.11.0
```

**Note**: If Elasticsearch and Kibana are in the same Docker network, use:
```bash
-e "ELASTICSEARCH_HOSTS=http://elasticsearch:9200"
```

## Access Kibana

1. **Wait 30-60 seconds** for Kibana to fully start
2. **Open browser**: http://localhost:5601
3. Kibana should automatically connect to Elasticsearch

## Create Index Patterns

Before exploring data, you need to create index patterns:

### For ESF Events

1. Go to **Stack Management** → **Index Patterns** (or **Settings** → **Index Patterns`)
2. Click **Create index pattern**
3. Index pattern name: `macos-telemetry-esf-*`
4. Click **Next step**
5. Time field: Select `@timestamp`
6. Click **Create index pattern**

### For UL Events

Repeat the same process with:
- Index pattern: `macos-telemetry-ul-*`
- Time field: `@timestamp`

## Explore Data

### Discover View

1. Go to **Discover** (left sidebar)
2. Select your index pattern (macos-telemetry-esf-*)
3. You should see events with:
   - Timestamp
   - Event name (exec, fork, create, etc.)
   - Process information (Image, CommandLine, ProcessId)
   - Event metadata

### Query Examples in Dev Tools

Go to **Dev Tools** (left sidebar) to run queries:

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
      "query": "event_name:exec AND Image:(*\\/tmp OR *\\/var\\/tmp)"
    }
  },
  "size": 10
}
```

## Create Visualizations

### Event Type Breakdown

1. Go to **Visualize Library** → **Create visualization**
2. Choose **Aggregation-based visualization**
3. Select your index pattern
4. Metric: **Count**
5. Buckets: **Terms** on `event_name.keyword`
6. Save and view

### Process Execution Timeline

1. Create new visualization
2. Choose **Vertical Bar Chart**
3. Y-axis: **Count**
4. X-axis: **Date Histogram** on `@timestamp`
5. Add filter: `event_name: exec`
6. Save

## Create Dashboards

1. Go to **Dashboards** → **Create dashboard**
2. Add visualizations you created
3. Add saved searches
4. Save dashboard

## Useful Fields for Filtering

- `event_name` - Event type (exec, fork, create, etc.)
- `Image` - Process executable path
- `CommandLine` - Full command line
- `ProcessId` - Process ID
- `ParentProcessId` - Parent process ID
- `User` - Username
- `event_type` - Numeric event type

## Troubleshooting

### Kibana won't connect to Elasticsearch

Check Kibana logs:
```bash
docker logs kibana
```

Verify Elasticsearch is accessible:
```bash
curl http://localhost:9200
```

### "Unable to fetch mapping" error

Make sure you've:
1. Created the index pattern correctly
2. Index pattern matches actual indices (check with `curl "http://localhost:9200/_cat/indices?v"`)
3. Wait a few minutes if indices were just created

### Kibana is slow

- Reduce time range in Discover
- Use filters to limit results
- Increase Docker memory allocation if needed

## Stop/Remove Kibana

```bash
docker stop kibana
docker rm kibana
```

## Using Docker Compose

For easier management, use the provided `docker-compose.yml`:

```bash
docker-compose up -d
```

This starts both Elasticsearch and Kibana together.

