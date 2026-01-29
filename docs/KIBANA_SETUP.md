# Kibana Setup Guide

Kibana provides a web-based UI to visualize and explore your macOS telemetry data.

## Quick Start

### Start Kibana

```bash
# Using docker-compose (recommended)
./scripts/start_services.sh
```

This starts both Elasticsearch and Kibana via docker-compose.

### Manual Start

If you prefer to start Kibana manually:

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
    "term": {"event.action": "exec"}
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
    "match": {"process.executable": "/usr/bin/curl"}
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
      "query": "event.action:exec AND process.executable:(*\\/tmp* OR *\\/var\\/tmp*)"
    }
  },
  "size": 10
}
```

## Create Visualizations

Pre-built dashboards are available at: http://localhost:5601/app/dashboards

To create custom visualizations:

### Event Collection Timeline (Line Graph)

1. Go to **Visualize Library** → **Create visualization**
2. Select **Lens** (recommended for Kibana 8.x)
3. Choose data view: **macos-telemetry-esf-***
4. Configure:
   - **X-axis**: `@timestamp` (Date Histogram)
   - **Y-axis**: Count
   - **Chart type**: Line
5. Save as: "macOS Event Collection Timeline"

### Event Types Distribution (Pie Chart)

1. Create new visualization → **Lens**
2. Data view: **macos-telemetry-esf-***
3. Configure:
   - **Primary metric**: Count
   - **Breakdown by**: `event.action` (Terms)
   - **Chart type**: Pie
4. Save as: "macOS Event Types Distribution"

### Top Processes (Horizontal Bar Chart)

1. Create new visualization → **Lens**
2. Data view: **macos-telemetry-esf-***
3. Configure:
   - **X-axis**: `process.executable.keyword` (Terms, Top 10)
   - **Y-axis**: Count
   - **Chart type**: Horizontal Bar
4. Save as: "macOS Top Processes"

## Create Dashboards

1. Go to **Dashboards** → **Create dashboard**
2. Click **Add** → **Add panels**
3. Add visualizations you created
4. Add saved searches as panels
5. Arrange and resize panels
6. Save dashboard

## Useful Fields for Filtering

**ECS Fields (recommended):**
- `event.action` - Event type (exec, fork, create, etc.)
- `process.executable` - Process executable path
- `process.command_line` - Full command line
- `process.pid` - Process ID
- `process.parent.pid` - Parent process ID
- `process.user.name` - Username

**Native ESF Fields:**
- `esf.event_type` - Numeric ESF event type
- `esf.event_name` - ESF event name

## Troubleshooting

### Kibana won't connect to Elasticsearch

Check Kibana logs:
```bash
docker logs kibana
```

Verify Elasticsearch is accessible:
```bash
curl -u elastic:changeme http://localhost:9200
```

### "Unable to fetch mapping" error

Make sure you've:
1. Created the data view correctly
2. Data view pattern matches actual indices (check with `curl -u elastic:changeme "http://localhost:9200/_cat/indices?v"`)
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

