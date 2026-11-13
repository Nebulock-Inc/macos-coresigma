# Kibana Setup Guide

Kibana provides a web-based UI to visualize and explore your macOS telemetry data.

## Quick Start

### Start Kibana

```bash
./scripts/bench_up.sh elastic
```

This starts Elasticsearch and Kibana 8.19.25 with Docker Compose, waits until both are healthy, and creates the index templates. The `elastic` password is `ELASTIC_PASSWORD` in `.env`. To use your own Kibana instead, set `KIBANA_URL` and `ES_URL` for the scripts.

## Access Kibana

1. **Wait 30-60 seconds** for Kibana to fully start
2. **Open browser**: http://localhost:5601
3. Kibana should automatically connect to Elasticsearch

## Create Data Views

```bash
./scripts/create_kibana_data_view.sh   # macos-telemetry-esf-* and macos-telemetry-ul-*, time field @timestamp
```

`scripts/create_lens_dashboards_ndjson.py` creates `macos-telemetry-*` (both) for its dashboards if it doesn't exist. To create one by hand: **Stack Management** → **Data Views** → **Create data view**, with `@timestamp` as the time field.

## Explore Data

### Discover View

1. Go to **Discover** (left sidebar)
2. Select your index pattern (macos-telemetry-esf-*)
3. You should see events with:
   - Timestamp
   - `event.action`: the eslogger event name (exec, fork, create, etc.)
   - Process fields (`process.executable`, `process.command_line`, `process.pid`)
   - `user.name`, `host.name`

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

**Use a Lucene query (the shape `sigma convert -t lucene -p macos_esf_ecs` produces):**
```json
GET macos-telemetry-esf-*/_search
{
  "query": {
    "query_string": {
      "query": "event.action:exec AND process.executable:(*\\/tmp\\/* OR *\\/var\\/tmp\\/*)"
    }
  },
  "size": 10
}
```

## Create Visualizations

Generate the coreSigma dashboards with `python3 scripts/create_lens_dashboards_ndjson.py`, or import `exports/all_dashboards_latest.ndjson` (see the README). They appear at http://localhost:5601/app/dashboards.

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
   - **X-axis**: `process.executable` (Terms, Top 10)
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

**ESF documents:**
- `event.action` - eslogger event name (exec, fork, create, etc.)
- `event.category`, `event.type` - ECS category and type
- `process.executable` - Process executable path
- `process.command_line` - Full command line
- `process.pid`, `process.parent.pid` - Process and parent IDs
- `process.parent.executable` - Parent executable
- `user.name`, `user.id` - Effective user
- `file.path` - File path (file events)

**UL documents:**
- `unified_log.subsystem`, `unified_log.category` - Subsystem and category
- `message` - Log message
- `process.executable` - Logging process

All fields: [FIELD_NAME_ORIGINS.md](FIELD_NAME_ORIGINS.md). There are no `esf.*` fields and no `.keyword` subfields.

## Troubleshooting

### Kibana won't connect to Elasticsearch

Check Kibana logs:
```bash
docker logs kibana
```

Verify Elasticsearch is accessible:
```bash
curl -u "elastic:$ES_PASSWORD" http://localhost:9200
```

### "Unable to fetch mapping" error

Make sure you've:
1. Created the data view correctly
2. Data view pattern matches actual indices (check with `curl -u "elastic:$ES_PASSWORD" "http://localhost:9200/_cat/indices?v"`)
3. Wait a few minutes if indices were just created

### Kibana is slow

- Reduce time range in Discover
- Use filters to limit results
- Increase Docker memory allocation if needed

## Stop/Remove Kibana

From the repository root:

```bash
docker compose stop                # stop the bench, keep its data
docker compose down -v             # remove the bench and its data volumes
```

Add `--profile splunk --profile opensearch --profile clickhouse` for the bench services you started with those profiles.

