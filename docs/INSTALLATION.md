# Installation and Configuration Guide

This guide provides step-by-step instructions for installing and configuring the macOS Sigma Pipelines for ESF and Unified Logging.

## Prerequisites

Before installing, ensure you have:

1. **macOS 11.0+ (Big Sur or later)** - Required for ESF and modern Unified Logging
2. **Python 3.9+** - Check with `python3 --version`
3. **Administrator/root access** - Required for ESF event collection
4. **Xcode Command Line Tools** - Install with `xcode-select --install`

### Optional (for Elasticsearch testing):
5. **Elasticsearch 8.0+** - Can be run via Docker
6. **Docker Desktop** - For easy Elasticsearch deployment

## Installation Steps

### Step 1: Clone the Repository

```bash
cd ~
git clone https://github.com/yourusername/macos-sigma-pipelines-new.git
cd macos-sigma-pipelines-new
```

### Step 2: Install Python Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Install Sigma CLI Tools

The Sigma CLI (`sigmatools`) is required for rule conversion:

```bash
pip install sigmatools
```

Verify installation:
```bash
sigma --version
```

### Step 4: Set Up Elasticsearch (Optional)

If you want to test the end-to-end pipeline with Elasticsearch:

#### Option A: Using Docker Compose (Recommended)

```bash
docker-compose up -d
```

This starts both Elasticsearch and Kibana. Wait for services to start:
```bash
curl http://localhost:9200
```

#### Option B: Using Docker (Manual)

```bash
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.11.0
```

Wait for Elasticsearch to start:
```bash
curl http://localhost:9200
```

#### Option C: Local Installation

Follow the [Elasticsearch installation guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html).

### Step 4.5: Configure Elasticsearch Index Templates

**Important**: Index templates ensure `@timestamp` is correctly mapped as a date field for Kibana compatibility.

```bash
bash scripts/setup_elasticsearch_templates.sh
```

This creates templates for:
- `macos-telemetry-esf-*` (ESF events)
- `macos-telemetry-ul-*` (UL events)

**Note**: Templates are automatically applied to new indices. If you have existing indices with wrong mapping, run:
```bash
bash scripts/fix_timestamp_mapping.sh
```

### Step 5: Configure Collectors

#### ESF Collector Configuration

The ESF collector requires root privileges. Create a launch daemon for automatic collection:

```bash
# Create launch daemon plist
sudo nano /Library/LaunchDaemons/com.macos.sigma.esf.plist
```

Add the following (adjust paths as needed):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.macos.sigma.esf</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/path/to/macos-sigma-pipelines-new/collectors/esf_collector.py</string>
        <string>--output</string>
        <string>elasticsearch</string>
        <string>--es-url</string>
        <string>http://localhost:9200</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/esf-collector.err</string>
    <key>StandardOutPath</key>
    <string>/var/log/esf-collector.log</string>
</dict>
</plist>
```

Load the daemon:
```bash
sudo launchctl load /Library/LaunchDaemons/com.macos.sigma.esf.plist
```

#### UL Collector Configuration

For Unified Logging, you can run the collector as a regular user or service:

```bash
# Test run
python3 collectors/ul_collector.py --output elasticsearch --es-url http://localhost:9200
```

### Step 6: Verify Installation

Run the end-to-end test suite:

```bash
python3 tests/test_e2e.py --es-url http://localhost:9200
```

Expected output:
```
======================================================================
End-to-End Test Suite
======================================================================

✓ PASS: Elasticsearch Connection
  Connected to cluster: docker-cluster

✓ PASS: Pipeline Loading
  ESF pipeline: macos-esf, UL pipeline: macos-ul

✓ PASS: Rule Conversion
  Converted process_execution_suspicious.yml to: event_type:9 AND Image:(...

✓ PASS: Event Ingestion
  Event indexed and retrieved successfully (ID: ...)

✓ PASS: Query Execution
  Query executed successfully: event_type:9 AND ProcessId:12345 (found 1 results)

======================================================================
Test Summary
======================================================================
Passed: 5/5

✓ All tests passed!
```

## Configuration

### Pipeline Configuration

The pipeline files are located in `pipelines/`:

- **`pipelines/macos_esf.yml`** - ESF event pipeline configuration
- **`pipelines/macos_ul.yml`** - Unified Logging pipeline configuration

These files define:
- Field mappings from native ESF/UL format to Sigma standard fields
- Log source definitions for different event categories
- Transformation rules

### Field Mappings

Key field mappings:

| Native Field | Sigma Field | Example |
|-------------|-------------|---------|
| `process.executable.path` | `Image` | `/usr/bin/ls` |
| `event.exec.args[]` | `CommandLine` | `ls -la /tmp` |
| `process.audit_token.pid` | `ProcessId` | `12345` |
| `process.ppid` | `ParentProcessId` | `12340` |

### Index Patterns

Events are indexed with date-based patterns:
- ESF: `macos-telemetry-esf-YYYY.MM.DD`
- UL: `macos-telemetry-ul-YYYY.MM.DD`

## Usage

### Converting Sigma Rules

Convert a rule to Elasticsearch Lucene query:

```bash
sigma convert -t lucene \
  -p pipelines/macos_esf.yml \
  rules/esf/process_execution_suspicious.yml
```

Convert to Elasticsearch EQL:

```bash
sigma convert -t eql \
  -p pipelines/macos_esf.yml \
  rules/esf/process_execution_suspicious.yml
```

### Running Collectors Manually

**ESF Collector:**
```bash
sudo python3 collectors/esf_collector.py \
  --output elasticsearch \
  --es-url http://localhost:9200
```

**UL Collector:**
```bash
python3 collectors/ul_collector.py \
  --output elasticsearch \
  --es-url http://localhost:9200
```

### Testing with Sample Data

Create a test event:

```bash
# Trigger a test process execution
/bin/ls /tmp

# Check if event appears in Elasticsearch
curl -X GET "localhost:9200/macos-telemetry-esf-*/_search?q=Image:/bin/ls&pretty"
```

## Troubleshooting

### Collector Not Starting

**Issue**: ESF collector fails with permission errors

**Solution**: Ensure the collector is running with root privileges:
```bash
sudo python3 collectors/esf_collector.py
```

### Events Not Appearing in Elasticsearch

**Issue**: Collector running but no events in Elasticsearch

**Solution**:
1. Check Elasticsearch is running: `curl http://localhost:9200`
2. Check collector logs: `/var/log/esf-collector.log`
3. Verify index exists: `curl "localhost:9200/_cat/indices?v"`

### Rule Conversion Fails

**Issue**: `sigma convert` fails with pipeline errors

**Solution**:
1. Verify pipeline YAML syntax: `python3 -c "import yaml; yaml.safe_load(open('pipelines/macos_esf.yml'))"`
2. Check rule file format matches Sigma specification
3. Ensure field names in rule match pipeline mappings

## Next Steps

- Review the sample rules in `rules/esf/` and `rules/ul/`
- Create custom rules for your environment
- Set up Kibana dashboards for visualization
- Configure alerting rules in Elasticsearch

## Additional Resources

- [Sigma Project Documentation](https://github.com/SigmaHQ/sigma)
- [pySigma Documentation](https://sigmahq-pysigma.readthedocs.io/)
- [macOS Endpoint Security Framework](https://developer.apple.com/documentation/endpointsecurity)
- [Elasticsearch Query DSL](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html)

