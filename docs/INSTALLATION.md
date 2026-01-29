# Installation and Configuration Guide

Complete guide for installing and configuring macOS CoreSigma.

## Prerequisites

Before installing, ensure you have:

1. **macOS 11.0+ (Big Sur or later)** - Required for ESF and modern Unified Logging
2. **Python 3.9+** - Check with `python3 --version`
3. **Administrator/root access** - Required for ESF event collection
4. **Xcode Command Line Tools** - Install with `xcode-select --install`
5. **Full Disk Access (FDA)** - Required for ESF collector (see below)

### Optional (for Elasticsearch):
6. **Docker Desktop** - For easy Elasticsearch/Kibana deployment
7. **Elasticsearch 8.x** - Can be run via Docker or installed locally

### Granting Full Disk Access

The ESF collector uses Apple's Endpoint Security Framework via `eslogger`, which requires **Full Disk Access** permission for the terminal application running the collector.

**To grant Full Disk Access:**

1. Open **System Settings** (or System Preferences on older macOS)
2. Navigate to **Privacy & Security** → **Full Disk Access**
3. Click the lock icon and authenticate if needed
4. Click the **+** button
5. Add your terminal application:
   - **Terminal.app** - `/Applications/Utilities/Terminal.app`
   - **iTerm2** - `/Applications/iTerm.app`
   - **VS Code Terminal** - Add the IDE application itself
6. **Restart your terminal** after granting access

**To verify FDA is working:**
```bash
# This should output JSON events (not an error)
eslogger exec --format json | head -1
```

If you see `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`, FDA has not been granted correctly.

## Installation Steps

### Step 1: Clone the Repository

```bash
git clone https://github.com/Nebulock-Inc/macos-coresigma.git
cd macos-coresigma
```

### Step 2: Run Setup Script

```bash
./setup.sh
source venv/bin/activate
```

This will:
- Create a Python virtual environment
- Install all dependencies
- Verify prerequisites

### Step 3: Start Elasticsearch and Kibana

#### Option A: Docker Compose (Recommended)

```bash
docker-compose up -d
```

Wait for services to be ready:
```bash
./scripts/start_services.sh
```

#### Option B: Manual Docker

```bash
# Elasticsearch
docker run -d --name elasticsearch \
  -p 9200:9200 -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=true" \
  -e "ELASTIC_PASSWORD=changeme" \
  docker.elastic.co/elasticsearch/elasticsearch:8.11.0

# Kibana
docker run -d --name kibana \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://elasticsearch:9200" \
  -e "ELASTICSEARCH_USERNAME=kibana_system" \
  -e "ELASTICSEARCH_PASSWORD=changeme" \
  --link elasticsearch \
  docker.elastic.co/kibana/kibana:8.11.0
```

### Step 4: Configure Authentication

CoreSigma supports multiple authentication methods. Choose one:

#### Option A: macOS Keychain (Recommended for Development)

```bash
./scripts/setup_credentials.sh
# Enter your Elasticsearch password when prompted
```

This stores credentials securely in macOS Keychain. No environment variables needed.

#### Option B: API Key (Recommended for Production)

```bash
./scripts/setup_credentials.sh --api-key
```

This creates a limited-scope API key and optionally stores it in `~/.coresigma/config.yml`.

#### Option C: Environment Variables

```bash
export ES_USER=elastic
export ES_PASSWORD=changeme
```

Or create a `.env` file:
```bash
cp env.example .env
# Edit .env with your credentials
source .env
```

#### Option D: Config File

Create `~/.coresigma/config.yml`:
```yaml
elasticsearch:
  url: http://localhost:9200
  username: elastic
  password: changeme
  # Or use API key instead:
  # api_key: "your_base64_encoded_api_key"
```

Set permissions:
```bash
chmod 600 ~/.coresigma/config.yml
```

#### Verify Authentication

```bash
./scripts/setup_credentials.sh --test
```

### Step 5: Configure Index Templates

```bash
./scripts/setup_elasticsearch_templates.sh
```

This creates index templates for:
- `macos-telemetry-esf-*` (ESF events)
- `macos-telemetry-ul-*` (UL events)

### Step 6: Deploy Detection Rules

```bash
python3 scripts/deploy_sigma_rules.py
```

This converts all Sigma rules and deploys them as Kibana Detection Rules.

### Step 7: Create Dashboards

```bash
python3 scripts/create_lens_dashboards_ndjson.py
```

## Running Collectors

### ESF Collector (requires sudo + Full Disk Access)

```bash
# With intelligent filtering (recommended)
sudo python3 collectors/esf_collector.py --output elasticsearch

# Run as daemon (background with auto-restart)
sudo python3 collectors/esf_collector.py --output elasticsearch --daemon

# Without filtering (all events - high volume!)
sudo python3 collectors/esf_collector.py --output elasticsearch --no-filtering

# Output to stdout for debugging
sudo python3 collectors/esf_collector.py --output stdout

# Custom log/pid locations
sudo python3 collectors/esf_collector.py --output elasticsearch --daemon \
    --log-file /var/log/my-esf.log --pid-file /var/run/my-esf.pid
```

### UL Collector

```bash
# Standard mode
python3 collectors/ul_collector.py --output elasticsearch

# Run as daemon (background with auto-restart)
python3 collectors/ul_collector.py --output elasticsearch --daemon

# Without filtering
python3 collectors/ul_collector.py --output elasticsearch --no-filtering
```

### Daemon Mode

Both collectors support `--daemon` mode which:
- Runs the collector in the background
- Auto-restarts on failure
- Logs to `/var/log/coresigma-{esf,ul}.log`
- Writes PID to `/var/run/coresigma-{esf,ul}.pid`

**Stop a daemon:**
```bash
# ESF
sudo kill $(cat /var/run/coresigma-esf.pid)

# UL
kill $(cat /var/run/coresigma-ul.pid)
```

**Check daemon status:**
```bash
# Check if running
ps aux | grep -E "esf_collector|ul_collector"

# View logs
tail -f /var/log/coresigma-esf.log
tail -f /var/log/coresigma-ul.log
```

## Running as a Service

### ESF Collector LaunchDaemon

Create `/Library/LaunchDaemons/com.coresigma.esf.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.coresigma.esf</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/macos-coresigma/venv/bin/python3</string>
        <string>/path/to/macos-coresigma/collectors/esf_collector.py</string>
        <string>--output</string>
        <string>elasticsearch</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/coresigma-esf.err</string>
    <key>StandardOutPath</key>
    <string>/var/log/coresigma-esf.log</string>
</dict>
</plist>
```

Load the daemon:
```bash
sudo launchctl load /Library/LaunchDaemons/com.coresigma.esf.plist
```

**Note**: When running as a LaunchDaemon, use the config file method for authentication (`~/.coresigma/config.yml` or set environment variables in the plist).

## Verification

### Check Elasticsearch Connection

```bash
curl -u elastic:changeme http://localhost:9200
```

### Check Indices

```bash
curl -u elastic:changeme "http://localhost:9200/_cat/indices?v" | grep macos
```

### Check Detection Rules

```bash
curl -u elastic:changeme "http://localhost:5601/api/detection_engine/rules/_find" \
  -H "kbn-xsrf: true" | python3 -m json.tool | head -20
```

### Check Events in Kibana

1. Open http://localhost:5601
2. Go to **Discover**
3. Select `macos-telemetry-esf-*` or `macos-telemetry-ul-*` index pattern
4. You should see events flowing in

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues and solutions.

### Quick Fixes

**No events appearing:**
```bash
# Check if collector is running
ps aux | grep collector

# Check collector logs
tail -f /var/log/coresigma-esf.log
```

**Authentication errors:**
```bash
# Test credentials
./scripts/setup_credentials.sh --test

# Reset credentials
./scripts/setup_credentials.sh
```

**Index template issues:**
```bash
# Re-run template setup
./scripts/setup_elasticsearch_templates.sh
```

## Next Steps

- Review [QUICKSTART.md](QUICKSTART.md) for a quick walkthrough
- Read [FILTERING_CONFIGURATION.md](FILTERING_CONFIGURATION.md) for tuning
- Check [KIBANA_SETUP.md](KIBANA_SETUP.md) for dashboard configuration
- Explore rules in `rules/esf/` and `rules/ul/`
