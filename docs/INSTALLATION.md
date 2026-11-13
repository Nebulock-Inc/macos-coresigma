# Installation and Configuration Guide

Complete guide for installing and configuring macOS CoreSigma.

## Prerequisites

Before installing, ensure you have:

1. **macOS 13 or later** - `eslogger` arrived in macOS 13, and older releases list fewer eslogger events. At startup the ESF collector runs `eslogger --list-events`, subscribes to the events the running release lists, and, if it skips any, prints one line naming them (in the daemon's log too; macOS 26 lists all of them); rules on those events can't fire on that Mac. The collector has been run on macOS 26 and unit-tested against shorter listings.
2. **Python** - The collectors use only the standard library and run on the stock `python3` (3.9). The conversion and deploy tooling (`requirements.txt`) needs Python 3.10 to 3.14 (pySigma 1.5.1; 3.15 has no PyYAML wheel yet, and PyYAML built without libyaml breaks pySigma's import); `setup.sh` builds its venv with the newest of `python3.14` … `python3.10` on your `PATH`, else `python3` if it's in that range, stops with a message if there is none, and rebuilds a venv made with a Python outside the range. The ClickHouse backend needs Python 3.13 or later and is installed separately, into the same venv: `pip install -r requirements-clickhouse.txt`. Without it, ClickHouse conversion isn't available and the tests that need it are skipped.
3. **Administrator/root access** - Required for ESF event collection
4. **Xcode Command Line Tools** - Install with `xcode-select --install`
5. **Full Disk Access (FDA)** - Required for ESF collector (see below)

### Optional (for Elasticsearch):
6. **Docker Desktop** - For the bench (`scripts/bench_up.sh`)
7. **Elasticsearch 8.x and Kibana** - The bench runs 8.19.25

### Granting Full Disk Access

The ESF collector uses Apple's Endpoint Security Framework via `eslogger`, which requires **Full Disk Access** permission for the terminal application running the collector, or, for the LaunchDaemon, for its Python (see [Running as a Service](#running-as-a-service)).

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
# This should output a JSON event (not an error)
sudo eslogger exec | head -1
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
./scripts/bench_up.sh elastic
```

This writes `.env` (the bench password and random Kibana encryption keys), starts Elasticsearch and Kibana,
waits until both are healthy, and creates the index templates (Step 5).

#### Option B: An Existing Elasticsearch and Kibana

Point the scripts at them with `ES_URL` and `KIBANA_URL`, configure credentials (Step 4), and create the index templates (Step 5).

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

With the Docker bench (Step 3, Option A), the password is in `.env`:
```bash
export ES_USER=elastic ES_PASSWORD="$(grep '^ELASTIC_PASSWORD=' .env | cut -d= -f2-)"
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

The config file is read only when PyYAML is installed in the interpreter that runs the collector (the venv has it; the stock `python3` doesn't).

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

This creates all 69 rules as Kibana detection rules, disabled (`--enable` enables them): EQL rules for the single-event rules and the two ordered correlations (EQL sequences), ES|QL rules for the other correlations. `--target splunk` writes all 69 rules to `splunk/coresigma_app` instead.

### Step 7: Create Dashboards

```bash
python3 scripts/create_lens_dashboards_ndjson.py
```

## Running Collectors

### ESF Collector (requires sudo + Full Disk Access)

sudo drops environment variables, and under sudo the Keychain lookup runs as root, not as you. Keep the credentials with `--preserve-env`. Run it with `/usr/bin/python3`: sudo keeps your `PATH` on macOS, so with the venv active a bare `python3` would run the venv's Python (owned by you) as root:

```bash
# With filtering (the default; see FILTERING_CONFIGURATION.md)
sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY /usr/bin/python3 collectors/esf_collector.py --output elasticsearch

# Run as daemon (background; restarts eslogger whenever it exits)
sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY /usr/bin/python3 collectors/esf_collector.py --output elasticsearch --daemon

# Without filtering (every subscribed event - high volume!)
sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY /usr/bin/python3 collectors/esf_collector.py --output elasticsearch --no-filtering

# Output to stdout for debugging
sudo /usr/bin/python3 collectors/esf_collector.py --output stdout

# Custom log/pid locations
sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY /usr/bin/python3 collectors/esf_collector.py --output elasticsearch --daemon \
    --log-file /var/log/my-esf.log --pid-file /var/run/my-esf.pid
```

### UL Collector

The UL collector has no filter of its own: `log stream` delivers only the lines its predicate selects (see [UL_TELEMETRY_TUNING.md](UL_TELEMETRY_TUNING.md)).

```bash
# Standard mode
python3 collectors/ul_collector.py --output elasticsearch

# Run as daemon: as a normal user, give pid and log paths you can write
python3 collectors/ul_collector.py --output elasticsearch --daemon \
    --pid-file "$HOME/Library/Logs/coresigma-ul.pid" --log-file "$HOME/Library/Logs/coresigma-ul.log"
```

Both collectors also take `--output splunk` (Splunk HEC at `--hec-url`, token in `SPLUNK_HEC_TOKEN`), `--output file --output-file PATH`, `--es-url`, and `--insecure` for the bench's self-signed certificates.

### Daemon Mode

Both collectors support `--daemon` mode which:
- Runs the collector in the background
- Restarts it: the ESF collector restarts eslogger whenever it exits (backing off up to 60 s when it can't start); the UL collector restarts 5 s after an error
- Logs to `/var/log/coresigma-{esf,ul}.log` and writes its PID to `/var/run/coresigma-{esf,ul}.pid` by default. Only root can write there, so a UL daemon run as a normal user needs `--pid-file` and `--log-file`, as above; without them it exits without a message.

**Stop a daemon:**
```bash
# ESF
sudo sh -c 'kill "$(cat /var/run/coresigma-esf.pid)"'   # the pid file is root-only, so cat runs under sudo too

# UL (the pid file you gave it)
kill $(cat "$HOME/Library/Logs/coresigma-ul.pid")
```

A collector flushes the documents it still holds before it exits, so it can take a few seconds after the signal (longer while Elasticsearch or HEC is down, since it retries before spooling). Wait for it to exit rather than following up with `kill -9`, which loses what wasn't flushed.

### Spool

The collectors never drop a document silently. When Elasticsearch or Splunk HEC can't take a batch (after five retries with backoff for a 429, a 5xx or a connection error, or at once for any other 4xx such as a mapping error), the documents go to a spool file and a line on stderr names it. After an outage, later batches are spooled without a request for 60 s, then one request probes the target again.

- **Where**: `.coresigma/spool/` in the home directory of the user the collector runs as (not `$HOME`). The ESF collector runs under sudo as root, so its undelivered events go to `/var/root/.coresigma/spool/`, owned by root: listing, reading, re-sending and deleting them all need `sudo`. The UL collector run as you spools to `~/.coresigma/spool/`.
- **Files**: `<target>-<UTC time>-<pid>-<n>.ndjson`, where the target is the index prefix (`macos-telemetry-esf`, `macos-telemetry-ul`) or, for Splunk, the sourcetype with `-` for `:` (`coresigma-esf` for sourcetype `coresigma:esf`, `coresigma-ul` for `coresigma:ul`). Documents the target refused with a 400 (the batch, or a `_bulk` item such as a mapping error) go to `<target>-<UTC time>-<pid>-<n>.rejected.ndjson` instead: sending them again fails the same way until the cause is fixed. Each line is `{"error": ..., "doc": ...}`. The directory is 0700 and the files 0600.
- **No size cap**: the spool grows until you re-send or remove it, so watch it during a long outage (about 0.8 MB a second for a busy laptop's Unified Log in testing).
- **Re-send memory** (a known limitation): `scripts/resend_spool.py` reads each spool file whole into memory before sending it. The collectors write one file per batch (500 documents at most), so even a long outage's gigabytes of spool are many small files; a large single file, such as spool files concatenated into one, needs its whole size in memory.

To re-send spooled documents once the cause (the `error` in each line) is fixed, use `scripts/resend_spool.py`. It sends them through the collectors' own sender, in batches of 500 with the same retries and the same credentials (`ES_API_KEY`, `ES_USER`/`ES_PASSWORD`, the Keychain or the config file; nothing on a command line):

```bash
sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY /usr/bin/python3 scripts/resend_spool.py --delete   # ESF: root's spool (root can't read your Keychain)
python3 scripts/resend_spool.py --delete               # UL: your spool
python3 scripts/resend_spool.py --output splunk --delete   # Splunk HEC spools (token in SPLUNK_HEC_TOKEN)
```

It sends only the spool files of its `--output` (`macos-telemetry-*` for Elasticsearch, `coresigma-*` for Splunk); it refuses named files of another target and leaves the others in the spool directory alone. Without file names it sends every such spool file but the `.rejected.ndjson` ones, which it counts and reports, exiting 1 while any are there; name them to re-send them once their `error` is fixed. A batch that fails again is spooled to a new file (a 400 to a new `.rejected.ndjson` file). With `--delete`, each source file is then removed: the documents that failed are in the new files and the others were sent, so a later run sends only the failures. If a batch can't be spooled again (an unwritable spool directory, a full disk), the script stops on that file and rewrites it to hold the batch it stopped on and everything after it; documents of that batch that were already sent are sent again on the next run. Don't run `--delete` while a collector is spooling: spool files are written in place under their final name, so a file still being written could be read and removed. `scripts/replay_capture.py`'s OpenSearch spools carry the same `macos-telemetry-*` names as Elasticsearch's: re-send them with `--es-url` pointing at OpenSearch, and without `--delete` until you've checked them, or a plain run sends them to Elasticsearch. Without `--delete` no file is removed or changed, and a later run sends every document again, including those in the new files. The script exits 1 if any document was spooled again or rejected, or if it skipped a `.rejected.ndjson` file. Don't send a spool in one `_bulk` request: an 80-second outage spooled 65 MB in testing, over Elasticsearch's default per-request indexing limit (HTTP 429). Spool lines don't keep the document's `_id`, so a document Elasticsearch had indexed before the error is indexed again.

**Check daemon status:**
```bash
# Check if running
ps aux | grep -E "esf_collector|ul_collector"

# View logs
sudo tail -f /var/log/coresigma-esf.log   # root-only
tail -f "$HOME/Library/Logs/coresigma-ul.log"   # the --log-file you gave the UL daemon
```

## Running as a Service

### ESF Collector LaunchDaemon

The daemon runs this checkout's code, and its Python, as root. Keep both writable only by root: a checkout in your home folder, or a Homebrew Python (owned by your user), lets anything running as you change what root runs.

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

Check that it stays up (`state = running` with a `pid`; `runs` climbing every 10 s means it keeps exiting) and read its output, which goes to the `StandardErrorPath` file (with `--output elasticsearch` the `StandardOutPath` file stays empty):
```bash
sudo launchctl print system/com.coresigma.esf | grep -E 'state =|pid =|runs =|last exit code'
sudo tail -f /var/log/coresigma-esf.err
```

To stop it, use `bootout`: KeepAlive restarts a killed collector. Delete the plist too, or it starts again at boot:
```bash
sudo launchctl bootout system/com.coresigma.esf
sudo rm /Library/LaunchDaemons/com.coresigma.esf.plist
```

**Note**: A LaunchDaemon runs as root, so the Keychain lookup doesn't see your credentials. Set `ES_USER`/`ES_PASSWORD` (or `ES_API_KEY`) under `EnvironmentVariables` in the plist, or use root's config file, `/var/root/.coresigma/config.yml` (with the venv's Python, which has PyYAML). The LaunchDaemon's Python needs Full Disk Access of its own; the grant to your terminal (above) doesn't cover it. Grant it to the interpreter the venv links to, not to `venv/bin/python3`, which is a symlink: run `realpath /path/to/macos-coresigma/venv/bin/python3`, then in **Full Disk Access** click **+**, press Cmd-Shift-G and paste that path (on a managed Mac, a PPPC profile for that path instead). Homebrew's Python is ad-hoc signed, so the grant holds for that build only: when `brew upgrade` changes the path, grant the new one. Without the grant the collector exits within seconds with status 1, launchd restarts it every 10 s, and `/var/log/coresigma-esf.err` repeats `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`.

## Verification

### Check Elasticsearch Connection

```bash
curl -u "elastic:$ES_PASSWORD" http://localhost:9200
```

### Check Indices

```bash
curl -u "elastic:$ES_PASSWORD" "http://localhost:9200/_cat/indices?v" | grep macos
```

### Check Detection Rules

```bash
curl -u "elastic:$ES_PASSWORD" "http://localhost:5601/api/detection_engine/rules/_find" \
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
sudo tail -f /var/log/coresigma-esf.log   # root-only
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
